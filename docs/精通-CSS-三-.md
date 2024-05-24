# 精通 CSS（三）

> 原文：[`zh.annas-archive.org/md5/6E7477B42C94A8805922EA40B81890C7`](https://zh.annas-archive.org/md5/6E7477B42C94A8805922EA40B81890C7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：网络字体

很长一段时间，我们只能使用一些基本字体，比如 Times New Roman、Georgia 和 Arial。如果你想要更远的偏离，你就会面临字体在别人查看你的网站时不显示的风险，因为他们可能没有安装那个字体。在这段时间里，每当我们想使用一个花哨的字体时，我们都必须将它保存为一个图片，这曾经带来了许多问题。幸运的是，现在网络字体正式出现了，这使我们能够在所有计算机上使用大量出色的字体。在本章中，您将学习有关网络字体的知识。首先，您将学习`@font-face`规则的基本语法，然后我们将讨论`@font-face`可能有点棘手，接着我们将介绍提供字体并将其传递到您的网站的服务，比如 Google Web Fonts 和 Typekit。最后我们将介绍图标字体。

# @font-face 属性

让我们从学习如何使用`@font-face`属性向网站添加网络字体开始这一章。首先，我们将在网站的一个文件夹中添加一个 OTF 文件，然后我们将在我们的 CSS 中定义一个新字体，最后，我们将将该 CSS 应用到我们网页上的元素。

# 直接将字体文件添加到网站

在本节的项目文件中，我们有一个名为`fonts`的新文件夹。在这个文件夹里，有一个名为`LeagueGothic-Regular`的 OTF 文件：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00289.jpeg)

现在这个字体就存在于我们网站的文件夹中，访问我们网站的最终用户将下载这个字体到他们的计算机上，就像他们下载 HTML、CSS 文件和图片一样。但首先，我们必须告诉它这样做，并在我们的 CSS 中查找它。

# 在我们的 CSS 中定义和应用新字体

在 CSS 中，就在我们的重置下面，让我们添加一个名为字体的新部分。添加`@font-face`；这将允许我们声明一个新字体：

```css
/****************
Fonts
****************/
@font-face {
    font-family: 'League-Gothic';
}
```

我将首先声明字体名称，可以是任何东西。所以即使字体叫`League Gothic-Regular`，你也可以把它命名为`Bananas Serif`。让我们称之为`League Gothic`，因为这是最有意义的。

我用单引号括起来有两个原因。一是它是一个网络字体，二是它有多个单词，应该总是用引号括起来，就像你会引用`'Times New Roman'`一样。接下来，我们将声明这个字体存在的位置，使用`src`属性：

```css
@font-face {
  font-family: 'League Gothic';
 src: url('../fonts/LeagueGothic-Regular.otf');
}
```

我们要确保拼写与 OTF 文件的名称完全匹配。请注意我使用了`../`。这是一条指令，要跳出`CSS`文件夹，然后进入`fonts`文件夹，查找`LeagueGothic-Regular.otf`。这是我们项目的文件夹结构：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00290.jpeg)

现在我们可以使用我们习惯的`font-family`属性将此字体添加到任何规则集中。我们也可以像通常一样指定回退，以防字体未被下载。在样式表的“全局”部分，有一个`h1`的规则集和另一个`h2`的规则集：

```css
h1 {
  font-weight: 700;
  font-size: 80px;
  color: #0072ae;
  margin-bottom: 10px; 
}
h2 {
  font-size: 30px;
  margin-bottom: 10px;
  color: #eb2428;
  font-weight: 700; 
}
```

在`h2`规则集下面，我们将添加另一个，针对`h1`标签和`h2`标签添加我们的新网络字体。

```css
h1, h2 {
  font-family: "League Gothic", Arial, Helvetica, sans-serif;
}
```

以下是前面代码的输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00291.jpeg)

以下是我们的字体以前是什么样子的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00292.jpeg)

当我们刷新时，哇！非常时尚的网络字体被添加到我们的网站上：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00293.jpeg)

我们已经成功地将网络字体添加到我们的网站，但不幸的是，我们所做的实际上并不能在所有浏览器中工作。由于排版可能是网页上最重要的事情，我们必须找到一个更好的解决方案。

# @font-face：有点棘手的事情

表面上，网络字体很容易，但实际上，当我们希望它们在所有现代浏览器中工作时，它们变得复杂起来。一些浏览器使用 OTF，其他使用 WOFF，还有一些使用 EOT、RTF 和 SVG。让我们来看看使用`@font-face`属性使网络字体工作的完整设置。

# 使其在所有浏览器中工作

```css
CSS Tricks, that describes the ideal @font-face at-rule. (*Using @font-face* by *Chris Coyier* of CSS-tricks.com, August 25, 2016, https://css-tricks.com/snippets/css/using-font-face/.)
```

```css
@font-face {
  font-family: 'MyWebFont';
  src: url('webfont.eot'); /* IE9 Compat Modes */
  src: url('webfont.eot?#iefix') format('embedded- 
  opentype'), /* IE6-   
  IE8 */
  url('webfont.woff2') format('woff2'), /* Super Modern 
  Browsers */
  url('webfont.woff') format('woff'), /* Pretty Modern   
  Browsers */
  url('webfont.ttf') format('truetype'), /* Safari, 
  Android, iOS */
  url('webfont.svg#svgFontName') format('svg'); /* Legacy 
  iOS */
}
```

这不仅是寻找字体的七个不同的`url`，还有五种不同的字体文件：`eot`、`woff2`、`woff`、`ttf`和`svg`！正如前面的代码示例中的注释所解释的那样，每种字体文件格式都支持不同的浏览器版本。

根据同一篇*CSS Tricks*文章，只有`woff`和`woff2`文件格式将为您提供相当不错的浏览器支持（Chrome 5+，Safari 5.1+，Firefox 3.6+，IE9+，Edge，Android 4.4+和 iOS 5.1+）：

```css
@font-face {
 font-family: 'MyWebFont';
 src: url('myfont.woff2') format('woff2'),
      url('myfont.woff') format('woff');
}
```

但这仍意味着你需要获取和托管两种文件格式，这当然不像五种文件格式那么具有挑战性，但也不是一件轻而易举的事情。

网络字体比我们希望的要复杂一些。大多数情况下，字体是通过服务提供的，这正是我们将在接下来的两个部分中看到的。Google Web 字体、Typekit 和其他服务使网络字体变得更加容易，并提供多种不同粗细和样式的高质量字体。在下一节中，我们将使用来自 Google 字体的字体。

# Google Web 字体

托管自己的网络字体并使用适当的 CSS 来支持所有浏览器稍微有些挑战。有更简单的方法来解决这个问题。我真的很喜欢 Google 字体；它们非常容易使用，而且 100%免费。字体的质量也非常好。在这一部分，我们将用 Google Web 字体替换我们托管的字体。第一步是去 Google 字体并选择我们将使用的两种字体。在两个 HTML 文档的标题中添加 CSS 文件的链接。最后，在我们的 CSS 中添加字体名称。

# 查找 Google 字体

前往[`fonts.google.com/`](https://fonts.google.com/)，搜索我们的标题字体：`Maven`。很酷的是，我们可以输入一些文本，比如说我们的网站标题，来看看这种字体中特定单词的样子。大多数字体服务都会输出类似于这样的东西：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00294.jpeg)

所以我们可以只输入 Old Chompy 并了解一下这个字体在我们的`h1`上会是什么样子。我们甚至可以增加字体大小。让我们搜索并使用**Maven Pro**；通过点击红色加号图标来实现。在屏幕底部，我们应该选择了一个字体系列：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00295.jpeg)

接下来我们将寻找并获取**Droid Serif**字体。底部将显示选择的 2 个字体系列：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00296.jpeg)

让我们打开底部的东西，获取更多信息：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00297.jpeg)

我们快要完成了；我们只是在验证和审查。从底部滑出的面板向我们展示了一些有趣的东西：

+   加载时间

+   如何在我们的页面上嵌入字体文件

+   如何在我们的 CSS 中指定这些字体

我可以通过转到*自定义*选项卡来添加额外的字体粗细和字体样式：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00298.jpeg)

在这里，我可以选择额外的字体粗细和字体样式。如果我选择太多，加载时间指示器就会变慢：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00299.jpeg)

我们只需要 Droid Serif 的普通、斜体和粗体，以及 Maven Pro 的普通和粗体，这从慢到中等：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00300.jpeg)

现在，我们的加载速度设置为中等。我真的很想处于绿色状态，但至少我们没有处于红色状态，所以我们就接受这个吧。

让我们回到*嵌入*选项卡，并复制这些字体文件的链接：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00301.jpeg)

这段代码实际上只是一个样式表。让我们把它粘贴到`index.html`和`shark-movies.html`的`head`标签中：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00302.jpeg)

我们可以看到这是我们用来指定样式的相同`<link/>`：

```css
<link href="https://fonts.googleapis.com/css?family=Droid+Serif:400,400i,700|Maven+Pro:400,700" rel="stylesheet">
```

实际上，这是一个指向`fonts.googleapis.com`的样式表，这就是它获取字体的地方。它实际上显示了两种字体选择，即：Droid Serif 和 Maven Pro。Google 字体托管在 Google 的服务器上，我们只需要进行一次 http 请求，这对性能来说很好。

# 在 CSS 中应用字体

现在我们想在我们的 CSS 中使用这些字体。正如你所看到的，他们确切地告诉我们如何做到这一点：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00303.jpeg)

首先，在我们的`h1`和`h2`中用`Maven Pro`替换`League Gothic`：

```css
h1 {
  font-size: 80px;
  color: #0072ae;
  margin-bottom: 10px; 
  font-family: "Maven Pro", Arial, Helvetica, sans-serif;
  font-weight: 700;
}
h2 {
  font-size: 30px;
  margin-bottom: 10px;
  color: #eb2428;
  font-family: "Maven Pro", Arial, Helvetica, sans-serif;
  font-style: italic;
}
```

下一步是添加**Droid Serif**。我实际上想确保我们的所有正文、所有段落、锚点和除了`h1`标签和`h2`标签之外的所有内容都使用**Droid Serif**。我们会多加一些小心，所以我们将添加备用字体。我们将指定备用字体为`Georgia`，然后是`Times New Roman`，然后是默认的`serif`，如下所示：

```css
body {
  background-color: #dcdcdc;
  font-family: "Droid Serif", Georgia, "Times New Roman", sans-serif;
  font-weight: 100;
  font-size: 16px; 
}
```

保存这些更改。现在当我们转到我们的网站时，在刷新之前，我们可以看到我们的`h1`和`h2`应用了**League Gothic**，然后我们的通用`Arial`用于段落：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00304.jpeg)

刷新后，我们得到了我们的新字体：这非常好。我们的`h1`和`h2`使用**Maven Pro**，我们的其他所有文本使用**Droid Serif**：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00305.jpeg)

在本节中，您学会了如何使用 Google 提供的免费字体资源。使用 Google 的 Web 字体是地球上最简单的使用字体的方式，除了根本不指定字体。在下一节中，我们将看看另一个很棒的字体资源——Typekit，这是 Adobe 提供的订阅字体库，提供了大量高质量的字体。

# Adobe Typekit

Adobe Typekit 是出色的订阅字体服务之一。但是，为什么要使用 Typekit，当 Google 提供免费字体时呢？我不想说您得到了 Google 的报酬，因为我认为 Google 的字体质量很高，选择很多，但我认为 Typekit 的字体选择和质量也非常出色。然而，我认为最好的功能是，这个字体服务对所有*Adobe Creative Cloud*订阅者免费。因此，如果您订阅了创意云套件，例如 Photoshop 和 Illustrator 等工具，您也可以访问 Typekit 上的每种字体。如果您不是 Adobe Creative Cloud 的订阅者，您也可以单独订阅 Typekit，这绝对值得。另一个很酷的功能是，您可以很容易地将字体同步到 Photoshop 和 Illustrator，并在这些工具中进行设计，而使用 Google Web 字体则不那么容易。在本节中，我们将从 Typekit 向我们的网站添加另一种字体。

# 从 Typekit 中选择字体

让我们去[`typekit.com/`](https://typekit.com/)：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00306.jpeg)

我将使用我的 Adobe ID 和密码登录。如果您没有 Adobe ID，或者既不是 Adobe 的创意云会员，也不是 Typekit 的独立服务会员，您需要注册才能跟着进行。我们可以浏览看起来不错的字体，但让我们实际搜索我们想要的字体`expo sans`：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00307.jpeg)

选择 Expo Sans 后，我们来到一个显示不同粗细和样式的页面。我们有两个基本选项可以使用，即全部同步或添加到套件。同步是为了将此字体同步到我的计算机，以便在 Photoshop、Illustrator 和其他 Adobe 产品中使用。将其添加到套件中允许我在 Web 上使用它。所以让我们这样做，然后点击“添加到套件”按钮：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00308.jpeg)

然后，我们将点击“创建套件”按钮，选择 Expo Sans Pro：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00309.jpeg)

我们将把它命名为`Old Chompy`，这是我们网站的名称。然后，对于域名，我将使用`localhost:8888`和`oldchompy.com`；`localhost:8888`将用于开发，`oldchompy.com`将用于网站投入生产后，因为那将是域名。然后我们将点击“继续”：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00310.jpeg)

这是使用 Typekit 的一个小缺点；您必须选择一个域。在整个课程中，我们一直通过文件系统直接向浏览器提供页面。我们还没有需要设置本地开发环境。通常，直到开始使用 AJAX 调用、服务器端代码或内容管理系统（CMS）时，您才需要这样做。为了确保 Typekit 的字体不能随意在任何地方使用，Typekit 将它们交付给特定的域名。

我会使用`localhost:8888`，这是我的本地服务器通过 MAMP 在我的电脑上运行的地方。建立本地开发环境远远超出了这个项目的范围，所以不要觉得你必须完全跟着这个特定的步骤。我还会输入这个站点理论上将公开的域名，即`localhost:8888`和`oldchompy.com`。

在我们进入这个嵌入代码之前，让我们回到网站，看看 URL 的第一部分：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00311.jpeg)

请注意，我现在通过`localhost:8888`以不同的方式访问我的网站。这是我的本地服务器正在运行的地方。这与我之前的访问方式不同，之前是直接通过文件系统，进入文件库网页服务器文档，然后进入我的站点文件夹。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00312.jpeg)

我将为整个课程的这一部分做这个。就像我之前说的，如果你无法跟上这部分，不要担心。

# 将字体添加到网站

让我们回到 Typekit 上的嵌入代码；这个屏幕给了我们 JavaScript 嵌入代码：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00313.jpeg)

我会复制这个，转到 Sublime Text，然后粘贴到我们 HTML 文件的`<head></head>`标签中。我会在我的`shark-movies.html`页面中做同样的事情，并保存：

```css
<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">

<!-- mobile -->
  <meta name="viewport" content="width=device-width, initial-scale=1.0, minimum-
  scale=1.0">

<!-- description -->
  <title>Section 7-Web Fonts - Mastering CSS</title>

<!-- stylesheets -->
  <link rel="stylesheet" href="css/style.css">

<!-- fonts -->
  <link href='http://fonts.googleapis.com/css?
  family=Droid+Serif:400,700|Maven+Pro:400,700' rel='stylesheet' type='text/css'>
 <!-- Typekit -->
<script src="img/ycq4ynz.js"></script>
<script>try{Typekit.load({ async: true });}catch(e){}</script>
```

好的，回到 Typekit。我会点击“继续”按钮，进入下一步：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00313.jpeg)

在下一个屏幕上，我们可以做几件事，包括选择我们想要包括的字重和样式。默认情况下，选择了常规、斜体、粗体和粗斜体，总重量为 134K。我可以选择其他字重和样式，它会显示给我看套件大小如何变化。现在，我会保留默认的四种字重和样式。接下来，让我们点击顶部附近的“在 CSS 中使用字体”链接：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00314.jpeg)

这给了我们想要使用的字体的名称，即`expo-sans-pro`：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00315.jpeg)

让我们复制`expo-sans-pro`，然后回到 CSS 文件。只是为了好玩，把它粘贴在我们的`h1`选择器中，在`Maven Pro`之前，然后保存：

```css
h1 {
  font-weight: 700;
  font-size: 100px;
  color: #0072ae;
  margin-bottom: 10px; 
  font-family: 'expo-sans-pro', 'Maven Pro', Arial, sans-serif;
  font-style: normal;
  font-weight: bold;
}
```

不过，在这个工作之前，我们实际上需要点击“发布”按钮：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00316.jpeg)

现在，它会告诉我们可能需要几分钟才能完全分布到他们的网络中，但通常情况下会比那快得多。如果我们现在去我们的网站并刷新，我们可以看到字体的变化：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00317.jpeg)

这是*Expo Sans Pro*，一个非常漂亮的字体。我几乎比*Maven Pro*更喜欢它，这就是使用 Typekit 或付费字体服务的好处之一：它们有如此多令人难以置信的高质量字体。

因此，总的来说，我们使用了 Typekit 的一个漂亮的字体，我很想使用它来代替*Maven Pro*，但我认为我们会保留 Maven。从 Typekit 这样的服务应用字体涉及一些额外的步骤，但总的来说，它仍然比自己托管字体要容易。在下一节中，我们将看看另一种我们可以使用的字体，叫做图标字体。

# 图标字体

在这一节中，我们将看看如何将图标字体添加到我们的网站。当您的网站上有实心、彩色的图标时，图标字体可以很好地工作。与将每个图像作为单独的请求不同，所有图标都是整个字体的一部分的请求——这更快。由于我们不使用图像，我们可以使用 CSS 来提供图像的颜色和大小，这意味着我们可以使图标更大而不会失去保真度。我们将在页脚中展示我们的图标字体。因此，首先我们必须为两个页面构建页脚，然后我们将从 ZURB Foundation 下载一个免费的图标字体。接下来，我们将使用 CSS 将图标字体添加到我们的网站。最后，我们将为图标添加一个`:hover`状态，以尝试如何使用 CSS 来改变它们的外观。

# 构建页脚

所以这是我们在最终网站的页脚中所追求的目标：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00318.jpeg)

我们希望有三列链接，每个链接都有一个图标。 传统上，您可以使用图像来实现这一点，但是如果您有很多图像，这可能会影响性能。 传统上，许多人将所有这些图标分组到一个称为“图像精灵”的图像文件中，并将其加载为背景图像，仅显示所需图像的背景图像部分，使用`background-position`属性。 这将确保您只有一个网络请求，而不是 10 个，因为您将使用一个图像文件。 这个过程很棘手，因为您必须使用`background-position`属性来找到您要查找的图像。 更大的问题是，当涉及更改颜色或添加新图标时，您必须更新精灵，然后更新 CSS。 图像精灵的最大问题是当您必须继续支持 HiDPI 或* Retina *设备时。 图标字体并不完美，但它们解决了这些棘手的问题。

在我们的两个 HTML 文件中，让我们复制页脚的这段代码：

```css
<!-- 
================ 
Footer
================
--> 
<footer>
  <div class="wrapper grouping">
    <ul>
      <li class="list-heading">Social</li>
      <li><a href=""><span></span>Facebook</a></li>
      <li><a href=""><span></span>Twitter</a></li>
      <li><a href=""><span></span>Google+</a></li>
      <li><a href=""><span></span>Dribble</a></li>
    </ul>
    <ul>
      <li class="list-heading">Interwebs</li>
      <li><a href=""><span></span>Github</a></li>
      <li><a href=""><span></span>Stack Overflow</a></li>
      <li><a href=""><span></span>Zurb Foundation</a></li>
    </ul>
    <ul>
      <li class="list-heading">Resources</li>
      <li><a href=""><span></span>Smashing Mag</a></li>
      <li><a href=""><span></span>Treehouse</a></li>
      <li><a href=""><span></span>Designer News</a></li>
    </ul>
    <p class="legal-copy clear">Ol' Chompy - The Shark Site</p>
  </div><!-- end wrapper -->
</footer>
```

这是没有添加任何 CSS 的样子：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00319.jpeg)

我们需要整理一下。 就在媒体查询开始之前，让我们放一些 CSS 使页脚吸附到位：

```css
/***************
Footer
***************/
footer {
  background: #fff url('../images/seaweed.jpg') repeat-x 0 0;
  padding: 142px 0;
  font-size: 14px;
  line-height: 1.7; 
}
footer ul {
  float: left;
  margin: 0 100px 50px 0; 
}
footer .list-heading {
  text-transform: uppercase;
  color: #333;
  margin-bottom: 30px;
  font-size: 17px; 
  font-family: 'Maven Pro', Arial, Helvetica, sans-serif;
}
footer a {
  color: #333;
}
footer li, 
footer p {
  color: #4D4D4D; 
  line-height: 30px;
}
footer li {
  margin-bottom: 10px;
}
.legal-copy {
  text-align: right;
  font-size: 10px;
}
```

这样看起来好多了：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00320.jpeg)

# 从 ZURB Foundation 下载免费图标字体

让我们转到 Zurb 页面，查看 Foundation Icon Fonts 3 [`zurb.com/playground/foundation-icon-fonts-3`](http://zurb.com/playground/foundation-icon-fonts-3)：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00321.jpeg)

这个图标集中有很多不同的图标字体。 让我们点击“下载字体”按钮。 在 Chrome 中，它将在左下角下载； 我们只需将文件夹放在桌面上，然后双击解压缩它。 然后，我们可以打开`Foundation-icons`文件夹：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00322.jpeg)

在这个文件夹中有一个 CSS 文件，几个字体文件，一个名为`preview.html`的文件，然后是一个充满`svgs`的文件夹。 CSS 文件的样子如下：

```css
@font-face {
  font-family: "foundation-icons";
  src: url("foundation-icons.eot");
  src: url("foundation-icons.eot?#iefix") format("embedded-opentype"),
       url("foundation-icons.woff") format("woff"),
       url("foundation-icons.ttf") format("truetype"),
       url("foundation-icons.svg#fontcustom") format("svg");
  font-weight: normal;
  font-style: normal;
}
```

# 将图标字体添加到我们的网站

在我们的 CSS 中，我们可以看到`@font-face`规则加载不同的字体文件，就像我们在本章的第二部分中查看的 Web 字体一样。 在此之下是每个图标字体的类名，后面是伪元素 before：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00323.jpeg)

我们已经了解了伪类，但还没有了解伪元素。 伪元素`:before`和`:after`基本上是“虚拟”的元素，它们将出现在您调用的元素之前或之后。 这是使用 CSS 添加内容的一种巧妙方式。 它添加的内容是与类名相关的图标。 因此，如果我们转到选择器的底部，我们可以看到它实际上设置了字体系列，所有不同的字体属性以及其他一些东西：

```css
... {
  font-family: "foundation-icons";
  font-style: normal;
  font-weight: normal;
  font-variant: normal;
  text-transform: none;
  line-height: 1;
  -webkit-font-smoothing: antialiased;
  display: inline-block;
  text-decoration: inherit;
}
```

之后，在下一个选择器中，您可以看到每个图标都添加了内容到其伪元素：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00324.jpeg)

这些内容是与字体系列中的字母对应的代码。 例如：

```css
fi-address-book:before { content: "\f100"; }
```

这是与地址簿图标对应的内容在字体系列中。 我们在这些代码行中看到的`fi-`前缀代表**foundation icon**。 如果您不完全理解所有这些，不要担心； 主要问题是我们需要将此 CSS 复制到我们的 CSS 文件中。 它有 594 行代码，所以我不想将其包含在我们现有的样式表中，因为这将使它比我想要的更加臃肿。 所以我们有两个选择。 我们可以从 CSS 文件中删除并找出我们计划使用的图标，或者我们可以将 CSS 文件链接到单独的文件中。 让我们单独链接到它-这样我们在需要时可以使用整个图标字体库。 理想情况下，稍后，我们将在转到生产之前从未使用的图标字体中删除出来，因为将该文件缩减到只使用的 10 个图标将其从 20kb 减少到 1kb！

让我们将此文件保存在我们项目的`css`文件夹中，并将其命名为`icons.css`：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00325.jpeg)

现在我们将进入我们的`index.html`文件，在这个文件的头部添加一个链接到`foundation-icons.css`，就在`style.css`的链接下面：

```css
<!-- stylesheets -->
 <link rel="stylesheet" href="css/style.css">
 <link rel="stylesheet" href="css/foundation-icons.css">
```

保存这个，复制它，并跳到 Shark Movies 粘贴它，然后保存。

接下来，让我们创建一个名为`icons`的新文件夹。我们将四个不同的字体文件拖到这个新文件夹中：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00326.jpeg)

现在这四个不同的字体文件都在`icons`文件夹中，回到`icons.css`文件，我们只需要改变源指向刚刚放置这些字体文件的文件夹。让我们在 url 前面加上`../icons/`，像这样：

```css
@font-face {
  font-family: "foundation-icons";
  src: url("../icons/foundation-icons.eot");
  src: url("../icons/foundation-icons.eot?#iefix") format("embedded-opentype"),
       url("../icons/foundation-icons.woff") format("woff"),
       url("../icons/foundation-icons.ttf") format("truetype"),
       url("../icons/foundation-icons.svg#fontcustom") format("svg");
  font-weight: normal;
  font-style: normal;
}
```

所以现在我们的 URL 指向了正确的文件夹。

现在我们需要在我们的 HTML 元素中添加图标类来加载图标。但首先我们需要确定使用哪些类。`preview.html`文件在这方面非常有帮助，所以让我们从`foundation-icons`文件夹中打开它：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00327.jpeg)

当我们打开它时，我们可以看到以不同大小显示的图标。搜索 Facebook，这里我们可以看到我们正在寻找的 Facebook 图标以及与之对应的类名`fi-social-facebook`：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00328.jpeg)

复制除了那个类名的句号之外的所有内容，并将其粘贴到`index.html`中 Facebook 的链接旁边：

```css
<footer>
  <div class="wrapper grouping">
    <ul>
      <li class="list-heading">Social</li>
      <li><a href=""><span class="fi-social-facebook"></span>Facebook</a></li>
      <li><a href=""><span></span>Twitter</a></li>
      <li><a href=""><span></span>Google+</a></li>
      <li><a href=""><span></span>Dribble</a></li>
    </ul>
    <ul>
      <li class="list-heading">Interwebs</li>
      <li><a href=""><span></span>Github</a></li>
      <li><a href=""><span></span>Stack Overflow</a></li>
      <li><a href=""><span></span>Zurb Foundation</a></li>
    </ul>
    <ul>
      <li class="list-heading">Resources</li>
      <li><a href=""><span></span>Smashing Mag</a></li>
      <li><a href=""><span></span>Treehouse</a></li>
      <li><a href=""><span></span>Designer News</a></li>
    </ul>
    <p class="legal-copy clear">Ol' Chompy - The Shark Site</p>

  </div><!-- end wrapper -->
</footer>
```

保存这个，现在当我们去我们的网站，我们将能够看到 Facebook 图标：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00329.jpeg)

# 图标字体样式

我们有两个问题：一是太小，二是离单词太近。我们应该对每个图标添加`margin-right`并使其变大。这意味着 HTML 中的每个`span`标签都需要一个类。让我们添加`class="icon"`如下：

```css
<footer>
  <div class="wrapper grouping">
    <ul>
      <li class="list-heading">Social</li>
      <li><a href=""><span class="icon fi-social-facebook"></span>Facebook</a></li>
      <li><a href=""><span class="icon"></span>Twitter</a></li>
      <li><a href=""><span class="icon"></span>Google+</a></li>
      <li><a href=""><span class="icon"></span>Dribble</a></li>
    </ul>
    <ul>
      <li class="list-heading">Interwebs</li>
      <li><a href=""><span class="icon"></span>Github</a></li>
      <li><a href=""><span class="icon"></span>Stack Overflow</a></li>
      <li><a href=""><span class="icon"></span>Zurb Foundation</a></li>
    </ul>
    <ul>
      <li class="list-heading">Resources</li>
      <li><a href=""><span class="icon"></span>Smashing Mag</a></li>
      <li><a href=""><span class="icon"></span>Treehouse</a></li>
      <li><a href=""><span class="icon"></span>Designer News</a></li>
    </ul>
    <p class="legal-copy clear">Ol' Chompy - The Shark Site</p>

  </div><!-- end wrapper -->
</footer>
```

现在在 CSS 中，在我们的页脚部分，让我们添加一个新的规则集来解决这两个问题：

```css
footer .icon {
  margin-right: 10px;
  font-size: 30px;
}
```

我们还可以添加一个过渡效果，因为我们将有一个悬停效果，这将有助于缓解状态变化。让我们添加一个过渡效果：

```css
footer .icon {
  margin-right: 10px;
  font-size: 30px;
 -webkit-transition: .25s color ease-in-out;
 transition: .25s color ease-in-out;
}
```

现在刷新网站，你会看到 Facebook 图标稍微变大了，而且有了更多的空间：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00330.jpeg)

现在我们需要为 Twitter、Google、Dribble 和 HTML 中的其他六个链接添加相应的类：

```css
<footer>
  <div class="wrapper grouping">
    <ul>
      <li class="list-heading">Social</li>
      <li><a href=""><span class="icon fi-social-facebook">
      </span>Facebook</a></li>
      <li><a href=""><span class="icon fi-social-twitter">
      </span>Twitter</a></li>
      <li><a href=""><span class="icon fi-social-google-plus">
      </span>Google+</a></li>
      <li><a href=""><span class="icon fi-social-dribbble">
      </span>Dribbble</a></li>
    </ul>
    <ul>
      <li class="list-heading">Interwebs</li>
      <li><a href=""><span class="icon fi-social-github">
      </span>Github</a></li>
      <li><a href=""><span class="icon fi-social-stack-overflow">
      </span>Stack Overflow</a></li>
      <li><a href=""><span class="icon fi-social-zurb"></span>Zurb 
      Foundation</a></li>
    </ul>
    <ul>
      <li class="list-heading">Resources</li>
      <li><a href=""><span class="icon fi-social-smashing-mag">
      </span>Smashing Mag</a></li>
      <li><a href=""><span class="icon fi-social-treehouse">
      </span>Treehouse</a></li>
      <li><a href=""><span class="icon fi-social-designer-news">
      </span>Designer News</a></li>
    </ul>
    <p class="legal-copy clear">Ol' Chompy - The Shark Site</p>

  </div><!-- end wrapper -->
</footer>
```

这是它的样子：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00331.jpeg)

好了！现在我们已经将所有与图标相关的类放在了正确的位置，并且我们的页脚上每个链接都有一个图标。图标字体的好处是它们在 HiDPI 设备上会清晰明了。此外，我们可以在悬停状态下更改颜色和其他属性，这是普通光栅图像所做不到的。让我们为所有这些添加一个快速的悬停状态。在我们的 CSS 中，让我们添加一个新的选择器：

```css
footer .icon {
  margin-right: 10px;
  font-size: 30px;
  -webkit-transition: .25s color ease-in-out;
  transition: .25s color ease-in-out;
}
footer a:hover .icon {
 color: #f00;
}
```

应用这个，你应该看到这个图标很好地过渡到了完全不同的颜色：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00332.jpeg)

图标字体是您网站的一个很好的选择。我建议在您的网站的非关键元素上使用图标字体，因为如果由于某种原因字体在用户的计算机上无法加载，就没有备用方案。备用方案通常默认为一个方块，或者更糟糕的是一个完全无关的字符或字母。在我们的情况下，我认为我们没问题，因为在我们的图标字体无法加载的情况下，我们仍然会有图标旁边的描述。图标字体的好处是，就像任何其他字体一样，它们可以流畅地缩放到视网膜设备。

# 摘要

我们通过讨论`@font-face`属性来开始本章关于 Web 字体的内容，使用它来向我们的网站添加字体。我们看了如何使用 Google 字体和 Typekit。最后，您学会了如何使用图标字体，并使用 Zurb 的图标字体构建网站的页脚。在下一章中，我们将讨论视网膜设备，并为 HiDPI 设备的世界准备我们的页面。


# 第八章：HiDPI 设备的工作流程

视网膜设备现在几乎是苹果电脑、平板电脑和手机的默认设备。此外，“视网膜”一词实际上是苹果公司为计算机设备注册的商标，是他们品牌化描述双倍（或更多）密度屏幕和设备的方式。我将松散地使用“视网膜”一词来描述任何具有高密度显示屏的设备，无论是由苹果制造还是其他制造商。视网膜设备上的所有内容都更清晰，因为与 CSS 设备显示器上的像素相比，现在有近四倍的像素；对于每个“CSS 像素”，现在有四个“设备像素”，从而实现更高质量的显示。不利的一面是，到目前为止我们使用的图像实际上在这样的设备上看起来不会那么好，因为我们没有考虑到更高密度的显示。

在本章中，我们将介绍一些针对视网膜显示器的图像技术。这包括使图像放大两倍。我们还将研究背景图像技术，使用 SVG，并在图像元素上使用`srcset`属性来进一步考虑视网膜。

# 2x 图像

2x 图像是宽度和高度的两倍。基本思路是使图像的宽度和高度是我们实际需要的两倍。然后我们将该图像添加到我们的 HTML 中。然后我们将使用 CSS 将图像限制为屏幕上的实际大小。我喜欢处理响应式设计中的灵活图像的方式与此相同：我喜欢确保图像将具有具有设置的包含元素`width`和`height`值。然后，我确保图像本身的`max-width`设置为 100%。这些要求已经具备。我的所有图像通常都有一个容器，在 CSS 中，我的所有图像都将其`max-width`设置为 100%。

# 创建视网膜大小的图像（2x）

所以让我们从鲨鱼电影页面上的光影开始。右键单击“大白鲨”电影图像并检查此元素：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00333.jpeg)

我们可以看到鲨鱼电影页面上的这些图像是 200 x 200 像素。我们的目标是用尺寸为 400 x 400 像素的图像替换它们。如您在下面的屏幕截图中看到的，我已经创建了三个与原始图像相同的图像，只是它们更大，并且带有`@2x.jpg`后缀，表示这些是视网膜版本：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00334.jpeg)

切换到 HTML，您会看到我已经为所有三个图像的文件名添加了`@2x`并保存了。例如，这是我们“Open Water”电影的文件名应该是这样的：

```css
<img src="img/open-water@2x.jpg" alt="Open Water movie">
```

# 使用 CSS 调整 2x 图像的大小

转到浏览器并刷新。现在，当您查看这张大白鲨的图像时，您实际上不会看到任何明显的区别：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00335.jpeg)

然而，快速检查显示正在提供`@2x`图像，但它被限制为 200 x 200 的大小，因此您可以看到原始图像是`400 x 400`，但显示为`200 x 200`：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00336.jpeg)

由于我们对响应式设计的基础，即时包含元素`.figure`已经设置了`23.958333333333`百分比的宽度（如下面的代码所示），这相当于网站最宽处的 200 像素：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00337.jpeg)

如果我们从 Chrome DevTools 的样式窗格中删除`width`，图像将会放大到其实际大小，即`400 x 400`：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00338.jpeg)

因此，是包含元素具有设置的`width`，以及`max-width`设置为 100%，使图像受限。如果我们从 Chrome DevTools 的样式窗格中删除这个`max-width`，图像将不再受限，如下所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00339.jpeg)

父元素的溢出选项设置为隐藏，这就是为什么图像的宽度不会超过 23.95%。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00340.jpeg)

# 在视网膜设备上检查图像质量

现在我们怎么知道图像在视网膜设备上会看起来很好呢？最好的办法是在视网膜设备上测试它，但我们也可以在 Chrome 中作弊一点，将其缩放到 200%。首先，让我们在 DevTools 中直接将宽度设置为 200px：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00341.jpeg)

然后让我们转到 Chrome 工具栏，并将缩放比例调整到 200%：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00342.jpeg)

前面的截图旨在演示在 200%缩放时，图像仍然非常清晰，这有点类似于模拟视网膜设备。

这似乎不是一个准备好视网膜的图像的坏方法。嗯，如果只是这么简单就好了。事实证明，使图像的高度和宽度增加一倍实际上使它们比 1x 版本大三到四倍。因此，如果你看一下`images`文件夹中的 Jaws 图像，原始大小为 28 KB，而 2x 版本（双倍密度版本）为 105 KB。这是原始大小的四倍！

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00343.jpeg)

因此，总之，这只是我们为视网膜网站做准备的开始。我们目前最大的问题是，我们为所有设备提供了一个巨大的视网膜大小的图像，即使那些不是视网膜的设备也是如此。这对于那些不会从中受益的站点来说，是额外的下载和页面负担，这是不负责任的。

在下一节中，我们将介绍类似的背景图像技术。

# 背景图像

为了处理背景图像，我们可以使用特殊的媒体查询来确定像素比，然后修改`background`属性以提供视网膜图像。在这一节中，我们将确定如何在视网膜领域处理背景图像。我们首先创建一个专门用于确定像素比的媒体查询。然后，我们将更新正在提供的图像为视网膜版本。页脚中的海藻是一个背景图像，因此将是这项任务的完美图像。

# 针对页脚中的海藻

这是在电影页面页脚上方的海藻：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00344.jpeg)

如果我们查看 CSS，发生的一切就是页脚有一个重复的背景图像。背景是海藻，我们让它沿着*x*轴重复：

```css
footer {
  background: #fff url('../images/seaweed.jpg') repeat-x 0 0;
  padding: 142px 0;
  font-size: 14px;
  line-height: 1.7; 
}
```

因此，我们需要有一个视网膜大小的`seaweed.jpg`版本。我在我的`images`文件夹中有这个，我把它命名为`seaweed@2x.jpg`：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00345.jpeg)

在样式表的最底部，在所有我们的媒体查询之后，让我们为视网膜背景图像保留一个位置：

```css
/***************
Retina, Background Images
***************/
```

这是我们将使用特殊媒体查询来检测视网膜的地方。

# 设备像素比的媒体查询

我们从第六章中记得这样的媒体查询，*变得响应式*：

```css
@media all and (max-width: 400px) {
  /*rule sets here*/
}
```

媒体查询有两个部分，媒体*类型*和媒体*特性*：

```css
@media *media type* and (*media feature*) {
  /*rule sets here*/
}
```

媒体类型可以是关键字值，如*screen*、*print*、*speech*和*all*。媒体特性也可以是许多东西。在响应式章节中，特性是浏览器的`max-width`。然而，对于视网膜，我们要查询屏幕的像素比：

```css
@media
screen and (-webkit-min-device-pixel-ratio: 2),
screen and (min-resolution: 192dpi) {
}
```

在前面的示例中发生了很多事情。有两个不同的查询针对两个不同的媒体特性。分隔这两个查询的逗号类似于说“或”。因此，如果前面的两个查询中的任何一个为真，则媒体查询将生效。但为什么要有两个查询？嗯，第一个查询是针对像 Safari 和旧版 Chrome 这样的 webkit 浏览器，设备的`min-device-pixel-ratio`为`2`。接下来，我们针对具有 192 像素每英寸或更高像素密度的设备。它不是使用设备像素比，而是使用`min-resolution: 192dpi`，这考虑到了不同的浏览器，比如 Windows 手机。这两个媒体特性基本上都是针对视网膜。

现在，在媒体查询中，我们将针对页脚并将背景图像更改为我们的视网膜版本。我会在页脚中输入一个开放的大括号，然后是`background-image`；URL 将是`../images/seaweed@2x.jpg`：

```css
@media
screen and (-webkit-min-device-pixel-ratio: 2),
screen and (min-resolution: 192dpi) {
 footer {
 background-image: url('../images/seaweed@2x.jpg');
 }
}
```

我们在浏览器中看不到明显的区别。不过，让我们检查一下页脚，以确保它仍然加载常规的`seaweed.jpg`文件，而不是`seaweed@2x.jpg`：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00346.jpeg)

我们检查这个的原因是因为我不是在视网膜设备上。我们可以使用一些技巧来确保这个工作。让我们去我们的 CSS 并将设备像素比更改为`1`：

```css
@media
screen and (-webkit-min-device-pixel-ratio: 1),
screen and (min-resolution: 192dpi) {
  footer {
    background-image: url('../images/seaweed@2x.jpg');
  }
}
```

让我们看看在浏览器中是什么样子的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00347.jpeg)

现在我们得到了 2x 版本，我们可以看到它明显更大。我们有两倍大小的图像；视觉上看起来是两倍大小。它没有被限制在我们预期的显示尺寸上。有一个名为`background-size`的属性，我们将使用它来解决这个问题。

# 仅向视网膜设备提供 2x 图像

我们必须使用`background-size`属性来确保海藻被适当地限制。我们将在页脚部分顶部持有非视网膜版本的规则集中放置`background-size`属性，而不是在媒体查询中。我们可以很容易地将其放在媒体查询中，这样也可以，但这将适用于非视网膜设备和视网膜设备，因此我们将添加水平`200px`和垂直`100px`的背景大小，如下面的代码所示：

```css
footer {
  background: #fff url('../images/seaweed.jpg') repeat-x 0 0;
  background-size: 200px 100px;
  padding: 142px 0;
  font-size: 14px;
  line-height: 1.7; 
}
```

保存这个并转到浏览器。当我们刷新网站时，海藻应该缩小到 200 x 100，恢复到其常规大小：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00348.jpeg)

如果您查看我们在 DevTools 中的样式，您会看到我们得到了`@2x`版本。您可以看到浏览器加载 CSS 的方式-它在顶部看到了媒体查询。这是正在使用的。下面是未加载的非媒体查询版本。这正是我们希望它工作的方式，这很好。

我们需要做的最后一件事是将媒体查询恢复为`device-pixel-ratio`为 2 而不是 1，所以，我们将更改它：

```css
@media
screen and (-webkit-min-device-pixel-ratio: 2),
screen and (min-resolution: 192dpi) {
  footer {
    background-image: url('../images/seaweed@2x.jpg');
  }
}
```

现在它将加载非视网膜版本，因为我使用的是非视网膜设备：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00349.jpeg)

只有视网膜尺寸的背景图像才会被视网膜设备下载，非视网膜设备会下载常规尺寸的背景图像。一切都很好，但这仍然是相当多的工作。我们可以以更少的工作量处理这些海藻，只需要一张图片-使用 SVG 而不是传统的光栅图形。

# 可伸缩矢量图形（SVG）

**可伸缩矢量图形**（**SVG**）-是一种基于 XML 的图形图像格式。它与 JPEG 和 PNG 等光栅格式不同，因为它可以在任何尺寸下缩放而不失去任何分辨率或出现像素化。这意味着我们不需要为视网膜或响应式布局使用多个图像！SVG 的另一个好处是文件大小可以比保存为 JPEG 或 PNG 的相同图像要小得多。所有主要浏览器都支持 SVG 格式，甚至可以追溯到 IE9。SVG 并不是站点上每个图像的替代品-它们特别适用于线条图，通常是通过设计软件（如 Adobe Illustrator）生成的。

在本节中，我们将看看如何将 Adobe Illustrator 文件保存为 SVG，以及我们可以将 SVG 添加到网站的三种不同方式：

+   将 SVG 添加为`background-image`

+   使用`<img>`标签添加 SVG

+   使用内联 SVG

我们的网站上有很多图像非常适合使用 SVG，包括网站顶部的鲨鱼：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00350.jpeg)

我们网站中间的所有不同海洋物种也非常适合作为 SVG：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00351.jpeg)

即使我们在上一节中处理的页脚中的海藻也非常适合 SVG：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00352.jpeg)

那么哪些图像不适合作为 SVG？嗯，我们电影页面上的光栅图像绝对不适合：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00353.jpeg)

# 将 Illustrator 文件保存为 SVG

我在 Illustrator 中打开了一个名为`seaweed.ai`的 Adobe Illustrator 文件。像 Illustrator 这样的程序是可以创建 SVG 或从头开始绘制 SVG 的地方。在本书中，使用 Illustrator 创建 SVG 远远超出了范围，但我想从这里开始只是为了展示 SVG 可能来自何处。

在*Illustrator CC 2017*中，将 AI 文件保存为 SVG 以供 Web 使用的最佳方法之一是使用文件* > *导出* > *屏幕导出...选项。

这个选项使用`artboard`名称作为文件名，所以在我们导出为 SVG 之前，让我们通过转到窗口* > * `画板`来重命名画板。让我们将 artboard1 重命名为 seaweed，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00354.jpeg)

现在，通过转到文件* > *导出* > *屏幕导出...选项，我们将获得一个 SVG 文件：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00355.jpeg)

这将弹出一个带有几个选项的屏幕。使用“导出到”字段，我们将选择保存此文件的位置，这将不可避免地在我们的`images`文件夹中。在单击右下角的“导出画板”按钮之前，我们还将更改格式为`SVG`：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00356.jpeg)

保存后，您会看到 SVG 为 1 KB。我们在上一节中使用的`@2x`版本为 13 KB！

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00357.jpeg)

因此，SVG 不仅比`@2x`版本小 13 倍，而且比常规版本小 6 倍，这真是太神奇了！现在让我们将其整合到我们的 CSS 中。

# 将 SVG 文件添加为背景图像

在我们的 CSS 中，在针对页脚的规则集内部，我要做的就是将格式从`.jpg`更改为`.svg` - 也就是从（`'.../images/seaweed.jpg'`）更改为（`'.../images/seaweed.svg'`），如下面的代码所示：

```css
footer {
  background: #fff url('../images/seaweed.svg') repeat-x 0 0;
  background-size: 200px 100px;
  padding: 142px 0;
  font-size: 14px;
  line-height: 1.7; 
}
```

因为现在我们有一个适用于非视网膜和视网膜设备的 SVG，所以我们将转到底部，并注释掉我们上一节中的这个媒体查询：

```css

/***************
Retina, Background Images
***************/
/*********** @media
only screen and (-webkit-min-device-pixel-ratio: 2),
only screen and (min-resolution: 192dpi) {
   footer {
    background-image: url('../images/seaweed@2x.jpg');
  } 
}
*************/
```

这是我们在上一节中用来为视网膜设备提供更大图像的方法，但是如果我们使用 SVG，我们就不需要所有这些额外的代码。所以我把它们都去掉了。

我将刷新浏览器，它看起来完全一样。让我们检查元素，如下面的截图所示。我们可以看到它正在提供`seaweed.svg`。我们从 2 张图片变成了 1 张。13 KB 变成了 1 KB。我们还去掉了一些复杂的媒体查询中的几行 CSS。您开始明白为什么 SVG 是纯粹的令人敬畏了吗？

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00358.jpeg)

# 将 SVG 添加为常规的<img>

您还可以将 SVG 用作常规`<img>`。我们碰巧在网站中间有几张图片 - 不同的海洋物种，这些将是使用 SVG 实现的完美候选者：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00359.jpeg)

我已经将章鱼、螃蟹和鲸鱼保存为`.svg`文件。所以让我们转到 HTML，简单地将章鱼、螃蟹和鲸鱼的图像从`.png`更改为`.svg`：

```css
<!-- 
===============
Secondary Sections
===============
-->
<section class="secondary-section grouping">
  <div class="wrapper">
    <div class="column">
      <figure>
        <img src="img/octopus-icon.svg" alt="Octopus">
      </figure>
      <h2>The Octopus</h2>
      <p>Lorem ipsum dolor... </p>
      <a href="#" class="button">Tenticals &raquo;</a>
    </div>
    <div class="column">
      <figure>
        <img src="img/crab-icon.svg" alt="Crab">
      </figure>
      <h2>The Crab</h2>
      <p>Lorem ipsum dolor... </p>
      <a href="#" class="button">Crabby &raquo;</a>
    </div>
    <div class="column">
      <figure><img src="img/whale-icon.svg" alt="Whale"></figure>
      <h2>The Whale</h2>
      <p>Lorem ipsum dolor... </p>
      <a href="#" class="button">Stuart &raquo;</a>
    </div>
  </div><!-- end wrapper -->
</section>
```

`images`文件夹中的文件名完全相同。唯一的区别是后缀是`svg`而不是`png`：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00360.jpeg)

保存这个。我们将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00361.jpeg)

在上图中，我们可以看到文件看起来不错；唯一的问题是它们似乎变大了一点。所以我们将它们缩小到我们想要的尺寸。

# 你无法阻止 SVG，你只能希望限制它们！

要限制图像的大小，我们需要设置`width`和/或`max-width`。我们实际上已经这样做了，但只是在媒体查询中，因此它不会在较大的屏幕上触发：

```css
@media screen and (max-width: 1023px){
  .intro-content {
    width: auto;
    float: none;
    padding-bottom: 0;
    margin-bottom: 30px;
  }
  .go-premium {
    width: auto;
    float: none;
    margin-top: 0;
  }
  .column {
    float: none;
    width: auto;
    padding: 0 50px;
  }
 .column figure {
 margin: 0 auto;
 width: 100%; 
 max-width: 250px;
 }
  .column h2 {
    text-align: center;
  }
}/* end of media query */

```

让我们从媒体查询中删除该规则集，并将其添加到我们最初定义响应式媒体查询之外的 3 列位置：

```css
****************
3 columns
****************/
.column {
  float: left;
  width: 31.25%; /* 300/960 */
  margin-left: 3.125%; /* 30/960 */
}
.column:first-child {
  margin-left: 0;
}
.column figure {
 margin: 0 auto;
 width: 100%;
 max-width: 250px; 
}
```

我们所做的就是使用自动边距来居中`figure`元素，确保其宽度是其容器的 100%，只要宽度不超过 250px（`max-width`）。

既然我们已经将它放在了正确的位置，这就是我们得到的结果：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00362.jpeg)

我们将每个 SVG 图像限制为最大宽度为`250px`。我们的螃蟹、章鱼和鲸鱼看起来非常好，立即就准备好了。

# 使用内联 SVG

我们对 SVG 还有另一个选项，称为内联 SVG。由于 SVG 实际上只是文本文件中的 XML，我们实际上可以直接将 SVG 代码嵌入到我们的 HTML 中。这样就不需要额外的 HTTP 请求（对性能有好处）。此外，它允许我们使用 CSS 来改变 SVG，例如提供一个酷炫的悬停状态或动画。这确实给了我们一个巨大的优势；它的重要性无法被过分强调。

所以我们要做的是转到 Sublime Text 中的`images`文件夹，然后打开`crab.svg`。但首先，让我们看看当我打开`crab.png`时会发生什么，Sublime 会显示一个图像：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00363.jpeg)

使用 SVG，它实际上显示了代码！你可以看到它是 XML，与 HTML 类似：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00364.jpeg)

我将复制并粘贴所有的 SVG 代码，并转到我们的`index.html`文件，然后删除整个`img`标签：

```css
<div class="column">
  <figure>
 <img src="img/crab-icon.svg" alt="Crab">
  </figure>
  <h2>The Crab</h2>
  <p>Lorem ipsum dolor... </p>
  <a href="#" class="button">Crabby &raquo;</a>
</div>
```

然后我们将其替换为 SVG 代码：

```css
<div class="column">
  <figure>
    <svg  viewBox="1.5 113.9 256 256">
 <path fill="#9E2610" d="M72.1 296.8s-31.8 11.7-37.9 20.5c0 0 3.5-21.3 
      30.9-32.7l7 12.2zm12.1 10.7s-21.9  
      22.8-23.4 32.7c0 0-5.8-19.3 12.5-40.1l10.9 7.4zm-15.9-28.7s-34 
      2.4-43.3 9.1c0 0 12.3-19.5 42.3-22.8l1 
      13.7zM185.4 295s31.8 11.7 37.9 20.5c0 0-3.5-21.3-30.9-32.7l-7 
      12.2z"/>
 <path fill="#D62D0E" d="M50.5 223.5S13 205.5 41 161c0 0 9-19.5 
      38-16.5L53.5 205l46-32.8s12.5 24.5-11    
      42.2c0 0-13.8 10.2-20.8 9 0 0 4.5 11 12 16.2l3.5 3.2-9.5 
      11c.1.2-20.7-15.3-23.2-30.3z"/>
 <path fill="#9E2610" d="M173.3 305.6s21.9 22.8 23.4 32.7c0 0 
      5.8-19.3-12.5-40.1l-10.9 7.4zm15.9-28.7s34 
      2.4 43.3 9.1c0 0-12.3-19.5-42.3-22.8l-1 13.7z"/>
 <path fill="#D62D0E" d="M207.9 223.5s37.5-18 9.5-62.5c0 
      0-9-19.5-38-16.5l25.5 60.5-46-32.8s-12.5 24.5 
      11 42.2c0 0 13.8 10.2 20.8 9 0 0-4.5 11-12 16.2l-3.5 3.2 9.5 11c0 .2 
      20.7-15.3 23.2-30.3z"/>
 <path fill="#D62D0E" d="M127.8 212s44-5.2 65.2 57.8c0 0 11.8 
      44.5-62.2 48.5 0 0-70.2 1.2-66.2-43.8-.1 0 
      6.6-54 63.2-62.5z"/>
 <circle fill="#FFFFFF" cx="103.8" cy="265.1" r="23.5"/>
 <circle fill="#FFFFFF" cx="153.6" cy="264.1" r="23.5"/>
 <circle cx="105.2" cy="263.8" r="14.8"/>
 <circle cx="152.2" cy="262.5" r="14.8"/>
 <ellipse transform="rotate(-45.37 157.15 256.57)" fill="#FFFFFF" 
      cx="157.1" cy="256.6" rx="4.7" 
      ry="7.2"/>
 <ellipse transform="rotate(-45.37 110.35 257.456)" fill="#FFFFFF" 
      cx="110.3" cy="257.4" rx="4.7" 
      ry="7.2"/>
 <path d="M78.5 290s12.7 20 51.6 19.5c0 0 34.2 1.5 49.2-19.5 0 0-15.8 
      17.5-49.2 17.2 0 0-36.1.3-51.6-
      17.2z"/>
 </svg>
  </figure>
  <h2>The Crab</h2>
  <p>Lorem ipsum dolor... </p>
  <a href="#" class="button">Crabby &raquo;</a>
</div>
```

哇，这是很多的代码... SVG 的缺点是你直接将大量代码放入你的标记中。你仍然会获得更好的性能，因为你不需要为它发出 HTTP 请求，但我们为此添加了接近 30 行的代码。

在 Chrome 中我们看不到任何变化；螃蟹看起来完全一样。所以我们不妨检查一下这个元素。现在我们可以看到它是内联 SVG 代码：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00365.jpeg)

你还可以看到你可能会认为你可以使用 CSS 来改变这些属性，因为每个路径实际上都是 Dom 中的一个单独的节点：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00366.jpeg)

例如，如果我们想的话，我们可以改变这行代码的填充颜色：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00367.jpeg)

让我们把它变成绿色：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00368.jpeg)

现在你得到了一个绿色的爪子：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00369.jpeg)

所以你可以看到你可能如何改变 SVG 的属性，对其进行动画处理，或者创建一个酷炫的悬停状态。你不能用 SVG 作为`background-image`或`img`标签来做到这一点，但你可以用内联 SVG 来做到这一点。

由于这是一种不同的媒体格式，它不是`img`标签，也不是`video`标签。它实际上是一个`SVG`标签。让我们转到样式表的顶部，进入我的重置。这是我们在媒体上设置`max-width: 100%`的地方，如下面的代码所示。我们还将向此列表添加一个 SVG：

```css
img, iframe, video, object, svg {
  max-width: 100%;
}
```

在下一节中，我们将讨论如何在`img`标签上使用`srcset`属性，以向高密度显示器提供视网膜图像，并向普通密度显示器提供正常大小的图像。

# 源设置属性（srcset）

SVG 仍然是向 HiDPI 设备提供视网膜图像的最受欢迎的方式，因为文件大小几乎总是比 JPG 和 PNG 小，而且对于视网膜和非视网膜设备只需要一个图像。但还有另一个非常好的选择出现了，叫做`srcset`。这个选项并不是要取代 SVG，而是要补充它，因为 SVG 不能用于传统的光栅图像和照片，这些更适合于 JPEG 和 PNG。

# 什么是 srcset？

`srcset`属性只是一组图像，就像名称所暗示的那样。我们可以提供不止一个图像供浏览器选择，而是一组图像，浏览器可以从中选择，并且只获取浏览器认为最适合设备的图像。

我们将专注于我们电影页面上的三个电影图像，它们都是光栅的、摄影的图像。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00370.jpeg)

在`movies.html`中，我们有一个`img`标签和每部电影的适当图片。所以对于 Sharknado，我们有`sharknado.jpg`：

```css
<img src="img/sharknado.jpg" alt="Sharknado movie">
```

对于 Jaws，我们有`jaws.jpg`：

```css
<img src="img/jaws.jpg" alt="Jaws movie">
```

让我们更新 Jaws 图像，并添加一个名为`srcset`的新属性，然后将我们的 Jaws 图像作为该属性的值：

```css
<img src="img/jaws.jpg" srcset="images/jaws.jpg" alt="Jaws movie">
```

正如我提到的，`srcset`是一组图像选择，供浏览器决定哪个最适合情况。让我们添加一组图像。

# 向 srcset 添加一组图像

要向`image`标签添加一组图像，用逗号分隔每个图像。我们首先提供常规大小的图像。然后我们将添加`images/jaws@2x.jpg`：

```css
<img src="img/jaws.jpg" srcset="images/jaws.jpg, images/jaws@2x.jpg" alt="Jaws movie">
```

实际上，浏览器需要其他东西来让它知道这是一个更大的图像，称为*像素密度描述符*，或者只是*X 描述符*。让我们添加它，如下面的屏幕截图所示：

```css
<img src="img/jaws.jpg" srcset="images/jaws.jpg 1x, images/jaws@2x.jpg 2x" alt="Jaws movie">
```

在每个图像字符串后面，我将提供一个空格，然后是 X 描述符。因此，第一个图像字符串将是`1x`，第二个将是`2x`。X 描述符是我们提供给浏览器的提示。这意味着我们在`1x`或正常像素密度显示器上使用`images/jaws.jpg`，在`2x`或 retina 显示器上使用更大的图像`images/jaws@2x.jpg`。

# 测试图像集

让我们看看图像集是否起作用。如果没有在 retina 显示屏上测试，这将会很困难。但让我们看看是否可以进行一些粗略的测试。Chrome 有一个很好的功能，如果我们检查一个图像，我们可以看到它的`src`属性和`srcset`属性。看看下面的代码：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00371.jpeg)

在这里，如果我们将鼠标悬停在每个图像的路径上，你会看到一个弹出窗口出现在正在提供的图像上。但是当我们悬停在`jaws@2x`上时，没有弹出窗口出现，因为该图像没有被提供：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00372.jpeg)

这是有道理的，因为我不是在 retina 显示屏上，所以它正在使用非 retina 图像。

让我们使用浏览器缩放技巧，这是我们在前面的部分中使用的，看看是否可以伪造一个 retina 设备。让我们放大到 200%：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00373.jpeg)

然后，刷新页面，以便它获取它认为最好的图像：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00374.jpeg)

当我在`src`和`srcset`中悬停在`jaws.jpg`上时，我们没有弹出窗口。但是当我们悬停在`jaws@2x.jpg`的路径上时，我们就会看到，如下所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00375.jpeg)

这告诉我，更大的图像正在被获取。这是好东西。

# 简化 srcset 属性

让我们再看一下代码，以简化`srcset`属性：

```css
<img src="img/jaws.jpg" srcset="images/jaws.jpg 1x, images/jaws@2x.jpg 2x" alt="Jaws movie">
```

我们需要保留原始的`src`作为不支持`srcset`的浏览器的备用。我们稍后会在本节中讨论浏览器支持有多好，但重要的是要记住，`src`属性是为了让不支持的浏览器不被忽视。

另一件需要注意的事情是，我们可以简化这个代码方程式。W3C 规范提到，对于新的用户代理，`src`属性参与资源选择，就好像它是在`srcset`中用`1x`描述符指定的一样。由于我们有传统的`src`属性，可以提供图像的`1x`版本，我们可以从`srcset`属性中删除第一个图像字符串，并简化我们的标记：

```css
<img src="img/jaws.jpg" srcset="images/jaws@2x.jpg 2x" alt="Jaws movie">
```

换句话说，我们可以从`srcset`属性中删除带有`1x`描述符的常规大小图像字符串，因为这已经在`src`属性中指定了。这样简化了它，这是好事。

现在让我们用类似的标记更新我们的另外两部电影，从《Sharknado》开始：

```css
<img src="img/sharknado.jpg" srcset="images/sharknado@2x.jpg 2x" alt="Sharknado movie">
```

我们将对电影《Open Water》做同样的事情：

```css
<img src="img/open-water.jpg" srcset="images/open-water@2x.jpg 2x" alt="Open Water movie">
```

# 浏览器支持

让我们讨论浏览器支持[caniuse.com](http://caniuse.com/)显示了大量绿色浏览器：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00376.jpeg)

Microsoft Edge 支持`srcset`，Chrome，Firefox，Safari，Opera，以及 iOS Safari 8 及更高版本也支持。

将选项更改为*日期相对*，显示支持在 iOS 上更早：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00377.jpeg)

它从 Safari 8.1 到 8.4 提供了部分支持。它支持"分辨率切换"，这就是我们使用 X 描述符所做的；然而，它不支持完整的语法，我稍后会在本节中详细讨论。一个值得注意的不支持的浏览器是 IE，甚至是 IE11。但是，Internet Explorer 将获取我们在传统源属性中指定的常规大小图像。

好处在于绝大多数高密度设备最终都会得到`2x`版本，而不支持的浏览器，很可能是非视网膜设备，将收到`1x`版本。

我要指出的是，你不一定只使用一个或两个图像路径。我将复制并粘贴三个图像路径，如下所示：

```css
<img src="img/sharknado.jpg" 
srcset="images/sharknado@1.5x.jpg 1.5x, 
        images/sharknado@2x.jpg 2x, 
        images/sharknado@4x.jpg 4x" 
alt="Sharknado movie">
```

正如你在前面的代码中看到的，我已经指定了一个可以用于`4x`显示、`2x`显示和`1.5x`显示的`image`。这让我想到另一点——你不一定要使用整数。你可以使用 1.5 或 1.325。

此外，我们只是向浏览器提供提示，所以即使我们看起来对哪个图像被服务有很大的控制，最终决定权还是在浏览器手中。这是基于除用户屏幕像素密度之外的因素，例如，缩放级别，正如我们已经看到的，以及其他因素，比如用户的网络条件。

因此，理论上，如果用户有一个视网膜设备，但网络条件不佳，浏览器会提供一个较小的图像，因为它会优先考虑图像的快速加载——加载会更快，但不会那么清晰。我们很可能在其他技术中看到了这种优先级的情况。例如，Netflix 可能会显示电影的模糊版本，直到它获得足够的带宽来向您展示同一部电影的高清版本。我们喜欢这样，因为我们宁愿快速得到一些东西来观看，而不是等待最好的版本来观看。

# 使用`srcset`属性的`W`描述符和 sizes 属性

请注意，`srcset`属性不是一个单一的技巧；我们已经讨论了它如何轻松处理视网膜图像。但`srcset`属性还有另一个用例，它使用`W`描述符和`sizes`属性：

```css
<img src="img/medium.png"
    srcset="images/big.png 1600w,
 images/small.png 600w"
 sizes="(min-width: 1000px) 1600px, 
 600px" />
```

它允许你根据浏览器的宽度来处理不同图像的服务。在桌面上，一个巨大的、英雄式的、全屏的图像看起来很漂亮，但如果你把它缩小并在更小的移动设备上提供服务，那么它的性能就会很差，因为小设备不需要超大的图像。

`w`描述符是对浏览器关于图像大小的提示；这里的`w`代表宽度。`sizes`属性添加了媒体查询和一个维度，告诉浏览器我们首选的图像渲染大小，如果浏览器宽度与媒体查询匹配，最后是如果浏览器宽度不匹配媒体查询的首选渲染大小。

我的意图不是解释`srcset`属性的这种替代用法的细节，而是让你知道`srcset`属性有更深层次。如果你想深入了解，我在我的网站上写了一篇文章，网址是[richfinelli.com/srcset-part-2/](http://www.richfinelli.com/srcset-part-2/)。我还写了一篇关于 X 描述符的文章，网址是[richfinelli.com/srcset-part-1/](http://www.richfinelli.com/srcset-part-1/)，如果你还想更深入地了解我们刚才谈到的内容。

# 总结

为视网膜设备开发需要额外的工作。我的建议是尽可能使用 SVG 作为为视网膜设备提供超清晰图像的首选。在 SVG 不可行的情况下——即照片——使用`img`标签的`srcset`属性，让浏览器能够智能地决定提供图像。`srcset`的浏览器支持很好，不支持的浏览器将退回到`src`属性。浏览器根据像素密度、缩放级别和其他因素，比如网络条件，最终决定使用哪个图像。

在下一章第九章，*Flexbox*，*Part 1*，我们将看到一个用弹性盒子布局网页部分的替代和更好的解决方案。


# 第九章：Flexbox，第一部分

Flexbox 是用于页面部分布局的模块，目前在 Internet Explorer 10 及以上版本中有很好的浏览器支持。从技术上讲，它并不是为全页面布局设计的；它更多用于页面的部分布局或给定组件的布局。

例如，以下三列（章鱼，螃蟹和鲸鱼）是使用浮动布局的，但我们将使用 flexbox 来完成完全相同的事情：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00378.jpeg)

Flexbox 是一个大主题，所以我们将在两章中涵盖它。本章将介绍基础知识，我们将解决实现 flexbox，从浮动切换到 flexbox，并介绍所有 flexbox 属性和简写。在下一章中，我们将构建一个新的部分-以下产品列表-以演示如何使用 flexbox 构建不同的东西。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00379.jpeg)

我将在最新版本的 Chrome 中编码，目前支持所有 flexbox 属性的非前缀版本。这将简化学习体验。但在完成之前，我们需要为最大的浏览器兼容性添加供应商前缀。

我们将涵盖以下主题：

+   CSS 的弹性盒布局模块概述

+   从浮动切换到 flexbox

+   Flexbox 属性和简写

# 弹性盒布局模块概述

什么是 flexbox？通常称为 flexbox，它的真实名称是*flexible box layout module*。它提供了一种更有效的方式来布局，对齐和分配父元素的子元素之间的空间，即使它们的大小和数量是未知的或动态的。Flexbox 定义了一种全新的布局模式。

传统上，有*块模式*，用于文档布局。有*内联模式*，用于文本；*表模式*，用于表格数据（表格）；和*定位模式*，用于明确位置而不太关心周围的其他元素。现在有*flexbox 模式*。那么 flexbox 做什么？它可以做很多真正有用的事情。在核心，flexbox 用于布局和对齐。以下列表说明了它更常见的用例：

+   元素的垂直或水平布局。

+   元素的左对齐或右对齐，就像您可以使用浮动一样，但没有浮动带来的额外麻烦。您还可以水平或垂直居中元素。

+   此外，您可以控制显示方向。例如，默认情况下，您可以按源顺序显示元素，也可以按相反方向显示。

+   此外，您可以明确控制元素并更改它们的显示顺序。

+   它轻松实现的另一件事是给你相等高度的列，这以前只能通过使用黑客来实现

+   它真正的乐趣在于它如何在父元素中分配元素以适应可用空间。

+   面向响应式设计

# 弹性术语

所以这都是令人兴奋的事情，我相信你想开始看到它的实际效果，但在我们跳入之前，我们需要做一些功课并学习弹性术语。

# Flex 容器和 flex 项目

首先，有一个称为*flex 容器*的东西，它本质上是包含所有*flex 项目*的元素。换句话说，它是一组元素的父元素；flex 项目是其父元素或 flex 容器的子元素。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00380.jpeg)

# 主要尺寸和交叉尺寸

这里有一个称为*主尺寸*和*交叉尺寸*的东西，如下所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00381.jpeg)

默认情况下，主尺寸是宽度，交叉尺寸是高度，但如果修改`flex-direction`，这可能会改变，这是我们将在下一节学习的内容。

# 主轴和交叉轴

此外，还有一个称为*主轴*的东西，默认情况下水平运行，以及*交叉轴*，默认情况下垂直运行，如下图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00382.jpeg)

# Justify-content 和 align-items

在本章节中，您将学习到一个叫做`justify-content`的属性，它控制沿主轴的对齐方式；`align-items`属性控制沿交叉轴的对齐方式。这是一个重要的概念。主轴和交叉轴可以根据`flex-direction`设置为`column`或`row`来切换。因此，主轴默认始终是水平轴，除非您使用`flex-direction: column`，垂直轴就成为主轴！

如果这是您第一次接触 flexbox，您可能会说：“嘿，慢点！”不用担心，这只是术语和一些属性和概念的介绍；不要指望立刻就能理解这一切。随着我们在接下来的章节中开始使用不同的属性，我们将更多地参考前面的图表，并且我们将在接下来的章节中深入讨论每一个属性。

# 从浮动到 flexbox

在本节中，我们将开始工作，将我们的列模块从基于浮动的布局更改为基于 flexbox 的布局（我很兴奋）。

首先，我们将从列中删除所有与浮动相关的属性，并将它们分解到最初的状态；然后，我们将使用`display: flex`将浮动布局转换为基于 flexbox 的布局，以立即看到结果。最后，我们将探讨`flex-direction`在响应式设计中的用途；当我们开始讨论较小的屏幕尺寸时，我们将讨论这一点。

# 从列部分删除与浮动相关的属性

好的，这是我们的三列布局：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00383.jpeg)

让我们回想一下，它在较小的宽度下变成了一个一列的管道：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00384.jpeg)

好了，让我们去 CSS 文件。现在我们将从我们的列中删除所有基于浮动的属性。

从这开始：

```css
****************
3 columns
****************/
.column {
  float: left;
  width: 31.25%; /* 300/960 */
  margin-left: 3.125%; /* 30/960 */
}
.column:first-child {
  margin-left: 0;
}
.columns figure {
  margin: 0 auto;
  width: 100%;
  max-width: 250px;
}
```

让我们基本上删除所有内容，使其看起来像这样：

```css
****************
3 columns
****************/
.column {

}

```

接下来，让我们在响应式媒体查询中删除基于浮动的代码。所以从这开始：

```css
@media screen and (max-width: 1023px){
  .intro-content {
    width: auto;
    float: none;
    padding-bottom: 0;
    margin-bottom: 30px;
  }
  .go-premium {
    width: auto;
    float: none;
    margin-top: 0;
  }
 .column {
 float: none;
 width: auto;
 padding: 0 50px;
 }
 .column figure {
 margin: 0 auto;
 width: 100%; 
 max-width: 250px;
 }
 .column h2 {
 text-align: center;
 }
}/* end of media query */
```

让我们将它改成这样：

```css
@media screen and (max-width: 1023px){
  .intro-content {
    width: auto;
    float: none;
    padding-bottom: 0;
    margin-bottom: 30px;
  }
  .go-premium {
    width: auto;
    float: none;
    margin-top: 0;
  }
}/* end of media query */
```

并在一个非常小的宽度的媒体查询中，让我们删除对列的最后一个引用。所以，从这开始：

```css
@media screen and (max-width: 550px) {
  h1 {
    font-size: 40px;
  }
  h2 {
    font-size: 26px;
  }
 .column {
 padding: 0;
 }
  .content-block .figure {
    width: 200px;
    display: block;
    margin-left: auto;
    margin-right: auto;
    float: none;
  }
  .content-block h1 {
    text-align: center;
  }
  .button-narrow {
    width: 100%;
  }
}/* end of media query */
```

让我们删除`.column {}`规则集，使其看起来像这样：

```css
@media screen and (max-width: 550px) {
  h1 {
    font-size: 40px;
  }
  h2 {
    font-size: 26px;
  }
  .content-block .figure {
    width: 200px;
    display: block;
    margin-left: auto;
    margin-right: auto;
    float: none;
  }
  .content-block h1 {
    text-align: center;
  }
  .button-narrow {
    width: 100%;
  }
}/* end of media query */
```

好了，如果我们刷新浏览器并扩大它，我们将回到堆叠布局：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00385.jpeg)

我们已经成功地从本节中删除了基于浮动的布局，因为我们的三列已经消失了。

# 使用`display: flex`打开 flexbox

现在我们将使用 flexbox 重新构建列。我们将查看我们的 index.html 文件。这是我们称之为列的区域的标记：

```css
<!-- 
===============
Secondary Sections
===============
-->
<section class="secondary-section grouping">
  <div class="wrapper">
    <div class="column">
      <figure>
        <img src="img/octopus-icon.png" alt="Octopus">
      </figure>
      <h2>The Octopus</h2>
      <p>Lorem ipsum dolor...</p>
      <a href="#" class="button">Tenticals &raquo;</a>
    </div>
    <div class="column">
      <figure>
        <img src="img/crab-icon.png" alt="Crab">
      </figure>
      <h2>The Crab</h2>
      <p>Lorem ipsum dolor...</p>
      <a href="#" class="button">Crabby &raquo;</a>
    </div>
    <div class="column">
      <figure><img src="img/whale-icon.png" alt="Whale"></figure>
      <h2>The Whale</h2>
      <p>Lorem ipsum dolor...</p>
      <a href="#" class="button">Stuart &raquo;</a>
    </div>
  </div><!-- end wrapper -->
</section>
```

每个`<div class="column"></div>`将成为我们的 flex 项目；`<div class="wrapper">`将成为我们的 flex 容器。为了便于理解，我将简化我们的标记如下：

```css
<div class="wrapper"> <!--flex container-->
  <div class="column">...</div> <!--flex item-->
  <div class="column">...</div> <!--flex item-->
  <div class="column">...</div> <!--flex item-->
</div> <!--end of flex container-->
```

让我们为 flex 容器添加一个新的类名"columns"，我们将使用它来定位我们的 flex 容器与我们的 flexbox 代码：

```css
<div class="wrapper columns"> <!--flex container-->
  <div class="column"></div> <!--flex item-->
  <div class="column"></div> <!--flex item-->
  <div class="column"></div> <!--flex item-->
</div> <!--end of flex container-->
```

让我们添加一个新的规则集，以定位我们将要成为 flex 容器的元素。要将某物转换为 flex 容器，只需添加`display: flex`：

```css
/****************
3 columns
****************/
.columns {
  display: flex;
}
.column {

}
```

flex 容器的子元素将自动成为 flex 项目。

请注意，子子孙孙的元素不会被视为 flex 项目，只有直接的子元素。

这就是我们得到的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00386.jpeg)

我们基本上通过一个简单的属性`display: flex`实现了我们的浮动布局。间距有点紧，但我们仍然有一个水平布局。

Flex 覆盖浮动。假设我们有许多浮动，即`float: left`，`float: right`和`float: none`；无论是什么，flex 项目都会忽略浮动，也就是说，它们没有任何影响。因此，一旦容器元素设置为`display: flex`，使子元素成为 flex 项目，浮动现在将被忽略在这些 flex 项目上。我可以随心所欲地浮动，但它对 flex 项目没有任何影响。

还有一件事要记住的是，每列现在都是相等的高度。但让我们做一件事。让我们在 flex 项目周围添加一个边框：

```css
/****************
3 columns
****************/
.columns {
  display: flex;
}
.column {
  border: 1px solid pink;
}
```

这就是它的样子：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00387.jpeg)

等高列，对吧？嗯，每列的内容量完全相同。所以即使我们使用浮动布局，我们也会得到等高的列。不等高是因为每列的内容量不同。我将删除螃蟹列中的一些段落文本：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00388.jpeg)

做完这些之后，你会发现即使它的内容少了很多，它的高度仍然相同。尽管在这里发生了一些其他事情，特别是螃蟹列的宽度与其他两列不同。我们将在本章后面讨论这个问题，但是我们默认情况下确实获得了等高，这是一个很难通过基于浮动的布局来实现的快速胜利。

# 改变 flex-direction

让我们看看通过添加`flex-direction`属性并将其值设置为`column`来改变布局方向有多简单。这个属性适用于`.columns`的 flex 容器。我还删除了粉色的`border`。

```css
/****************
3 columns
****************/
.columns {
  display: flex;
 flex-direction: column;
}
.column {
}
```

我们保存这个设置，哇！我们从水平变成了垂直：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00389.jpeg)

一些我们可能想要的居中对齐已经消失了；然而，布局仍然是垂直的。所以这很有趣。

另一件事是我们可以将`flex-direction`设置为`column-reverse`：

```css
/****************
3 columns
****************/
.columns {
  display: flex;
  flex-direction: column-reverse;
}
.column {
}
```

之前，我们的章鱼首先出现；现在如果我们刷新浏览器，我们的鲸鱼首先出现，章鱼最后出现：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00390.jpeg)

然而，如果我们查看我们的 DevTools，我们会发现章鱼仍然是源顺序中的第一个，但是最后一个被显示出来：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00391.jpeg)

因此，源顺序没有改变，只是显示顺序改变了。

现在是一个好时机来谈谈我们的 flexbox 图表。当`flex-direction`设置为`row`时，这个图表适用——flex 项目水平排列：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00392.jpeg)

然而，当`flex-direction`改为`column`时，图表也会改变：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00393.jpeg)

交叉轴现在从左到右，主轴从上到下，flex 项目现在堆叠在彼此上方。

`flex-direction`的默认值是`row`；`flex-direction: row`。

我们还可以将`flex-direction`设置为`row-reverse`，它会按你所想的那样：水平排列 flex 项目，但顺序相反。让我们看一下下面的图片；我们有鲸鱼、螃蟹和章鱼的顺序相反：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00394.jpeg)

让我们从`.column`的 flex 容器中删除`flex-direction`属性，它将默认为行，这正是我们想要的：

```css
/****************
3 columns
****************/
.columns {
  display: flex;
}
.column {
}
```

# 浏览器缩小

现在让我们考虑一下更小的设备，缩小我们的浏览器。在接近平板尺寸时，会有点紧：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00395.jpeg)

在我们的媒体查询中，我们最初删除了所有的`float`内容。让我们将`flex-direction`改为`column`：

```css
@media screen and (max-width: 550px) {
  h1 {
    font-size: 40px;
  }
  h2 {
    font-size: 26px;
  }
  .columns {
 flex-direction: column;
 }
  .content-block .figure {
    width: 200px;
    display: block;
    margin-left: auto;
    margin-right: auto;
    float: none;
  }
  .content-block h1 {
    text-align: center;
  } 
  .button-narrow {
    width: 100%;
  }
}/* end of media query */
```

我们又回到了较窄浏览器宽度下的一列堆叠布局：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00396.jpeg)

正如你所看到的，仍然存在一些间距和对齐的问题，我们将在下一节中使用 flexbox 来解决这些问题。

总之，我们从列部分中删除了所有基于浮动的布局 CSS，并添加了使用`display: flex`的 flexbox 布局。我们还改变了`flex-direction`，正如我们所看到的，它决定了主轴和交叉轴的方向。

# 理解 flex-grow、flex-basis、flex-shrink 和 flex

让我们试着理解 flexbox 的尺寸属性。在这一节中，我们将使用`flex-grow`、`flex-shrink`、`flex-basis`以及它们的快捷方式`flex`来调整 flex 项目的尺寸。所有这些属性都适用于 flex 项目，而不是 flex 容器。

# 使用 flex-grow

首先，我们来看一个新页面——`flexbox.html`。你可能已经猜到了，有一个`<section>`将成为 flex 容器，还有 5 个`<div>`将成为 flex 项目。

```css
<!--
====================
Flexbox Demo
====================
-->
<section class='flex-container'>
    <div class="flex-item flex-item1">item 1</div>
    <div class="flex-item flex-item2">item 2</div>
    <div class="flex-item flex-item3">item 3</div>
    <div class="flex-item flex-item4">item 4</div>
    <div class="flex-item flex-item5">item 5</div>
</section>
```

这是我们在添加 flexbox 属性之前将要开始的 CSS：

```css
/***************
Flexbox demo
***************/
.flex-container {
  margin-top: 200px;
}
.flex-item {
  padding: 20px;
}
.flex-item1 { background: deeppink;}
.flex-item2 { background: orange; }
.flex-item3 { background: lightblue; }
.flex-item4 { background: lime; }
.flex-item5 { background: olive; }
```

这是在浏览器中的样子：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00397.jpeg)

通过在我们的 CSS 文件中的 flex 容器中添加`display: flex`来打开 flexbox：

```css
.flex-container {
  margin-top: 200px;
 display: flex;
}
```

好了，如果我们刷新浏览器，这为我们创建了一个水平行，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00398.jpeg)

flex-grow 是我们将要看的第一个 flexbox 大小调整属性，它是一个因子。它确定如何沿着 flex 容器的主轴分配“剩余空间”。让我们明确一下，当我说“剩余空间”时我的意思是什么。那就是 flex 容器内未填充的空间，即 flex 项没有占用的空间。在我们的例子中，就是右侧的这个空白空间：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00399.jpeg)

再次，`flex-grow`决定如何将剩余空间分配给 flex 项。让我们应用它到我们的 flex 项，使用值`1`：

```css
.flex-container {
  margin-top: 200px;
  display: flex;
}
.flex-item {
  padding: 20px;
  flex-grow: 1;
}
```

`flex-grow: 1`将强制将剩余空间均匀分配给所有的 flex 项。每个 flex 项都会得到之前未占用的空间的相等部分：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00400.jpeg)

当我缩小浏览器时，我们可以看到我们实现了一个完全流动的网格，而不使用`width`属性和计算 100 如何平均分成 5 的确切百分比！

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00401.jpeg)

让我们为第二个 flex 项创建一个新的规则集（每个 flex 项都有一个唯一的类，第二个是`flex-item2`）。我们将添加一个`flex-grow`属性，值为`2`，这将把剩余空间的两倍分配给第二个 flex 项：

```css
.flex-container {
  margin-top: 200px;
  display: flex;
}
.flex-item {
  padding: 20px;
  flex-grow: 1;
}
.flex-item2 {
 flex-grow: 2
}
```

如果我们刷新浏览器，它应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00402.jpeg)

注意，`flex-item2`的宽度不一定是其他项的两倍；它只是得到了其他项两倍的剩余空间。这是一个值得注意的区别。而且，如果我们缩小浏览器窗口，我们可以看到随着浏览器窗口的缩小，它变窄，直到达到一定的宽度，然后它们大致相同。当有额外的空间时，它会尝试分配更多的空间给`flex-item2`，因为它具有更高的`flex-grow`因子：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00403.jpeg)

我们也可以将`flex-item2`的`flex-grow`设置为`0`，这是`flex-grow`的默认值。这基本上表示不要将任何剩余空间分配给这个 flex 项：

```css
.flex-item2 {
  flex-grow: 0
}
```

第二个 flex 项不会增长以占用任何额外的空间；剩下的四个项会占用可用的额外空间：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00404.jpeg)

# 使用 flex-basis

让我们再看一下 flex 项的另一个属性：`flex-basis`。请注意，`flex-basis`是在根据`flex-grow`和`flex-shrink`进行剩余空间分配之前的 flex 项的初始主尺寸；我们很快会讨论后者。现在，让我们把`flex-basis`简单地看作是宽度。所以，对于`flex-item2`，让我们给它一个`flex-basis`为`400px`并移除它的`flex-grow`因子：

```css
/***************
Flexbox demo
***************/
.flex-container {
  margin-top: 200px;
  display: flex;
}
.flex-item {
  padding: 20px;
  flex-grow: 1;
}
.flex-item2 {
 flex-basis: 400px;
}
```

如果你刷新浏览器，它将把第二个 flex 项的大小设置为`400px`。但是如果我们真正看一下，它的大小要比 400 像素多一点：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00405.jpeg)

然而，我仍然将`flex-grow`应用到所有的 flex 项，包括这一个。让我们改变一下，让我们的第二个 flex 项具有默认值`flex-grow: 0;`：

```css
.flex-item2 {
 flex-grow: 0;
    flex-basis: 400px;
}
```

现在当你刷新浏览器，你会看到它确切地是 400 像素：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00406.jpeg)

它会一直是 400 像素，直到我们开始缩小浏览器；在某个时候，它会开始让步。一旦空间开始变得非常有限，它决定将它缩小到小于 400 像素；这就是`flex-basis`定义中*初始主尺寸*部分发挥作用的地方。我们告诉 flexbox 我们希望第二个 flex 项的宽度为 400 像素，flexbox 会遵守这一点，直到 flex 容器没有足够的空间来容纳它。然后，它开始减小第二个 flex 项的宽度，以适应最佳布局。

让我们再次移除`flex-grow`：

```css
.flex-item2 {
  flex-basis: 400px;
}
```

请注意，`flex-basis`不仅仅是宽度：当`flex-direction`设置为`row`时，它是宽度，这是默认值，当`flex-direction`设置为`column`时，它是高度。从技术上讲，因为它不是宽度或高度，它是主要尺寸。

你开始明白为什么我们花了那么多时间来学习 flex 术语了吗？如果其中有任何内容让您感到困惑，我建议您回到本章的开头复习 flex 术语。

所以让我们将`flex-direction`更改为`column`。我们将在 flex 容器上执行此操作：

```css
.flex-container {
  margin-top: 200px;
  display: flex;
 flex-direction: column;
}
.flex-item {
  padding: 20px;
  flex-grow: 1;
}
.flex-item2 {
  flex-basis: 400px;
}
```

现在，由于主轴是垂直运行，`400px`的`flex-basis`现在是第二个 flex 项目的高度。您可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00407.jpeg)

因此，`flex-basis`会覆盖任何设置的高度。让我们举个例子，为第二个 flex 项目输入一个`height`为`800px`：

```css
.flex-item2 {
  flex-basis: 400px;
 height: 800px;
}
```

我们看到高度仍然是 400 像素。实际上，我应该说主要尺寸是 400 像素，它应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00408.jpeg)

因此，`flex-basis`还接受两个关键字：`auto`和`content`。`auto`关键字的意思是，“去查看`width`或`height`属性”。由于`flex-direction`目前是`column`，当我们将`flex-basis`更改为`auto`时，`800px`的`height`不应再被忽略：

```css
.flex-item2 {
 flex-basis: auto;
  height: 800px;
}
```

高度现在是 800 像素：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00409.jpeg)

因此，`auto`是`flex-basis`的默认值。还有另一个可用的关键字叫做`content`；这意味着 flex 项目的大小是基于 flex 项目内容的大小。目前最新版本的 Chrome 不支持这一点，所以我不会演示它；但是，一旦浏览器开始实现它，它似乎会在未来变得有用。

好了，我将删除`height`和`flex-basis`。我还将删除`flex-direction`，最终得到我们的 CSS 如下：

```css
.flex-container {
  margin-top: 200px;
  display: flex;
}
.flex-item {
  padding: 20px;
  flex-grow: 1;
}
.flex-item2 {

}
```

这是它的样子：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00410.jpeg)

# 使用 flex-shrink

`flex-shrink`可以被认为是`flex-grow`的相反。虽然`flex-grow`确定了当有剩余空间时，flex 项目应该消耗多少额外空间，与其他项目成比例，`flex-shrink`确定了当没有剩余空间时，flex 项目本身应该如何与其他项目成比例收缩。因此，让我们看看这个过程并逐步进行。

首先，让我们为每个 flex 项目添加`flex-basis`为`200px`，并临时删除`flex-grow`：

```css
.flex-container {
  margin-top: 200px;
  display: flex;
}
.flex-item {
  padding: 20px;
  flex-basis: 200px;
}
.flex-item2 {

}
```

因此，如果`flex-basis`设置为 200 像素，每个 flex 项目将是 200 像素宽，任何额外的空间都不允许在任何 flex 项目中，因为`flex-grow`已被移除。它应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00411.jpeg)

让我们将`flex-grow`的值重新添加到我们的`flex-item`类中：`1`。

```css
.flex-item {
  padding: 20px;
  flex-basis: 200px;
  flex-grow: 1;
}
```

再次，额外的空间分配给每个 flex 项目。`flex-basis`属性只是初始主尺寸的起点（请注意我没有说“初始宽度”，而是“宽度”）。但是每个 flex 项目都变得更宽，以吸收均匀分配给每个项目的额外空间。这是您的页面目前应该看起来的样子：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00412.jpeg)

让我们在第二个 flex 项目上添加一个`flex-shrink`属性。我们将使用一个因子`2`，如下面的代码所示：

```css
.flex-container {
  margin-top: 200px;
  display: flex;
}
.flex-item {
  padding: 20px;
  flex-basis: 200px;
  flex-grow: 1;
}
.flex-item2 {
  flex-shrink: 2;
}
```

随着浏览器尺寸的减小，所有项目都会收缩。除了第二个 flex 项目，它的收缩量是其他 flex 项目的两倍，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00413.jpeg)

如果没有为 flex 项目指定，`flex-shrink`的默认值为`1`。因此，让我们为所有 flex 项目添加`flex-shrink: 1`，除了第二个 flex 项目，它的`flex-shrink`设置为`2`，只是为了证明没有任何变化： 

```css
.flex-container {
  margin-top: 200px;
  display: flex;
}
.flex-item {
  padding: 20px;
  flex-basis: 200px;
  flex-grow: 1;
 flex-shrink: 1;
}
.flex-item2 {
  flex-shrink: 2;
}
```

我们可以看到，当我们使浏览器变小时，实际上没有任何变化；第二个 flex 项目仍然比其他项目收缩得更多，如下面的示例所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00414.jpeg)

您还可以做的一个好玩的事情是将`flex-shrink`设置为`0`，以确保项目不会收缩。让我们为第二个 flex 项目这样做：

```css
.flex-container {
  margin-top: 200px;
  display: flex;
}
.flex-item {
  padding: 20px;
  flex-basis: 200px;
  flex-grow: 1;
  flex-shrink: 1;
}
.flex-item2 {
 flex-shrink: 0;
}
```

现在刷新浏览器。当空间有限时，所有其他 flex 项目都会收缩，除了项目 2；它保持着`flex-basis: 200px`：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00415.jpeg)

# 使用 flex 快捷方式

还有一个名为 `flex` 的快捷属性，可以替代使用 `flex-grow`、`flex-shrink` 和 `flex-basis`。让我们用 `flex` 替换 `flex-basis`、`flex-grow` 和 `flex-shrink`：

```css
.flex-container {
  margin-top: 200px;
  display: flex;
}
.flex-item {
  padding: 20px;
 flex: 1 1 200px;
}
.flex-item2 {
  flex-shrink: 0;
}
```

因此，`flex` 中值的顺序如下：`flex-grow`、`flex-shrink` 和 `flex-basis`：

```css
.flex-container {
  margin-top: 200px;
  display: flex;
}
.flex-item {
  padding: 20px;
 flex: 1 1 200px; /* order: flex-grow, flex-shrink, flex-basis */
}
```

如果我们刷新浏览器，它将做与我们使用非快捷属性时完全相同的事情：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00416.jpeg)

对于第二个 flex 项目，它只有 `flex-shrink`，所以我们可以使用 `flex: 1 0` 的快捷方式。`flex-basis` 将智能地设置为其默认值 `auto`，可以省略。我们需要将值设置为 `1 0`，因为 `flex-grow` 的默认值是 `1`，因此即使我们没有显式设置 `flex-grow`，我们也需要将其值添加到我们的快捷方式中。我们还将删除现有的 `flex-shrink`：

```css
.flex-container {
  margin-top: 200px;
  display: flex;
}
.flex-item {
  padding: 20px;
  flex: 1 1 200px; /* order: flex-grow, flex-shrink, flex-basis */
}
.flex-item2 {
 flex: 1 0; /* order: flex-grow, flex-shrink */
}
```

同样，在浏览器中我们看不到任何变化，这正是我们从小的重构中想要的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00417.jpeg)

因此，`flex: 1 0` 意味着 `flex-grow = 1` 和 `flex-shrink = 0`。如前所述，`flex-basis` 默认为 `auto`，因此我们不需要在这里添加它。还有一个关键字 `none`，基本上是说不要增长、不要收缩，并且查看我的宽度或高度作为主要大小，换句话说，不要伸缩。这个快捷方式很简洁，但在开始使用 flexbox 时，我建议使用每个属性单独使用，直到完全理解每个属性在做什么。

# 更多布局，更多定位

本节介绍了使用 flexbox 进行更多布局和更多定位。在这里，我们将查看一个新属性 `justify-content`，以及如何在彼此之间嵌套 flexbox，最后使用自动边距。

在开始之前，让我们通过去掉我们的 flex 快捷方式来重置一些 `flex` 属性：

```css
.flex-container {
  margin-top: 200px;
  display: flex;
}
.flex-item {
  padding: 20px;
}
.flex-item2 {

}
```

通过移除 flex 快捷方式，每个 flex 项目都不再关心增长、收缩或它们的初始主要大小应该是什么：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00418.jpeg)

# 使用 `justify-content` 属性

首先是 `justify-content`，这是一个决定内容是否在主轴的起始位置、结束位置或中间位置对齐的 flex 容器属性。让我们添加 `justify-content` 并将其设置为 `flex-start`，如下面的代码片段所示：

```css
.flex-container {
  margin-top: 200px;
  display: flex;
 justify-content: flex-start;
}
```

`flex-start` 是 `justify-content` 的默认值，因此没有任何变化：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00419.jpeg)

`flex-start` 将 flex 项目定位在主轴的起始位置。请记住，当未指定 `flex-direction` 或指定为 `row` 时，主轴水平从左到右。因此，`flex-start` 将是左边缘，`flex-end` 将是右边缘：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00420.jpeg)

现在让我们将值更改为 `flex-end`：

```css
.flex-container {
  margin-top: 200px;
  display: flex;
 justify-content: flex-end;
} 
```

内容现在定位到右侧：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00421.jpeg)

这很像使用 `float:right`，只是没有所有额外的麻烦和与浮动相关的问题：没有清除、没有折叠，也没有重新排列浮动项目。基本上，我们只是将 flex 项目定位到右侧。

这非常有用，但真正的魔力是当我们使用 `justify-content: center` 时发生的：

```css
.flex-container {
  margin-top: 200px;
  display: flex;
  justify-content: center;
}
```

哦，天哪，我们刚刚将 flex 项目居中了！

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00422.jpeg)

从来没有 `float: center`。诚然，我们可以通过在容器上将左右边距设置为 `auto` 来居中物品。但问题是，这样做时我们总是必须指定容器的 `width`；因此，如果容器中的项目数量发生变化，我们还必须更改 `width` 属性。有其他居中的技巧，但没有一个像这样简单和灵活。

Flexbox 本质上更适合动态内容，不需要定义任何 `width`；让我们在 HTML 中添加另一个 flex 项目来证明这一点：

```css
<section class="flex-container">
    <div class="flex-item flex-item1">item 1</div>
    <div class="flex-item flex-item2">item 2</div>
    <div class="flex-item flex-item3">item 3</div>
    <div class="flex-item flex-item4">item 4</div>
    <div class="flex-item flex-item5">item 5</div>
 <div class="flex-item flex-item1">item 6</div>
</section>
```

现在我们有六个项目，它们都仍然居中：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00423.jpeg)

但等等，还有更多！有一个名为 `space-between` 的关键字可以使用：

```css
.flex-container {
  margin-top: 200px;
  display: flex;
 justify-content: space-between;
}

```

这个关键字`space-between`在每个项之间均匀分配了额外的空间。因此每个元素之间都有"空间"：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00424.jpeg)

注意第一个和最后一个元素紧贴边缘；第一个 flex 项紧贴其容器的最左边缘；最后一个 flex 项紧贴其容器的最右边缘。

还有另一个值，`space-around`做了一些略有不同的事情：

```css
.flex-container {
     margin-top: 200px;
     display: flex;
    justify-content: space-around;
 }
```

请注意，`space-around`重新分配了容器周围所有 flex 项的额外空间，甚至是第一个和最后一个，而`space-between`只在每个项之间插入额外的空间。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00425.jpeg)

让我们回到主页，在一个更实际的例子中实现这一点，也就是我们的三列：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00426.jpeg)

我们的三列设置为`display: flex`，但没有应用其他 flex 属性。flex 项已经有点居中，因为 flex 容器已经居中。然而，我们希望每个 flex 项之间有一些空间。因此，在我们的 CSS 区域中，让我们说`justify-content: space-between`。与我们目前正在做的无关。我还在我们的海洋生物上设置了`max-width: 50%`，这样它们就不会太大。但更重要的是`justify-content`：

```css
.columns {
  display: flex;
 justify-content: space-between;
}
.column {

}
.column figure {
 max-width: 50%;
}
```

没有任何变化！

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00427.jpeg)

这是因为每列中的文本。内容推动每个 flex 项填充可用的空间。因此，我们需要为这些项添加`width`或`flex-basis`，以明确定义我们希望每列有多宽。这是因为由于没有额外的空间，flexbox 无法重新分配 flex 项以在每个 flex 项之间放置额外的空间。我们需要一些额外的空间。

让我们通过向每列添加`flex-basis: 30%`来实现这一点：

```css
.columns {
  display: flex;
  justify-content: space-between;
}
.column {
 flex-basis: 30%;
}
.column figure {
  max-width: 50%;
}
```

刷新页面，你应该看到这个：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00428.jpeg)

注意空间在每个项之间均匀分布。太棒了！我们还有一点清理要做。底部的按钮在每列底部的位置不一致；现在这并不太明显，因为每列内的内容相对相同；然而，如果我们使每列中的内容量有很大的不同，这将变得更加明显：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00429.jpeg)

我们如何解决这个问题？好吧，记住，在我们的情况下，flex 容器是列，每列是一个 flex 项。按钮不是一个 flex 项，因为它在列内。这就是嵌套的 flexbox 发挥作用的地方。

# 嵌套的 Flexbox

让我们将列转换为嵌套的 flex 容器：

```css
.columns {
  display: flex;
  justify-content: space-between;
}
.column {
  flex-basis: 30%;
 display: flex;
}.column figure {
  max-width: 50%;
}
```

当然，容器的 flex 项默认设置为`flex-direction:row`，因此它们都水平地坐在一起，这完全破坏了事情：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00430.jpeg)

显然，这不是我们想要的样子，但我们可以很容易地解决这个问题。让我们将`flex-direction`更改为`column`，如下面的代码片段所示：

```css
.column {
  flex-basis: 30%;
  display: flex;
  flex-direction: column;
}
```

很好，我们又回到了正轨。看起来和我们将列设置为 flex 容器之前一样：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00431.jpeg)

这对我们有什么帮助？嗯，我们可以开始使用`justify-content`，也许我们可以说`justify-content`，`space-between`：

```css
.column {
  flex-basis: 30%;
  display: flex;
  flex-direction: column;
 justify-content: space-between;
}
```

这使按钮在底部很好地放置，但现在在内容的中间。每个 flex 项之间的空间均匀分布，这对于每列来说是不同的，因此看起来不太好：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00432.jpeg)

让我们恢复`justify-content`的默认值：

```css
.column {
  flex-basis: 30%;
  display: flex;
  flex-direction: column;
  justify-content: flex-start;
}
```

这将所有内容移回顶部，因为`flex-direction`是`column`，主轴现在是上下方向的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00433.jpeg)

# 使用自动边距

关于 flexbox 的一个显著特点是它对`margin`的`auto`关键字进行了全新的处理。自动边距现在与 flexbox 密切配合。我现在可以将我的按钮作为选择器，并给它`margin-top`为`auto`：

```css
.columns {
  display: flex;
  justify-content: space-between;
}
.column {
  flex-basis: 30%;
  display: flex;
}
.column figure {
  max-width: 50%;
}
.column .button {
 margin-top: auto;
}
```

砰！按钮上方的空间现在自动计算，按钮位于每列的底部：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00434.jpeg)

当 flex-direction 是 row 时，这也适用；您可以使用`margin-left: auto;`或`margin-right: auto`将 flex 项紧贴到其 flex 容器的外边缘。

为了举例说明，让我们回到我们的 flexbox 演示示例，我们可以将 flex 容器的`justify-content`更改为`flex-start`，然后添加另一个规则集，使用`margin-left: auto`将最后一个 flex 项推到右边缘：

```css
/***************
Flexbox demo
***************/
.flex-container {
  margin-top: 200px;
  display: flex;
 justify-content: flex-start;
}
.flex-item {
  padding: 20px;
}
.flex-item:last-child {
 margin-left: auto;
}
```

所有的 flex 项都排在左边-在它们的`flex-start`处-除了最后一个 flex 项，它紧贴在右边-或者在`flex-end`处-因为我们自动计算它的左边距：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00435.jpeg)

让我们回到主页，看看我们的列。关于这些列的最后一件事：红色标题不是每个都在同一垂直位置对齐，因为我们的每个海洋生物 SVG 的高度略有不同：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00436.jpeg)

让我们给每个海洋生物一个`flex-basis`为`150px`。由于`flex-direction`是`column`，`flex-basis`可以被视为高度；因此，我们基本上给每个图形相同高度的`150px`：

```css
.columns {
  display: flex;
  justify-content: space-between;
}
.column {
  flex-basis: 30%;
  display: flex;
  flex-direction: column;
}
.column figure {
  max-width: 50%;
 flex-basis: 150px;
}
.column .button {
  margin-top: auto;
}
```

现在这些红色标题将整齐地排在一起：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00437.jpeg)

总之，`justify-content`沿着主轴定位和重新分配额外的空间。您可以整天嵌套 flexbox，并且自动边距非常方便，可以让您将内容定位到 flex 容器的相反边缘，这是一个非常常见的 UI 模式。

# 总结

在本章中，我们已经涵盖了 flexbox 的大量内容，包括所有基本的 flexbox 属性。在下一章中，当我们学习如何对齐和流动 flexbox 内容以及所需的属性时，我们将继续进行。我们还将创建一个新的 UI 模式-产品列表-并看看 flexbox 如何在那里发挥作用。
