# HTML5 多媒体开发秘籍（三）

> 原文：[`zh.annas-archive.org/md5/E84C7ACCB273D1B70039D0DDC29824AC`](https://zh.annas-archive.org/md5/E84C7ACCB273D1B70039D0DDC29824AC)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：使用 JavaScript 进行交互

在本章中，我们将涵盖：

+   使用 JavaScript 播放音频文件

+   使用文本的拖放 API

+   使用`vid.ly`和 jQuery 实现跨浏览器视频支持

+   使用 jQuery 动态显示视频

+   使用 jQuery 创建可移动的视频广告

+   使用`Easel.js`和`canvas`标签控制图像的显示

+   使用`Easel.js`和`canvas`标签来显示一系列图像的动画

+   使用`canvas`标签和 JavaScript 进行随机动画和音频

# 介绍

虽然 HTML5 可能会结束对 Flash 的许多丰富媒体应用程序的使用，但它正在导致 JavaScript 比以前更受欢迎。有许多库和插件可用于增强和扩展 HTML5 和 CSS3，以创建丰富的交互体验。

本章包含了一些示例，展示了 JavaScript 如何与 HTML5 标签（如音频、视频和画布）、CSS3 选择器和元素一起使用。

# 使用 JavaScript 播放音频文件

HTML5 在互联网上如何使用音频文件提供了更多的灵活性。在这个示例中，我们将创建一个游戏，练习使用音频标签和 JavaScript 加载和播放声音。

## 准备工作

您需要一个要播放的音频文件，一张图片，以及支持 HTML5 的现代浏览器。本章的示例文件可以从[`www.packtpub.com/support?nid=7940`](http://www.packtpub.com/support?nid=7940)下载。Free Sound Project ([`freesound.org`](http://freesound.org))有您可以使用的音频文件，只要给予制作人信用，照片可以在[`www.Morguefile.com`](http://www.Morguefile.com)找到，供您在个人项目中使用。

## 如何做...

现在我们准备创建一系列按钮和一个简短的 JavaScript 程序，当其中一个按钮被按下时，它将播放一个随机的音频文件。

打开您的 HTML 编辑器并创建一个 HTML5 页面的开头部分。

```html
<!DOCTYPE html><html lang="en"><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"> <title>Playing a sound file with JavaScript</title>

```

因为我们只有一些样式，我们将把它们添加到 HTML 页面的 head 区域。

```html
<style>h1{font-family:"Comic Sans MS", cursive; font-size:large; font-weight:bold;}
button{ padding:5px;margin:5px;}
button.crosshair { cursor: crosshair; }
button.crosshairthree {margin-left:40px;
cursor:crosshair;} </style>

```

脚本需要创建三个变量。打开脚本标签并创建变量，应该看起来像下面的代码块：

```html
<script>//variables
var mySounds=new Array();
mySounds[0]="boing";
mySounds[1]="impact";
mySounds[2]="squeak";
mySounds[3]="whack";
mySounds[4]="space";
var soundElements;
var soundChoice;

```

现在我们已经为脚本创建了全局变量，我们可以创建函数。键入`function whackmole(){`开始函数，然后在新行上键入`var i = Math.floor(Math.random() * 5)`;使用 JavaScript 数学库生成一个随机数。接下来，键入`soundChoice = mySounds[i]`;将数组值分配给`soundChoice`。使用`soundElements[soundChoice].play();}`关闭函数。您的函数代码目前应该看起来像下面的代码：

```html
function whackmole() {
var i = Math.floor(Math.random() *5);
soundChoice = mySounds[i];
soundElements[soundChoice].play();}

```

键入`function init(){`开始函数。在新行上，键入`soundElements = document.getElementsByTagName("audio");} </script>`来完成我们的 JavaScript 代码块。它应该看起来像下面的代码块：

```html
function init(){
soundElements = document.getElementsByTagName("audio");}
</script>

```

关闭 head 标签并键入 body 标签，添加一个`init()`函数调用，使其看起来像：

```html
</head><body onLoad="init();">

```

使用`<header>`标签为页面的头部区域创建一个标题区域。使用标题标签`<h1>`显示页面的标题：

```html
<header><h1>Whack A Mole!</h1></header>

```

有五个按钮来创建一个平衡的外观，它们都被分配了一个类。

```html
<section> <p> <button class="crosshair" onclick="whackmole();"> <img src="img/downmole.png" width="37" height="24" alt="Mole peeping out of hole"></button>
<button class="crosshair" onclick="whackmole();"> <img src="img/downmole.png" width="37" height="24" alt="Mole peeping out of hole"></button></p>

```

第三个按钮的类名为`crosshairthree`，以便我们更好地控制它在屏幕上的位置。

```html
<p style="padding-left:30px;"><button class="crosshair" onclick="whackmole();"><img src="img/downmole.png" width="37" height="24" alt="Mole peeping out of hole"></button></p> <p><button class="crosshair" onclick="whackmole();"> <img src="img/downmole.png" width="37" height="24" alt="Mole peeping out of hole"></button><button class="crosshair" onclick="whackmole();"><img src="img/downmole.png" width="37" height="24" alt="Mole peeping out of hole"></button></p></section>

```

如果您正在使用本书的代码文件，那么音频文件标签应该类似于下面的代码块：

```html
<section><audio id ="boing" autobuffer>
<source src="img/cartoonboing.ogg" />
<source src="img/cartoonboing.mp3" /></audio>
<audio id ="impact" autobuffer>
<source src="img/cartoonimpact.ogg" />
<source src="img/cartoonimpact.mp3" /></audio>
<audio id ="squeak" autobuffer>
<source src="img/cartoonsqueak.ogg" />
<source src="img/cartoonsqueak.mp3" /></audio>
<audio id ="whack" autobuffer>
<source src="img/cartoonwhack.ogg" />
<source src="img/cartoonwhack.mp3" /></audio>
<audio id="space" autobuffer>
<source src="img/cartoonspaceboing.ogg" />
<source src="img/cartoonspaceboing.mp3" /></audio>

```

使用以下标签完成页面：

```html
</section></body></html>

```

将文件保存为`playing-audio-files-with-javascript.html`并在浏览器中查看。它应该看起来类似于以下屏幕截图：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_07_01.jpg)

## 它是如何工作的...

首先，我们创建了一个基本的 HTML5 页面。然后，我们添加了 CSS 样式，为按钮添加了背景图像，并在鼠标或指向设备移动到按钮上时将鼠标图标更改为十字准星。这给我们提供了一个视觉模拟的瞄准武器，比默认的鼠标图标更有趣。

创建了三个变量以在脚本中使用：`mySounds，soundElements`和`soundch`。我们创建的第一个函数名为`whackmole()`包含一个内部变量`i`，该变量保存了随机生成的数字的结果。`Math.random()`导致生成一个伪随机数。然后我们将其乘以`5`，我们的音频文件数量，并将结果用于`Math.floor()`以创建一个值范围从零到五的整数。然后将该值分配给临时变量`i`，然后用于使用随机生成的数组值填充变量`mySounds`。将新的数组值存储在变量`soundChoice`中，`soundChoice = mySounds[i]`。这使我们能够在按下按钮时使用`soundElements[soundChoice].play()`触发`audio`标签的`play()`动作。

我们创建的第二个函数是`init()`，稍后我们将其与`onLoad`一起绑定到`body`标签，以便我们可以使用`audio`标签及其数组值在`soundElements`变量中获取音频文件。

接下来，我们添加了`<body onLoad="init();">`标签，并在页面上添加了一系列包含可爱的鼹鼠图像的按钮。每个按钮都包含一个`onClick()`事件，该事件调用了`whackmole()`函数。我们的第三个按钮与其他按钮的类不同，`crosshairthree`，它在按钮左侧添加了额外的边距，使其看起来更加居中。

### 注意

Firefox 目前存在一个怪癖，如果您不首先列出`.ogg`音频源，它将无法找到它。

最后，我们使用`<audio>`和`<source>`标签将声音文件添加到页面中。使用源标签列出了每个文件的`ogg`和`mp3`格式。因为源标签被认为是其所包围的父音频标签的“子级”，所以根据使用的浏览器不同，任何文件格式都会播放，因为不同的浏览器目前更喜欢不同的声音文件格式。

## 还有更多...

您可以看到，通过为不同的图像播放不同的声音文件，非常容易创建一个类似于儿童读物的形状或动物的页面的应用程序。

### 使用 jQuery 控制音频剪辑的外观

jQuery 中的`.animate`函数为使音频控件在访问者采取行动时出现，淡出和消失提供了新的方法，这是丰富媒体体验的一部分。以下是一个示例，演示了如何使音频控件淡出，然后迅速重新出现：

```html
<script> $(document).ready(function(){
$('audio').delay(500).hide('fade', {}, 1000 ).slideDown('fast'); }); </script>
<!- - the HTML -- ><audio id ="boing" autobuffer> <source src="img/cartoonboing.ogg" /> <source src="img/cartoonboing.mp3" /></audio>

```

我们将在本章的一个示例中使用视频文件执行类似的技巧。

## 另请参阅

第八章 *拥抱音频和视频*将涵盖有关音频标签及其使用方式的更多信息。

# 使用文本的拖放 API

虽然所有浏览器都可以本地拖动图像或链接，但放置对象以前需要复杂的 JavaScript 或第三方库。拖放 API 旨在提供一种更简单，标准化的方式，使用户能够将任何类型的对象放入标识区域。实际上，在不同浏览器中使用该 API 是一项挑战。目前主要支持此 API 的浏览器是 Firefox，Chrome 和 Safari。

## 准备就绪

在[`www.packtpub.com/support?nid=7940`](http://www.packtpub.com/support?nid=7940)下载本教程的代码。本教程标题中使用的字体来自[`www.fontsquirrel.com`](http://www.fontsquirrel.com)，您也可以在那里下载不同的字体。本教程可能无法在 Internet Explorer 中使用。我们将创建一个井字棋游戏，演示拖放 API 的工作原理。

## 如何做...

打开您的 HTML 编辑器，首先创建一个基本的 HTML5 页面。我们将添加两个样式表链接，一个用于支持我们将为页面标题加载的`@fontface`字体，另一个用于我们的主样式表。输入以下代码，然后将文件保存为`using-drag-drop-api.html`。

```html
<!DOCTYPE html><html lang="en"> <head> <meta charset="utf-8"> <title>Using the drag-and-drop API element</title> <link rel="stylesheet" href="fonts/specimen_files/specimen_stylesheet.css" type="text/css" charset="utf-8" /> <link rel="stylesheet" href="stylesheet.css" type="text/css" charset="utf-8" />

```

让我们继续为页面添加样式。创建或打开名为`stylesheet.css`的 CSS 文件。将页面的整体`margin`设置为`100px`，默认颜色设置为`#666`。

```html
@charset "UTF-8";/* CSS Document */body { margin:100px; color:#666; }

```

页面的内容标签应该都设置为`display:block`，如下面的代码所示：

```html
article, aside, figure, footer, header, hgroup, menu, nav, section { display:block; }

```

现在，我们指定`@fontface`信息。代码和字体文件来自于`www.fontsquirrel.com`字体包，该字体包包含在本教程的代码文件中。

```html
@font-face { /* This declaration targets Internet Explorer */ font- family: '3DumbRegular';src: url('3dumb-webfont.eot');}@font-face {/* This declaration targets everything else */font-family: '3DumbRegular';src: url(//:) format('no404'), url('fonts/3dumb- webfont.woff') format('woff'), url('fonts/3dumb-webfont.ttf') format('truetype'), url('fonts/3dumb-webfont.svg#webfontlNpyKhxD') format('svg');font-weight: normal;font-style: normal;}

```

为`h1`标签添加颜色，并将`font-family`属性设置为`3DumbRegular`，这是我们字体的名称。

```html
h1{color:#C60;font-family: '3DumbRegular';}

```

创建一个名为`gametilebox`的新 div 来容纳组成游戏块的字母。将该框的`float`属性设置为`left`，宽度和高度设置为`280px`。按照以下代码片段中所示的方式设置`padding, margin-right, border`和`background-color`。

```html
#gametilebox{ float:left;width:280px; height:280px; padding:10px; margin-right:30px; border:1px solid #000; background-color:#ccc; }

```

游戏板将共享许多与瓷砖框相同的属性，因此复制`gametilebox`的样式，粘贴并命名为“gameboard”。添加一个`background-image`属性，其 url 为`images/tictactoegrid.jpg`，并将`background-color`设置为`aa`。

`gameboard div`应该看起来像以下代码：

```html
#gameboard { float:left; width:280px; height:280px; padding:10px; margin-right:30px;border:1px solid #000; background-image:url(images/tictactoegrid.jpg); background-color:#aaa;}

```

让我们为放置字母的`div`块添加样式。所有`block` div 的`float`应该设置为`left`。`width`不应大于`85px`，`height`不应大于`80px`。它们将位于 3x3 的网格上，因此第二行和第三行的第一个块也需要具有`clear:both`属性。第二行和第三行的第三个块应该具有较低或没有`padding`和`margin-right`属性。因为有九个，所以这里只显示了一个块代码的示例：

```html
#blockA {float:left; width:75px; height:75px; padding:5px 5px 5px 2px; margin-right:10px; border:none; background-color:red;}
#blockB {float:left; width:75px; height:75px; padding:5px; margin-right:10px; border:none; background-color:blue;}

```

现在，我们将为字母游戏块设置样式。在样式表中创建一个名为`lettertile`的新类，然后按照以下方式设置类的属性：

```html
.lettertile { width:60px; height:60px; padding:5px; margin:5px; text-align:center; font-weight:bold;font-size:36px;color:#930; background-color:transparent;display:inline-block;}

```

我们将添加的最后一个样式是`draggable`属性。创建下面的样式以帮助跨浏览器兼容性：

```html
*[draggable=true] { -moz-user-select:none; -khtml-user-drag: element; cursor: move;}

```

样式表已经完成，现在我们可以开始编写脚本来拖动字母块并放置它们。

打开先前创建的 html 页面`using-drag-drop-api.html`，并为 IE 浏览器键入以下代码：

```html
<!--[if IE]><script src="img/html5.js"> </script><![endif]-->

```

在样式表链接的下面添加一个开放的`<script>`标签，并键入第一个函数`dragDefine(ev)`，它接受一个事件参数，然后跟着一个`{`。在大括号之后，键入`ev.dataTransfer.effectAllowed ='move'`；然后，在新的一行上，键入`ev.dataTransfer.setData("text/plain", ev.target.getAttribute('id'))`；以设置数据类型和目标属性。最后，键入`return true`；并加上一个闭合的`}`以完成函数。

```html
function dragDefine(ev) {ev.dataTransfer.effectAllowed = 'move'; ev.dataTransfer.setData("text/plain", ev.target.getAttribute('id')); return true;}

```

现在，我们需要定义`dragOver`函数。键入`dragOver(ev)`和一个开放的`{`，然后通过添加`ev.preventDefault()`来调用`preventDefault()`函数。函数块应该类似于下面的代码：

```html
function dragOver(ev) { ev.preventDefault();}

```

我们需要的下一个函数是指示拖动完成的函数。键入`function dragEnd(ev)`，然后输入`{`。键入`return true; }`以完成函数。

键入`function dragDrop(ev)`并打开一个`{`，然后转到新的一行添加我们的第一个方法。键入`var idDrag = ev.dataTransfer.getData("Text")`；创建一个将保存文本字符串的拖动变量，然后键入`ev.target.appendChild (document.getElementById(idDrag))`；。最后，键入`ev.preventDefault()`；完成函数块应该看起来像以下代码：

```html
function dragDrop(ev) {
var idDrag = ev.dataTransfer.getData("Text");
ev.target.appendChild(document.getElementById(idDrag));
ev.preventDefault();} </script>

```

关闭页面的头部部分。键入`<body><header>`，然后`<h1>拖放井字棋</h1></header>`以完成页面的标题。

```html
</head><body><header><h1>Drag and Drop Tic Tac Toe</h1></header>

```

接下来，键入`<section><h3>将字母从灰色框拖到游戏板上（然后再拖回来！）</h3>`。

创建一个 ID 为`"gametilebox"`的 div，并设置`ondragover ="dragOver(event)"`和`ondrop="dragDrop(event)"`。它应该看起来像以下语句：

```html
<div id="gametilebox" ondragover="dragOver(event)" ondrop="dragDrop(event)">

```

现在，我们将为每个游戏瓷砖创建一个`div`。创建六个**"X"**瓷砖和六个**"O"**瓷砖，每个都以`"lettertile"`开头并以值从`1-12`的数字结尾的`id`。每个`div`将包含类`"lettertile"`，每个`draggable`属性将包含值`"true"`。每个瓷砖还将包含`ondragstart="return dragDefine(event)"`和`ondragend="dragEnd(event)"`。`div`块应该看起来像以下代码：

```html
<div id="lettertile1" class="lettertile" draggable="true" ondragstart="return dragDefine(event)" ondragend="dragEnd(event)">X</div>
<div id="lettertile2" class="lettertile" draggable="true" ondragstart="return dragDefine(event)" ondragend="dragEnd(event)">X</div>
<div id="lettertile3" class="lettertile" draggable="true" ondragstart="return dragDefine(event)" ondragend="dragEnd(event)">X</div>

```

现在，我们可以为我们在**stylesheet.css**中创建的那些块样式创建实际的`divs`。首先输入`<div id= "gameboard">`。应该有一个`div`对应每个块 id，从"blockA"到"blockI"。它们每个都将包含一个`ondragover="return dragOver(event)"`和一个`ondrop="dragDrop(event)"`。它们应该看起来像以下代码块。

```html
<div id="blockA" ondragover="return dragOver(event)" ondrop="dragDrop(event)"></div>
<div id="blockB" ondragover="return dragOver(event)" ondrop="dragDrop(event)"></div>
<div id="blockC" ondragover="return dragOver(event)" ondrop="dragDrop(event)"></div>

```

使用`body`和`html`结束标签关闭页面，将文件命名为`"using-drag-drop-api.html"`，然后在浏览器窗口中查看结果。拖动几个字母，结果应该类似于以下截图：

![如何做...拖放 API 使用，带有文本](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_07_02.jpg)

## 工作原理...

首先，我们创建了一个基本的 HTML5 页面，并使用`@fontface`添加了一个草图字体作为标题，以使我们的游戏具有有趣的视觉效果。接下来，我们通过将`margin`设置为`body`和所有块级元素来设置页面的样式，以更好地控制这些元素的呈现。在设置标题字体样式后，我们为游戏瓷砖框定义了`width`和`height`。这将是容纳组成游戏瓷砖的字母的容器。

我们通过在 IE 浏览器中键入一个特殊的注释标签来开始我们的脚本，以指向额外的脚本文件来触发 HTML5 元素：`<!--[if IE]><script src="img/html5.js"></script><![endif]-->`。这是由 Remy Sharp (http://remysharp.com/html5-enabling-script/)根据 MIT 许可证提供的，可以让我们在处理 Internet Explorer 时保持理智。

`dragDefine()`函数在用户开始拖动物品时被调用。它首先使用`dataTransfer.effectAllowed='move'`来检查物品是否可拖动。然后使用`dataTransfer.setData("text/plain")`设置要传输的数据类型为`text`，并使用`target.getAttribute('id'))`来识别目标的`id`。该函数返回 true，表示可以拖动对象。

接下来，我们定义了`dragOver`函数，当被拖动的物品位于另一个物品上方时调用，接受一个名为`ev`的事件参数，然后用它来调用`preventDefault()`以允许放置物品。拖放 API 规范明确规定，我们必须取消拖动，然后准备放置。

然后创建了`dragEnd()`函数，在拖动完成时返回 true。它还接受一个事件参数。

完成所有拖动功能后，我们准备创建代码来放置物品。`dragDrop()`函数接受一个事件参数，并使用该值获取文本对象的值，然后将其传递给一个新变量`var idDrag`来保存文本字符串，然后再使用`getElementById`来识别正确的元素 ID 进行放置。与`dragEnd()`一样，我们必须调用拖放 API 中的`preventDefault()`函数来指示可以放置对象。

在关闭页面的头部区域后，我们在正文中放置了内容框来容纳我们的字母瓷砖和游戏板。这些由两个父 div 容器组成，每个容器都包含包含字母瓷砖或游戏板网格部分的子 div。

每当字母瓷砖被拖动到游戏瓷砖框上时，游戏瓷砖框都会调用`dragOver()`函数。字母瓷砖 div 本身通过`draggable="true"`可拖动，并在拖动时返回`dragDefine()`。拖动停止时，它们调用`dragEnd()`函数。

因为我们希望字母瓦片在游戏板的特定区域内下落并停留，所以我们为网格上的每个单独块创建了 div，以便在它们被放置到板上时保持我们的字母位置，并在对象被拖动到它们上时返回`dragOver`事件，并在对象被放置到它们上时调用`dragDrop()`。

为什么要使用块 div？我们本可以在左边设置我们的游戏瓦片框，在右边设置游戏板，然后完成。结果将是，当我们从左边的框拖动瓦片到游戏板时，它们会被放置在上面，并按照它们被放置的顺序排列，而不是我们想要放置它们的位置。当您想要对列表进行排序时，默认行为是可以接受的，但当需要精确控制对象放置位置时，就不行了。

我们需要覆盖对象被放置时产生的默认行为。我们创建了九个游戏板块，都是相同的基本大小。每个块的主要变化是`padding`和`margin`。

花一些时间阅读[`www.whatwg.org/specs/web-apps/current-work/multipage/dnd.html`](http://www.whatwg.org/specs/web-apps/current-work/multipage/dnd.html)上的拖放规范，你会注意到他们明确表示他们只定义了一个拖放机制，而不是你必须执行的操作。为什么？使用智能手机或其他触摸屏设备的用户可能没有鼠标等指针设备。

## 还有更多...

拖放 API 的演示可以通过多种方式构建成一个完整的游戏，包括计分；游戏板重置按钮和其他交互元素。

### 创建基于画布的井字棋游戏

可以使用两个画布，一个用于游戏瓦片框，另一个用于游戏板。可以使用画布动态绘制板和游戏瓦片，然后将分数或消息（如“你赢了”）写入屏幕。

### 在用户玩游戏时显示响应消息

Remy Sharp 在[`html5demos.com/drag-anything`](http://html5demos.com/drag-anything)上有一个很棒的演示，展示了当对象被放置时如何在屏幕上显示消息。

要放置的对象的源标记可能类似于：

```html
<div id="draggables"><img src="img/picean.png" alt="Fish" data-science-fact="Fish are aquatic vertebrates (animals with backbones) with fins for appendages." /> </div>

```

当对象被拖动到时，“放置区”框可能看起来像：

```html
<div class="drop" id="dropnames" data-accept="science-fact"> <p>Learn a science fact!</p> </div>

```

当图像被放置到框中时，您会看到包含“data-science-fact”的文本，而不是图像。

## 另请参阅

jQuery 的 Packt 书籍，本书中的其他配方，高级 HTML5 Packt 书籍。

# 使用 vid.ly 和 jQuery 支持跨浏览器的视频

支持大多数浏览器需要将视频编码为多种格式，然后将正确的格式提供给浏览器。在这个示例中，我们将使用一个名为 vid.ly 的在线视频显示库([`www.vid.ly`](http://www.vid.ly))来在多个浏览器上可靠地准备和分享视频，并使背景颜色随时间变化。

## 准备工作

您需要一个视频上传到[`www.vid.ly`](http://www.vid.ly)。一些浏览器不允许本地提供文件，因此您可能还需要一个可以上传文件并测试页面的位置。

## 如何做...

键入`<!DOCTYPE html> <html lang="en"> <head>`，然后开始添加样式声明，键入`<style type="text/css"> h2{color:#303;}`。

样式化一个包含特色内容的 div：`#featured {position:relative; padding: 40px; width: 480px; background-color:#000000; outline: #333 solid 10px; }`。

键入`video {padding: 3px;background-color:black;}`来创建视频标记的样式，然后添加一个闭合的`</style>`标记。

声明页面中使用的脚本。输入`<script src="img/jquery.min.js" type="text/javascript" charset="utf-8"></script>`来引用主要 jQuery 库的最小化版本。然后，输入`<script type="text/javascript" src="img/jquery-ui.min.js"></script>`来引用用于颜色变化效果的 jQuery UI 库。最后，我们将引用我们自己的脚本，通过在关闭`</head>`标签之前输入`<script type="text/javascript" src="img/mycolor.js"></script>`。

输入一个开放的`<body>`和`<section>`标签，然后输入`<header> <h2>Featured Video</h2></header>`以显示页面标题。

现在，我们可以创建一个 div 来容纳我们之前设计的特色内容。输入`<div id="featured"> <p>此视频已通过<a href="http://vid.ly">vid.ly</a>转换为跨浏览器格式</p>`。

下一步是将视频剪辑上传到[`vid.ly`](http://vid.ly)进行转换成多个文件格式。当过程完成时，您将收到一封电子邮件，然后可以获取视频的代码片段，如下面的屏幕截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_07_03.jpg)

复制网站上的代码，然后粘贴到您的页面中。视频和脚本标签中的`src`值应该是 vid.ly 给出的 URL。代码块应该如下所示：

```html
<video id= "vidly-video" controls="controls" width="480" height="360"> <source src="img/7m5x7w?content=video"/> <script id="vidjs" language="javascript" src="img/html5.js"></script> </video>

```

为了增加一点额外的乐趣，让我们在页面上添加另一个视频标签。输入以下代码：`<p>哎呀，这是一个宝宝视频！</p>`，为视频标签使用不同的 id 并调整大小如下：`<video id="tinymovie1" controls="controls" width="190" height="120">`，然后使用相同的源标签：`<source src="img/7m5x7w?content=video"/><script id="vidjs" language="javascript" src="img/html5.js"></script></video>`，然后关闭页面：`</div> </section></body></html>`。将文件保存为`display-videos-using-videly.html`。

我们要做的最后一件事是创建一个 jQuery 脚本来改变`#featured` div 的背景颜色。打开您的编辑器，创建一个名为`myColor.js`的新文件。

输入`$(document).ready(function() {`，然后转到新行并输入将调用动画函数并改变背景颜色的代码：`$('#featured').animate({'backgroundColor':'#ff3333', 'color': '#ffffff'}, 6000);})`;。

在浏览器中加载页面，观察主视频加载时颜色的变化。您可以看到以下屏幕截图显示了它应该是什么样子：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_07_04.jpg)

## 它是如何工作的...

首先，我们创建了一个标准的 HTML5 页面，并开始添加样式声明。我们将`featured` div 的位置设置为相对位置，以便在将来如果我们决定添加额外的 jQuery 效果时具有更大的灵活性。通过将`padding`设置为`40px`，将`outline`颜色设置为深灰色并设置为`10px`的粗细，创建了强烈的视觉效果。默认的背景颜色设置为黑色`(#000000)`，以便与最终的红色背景进行高对比度的比较。

接下来，我们对`video`标签进行了样式设置，使其在加载时具有黑色的`background-color`。我们还可以在这里添加一个背景图像作为海报。

接下来，使用`<script src="img/jquery.min.js" type="text/javascript" charset="utf-8"></script>`声明了基本的 jQuery 脚本。因为它不包含`animate()`等效果，我们还需要引用用于颜色变化效果的 jQuery UI 库的最小化版本。然后，我们通过输入`<script type="text/javascript" src="img/mycolor.js"></script>`来添加对我们自己脚本的引用。进一步减小脚本文件大小的另一种方法是创建一个自定义脚本，其中只包含来自 jQueryUI 库的动画效果。

接下来，我们创建了主页内容，包括指向 vid.ly 上视频的链接。 vid.ly 提供的默认代码会给`video`标签应用一个 ID 为`'vidley video'`，但如果你想使用自己的样式 ID 或者为每个视频使用不同的 ID，那么可以省略这一部分。另一个选择是给所有视频分配相同的类，然后根据需要分配它们唯一的 ID。

## 另请参阅

第八章，*拥抱音频和视频*更详细地介绍了视频元素。

# 使用 jQuery 动态显示视频

视频元素使我们能够像处理图像一样处理视频，并以有趣和令人兴奋的方式操纵它们。

## 准备工作

你需要一个以多种文件格式提供的视频（本书的章节代码中提供了这些格式）。建议将文件上传到服务器，因为并非所有浏览器都能以可预测的方式本地播放文件。

## 如何做...

首先，我们需要准备一个 HTML5 页面来放置它。输入我们页面的开头标签：`<!DOCTYPE html> <html lang="en"> <head> <meta charset="utf-8" /> <title>Video Explosion</title>`。

打开下载的代码文件中的`stylesheet.css`文件，或者创建一个同名的新文件。

为 body 输入以下内容`style: body {background: white;color:#333333; }`，然后按照以下方式为 div 标签添加样式：`div {float:left; border:1px solid #444444;padding:5px;margin:5px; background:#999999;}`。

我们需要创建和样式化的第一个唯一的 div 是`#featured`。输入`#featured {position:relative; width: 480px; background-color:#f2f1f1;}`来创建样式。

现在创建一个名为`details`的 div 来容纳一个小的信息框。输入`#details{ position:relative;display:block;background-color:#6CF;color:#333333; padding:10px;}`来创建一个将显示在`featured` div 旁边的 div。

保存`css`文件，并在 html 页面的头部使用链接标签引用它，输入`<link rel="stylesheet" href="css/stylesheet.css"type="text/css" media="screen" charset="utf-8"/>`。

在样式表链接下方输入以下主 jQuery 库的链接：`<script src="img/jquery-latest.js" type="text/javascript" charset="utf-8"></script>`，然后在这个配方的代码文件中链接到 jQuery UI 库，输入`<script type="text/javascript" src="img/jquery-ui.min.js"></script>`。最后，通过输入`<script type="text/javascript" src="img/explode.js"></script>`来添加对即将创建的脚本的引用，以完成引用的脚本。

创建一个新文件并命名为`explode.js`，并将其存储在一个名为`js`的新子文件夹中。输入`$(document).ready(function(){}`。在两个大括号({})之间输入`$('h1').effect('shake', {times:5}, 200)`；创建一个语句，将导致 featured div 标签中包含的内容爆炸。在新的一行上，输入`$('#featured').effect('shake', {times:3}, 100).delay(500).hide('explode',{}, 2000).slideDown('fast');)`；以完成脚本。你的代码块应该类似于以下代码块：

```html
$(document).ready(function(){ $('h1').effect('shake', {times:5}, 200); $('#featured').delay(2000).hide('explode', {}, 2000 ).slideDown('fast'); });

```

保存文件并返回到 html 页面。

在 HTML 文件中添加`</head>`的闭合标签和`<body>`的开头标签。接下来，输入一个开头的`<header>`标签和标题文本：`<h1>Featured Moto Video</h1>`，然后输入`</header>`标签以完成头部区域。

创建一个开头的`<section>`标签，然后输入`<div id="featured">`，来容纳我们的视频标签和相关元素。输入`<video id="movie" width="480" height="360" preload controls>`，然后为三种视频文件类型添加一个源标签：`<source src='motogoggles.ogv' type='video/ogg; codecs="theora, vorbis"'/> <source src='motogoggles.mp4' type='video/mp4; codecs="avc1.42E01E, mp4a.40.2"'/> <source src='motogoggles.webm' type='video/webm; codecs="vp8, vorbis"'/>`，然后关闭`</video>`标签和`</div>`标签。

最终的内容块包含在`details` div 中。要创建它，输入`<div id="details">`，然后添加一个带有文本的标题标签`<h1>Details</h1>`，最后是一个简短的解释性文字段落：`<p>视频将爆炸然后再次出现！</p>`。关闭`</div></section> </body></html>`标签。将 HTML 文件保存为`exploding-video-dynamically.html`，在浏览器中打开以查看结果。它们应该与以下截图类似，显示视频分成几个部分并爆炸。

![如何操作...视频操作，使用 jQuery](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_07_05.jpg)

## 它是如何工作的...

`stylesheet.css`文件包含了特色 div 的样式，确定了页面上视频对象的定位。首先要注意的是`position`被设置为`relative`。这使我们能够使用 jQuery 移动视频对象并对其执行其他操作。

我们创建了一个名为`details`的 div，其`position`也是`relative`，但`background-color`设置为`浅蓝色(#6CF)`。不同的颜色将有助于在视觉上将其与视频对象区分开来。

接下来，我们添加了 jQuery 库脚本。为了能够访问`animate`类中包含的方法和函数，需要引用 jQuery UI 库。在这个例子中，我们是在本地引用它，但您也可以像访问主要的 jQuery 库一样链接到它。

最后，我们能够编写自己的脚本来使页面上的元素摇晃和爆炸！我们创建了一个语句来验证页面是否准备好接受我们的代码，方法是输入`$(document).ready(function(){}`。这个函数查询 DOM 并询问页面是否已加载并准备好接受脚本。在创建 jQuery 脚本时，使用这个包装函数是最佳实践。我们使用别名符号`$`来调用 jQuery 函数，抓取`h1`选择器并对其应用包含`shake`参数的`effect`动作，使元素侧向移动，其中又包含了摇动元素的次数参数。摇动应持续的时间间隔以毫秒定义，本例中为`200`。我们使用选择器`$('#featured')`来抓取特色 div 元素，并像对`h1`标签所做的那样，对其进行`shake`操作（只摇动三次以增加变化），每次摇动持续`100`毫秒。现在我们添加了一些新的动作。在`shakes`和爆炸之间添加了`500`毫秒的`delay`命令，使用`.delay(500)`。然后我们附加了`hide`动作，参数为`explode`，默认情况下将发生一次，持续时间为`2000`毫秒。视频爆炸后，`slidedown`动作以`fast`参数将其滑回屏幕上。请注意，爆炸所用的时间有点长，这样我们可以更容易地看到它。使用`100-500`毫秒的时间间隔会产生更真实的爆炸效果。如果您只想要视频本身而不是特色标签提供的背景或边框，也可以直接使用`$('video')`来抓取视频标签。

回到 HTML 文件，我们将视频放在一个名为`featured`的容器 div 中，并创建了一个父`video`标签，它将`preload`并包含默认的`controls`。在关闭`video`标签之前，我们在其中嵌套了三种视频文件类型的`source`标签，以便不同浏览器的用户可以观看视频：我们没有提供 FLASH 回退，但我们可以使用 JavaScript 库，比如`Video.js`。然后我们关闭了`</video>`标签和特色 div 标签`</div>`。

最后，我们创建了一个 div 来保存关于用户可以期待在`details` div 中发生的信息。

## 还有更多...

视频元素、JavaScript 和 canvas 标签还有很多可以做的事情。继续阅读更多实验。

### 使用视频和画布进行更多交互式爆炸

Sean Christmann 在[`www.craftymind.com`](http://www.craftymind.com)上有一个令人惊叹的实验，可以让您在视频播放时实时爆炸多个部分，使用多个画布。您可以在这里查看：[`www.craftymind.com/2010/04/20/blowing-up-html5-video-and-mapping-it-into-3d-space/`](http://www.craftymind.com/2010/04/20/blowing-up-html5-video-and-mapping-it-into-3d-space/)，但请注意——在 Firefox 中这会消耗大量资源。

### 爆炸是怎么回事？

乍一看似乎没有任何真正的实际原因来首先分解视频。然而，这对于模仿独特的过渡效果或对用户在游戏中的操作做出响应可能非常有用。

### 实时色度键背景替换

Firefox 开发人员一直在尝试操纵视频元素。他们创建了一个教程，解释了他们如何使用画布、JavaScript 和视频元素的属性执行色度键替换。您可以在[`developer.mozilla.org/En/Manipulating_video_using_canvas`](http://https://developer.mozilla.org/En/Manipulating_video_using_canvas)上阅读相关内容并查看演示。

想象一下在网站上显示视频，其中展示了异国情调的背景或者创建了产品和人的互动混搭。

## 另请参阅

本书的第八章*拥抱音频和视频*中深入探讨了视频元素。

# 使用 jQuery 移动视频广告

我们将在网站上创建一个视频广告，当用户向下滚动页面时，它会移动，使用 jQuery 和视频标签。

## 准备工作

您将需要多种格式的视频文件，如`.ogg/.ogv, .mp4`和`.webm`，或者使用视频服务，如[`www.vid.ly.com`](http://www.vid.ly.com)来提供跨浏览器视频。这个例子没有在 Internet Explorer 中进行测试，但应该在 Safari、Google Chrome、Opera 和 Firefox 的最新版本中正常工作。

## 如何做…

我们将首先创建一个典型的网站页面。在编辑器中打开一个新文件，并将其保存为`movable-video-ad.html`。输入`<!DOCTYPE html> <html lang="en"><head><meta charset="utf-8" /><title>Movable Video Ad</title>`来放置页面上的第一个标签。

现在，为我们的默认样式表创建一个引用链接`<link rel="stylesheet" href="css/main.css" type="text/css" media="screen" charset="utf-8" />`，以及一个名为`<link rel="stylesheet" href="css/scroll.css" type="text/css" media="screen" charset="utf-8" />`的辅助样式表。

接下来，为 jQuery 脚本创建引用链接。输入`<script src="img/jquery-1.4.min.js" type="text/javascript" charset="utf-8"></script>`来引用核心 jQuery 代码。添加链接语句`<script type="text/javascript" src="img/jquery-ui-1.7.2.custom.min.js"></script>`。我们将链接到的最终脚本是我们为名为`myAd.js`的配方创建的自己的脚本，它将存储在我们创建的名为"js"的子文件夹中。输入`<script type="text/javascript" src="img/myAd.js"></script>`来链接到该文件。

输入`</head><body><div id="container">`来开始页面的内容区域。通过输入`<header> <h1>Motocross Mania</h1></header>`来显示页面标题。

开始添加页面内容，输入`<div id="content"> <h2>No dirt = no fun</h2>`。现在可以通过输入文本`<div id="motoad"><h3>Buy this movie!</h3>`，然后在段落元素标签中包含电影标题`<p><strong>MotoHelmet</strong></p>`来添加包含广告的 div 到页面中。

然后应该添加一个视频标签`<video width="190" height="143" preload controls>`。输入包含每种视频格式的源标签，如下面的代码块所示：

```html
<source src='video/motohelmet.ogv' type='video/ogg; codecs="theora, vorbis"'/> <source src='video/motohelmet.mp4' type='video/mp4; codecs="avc1.42E01E, mp4a.40.2"'/> <source src='video/motohelmet.webm' type='video/webm; codecs="vp8, vorbis"'/></video>

```

关闭`</div>`标签并保存目前的进展。

创建一个带有 id 为 intro 的段落`<p id="intro">`来包含文本`We review the best motorcross gear ever!!!`。在段落标签和文本后面跟着一个虚拟链接列表：`<ul><li><a href="#">Helmets</a></li> <li><a href="#">Gloves</a></li><li><a href="#">Goggles</a></li></ul>`，用`</p>`关闭段落，然后创建一个新的 div 来包含一个虚拟新闻内容块，然后是另外两个虚拟 div 块，一个页脚标签和关闭页面元素，如下面的代码块所示：

```html
<div id="news"><h2>Latest News</h2> <p>Trip Ousplat admits he doesn't do his own stunts! "My mom makes
me use a stunt double sometimes," The shy trick-riding sensation explains.</p> <p>Gloria Camshaft smokes the competition for a suprise win at the Hidden Beverage Playoffs</p> <p>Supercross competitors report more injuries; jumps more extreme than ever</p><p>James Steward still polite, reporters bored</p>
</div><div id="filler"><h2>On Location</h2> <p>Grass is not greener as there is no grass on most motorcross trails experts claim </p></div> <p id="disclaimer">Disclaimer! Anything you choose to do is at your own risk. Got it? Good.</p><footer><p>&copy; Copyright 2011 Motocross Extreme Publications, Inc.</p></footer></div></body></html>

```

现在，我们将在`main.css`文件中为页面元素设置样式。第一个关键样式是`#container` div。它应该有一个`0 auto`的边距和`650px`的宽度。接下来，`#motoad` div 应该被设置为`右浮动`，并包含一个`200px`的宽度来容纳视频元素。最后，`#intro` div 应该包含一个较短的宽度`450px`。这三种样式应该类似于下面显示的代码块：

```html
#container{ margin:0 auto;text-align:left; width: 650px;}
#motoad{ float:right;width:200px;}
#intro{width:450px;}

```

其余的样式都是对填充和颜色或其他标准声明的微小调整。

现在，打开`scroll.css`文件来定义样式，以帮助我们的广告滚动。我们将级联`#motoad`的属性，以形成一个可以移动的 div 块。接下来，定义`#content`属性的`height`，以及段落和`h2`元素的宽度。`scroll.css`中的样式现在应该如下所示：

```html
#motoad {display:block;position: relative; background-color:#FC0;width:200px;padding:10px;}
#content { height:1000px;}
p {width:450px;}h2 {width:460px;}

```

保存文件，并准备创建我们的 jQuery 脚本。

打开或创建`myAd.js`，并开始输入文档准备函数`$(document).ready(function(){}`和花括号。在花括号之间点击 enter，并输入滚动函数`$(window).scroll(function() {`。在该函数的开花括号后面输入命令：`$('#motoad').stop().animate({top: $(document).scrollTop()},'slow','easeOutBack')`;。用" });});"关闭脚本。我们的 jQuery 脚本现在应该看起来像下面的代码块：

```html
$(document).ready(function(){ $(window).scroll(function() { $('#motoad').stop().animate({top: $(document).scrollTop()},'slow','easeOutBack'); }); });

```

保存所有文件，并在浏览器窗口中加载 HTML 页面。在开始滚动页面之前，页面应该看起来像下面的截图。

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_07_06.jpg)

尝试上下滚动页面。广告应该随着页面的上下移动而上下移动。结果应该类似于以下截图：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_07_07.jpg)

## 它是如何工作的...

在创建具有不同内容元素的典型 HTML 页面后，我们准备为 CSS 页面设置样式。我们将 CSS 分为两个文件，`main.css`和`scroll.css`，这样当我们在 jQuery 脚本中调用滚动函数并积极应用它时，页面上的内容元素会缩小，以便我们的广告可以轻松移动，而不会阻塞页面上的任何信息。

我们希望在调用窗口滚动事件时使`#motoad` div 标签移动。为此，我们使用别名符号`$`来抓取 DOM 中的`window`选择器，并将其应用于包含默认滚动动作参数的`scroll`动作。使用这个函数，我们然后创建了控制`#motoad` div 块行为的命令。我们给它了`stop`的动作，这样它就准备好进行动画了。`animate`动作被链接到`stop`命令。我们应用到`#motoad` div 的`animate`的第一个参数使得 div 在文档窗口中的滚动条移动时移动。`slow`参数控制了广告上下移动的速度，`easeOutBack`参数引用了一个缓动命令，以创建流畅的动画运动，而不是突然开始或停止。

## 还有更多...

在这个示例中，我们通过使其响应页面上的用户操作来为自定义 HTML 元素添加动画效果。这只是我们可以微妙地添加效果的一种方式，可以用于实际解决方案。

### 有 HTML 元素，就会旅行

探索 jQuery UI 库，你会被许多可以操纵和样式化任何 HTML 元素的方式所启发。访问[`jqueryui.com`](http://jqueryui.com)查看演示和文档。

## 另请参阅

学习 jQuery：使用简单的 JavaScript 技术实现更好的交互设计和 Web 开发，可从 Packt Publishing 获取。

# 使用 Easel.js 和 canvas 标签控制图像的显示

JavaScript 库`Easel.js`减少了使用`canvas`标签创建动画和丰富交互环境的复杂性。在这个示例中，我们将使用一个名为"sprites"的单个文件中的一系列图像，以展示如何使用`Easel.js`来控制精灵中选择性显示的图形图像。

## 准备工作

您需要下载`Easel.js`库，或者使用本示例的代码文件中的副本。

## 如何做...

创建一个 HTML5 文件的开头标签。您的代码应该类似于以下代码块：

```html
<!DOCTYPE HTML><html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8"><title> Animating images using BitmapSequence and SpriteSheet</title>

```

接下来，链接到在本示例中使用的主样式表`styles.css`：<link href="styles.css" rel="stylesheet" type="text/css" />。

接下来，我们将通过插入以下脚本文件的链接来导入`Easel.js`框架库：`UID.js, SpriteSheetUtils.js, SpriteSheet.js, DisplayObject.js, Container.js, Stage.js, BitmapSequence.js`和`Ticks.js`。您可以在这里看到每个脚本文件的路径和链接：

```html
<script src="img/UID.js"></script><script src="img/SpriteSheetUtils.js"></script><script src="img/SpriteSheet.js"></script><script src="img/DisplayObject.js"></script><script src="img/Container.js"></script><script src="img/Stage.js"></script><script src="img/BitmapSequence.js"></script><script src="img/Tick.js"></script>

```

接下来，创建一个开头的`<script>`标签，并声明以下三个变量：`var canvas; var stage; var critterSheet = new Image()`;用于我们的脚本。

输入`function init(){`开始函数，并跟随`canvas = document.getElementById("testCanvas")`;将页面主体中的 canvas 与 canvas 变量绑定。通过输入`critterSheet.onload = handleImageLoad`;准备加载一个新的`spriteSheet`。`critterSheet`变量存储精灵图像的来源。输入`critterSheet.src = "images/moles.png"`;加载我们自己的一系列鼹鼠图像。函数块应该像下面的代码块一样：

```html
function init() {
canvas = document.getElementById("testCanvas");
critterSheet.onload = handleImageLoad;
critterSheet.src = "images/moles.png";}

```

我们将创建的第二个函数是`handleImageLoad()`。输入`function handleImageLoad() {`然后输入`stage = new Stage(canvas)`;创建一个新的 stage 实例。输入`var spriteSheet = new SpriteSheet(critterSheet, 76, 80);`创建一个新的`spriteSheet`。创建一个名为`critter1`的新位图序列变量，并使用 x 和 y 坐标定义其在舞台上的位置，输入：`var critter1 = new BitmapSequence(spriteSheet); critter1.y = 85; critter1.x = 85`;。通过输入`critter1.gotoAndStop(1)`从我们的精灵表`moles.png`中添加一个 critter。然后使用命令`stage.addChild(critter1)`将其添加到舞台上。

克隆我们创建的第一个`critter1`变量，并通过输入`var critter2 = critter1.clone()`将其值传递给一个新的 critter 变量。通过添加`critter2.x += 120`将新变量定位到第一个 critter 的右侧。

输入`critter2.gotoAndStop(0)`为`critter2`变量赋值。克隆 critter 1 和 critter 2 的代码块应该如下所示的代码块：

```html
var critter2 = critter1.clone();
critter2.x += 120;
critter2.gotoAndStop(0);
stage.addChild(critter2);

```

`Tick.setInterval(300)`;和`Tick.addListener(stage)`;是我们将添加到脚本的最后两个语句。关闭`handleImageLoad()`函数的大括号（}），然后输入一个闭合的脚本标签。

关闭`</head>`标签，然后输入带有`onload`属性的开头`body`标签，调用`init()`函数。为内容创建一个名为"description"的 div。添加一个名为`canvasHolder`的 div 来包含 canvas 元素。在页面底部显示图像文件`moles.png`。

```html
<body onload="init();">
<div class="description">Using <strong>BitmapSequence</strong> to animate images from a <strong>SpriteSheet</strong>.
</div>
<div class="canvasHolder">
<canvas id="testCanvas" width="980" height="280" style="background-color:#096"></canvas> </div> </p><p>The original moles.png spritesheet file with all the images:<br/><img src="img/moles.png"/></p> </body></html>

```

将文件保存为`whack-mole-easel-test-single.html`。结果可以在以下截图中看到：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_07_08.jpg)

## 它是如何工作的...

在设置 HTML5 页面的开头之后，我们准备导入`Easel.js`框架并创建我们的主要脚本。

我们创建了一个开头的`<script>`标签，并声明了以下全局变量：`var canvas; var stage; var critterSheet = new Image()`;用于我们的脚本。

当页面加载时，将调用创建的`init()`函数。它包含了`canvas`变量，该变量正在被分配选择器`testCanvas`，使用`document.getElementById("testCanvas")`将页面主体中的画布与画布变量绑定。接下来，我们准备通过输入`critterSheet.onload = handleImageLoad`来加载一个新的`spriteSheet`。`critterSheet`变量存储了精灵图像的来源。输入`critterSheet.src = "images/moles.png"`使我们能够访问我们自己的一系列鼹鼠图像。

我们创建的第二个函数是`handleImageLoad()`。在这个函数中，我们做了大部分的工作，首先创建了一个舞台的新实例，使用`stage = new Stage(canvas)`。接下来，我们使用`var spriteSheet = new SpriteSheet(critterSheet, 76, 80)`创建了一个新的`spriteSheet`。

现在我们有了一个精灵图实例，我们可以创建一个新的位图序列变量，称为`critter1`，并定义其在舞台上的位置，使用 x 和 y 坐标，输入：`var critter1 = new BitmapSequence(spriteSheet);critter1.y = 85;critter1.x = 85`。接下来，我们通过数字引用我们想要添加的帧，以便首先将正确的动作应用于 critter，然后应用于舞台。我们通过输入`critter1.gotoAndStop(1)`将`critter1`变量链接到我们精灵表`moles.png`上的第二个图像。我们使用命令`stage.addChild(critter1)`将图像添加到舞台上。

我们克隆了我们创建的第一个`critter1`变量，并通过输入`var critter2 = critter1.clone()`将其值传递给一个新的 critter 变量。我们通过添加到其当前位置值来将新变量定位在第一个 critter 的右侧，使用`critter2.x += 120`。我们通过命令`BitSequence`去到`moles.png`上的第一个图像的位置，并在那里停止，并将其分配给`critter2`变量。

我们添加了`Tick.setInterval(300)`，在`Ticks`之间应用了`300`毫秒的时间间隔。Tick 接口充当全局定时设备，使我们能够返回每秒的帧速率（FPS）（如果需要的话）。我们向舞台添加了一个监听器`Tick.addListener(stage)`，它像其他类型的监听器一样监听`Ticks`。这可以用来在指定的时间重新绘制舞台，或执行其他与时间相关的操作。

我们使用`onload`属性在`body`标签中调用`init()`函数。这会导致`init()`函数在页面加载时被调用。

## 另请参阅

*制作图像序列*教程。

# 使用 Easel.js 和 canvas 标签来制作图像序列动画

我们可以通过使用`Easel.js` JavaScript 库创建数组和函数来操纵`canvas`元素，从而制作称为精灵的图像条的动画。在本教程中，我们将制作相同的图像条动画，但显示两个不同时间序列。

## 准备工作

下载本教程的代码文件，使用`Easel.js`框架库以及支持文件。您需要一个能够正确显示 HTML5 元素并测试本教程中使用的代码的最新浏览器。

## 如何做...

创建一个 HTML5 文件的开头标签。您的代码应该类似于以下代码块：

```html
<!DOCTYPE HTML><html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8"><title> Animating images using BitmapSequence and SpriteSheet</title>

```

链接到本教程中使用的主样式表`styles.css`：`<link href="styles.css" rel="stylesheet" type="text/css" />`。

通过插入以下脚本文件的链接来导入`Easel.js`框架库：`UID.js, SpriteSheetUtils.js, SpriteSheet.js, DisplayObject.js, Container.js, Stage.js, BitmapSequence.js`和`Ticks.js`。参考前面的示例，了解框架块应该是什么样子。

创建一个开头的`<script>`标签，并声明以下三个变量：`var canvas;var stage;var critterSheet = new Image()`；用于我们的脚本。

输入`function init(){`开始函数，然后跟上`canvas = document.getElementById("testCanvas")`。

准备加载一个新的`spriteSheet`，键入`critterSheet.onload = handleImageLoad`;。键入`critterSheet.src = "images/moles.png"`;加载我们自己的一系列鼹鼠图像。函数块应如下所示：

```html
function init() {
canvas = document.getElementById("testCanvas");
critterSheet.onload = handleImageLoad;
critterSheet.src = "images/moles.png";}

```

我们将创建的第二个函数是`handleImageLoad()`。键入函数`handleImageLoad() {`然后`stage = new Stage(canvas)`;创建一个新的舞台实例。键入`var spriteSheet = new SpriteSheet(critterSheet, 80, 80)`;创建一个新的`spriteSheet`。现在我们有了一个精灵表，创建一个新的位图序列变量名为`critter1`，并使用 x 和 y 坐标定义其在舞台上的位置，键入：`var critter1 = new BitmapSequence(spriteSheet)`;然后`critter1.y = 100;critter1.x = 90`;。接下来，我们将创建一个数组，将其映射到原始`spritesheet`文件上的每个图像，输入`var frameData = {shymole:0, upmole:1, downmole:2, whacked:3, whackedow:4, clouds:5,tinycloud:6, cloudgroup:7}`;这样我们就有了八个名称值，每个名称值都与一个数组 id 相关联。

到目前为止，`handleImageLoad()`的代码块应如下所示：

```html
function handleImageLoad() {
stage = new Stage(canvas);
var spriteSheet = new SpriteSheet(critterSheet, 80, 80);
var critter1 = new BitmapSequence(spriteSheet);
critter1.y = 100;
critter1.x = 90;
var frameData = {shymole:0, upmole:1, downmole:2, whacked:3, whackedow:4, clouds:5,tinycloud:6, cloudgroup:7};

```

通过键入`spriteSheet = new SpriteSheet(critterSheet, 80, 80, frameData)`;使用它作为参数创建一个新的`spriteSheet`。

创建一个新的位图序列变量名为`critter1`，并应用图像精灵，键入：`critter1gotoAndStop(0)`;。使用`stage.addchild(critter1)`;将`critter1`添加到`stage`中。

通过键入克隆第一个`critter1`变量，并将其值传递给一个新的 critter 变量：`var critter2 = critter1.clone()`;。使用`critter2.x += 120`;定义新变量的`x`值。通过键入`critter2.gotoAndStop(5)`;为`critter`分配其自己的图像。添加新的`spriteSheet`，创建`critter 1`和克隆`critter 2`的代码块应如下所示：

```html
spriteSheet = new SpriteSheet(critterSheet, 80, 80, frameData);
critter1.gotoAndStop(0);
stage.addChild(critter1);
var critter2 = critter1.clone();
critter2.x += 120;critter2.gotoAndStop(5);

```

键入：`var critter3 = critter2.clone(); critter3.spriteSheet = spriteSheet`;。就像我们之前创建的其他 critter 变量一样，通过将`10`添加到其当前值来重新定义`critter3`的`x`值：`critter3.x += 10`;。以下代码块显示了我们所做的事情：

```html
var critter3 = critter2.clone();
critter3.spriteSheet = spriteSheet;
critter3.x += 10;

```

通过名称引用`moles.png`中的图像`frames`，键入`critter3.gotoAndStop("upmole")`;。通过克隆一个新变量并引用一个新帧，将当前的`upmole`帧图像替换为不同的帧：`var critter4 = critter3.clone(); critter4.gotoAndStop("downmole")`;。通过键入将该帧向右移动`10`像素：`critter4.x += 10`;。

再次交换帧并将我们的新帧向右移动`10`像素：`var critter5 = critter4.clone(); critter5.gotoAndStop("shymole"); critter5.x += 10`;。让我们看一下到目前为止我们应该有的代码块：

```html
critter3.gotoAndStop("upmole");
var critter4 = critter3.clone();
critter4.gotoAndStop("downmole");
critter4.x += 10;
var critter5 = critter4.clone();
critter5.gotoAndStop("shymole");
critter5.x += 10;

```

通过键入循环遍历我们的`moles.png`文件中的帧：

```html
var critter6 = critter1.clone(); critter6.x = critter5.x + 100; critter6.gotoAndPlay(3);stage.addChild(critter6);.

```

向舞台添加第二个动画序列，当新的 critter 精灵添加到舞台时，通过引用不同的起始帧来改变动画的时间：`var critter7 = critter1.clone(); critter7.x = critter6.x + 100; critter7.gotoAndPlay(1); stage.addChild(critter7)`;。

我们的两个动画序列现在应包含以下代码：

```html
var critter6 = critter1.clone();
critter6.x = critter5.x + 100;
critter6.gotoAndPlay(3);
stage.addChild(critter6);
var critter7 = critter1.clone();
critter7.x = critter6.x + 100;
critter7.gotoAndPlay(1);
stage.addChild(critter7);

```

`Tick.setInterval(200)`;和`Tick.addListener(stage)`;是我们将添加到脚本的最后两个语句。关闭`handleImageLoad()`函数的大括号（}），然后键入一个闭合的脚本标签。

键入`</head>`，然后`<body onload="init()">`。创建一个名为`"description"`的 div 来容纳内容。最后一个 div 是`canvasHolder`，包含 canvas 元素。将宽度设置为`600`，高度设置为`280`，背景颜色设置为浅灰色`(#ccc)`。添加指向图像文件`moles.png`的链接，以便用户可以查看`moles.png`中引用的图像精灵。

保存文件，并在浏览器窗口中打开。您应该在屏幕左侧看到一个静止的画面（闭着眼睛的鼹鼠头像），以及屏幕右侧循环播放的两个动画序列。以下截图显示了这两个序列如何加载相同的帧，但时间不同。

![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_07_09.jpg)

## 工作原理...

创建 HTML 页面和引用 canvas 的第一步与上一个步骤相同。

创建`spriteSheet`后，我们创建了一个新变量来保存我们的精灵帧，名为`critter1`，并通过输入以下内容定义了帧位置的`x`和`y`坐标：`var critter1 = new BitmapSequence(spriteSheet); critter1.y = 100;critter1.x = 90`。

我们创建了数组`var frameData`来声明八个键值对。然后，我们能够创建一个新的`spriteSheet`，它接受了`spriteSheet`名称、每个帧的默认高度和宽度的参数，并使用`frameData`一次性将所有帧从`moles.png`加载到`spriteSheet`中。

接下来，我们尝试使用`frameData`通过数字值和名称键引用帧，创建一系列位图序列，然后用它们的克隆替换它们。

我们对序列进行了动画处理，并将它们放置在舞台上。它们都遵循相同的格式，但通过改变`gotoAndPlay`操作中的数字参数，它们在不同的帧上开始它们的动画序列。

最后，我们添加了`Tick.setInterval(200)`;，它在 Ticks 之间应用了 200 毫秒的时间间隔。Tick 接口充当全局定时设备，使我们能够返回每秒的帧速率（FPS）（如果需要的话）。我们向舞台添加了一个监听器`Tick.addListener(stage)`;，它像其他类型的监听器一样监听 Ticks。这可以用来在指定的时间重新绘制舞台，或执行其他与时间相关的操作。我们使用`onload`属性在`body`标签中调用`init()`函数。这会导致在页面加载时调用`init()`函数。

## 还有更多...

`Easel.js`和其他类似的库使得控制 HTML5 元素变得更加容易。但是要小心使用它们，因为有些可能不够稳定，无法在生产环境中使用。

### 海盗喜欢雏菊，你也应该喜欢

`Easel.js`的创建者被微软要求创建一个名为"Pirates love daisies"的概念性网络游戏（[`www.pirateslovedaisies.com`](http://www.pirateslovedaisies.com)），完全使用 HTML5 和 JavaScript，并且大量依赖`Easel.js`库来操作`canvas`元素。您可以在任何网络浏览器中玩这个游戏，或许具有讽刺意味的是，它还为使用 Internet Explorer 9 浏览器的访问者提供了特殊功能。

### 老派计算机动画技术的回归

当我第一次在计算机上玩游戏时，游戏屏幕上有 256 种颜色和 8 位动画是一件大事。计算机动画师使用了许多技巧来复制水流动等效果。重温那些日子（或者第一次通过来自 effect games 的演示发现它们：[`www.effectgames.com/demos/canvascycle/`](http://www.effectgames.com/demos/canvascycle/)）。

## 另请参阅

本书中有一个完整的章节充满了 canvas 的示例。如果你跳过了它们，现在去看看吧。

# 使用 canvas 标签和 JavaScript 进行随机动画和音频

在这个示例中，我们将使用 canvas 标签来绘制和动画一系列形状。我们还将使用音频标签循环播放音频文件，同时显示动画。我们正在改编 Michael Nutt 创建的原始动画。我们将创建一个更慢、更轻松的动画，看起来像是摇曳的草。

## 准备工作

您将需要一个最近更新的浏览器，如 Firefox 3.6 或 Google Chrome，以及多种格式的音频文件。在 Opera 浏览器 9 和 10 中显示的大小不同（较小）。音频也不会在这些版本的 Opera 中播放。

## 如何做...

首先，打开一个新的 HTML5 页面，并将其命名为`random-animation-with-audio.html`。输入 HTML5 页面的开头，包括页面标题：

```html
<!DOCTYPE html> <html lang="en"> <head><meta charset="utf-8" /> <title>Canvas Reggae</title>.

```

然后，添加链接到将在页面加载时导入的 JavaScript 和 CSS 文件：`<script type="text/javascript" src="img/animatedlines.js"></script><link rel="stylesheet" href="css/stylesheet.css" type="text/css" media="screen" charset="utf-8" />`，并使用`</head>`关闭 head 标签。

输入`<body onLoad="init();">`以在页面加载时激活`init()`函数。

接下来，创建页面的标题`<header><h1>CANVAS Reggae</h1></header>`，然后通过输入`<canvas id="tutorial" width="480" height="360"></canvas>`添加 canvas 元素。

创建一个新的 div，其中`id`为 credits，用于保存指向 Michael 网站的链接：`<div id="credits">Based on Canvas Party by <a href="http://nuttnet.net/">Michael Nutt</a>&nbsp;&nbsp;`。然后向 div 添加一个链接，以获取音频元素，并在单击链接时应用`pause()`函数来暂停音乐：`<a href="#" onClick="document.getElementsByTagName('audio')[0].pause();">[OFF]</a></div>`。

现在，输入音频标签，并将 autoplay 设置为 true，loop 设置为 loop：`<audio autoplay="true" loop="loop">`创建两个 source 标签来包含音频格式：`<source type="audio/ogg" src="img/randomreggae.ogg" /><source type="audio/mpeg" src="img/randomreggae.mp3" />`。

在关闭音频标签之前，我们将添加一段文本，如果不支持音频标签，将显示：`您的浏览器不识别 HTML5 音频标签`。

关闭音频、body 和 html 标签，并保存页面。

在创建脚本之前，打开`stylesheet.css`页面，并输入以下内容：

```html
body { margin: 0; background-color: #000; color: #FFF; font-family: Helvetica, sans-serif; }
a { color: #FFF; }
h1 { position: absolute; top: 0; margin: auto; z-index: 50; padding: 10px; background-color: #000; color: #FFF; }
div#credits { position: absolute; bottom: 0; right: 0; padding: 10px; }
audio { position: absolute; visibility: hidden; }

```

现在 HTML 和 CSS 页面都已构建，我们将着手处理动画脚本。创建一个新的 JavaScript 文件，并将其命名为`animatedLines.js`。我们将把它放在一个名为`js`的新子文件夹中。

首先，我们将声明 flatten 变量并创建一个新的数组函数：`var flatten = function(array) { var r = [];`。接下来，在函数内部，我们将创建一个`for`语句来声明一个以一个对象开始的数组（`var i = 0`），然后在数组长度大于`i`时增加数组的大小。通过使用`push`函数，我们将输入新值到数组中：`r.push.apply(r, array[i]);}`，最后通过返回数组来结束函数：`return r; }`。

到目前为止，我们的脚本应该看起来像以下代码块：

```html
var flatten = function(array) { var r = [];
for(var i = 0; i < array.length; i++) {
r.push.apply(r, array[i]); }
return r; }

```

接下来，我们将创建一个名为 shuffle 的函数，该函数接受一个数组作为参数。输入`function shuffle(array) { var tmp, current, top = array.length;`。在函数内部，我们有一个 if/while 循环来遍历数组中的值。通过输入以下代码将其添加到脚本中：`var tmp, current, top = array.length; if(top) while(--top) { current = Math.floor(Math.random() * (top + 1)); tmp = array[current]; array[current] = array[top]; array[top] = tmp; }`。在函数末尾返回`array`值。我们的随机打乱数组值的函数现在应该看起来像以下代码块：

```html
function shuffle(array) {
var tmp, current, top = array.length;
if(top) while(--top) {
current = Math.floor(Math.random() * (top + 1));
tmp = array[current];
array[current] = array[top];
array[top] = tmp; }
return array; }

```

现在，我们准备创建一个全局的`canvas`变量和一个`context`变量，输入：`var canvas;`和`var ctx;`。

创建了这些变量后，我们可以将`init()`函数添加到脚本中，所有操作都从这里开始。输入`function init() {`然后输入语句将我们的 canvas 变量与 canvas 元素关联起来：`canvas = document.getElementById('tutorial');`。

现在，我们将创建一个`if`语句来设置我们的 canvas 变量的宽度和高度属性：`if (canvas.getContext) {canvas.width = window.innerWidth; canvas.height = window.innerHeight - 100; ctx = canvas.getContext('2d'); ctx.lineJoin = "round"; setInterval("draw()", 300); }。这`完成了`init()`函数。

接下来，我们为浏览器窗口添加一个监听器，以便在调整大小时检测：`window.addEventListener('resize', function() {canvas.width = window.innerWidth;canvas.height = window.innerHeight - 100; });}`。

我们脚本的最新添加现在应该看起来像：

```html
function init() {
canvas = document.getElementById('tutorial');
if (canvas.getContext) {
canvas.width = window.innerWidth;
canvas.height = window.innerHeight - 100;
ctx = canvas.getContext('2d');
ctx.lineJoin = "round";
setInterval("draw()", 300); }
window.addEventListener('resize', function() {
canvas.width = window.innerWidth;
canvas.height = window.innerHeight - 100; }); }

```

我们终于准备好创建一个函数来在画布上绘制形状。这个函数将包含大部分驱动形状动画的脚本。键入`function draw(){ctx.globalCompositeOperation = "darker"; ctx.fillStyle = '#000'; ctx.fillRect(0, 0, canvas.width, canvas.height);ctx.globalCompositeOperation = "lighter";to`设置画布背景的外观。

现在，我们将输入用于动画的颜色。我们将创建一个包含`rgba`值的数组数组。键入：`var colors = ["rgba(134, 154, 67, 0.8)", "rgba(196, 187, 72, 0.8)", "rgba(247, 210, 82, 1)", "rgba(225, 124, 20, 0.8)"];。我们`已经定义了颜色，现在我们将使用一个包含宽度和高度值的数组来设置形状的宽度和高度：`var data = [ [ [5, 20], [15, 2] ], [ [50, 12], [10, 14], [3, 21] ], [ [60, 8]], [ [30, 24], [15, 4], [10, 17] ], [ [5, 10] ], [ [60, 5], [10, 6], [3, 26] ], [ [20, 18] ], [ [90, 11], [40, 13], [15, 10] ], [ [70, 19] ], ]`。

现在我们可以通过使用`data = shuffle(data)`来改变它们的宽度和高度来使形状动起来。

为了使形状上下以及左右移动，我们需要"压扁"或压缩它们的高度。创建一个新变量来包含`var flatData = flatten(data)`；

现在我们将扭曲线条，使它们看起来像是在不同方向上拉动，并使用`bezierCurve`。这是一个大的函数块，包含在我们之前创建的`draw()`函数中，所以输入`link()`函数如下所示：

```html
link(topPos, bottomPos, width) {
var padding = 100;
ctx.lineWidth = width;
ctx.beginPath();
var height = parseInt(canvas.height - padding);
var pull = 100;
var topLeft = topPos + (width / 2) + padding;
var bottomLeft = bottomPos + (width / 2) + padding;
ctx.moveTo(topLeft, padding);
ctx.bezierCurveTo(topLeft, pull, bottomLeft, height - pull, bottomLeft, height);
ctx.stroke(); }

```

现在，当我们仍然在`draw()`函数中时，让我们添加一个新变量来表示形状的起点，然后添加一个`for`循环来创建一个可以容纳数据值集合数组的新变量。以下是变量和循环代码：`Var topStartingPoint = 0; for(var i in data) { var group = data[i]; var color = colors[ i % colors.length ];ctx.strokeStyle = color`。

通过创建一个嵌套的`for`循环，将一组数据值传递给一个名为`line`的新变量，进一步进行。`for(var j in group) { var line = group[j]`；然后我们可以在创建一个初始值为零的`bottomStartingPoint`变量后进行操作：`var bottomStartingPoint = 0`。

第三个嵌套的`for`循环将允许我们进一步控制形状的定位和移动：`for(var k in flatData) { if(flatData[k][1] < line[1]) { bottomStartingPoint += flatData[k][0] + 11;} }`。

最后，我们使用 link 来设置线条的顶部和底部起点，`link(topStartingPoint, bottomStartingPoint, line[0])`；然后将`topStartingPoint`赋值为其当前值加上线条数组。最后一条语句将`topStartingPoint`的值设置为其当前值加上五：`topStartingPoint += line[0]; } topStartingPoint += 5; }}`。保存脚本文件。

在浏览器中打开文件`random-animation-with-audio.html`，您应该看到线条来回摆动，类似于以下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_07_10.jpg)

## 它是如何工作的...

首先，我们创建了一个 HTML5 页面，其中包含对在页面加载时导入的 JavaScript 和 CSS 文件的链接：`<script type="text/javascript" src="img/animatedlines.js"></script><link rel="stylesheet" href="css/stylesheet.css" type="text/css" media="screen" charset="utf-8" />`。为了激活我们的动画序列，我们将`init()`函数放在 HTML 页面的 body 标签中。当页面加载时，`animatedLines.js` JavaScript 文件中的`init()`函数将通过`<body onLoad="init();">`进行初始化。

我们使用`body`样式设置了全局默认的`margin`为`0`，页面的`background-color`，字体`color`和`font-family`。我们为基本链接颜色设置了样式，然后为`h1`标题标签设置了样式，使其以`position: absolute; top: 0`的方式显示在`top`位置，并通过将`z-index`设置为`50`始终显示在大多数其他内容块的上方。`#credits` div 被定位在页面的右下角，音频标签使用`visibility: hidden`进行隐藏。

我们创建了一个名为`animatedLines.js`的新脚本，并首先定义了一系列变量和函数来控制形状的行为。

我们设置了一个名为`flatten`的数组，它会向自身添加新值。接下来，我们需要一个函数来随机遍历数组值。我们使用`Math.floor(Math.random()`语句来计算一个随机数，并将结果乘以变量`top + 1`的当前值的总和。然后我们将一个整数值返回给变量`current`。

我们通过使用`document.getElementById`在页面加载时抓取`canvas`元素的 ID 来定义了`canvas`变量的尺寸值。我们使用 DOM 设置了`canvas`变量的`width`和`height`属性：`canvas.height = window.innerHeight - 100; ctx = canvas.getContext('2d')`；然后创建了一个语句来将`lineJoin`应用到`canvas`的`2d`上下文中，并设置参数为`round`。我们使用`setInterval()`函数将画布上的线条绘制速度设置为`300`毫秒。数字越大，动画看起来越慢。我们为浏览器窗口添加了一个监听器，以便检测调整大小时使用`window.addEventListener`，其中包含了浏览器窗口和画布的尺寸参数。

然后使用`draw()`函数将形状绘制到画布上。使用`globalCompositeOperation = "darker"`来使线条在相互交叠时变暗。线条在画布舞台前部重叠时，使用`globalCompositeOperation = "lighter"`来设置画布背景的外观。

用于装饰线条的颜色需要以`rgba`格式。`rgba`中的'a'指的是 alpha 值，控制每种颜色的可见性。每个`rgba`值设置都包含在一个数组中，然后成为数组列表。我们需要相匹配的宽度和高度值集合用于线条。这些存储在数组`var data`中。

接下来，我们将`data`数组分配给从我们的`shuffle()`函数返回的值，以便我们可以随机化屏幕上线条的外观。然后，我们将`flatData`变量分配给从`flatten()`函数返回的值。为每条线分配一个拉动值使我们能够将其移动一定数量的像素。我们将这个与`bezierCurve`结合起来使线条弯曲。

## 还有更多...

结合音频标签、画布动画和 JavaScript 听起来是创建酷炫可视化效果的有趣方式。然而，这些效果在很大程度上依赖于浏览器的支持，因此目前许多网络浏览器用户无法正确查看它们。我的意思是，大多数标准浏览器在一两年内都无法播放它们。

### 使用尖端浏览器可视化您的音频

如果你已经下载了 beta 版的 Firefox 4，你就可以访问 Firefox 音频和视频 API。你将能够使用类似 Spectrum Visualizer 的工具查看和创建自己的音频可视化：

[`www.storiesinflight.com/jsfft/visualizer/index.html`](http://www.storiesinflight.com/jsfft/visualizer/index.html)

### 在 HTML5 中推动音频的实现

Alexander Chen 一直在尝试通过移植基于 Flash 的应用程序来实验音频和画布。他在使用多个音频文件时遇到了一些问题，这些问题在他的博客上有详细介绍：

[`blog.chenalexander.com/2011/limitations-of-layering-html5-audio/`](http://blog.chenalexander.com/2011/limitations-of-layering-html5-audio/)

## 另请参阅

画布和


# 第八章：拥抱音频和视频

在本章中，我们将涵盖：

+   对 Flash 说不

+   理解“音频”和“视频”文件格式

+   为所有人显示“视频”

+   创建可访问的“音频”和“视频”

+   打造时髦的“音频”播放器

+   为移动设备嵌入“音频”和“视频”

# 介绍

> “Flash 是在 PC 时代创建的-为 PC 和鼠标。Flash 对 Adobe 来说是一个成功的业务，我们可以理解他们为什么想将其推广到 PC 之外。但移动时代是关于低功耗设备、触摸界面和开放的网络标准，所有这些领域 Flash 都做得不够好。提供其内容给苹果移动设备的媒体机构的大量增加表明，Flash 不再是观看视频或消费任何类型网络内容的必要条件。”- 史蒂夫·乔布斯

与我们已经看过的许多其他新技术一样，在开源 HTML5 标准中，新的“音频”和“视频”元素比以往任何时候都更加成熟和可用。这是一件好事，因为用户对多媒体的期望比以往任何时候都要高。在过去，我们使用需要 10 分钟才能下载一张照片的 300 波特调制解调器。后来，我们使用 Napster 非法下载 MP3“音频”文件。现在，我们在移动设备上播放电视和色情内容。由于带宽管道变得越来越宽，我们对互动娱乐的需求几乎变得无法满足。现在是展示成果的时候了。

多年来，视频播放在网页上一直是 QuickTime、RealPlayer 和 Flash 之间的战斗。这些浏览器插件安装起来很容易，*通常*能产生预期的结果。

随着时间的推移，QuickTime 和 RealPlayer 继续作为播放平台，但专有 Flash 工具的制造商也创建了一个强大的开发环境，使设计师和开发人员都认为它是一个可行的平台。

虽然 QuickTime 和 RealPlayer 仍然存在，但 Flash 赢得了这场战争。对于动画和卡通来说，Flash 是理想的工具。但它是否仍然是最好的“音频”和“视频”播放工具呢？史蒂夫·乔布斯肯定不这么认为。

2010 年，苹果电脑的负责人乔布斯划定了界限，并表示 Flash 永远不会出现在他最畅销的 iPhone 和 iPad 上。相反，他坚定地支持开放的 HTML5 标准，并引发了一场在线圣战。

不久之后，“Flash 的死亡”宣言成为媒体头条和博客圈的热门话题。有些人写得如此恶毒，好像一道堤坝决堤，所有积累的污秽和淤泥都被允许淹没我们的多媒体对话。

很快，即使非网页设计师和开发人员也开始注意到，比如 C.C. Chapman，著名书籍《内容*规则*》的作者，表达了他对《今日秀》无法在 iPad 上观看的不满：

![Introduction](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_08_01.jpg)

这个问题迅速渗透到我们的在线娱乐讨论中。你不再需要成为网页设计师或开发人员才知道这里存在真正的问题。

C.C.说得简单明了，但作者知道他在谈论史蒂夫制造的 Flash/HTML5“视频”战争时，他已经说错了话。有时他争论得太过激和傲慢，但事实是，像网页设计师杰西卡·邦恩这样头脑清晰的人在提醒我们，Flash 和 HTML5“视频”可以和平共存。

自从史蒂夫做出上述宣言以来不到一年的时间，像 ABC、CBS、CNN、ESPN、Facebook、Fox News、MSNBC、National Geographic、Netflix、《纽约时报》、NPR、People、《体育画报》、《时代》、Vimeo、《华尔街日报》、YouTube 等网站都采用了新的 HTML5“音频”和“视频”元素。截至目前，超过 60%的网络“视频”现在都已经准备好使用 HTML5。可以说，新的 HTML5“音频”和“视频”功能是一些最令人兴奋和期待的新发展！

支持新的 HTML5“音频”和“视频”元素的浏览器包括：

![Introduction](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_08_02.jpg)

在这一章中，我们将看一些现实生活中的例子，比如对 Flash 说不，理解新的`video`和`audio`文件格式，为所有人显示`video`，创建可访问的`audio`和`video`，打造时尚的`audio`播放器，以及为移动设备嵌入`audio`和`video`。

现在，让我们开始吧！

# 对 Flash 说不

作者的妈妈过去常说，万事都有其时机和地点，我们相信 Flash 也有其时机和地点。只是现在，随着技术的成熟，作者认为 Flash 的时间和地点越来越少。

![对 Flash 说不](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_08_03.jpg)

在那些糟糕的旧日子里，如果我们想在网页中使用 YouTube 视频，比如“Neutraface”，这是排版界对 Lady Gaga 的“Pokerface”的回应，我们就不得不使用一些丑陋的代码，比如这样：

```html
<object width="640" height="390">
<param name="movie" value="http://www.youtube.com/v/xHCu28bfxSI?fs=1&amp;hl=en_US"> </param>
<param name="allowFullScreen" value="true"></param>
<param name="allowscriptaccess" value="always"></param>
<embed src="img/xHCu28bfxSI?fs=1&amp;hl=en_US" type="application/x-shockwave-flash" allowscriptaccess="always" allowfullscreen="true" width="640" height="390"></embed>
</object>

```

那段代码又长又丑陋，而且复杂，无法通过验证测试。它还依赖于第三方插件。呃。

多年来，我们忍受了那些垃圾，但不再。现在我们可以重建它——我们有技术了。

## 如何做...

现在，我们可以使用更加优雅的东西，而不是臃肿的`object`代码：

```html
<video src="img/videosource.ogv"></video>

```

这就是所需的全部。它简短、漂亮，而且验证通过。最重要的是，它不需要插件。再告诉我，为什么我们认为 Flash 是个好主意。

为了增加一些样式和功能，让我们再加入一点代码。

```html
<video src="img/videosource.ogv" controls height="390" width="640"></video>

```

## 它是如何工作的...

那段代码应该很简单。你可能已经猜到，`src`指的是源`video`文件，`controls`表示`video`应该使用标准的播放和音量控件，`height`和`width`是不言自明的。

现代浏览器现在有了自己的原生 HTML5`audio`和`video`播放控件。让我们来看看每一个，从苹果 Safari 开始：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_08_04.jpg)

这是谷歌 Chrome 显示播放控件的方式：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_08_05.jpg)

微软 Internet Explorer 9 以不同的方式显示它：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_08_06.jpg)

然后，Mozilla Firefox 以不同的方式做到了：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_08_07.jpg)

不足为奇的是，Opera 以另一种方式显示播放控件：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_08_08.jpg)

所有这些看起来都不一样。如果每一个不同的外观都满足你的需求，太好了！如果不是，那肯定需要更多的工作来让它们行为和外观相似。

## 还有更多...

还有一些可选的属性我们可以包括。它们是：

+   `autobuffer` - 这个布尔属性告诉浏览器在用户点击播放按钮之前就开始下载歌曲或电影。

+   `autoplay` - 你可能已经猜到，这告诉浏览器自动播放 HTML5`audio`或`video`。

+   `loop` - 也是一个布尔属性，它会一遍又一遍地播放 HTML5`audio`或`video`文件。

+   preload - preload 属性在播放之前开始加载文件。

+   `poster` - `poster`属性是在新的 HTML5`video`加载时显示的静态占位图像。显然，这个属性不适用于 HTML5`audio`文件。

无论你包括了这些可选属性中的哪些，你最终都会得到一种更漂亮、更语义化、更可访问的显示`audio`和`video`的方法，比起依赖 Flash 为你提供它们。

### 一些好消息

与`canvas`章节不同，关于新的 HTML5`audio`和`video`元素的好消息是它们是可访问的。新的 HTML5`audio`和`video`元素具有键盘可访问性。由于浏览器现在原生地处理新的 HTML5`audio`和`video`元素，它可以像按钮一样支持你的键盘。这一点单独就足以推动这项新技术的接受。

### 带样式的视频

新的 HTML5 `audio`和`video`元素可以使用 CSS 进行视觉样式设置。我们可以使用 CSS 不仅控制播放器的大小，还可以添加`:hover`和`:transform`效果。此外，我们可以使用 JavaScript 来控制新的 HTML5 `audio`和`video`的行为。很酷！

### 保护你的资产

Flash 确实提供优势的一个领域是保护你的`音频`和`视频`内容。请记住，新的 HTML5 `audio`和`video`元素天生是开源的，没有数字版权管理。如果保护你的`音频`或`视频`文件不被下载对你来说很重要，那么新的 HTML5 `audio`和`video`元素不适合你 - Flash 可能仍然适合。这并不是说 Flash 能够终极保护不被盗用 - 只是说，Flash 默认隐藏了媒体轨道的能力，而新的 HTML5 `<audio>`和`<video>`元素则默认将这些文件完全暴露给任何人。然而，Flash Media Server 可以完全保护你的资产。

仍然不确定是选择 HTML5 音频和视频还是 Flash？试试这个方便的提示列表。

HTML5 的好处包括：

+   **可访问性：**如果可访问性对你很重要（应该是的），那么新的 HTML5 `audio`和`video`元素是你最好的选择。

+   **iOS：**如果你希望你的`音频`和`视频`能在 iPhone 或 iPad 上显示，HTML5 是你唯一的选择。

+   **移动设备：**除了苹果的移动设备外，其他移动设备对新的 HTML5 `audio`和`video`元素有很好的支持。

+   `视频/音频` **流媒体：**如果你正在流媒体的内容不是专有的，也不需要版权管理，HTML5 是你的完美选择。

Flash 的好处包括：

+   **可访问性：**如果你不在乎盲人或聋人，也不支持他们。谁在乎你是否被起诉呢？

+   **动画：**毫无疑问，使用 Flash 的最好理由是如果你的网站有复杂的动画。像[`jibjab.com`](http://jibjab.com)这样的网站如果没有 Flash 就无法存在。

+   **仅桌面开发：**如果你不需要支持移动用户。那只是一个时尚。

+   `视频/音频` **流媒体：**如果你不喜欢分享并且必须锁定你的`音频`或`视频`，使其不容易被人下载，那就坚持使用 Flash。

+   **网络摄像头：**如果你使用网络摄像头（除了[`chatroulette.com`](http://chatroulette.com)之外，还有谁在用？），那么 Flash 就是最好的选择。

这真的是使用 Flash 的最具说服力的理由吗？

![保护你的资产](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_08_09.jpg)

## 另请参阅

想要能够在所有主要浏览器中播放新的 HTML5 `audio`和`video`元素，甚至包括远至 Internet Explorer 6？谁不想呢？如果是这样，那就去看看免费的开源 Projekktor 项目，网址是[`projekktor.com`](http://projekktor.com)。Projekktor 是 Sascha Kluger 的创意，它使用 JavaScript 来确保各种支持的浏览器都能正确解释和显示特定的 HTML5 `video`文件格式。

# 了解音频和视频文件格式

有很多不同的`音频`和`视频`文件格式。这些文件不仅可能包括`视频`，还可能包括`音频`和元数据 - 都在一个文件中。这些文件类型包括：

+   `.avi` - 一个来自过去的冲击，音频视频交错文件格式是由微软发明的。不支持今天大多数现代的`音频`和`视频`编解码器。

+   `.flv` - Flash `视频`。这曾经是 Flash 完全支持的唯一`视频`文件格式。现在它还包括对`.mp4`的支持。

+   `.mp4`或`.mpv` - MPEG4 基于苹果的 QuickTime 播放器，并需要该软件进行播放。

## 它是如何工作的...

前面提到的每种`视频`文件格式都需要浏览器插件或某种独立软件进行播放。接下来，我们将看看不需要插件或特殊软件以及支持它们的浏览器的新开源`音频`和`视频`文件格式。

+   H.264 已经成为最常用的高清视频格式之一。它被用于蓝光光盘以及许多互联网视频流网站，包括 Flash、iTunes 音乐商店、Silverlight、Vimeo、YouTube、有线电视广播和实时视频会议。此外，H.264 有专利，因此从定义上来说，它不是开源的。支持 H.264 视频文件格式的浏览器包括：![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_08_10.jpg)

### 提示

谷歌现在部分地拒绝了 H.264 格式，更倾向于支持新的 WebM 视频文件格式。

+   Ogg 可能听起来有点滑稽，但它的潜力是非常严肃的，我向你保证。Ogg 实际上是两种东西：Ogg Theora 是一种视频文件格式；Ogg Vorbis 是一种音频文件格式。Theora 实际上更多地是一种视频文件压缩格式，而不是播放文件格式，尽管它也可以用于播放。它没有专利，因此被视为开源。我们将在下一节讨论 Ogg Vorbis。

### 提示

有趣的事实：根据维基百科，“Theora 是以 Max Headroom 电视节目中 Edison Carter 的控制器 Theora Jones 的名字命名的。”

支持 Ogg 视频文件格式的浏览器包括：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_08_11.jpg)

+   WebM 是在线视频文件格式竞赛中最新的参与者。这种开源音频/视频文件格式的开发由谷歌赞助。WebM 文件包含 Ogg Vorbis 音频流和 VP8 视频流。它得到了许多媒体播放器的支持，包括 Miro、Moovidia、VLC、Winamp 等，YouTube 也有初步支持。Flash 的制造商表示未来将支持 WebM，Internet Explorer 9 也将支持。目前支持 WebM 的浏览器包括：![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_08_12.jpg)

## 还有更多...

到目前为止，这似乎是一长串音频和视频文件格式，最多只有零星的浏览器支持。如果你开始有这种感觉，那么你是对的。

事实上，没有一个音频或视频文件格式能够成为统治它们所有的真正格式。相反，我们开发人员通常必须以多种格式提供新的音频和视频文件，让浏览器决定它最舒适和能够播放的格式。目前这有点麻烦，但希望未来我们能够选择更少的格式，获得更一致的结果。

### 音频文件格式

还有一些音频文件格式。让我们来看看这些。

+   AAC - 高级音频编码文件更为人所知的是 AAC。这种音频文件格式被设计成在相同比特率下比 MP3 更好听。苹果使用这种音频文件格式来制作 iTunes 音乐商店的音频文件。由于 AAC 音频文件格式支持 DRM，苹果提供受保护和非受保护格式的文件。AAC 有专利，因此从定义上来说，我们也不能完全称其为开源音频文件格式。所有苹果硬件产品，包括他们的 iPhone 和 iPad 移动设备以及 Flash，都支持 AAC 音频文件格式。支持 AAC 的浏览器包括：![音频文件格式](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_08_13.jpg)

+   MP3 - MPEG-1 音频层 3 文件更为人所知的是 MP3。除非你一直躲在石头下，你知道 MP3 是当今最普遍使用的音频文件格式。这些文件可以播放两个声道的声音，并且可以使用多种比特率进行编码，最高可达 320。一般来说，比特率越高，音频文件的音质就越好。这也意味着文件大小更大，因此下载速度更慢。MP3 有专利，因此从定义上来说，我们也不能完全称其为开源音频文件格式。支持 MP3 的浏览器包括：![音频文件格式](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_08_14.jpg)

+   Ogg - 我们之前讨论过 Ogg Theora 视频文件格式。现在，让我们来看看 Ogg Vorbis 音频格式。正如之前提到的，Ogg 文件没有专利，因此被视为开源。

### 提示

另一个有趣的事实是：根据维基百科，“Vorbis 是以《小神》中的 Exquisitor Vorbis 角色命名的。”

![音频文件格式](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_08_15.jpg)

### 文件格式不可知。

我们花了很多时间来检查这些不同的视频和音频文件格式。每种格式都有其优点和缺点，并且受到各种浏览器的支持（或不支持）。有些比其他的效果更好，有些听起来和看起来比其他的更好。但好消息是：新的 HTML5 `<video>`和`<audio>`元素本身是文件格式不可知的！这些新元素不在乎您引用的视频或音频文件的类型。相反，它们提供您指定的内容，并让每个浏览器做它最舒服的事情。

### 有一天我们能停止这种疯狂吗？

最重要的是，直到一个新的 HTML5 音频和一个新的 HTML5 视频文件格式成为所有浏览器和设备的明确选择，音频和视频文件将不得不被编码多次进行播放。不要指望这种情况很快会改变。

# 为所有人显示视频

根据作者 Mark Pilgrim 的说法，您的 HTML5 网络视频工作流程将如下所示：

+   制作一个使用 WebM（VP8 和 Vorbis）的版本。

+   制作另一个版本，该版本在 MP4 容器中使用 H.264 基线视频和 AAC“低复杂度”音频。

+   制作另一个版本，该版本在 Ogg 容器中使用 Theora 视频和 Vorbis 音频。

+   从单个`<video>`元素链接到所有三个视频文件，并回退到基于 Flash 的视频播放器。

Kroc Camen 在创建“面向所有人的视频”时确实做到了这一点，这是一段 HTML 代码，如果用户的浏览器可以处理它，就会显示新的 HTML5 视频元素，如果不能，就会显示 Flash 电影 —— 而无需 JavaScript。让我们看看 Kroc 是如何做到的：[`camendesign.com/code/video_for_everybody`](http://camendesign.com/code/video_for_everybody)。

![为所有人显示视频](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_08_16.jpg)

## 如何做...

```html
<video controls height="360" width="640">
<source src="img/__VIDEO__.MP4" type="video/mp4" />
<source src="img/__VIDEO__.OGV" type="video/ogg" />
<object width="640" height="360" type="application/ x-shockwave-flash" data="__FLASH__.SWF">
<param name="movie" value="__FLASH__.SWF" />
<param name="flashvars" value="controlbar=over&amp; image=__POSTER__.JPG&amp;file=__VIDEO__.MP4" />
<img src="img/__VIDEO__.JPG" width="640" height="360" alt="__TITLE__" title="No video playback capabilities, please download the video below" />
</object>
</video>
<p><strong>Download Video:</strong>
Closed Format: <a href="__VIDEO__.MP4">"MP4"</a>
Open Format: <a href="__VIDEO__.OGV">"Ogg"</a>
</p>

```

仔细观察，很容易看出 Kroc 做了什么。首先，他调用了浏览器本地播放控件，以及新的 HTML5 视频元素的相关高度和宽度。

```html
<video controls height="360" width="640">

```

接下来，Kroc 依次调用每个新的 HTML5 视频源，从 MP4 文件开始。桌面浏览器不太在乎 HTML5 视频文件的顺序，但 iPad 对于想要首先指定 MP4 文件很挑剔，所以好吧。又是你赢了，史蒂夫·乔布斯。

```html
<source src="img/__VIDEO__.MP4" type="video/mp4" />
<source src="img/__VIDEO__.OGV" type="video/ogg" />

```

然后，Kroc 通过调用相同文件的 Flash 视频版本来保险，以应对无法处理新的 HTML5 视频元素的软弱浏览器。

```html
<object width="640" height="360" type="application/x-shockwave-flash" data="__FLASH__.SWF">
<param name="movie" value="__FLASH__.SWF" />
<param name="flashvars" value="controlbar=over&amp; image=__POSTER__.JPG&amp;file=__VIDEO__.MP4" />
<img src="img/__VIDEO__.JPG" width="640" height="360" alt="__TITLE__" title="No video playback capabilities, please download the video below" />
</object>

```

最后，Kroc 通过提示用户选择性地下载新的 HTML5 视频文件本身，以封闭（MP4）和开放（Ogg）格式进行了精心的处理。分享就是关怀。

```html
<p><strong>Download Video:</strong>
Closed Format: <a href="__VIDEO__.MP4">"MP4"</a>
Open Format: <a href="__VIDEO__.OGV">"Ogg"</a>
</p>

```

### 提示

当然，您可以用自己文件的路径替换“_VIDEO_.MP4”之类的东西。

这种方法非常成功，因为无论您使用什么网络浏览器，您都可以看到*某些东西* —— 而无需使用 JavaScript 或下载 Flash。

## 它是如何工作的...

这个概念实际上非常简单：如果您的浏览器能够播放新的 HTML5 视频元素文件，那么您将看到它。如果它不能做到，代码堆栈中还包括了一个 Flash 电影，所以您应该会看到它。如果由于某种原因，您的浏览器无法原生支持新的 HTML5 视频元素，Flash 播放器崩溃或不可用，您将看到一个静态图像。每个人都有保障。

使用此方法将显示新的 HTML5 视频元素的浏览器包括：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_08_17.jpg)

使用此方法将显示 Flash 视频的浏览器包括：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_08_18.jpg)

## 还有更多...

所有其他 Flash 视频嵌入方法都会提示用户下载 Flash（如果尚未安装）。《面向所有人的视频》独特之处在于它不会这样做。作者 Kroc Camen 是有意为之，他说：

> “用户已经有足够的安全问题了，而不需要随机的网站提示他们安装东西-对于那些不想要或无法使用 Flash 的人来说，这更加恼人。”

### 浪费 mime 是一件可怕的事情

Kroc 提醒我们确保我们的服务器使用正确的`mime-types`并建议将这些行放在你的`.htaccess`文件中：

```html
AddType video/ogg .ogv
AddType video/mp4 .mp4
AddType video/webm .webm

```

### 外部“Video for Everybody”

现在 WordPress 有一个“Video for Everybody”插件，网址是[`wordpress.org/extend/plugins/external-video-for-everybody`](http://wordpress.org/extend/plugins/external-video-for-everybody)。现在你也可以在你的博客上轻松使用 Kroc 的方法。

### 灵活地处理你的方法

稍后我们将看一种方法，它实现了与 Kroc 的方法几乎相同的功能，但这次是用 JavaScript。记住：做对你、你的项目和最重要的是你的客户最有意义的事情。

## 另见

Humanstxt.org 是一个让网站开发者更加知名的项目。该网站鼓励开发者包含一个小文本文件，其中包含每个贡献创建和构建网站的团队成员的信息。请访问：[`humanstxt.org`](http://humanstxt.org)。

# 创建无障碍音频和视频

我们已经非常广泛地研究了如何向人们提供在线 HTML5 `video`，而不管他们的浏览器是什么，但对于依赖辅助技术的人，我们并没有给予太多关注。现在结束了。

## 如何做到...

首先，我们将从 Kroc Camen 的“Video for Everybody”代码块开始，然后检查如何使其对辅助功能友好，最终看起来像这样：

```html
<div id="videowrapper">
<video controls height="360" width="640">
<source src="img/__VIDEO__.MP4" type="video/mp4" />
<source src="img/__VIDEO__.OGV" type="video/ogg" />
<object width="640" height="360" type="application/ x-shockwave-flash" data="__FLASH__.SWF">
<param name="movie" value="__FLASH__.SWF" />
<param name="flashvars" value="controlbar=over&amp; image=__POSTER__.JPG&amp;file=__VIDEO__.MP4" />
<img src="img/__VIDEO__.JPG" width="640" height="360" alt="__TITLE__" title="No video playback capabilities, please download the video below" />
</object>
<track kind="captions" src="img/videocaptions.srt" srclang="en" />
<p>Final fallback content</p>
</video>
<div id="captions"></div>
<p><strong>Download Video:</strong>
Closed Format: <a href="__VIDEO__.MP4">"MP4"</a>
Open Format: <a href="__VIDEO__.OGV">"Ogg"</a>
</p>
</div>

```

## 它是如何工作的...

你会注意到的第一件事是，我们将新的 HTML5 `video`元素包装在一个`div`包装器中。虽然从语义上讲这并不是严格必要的，但它将为我们的 CSS 提供一个很好的“钩子”。

```html
<div id="videowrapper">

```

下一部分的大部分内容应该是从前一部分中可以识别出来的。这里没有改变：

```html
<video controls height="360" width="640">
<source src="img/__VIDEO__.MP4" type="video/mp4" />
<source src="img/__VIDEO__.OGV" type="video/ogg" />
<object width="640" height="360" type="application/ x-shockwave-flash" data="__FLASH__.SWF">
<param name="movie" value="__FLASH__.SWF" />
<param name="flashvars" value="controlbar=over&amp;
image=__POSTER__.JPG&amp;file=__VIDEO__.MP4" />
<img src="img/__VIDEO__.JPG" width="640" height="360" alt="__TITLE__" title="No video playback capabilities, please download the video below" />
</object>

```

到目前为止，我们仍然使用的是向能够处理它的浏览器提供新的 HTML5 `video`元素的方法，并将 Flash 作为我们的第一个备用选项。但是如果 Flash 不是一个选择，接下来会发生什么就变得有趣起来：

```html
<track kind="captions" src="img/videocaptions.srt" srclang="en" />

```

你可能会想，那是什么鬼。

> “`track`元素允许作者为媒体元素指定显式外部定时文本轨道。它本身不代表任何东西。”- W3C HTML5 规范

现在我们有机会使用 HTML5 规范的另一个新部分：新的`<track>`元素。现在，我们可以引用`kind="captions"`中指定的外部文件类型。你可以猜到，`kind="captions"`是用于字幕文件，而`kind="descriptions"`是用于`audio`描述。当然，`src`调用特定的文件，`srclang`设置新的 HTML5 `track`元素的源语言。在这种情况下，`en`代表英语。不幸的是，目前没有浏览器支持新的`track`元素。

最后，我们允许最后一点备用内容，以防用户无法使用新的 HTML5 `video`元素或 Flash 时，我们会给他们一些纯文本内容。

```html
<p>Final fallback content</p>

```

现在，即使用户看不到图像，他们至少会得到一些描述性内容。

接下来，我们将创建一个容器`div`来容纳我们基于文本的字幕。因此，目前没有浏览器支持新的 HTML5 `audio`或`video`元素的闭合字幕，我们将留出空间来包含我们自己的字幕：

```html
<div id="captions"></div>

```

最后，我们将包括 Kroc 的文本提示，以下载 HTML5 `video`的封闭或开放文件格式：

```html
<p><strong>Download Video:</strong>
Closed Format: <a href="__VIDEO__.MP4">"MP4"</a>
Open Format: <a href="__VIDEO__.OGV">"Ogg"</a>
</p>

```

## 还有更多...

除了新的 HTML5 `audio`和`video`元素的可选`controls`属性之外，还有可选的`loop`属性。你可能会猜到，这个例子将允许 HTML5 `video`一直播放：

```html
<video controls height="360" loop width="640">

```

### 始终考虑无障碍。

我们默认提供的最终描述性内容可能是为使用辅助技术的人提供可下载链接的替代位置。这将使能够看到或听到的人无法下载，因此你应该确定这种方法是否适合你。

### 浏览器支持

对新的 HTML5 `audio`和`video`元素具有最佳辅助功能支持的网络浏览器包括：

![浏览器支持](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_08_19.jpg)

### 查看更多

你可以在[`html5accessibility.com`](http://html5accessibility.com)上跟踪 HTML5 的可访问性。该网站跟踪新的 HTML5 功能，如`audio`和`video`在哪些浏览器中可用。你可能会惊讶地发现，截至目前，Opera 是最不友好的可访问性的网络浏览器，甚至低于微软 Internet Explorer 9。惊喜吧。

## 另请参阅

Video.Js 是另一个免费的开源 HTML5 视频播放器。它很轻量，不使用任何图像，但通过 CSS 完全可定制。它看起来很棒，并支持苹果 Safari、Google Chrome、微软 Internet Explorer 9、Mozilla Firefox 和 Opera，同时还支持 IE 6-8 的回退。它甚至适用于 iPhone、iPad 和 Android 等移动设备。请访问[`videojs.com`](http://videojs.com)查看。

# 打造流畅的音频播放器

Neutron Creations 的负责人和联合创始人兼前端开发人员本·博迪恩为 Tim Van Damme 的 The Box 播客创建了一个定制的 HTML5 `audio`播放器，网址为[`thebox.maxvoltar.com`](http://thebox.maxvoltar.com)。本的创作快速、直观且流畅。让我们深入了解他是如何做到的。

![打造流畅的音频播放器](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_08_20.jpg)

本的自定义 HTML5 `audio`播放器具有被采访者（在这种情况下是 Shaun Inman）的吸引人照片，一个播放/暂停按钮，指示播放进度的轨道，以及如果你愿意，将 HTML5 `audio`播放器弹出到一个单独的窗口的能力。就是这样。没有更多的需要。作为一个额外的触摸，注意 HTML5 `audio`播放器条的轻微透明度细节。平滑。

## 如何做到这一点...

起初，本的标记似乎看起来非常简单：

```html
<p class="player">
<span id="playtoggle" />
<span id="gutter">
<span id="loading" />
<span id="handle" class="ui-slider-handle" />
</span>
<span id="timeleft" />
</p>

```

等一下，我听到你在想，“HTML5 `audio`标签在哪里？！”别担心。本是个聪明人，对此有计划。但首先让我们看看他到目前为止做了什么。

```html
<p class="player">

```

到目前为止，这很简单。本创建了一个包装元素（在这种情况下是`<p>`）来放置他的播放器。他可以使用`<div>`吗？也许。做对你和你的项目最有意义的事情。

```html
<span id="playtoggle" />

```

然后，本使用这个自闭合的（注意末尾的斜杠）`span`来进行播放/暂停切换按钮。

```html
<span id="gutter">
<span id="loading" />
<span id="handle" class="ui-slider-handle" />
</span>

```

现在，事情变得有趣起来。本的“排水沟”`span`包含了时间轴轨道，显示 HTML5 `audio`文件的加载或缓冲进度的条形元素，以及指示播放头的圆形元素，如果你选择，可以来回“擦洗”。

```html
<span id="timeleft" />

```

最后，本使用另一个自闭合的`span`来显示剩余的时间，以分钟和秒为单位。

### 提示

`<span>`元素可以胜任，但它并不是非常语义化，是吗？Patrick H. Lauke 迅速指出，使用可聚焦元素将大大提高这种方法对依赖辅助技术的人的可访问性。

## 它是如何工作的...

本使用 jQuery 来检测对 HTML5 `audio`的支持。

```html
if(!!document.createElement('audio').canPlayType) {
var player = '<p class="player"> ... </p>\
<audio>\
<source src="img/episode1.ogg" type="audio/ogg"></source>\
<source src="img/episode1.mp3"
type="audio/mpeg"></source>\
<source src="img/episode1.wav" type="audio/ x-wav"></source>\
</audio>';
$(player).insertAfter("#listen .photo");
}

```

在这段代码中，我们可以看到如果浏览器支持 HTML5 `audio`，它将提供完整的 HTML5 `<audio>`标签，包括对`.ogg, .mp3`和`.wav`的回退，这是我们尚未使用过的文件格式。由于新的 HTML5 `<audio>`和`<video>`元素是文件格式不可知的，`.wav`文件也应该可以正常工作。

本已经创建了一个简单的 JavaScript 代码片段，允许浏览器做他们感觉最舒服的事情。如果这对你和你的项目有意义，考虑这种方法，但记住，你依赖 JavaScript 来完成大部分工作，而不是我们已经看过的其他方法，这些方法不依赖于它。

### 提示

请注意，如果您使用`<div>`来包含 HTML5“视频”播放器，那么 JavaScript 也必须进行调整。简而言之，`<p class="player">`...`</p>`将被更改为`<div class="player">`...`</div>`。

## 还有更多...

到目前为止，我们已经为播放器设置了标记，并“嗅探”以查看任何特定浏览器想要的文件格式。现在，我们需要添加一些功能。

```html
audio = $('.player audio').get(0);
loadingIndicator = $('.player #loading');
positionIndicator = $('.player #handle');
timeleft = $('.player #timeleft');
if ((audio.buffered != undefined) && (audio.buffered.length != 0)) {
$(audio).bind('progress', function() {
var loaded = parseInt(((audio.buffered.end(0) / audio.duration) * 100), 10);
loadingIndicator.css({width: loaded + '%'});
});
}
else {
loadingIndicator.remove();
}

```

然后添加一个函数来计算播放头的位置，以确定剩余时间，要小心包括前导零（如果需要的话）。

```html
$(audio).bind('timeupdate', function() {
var rem = parseInt(audio.duration - audio.currentTime, 10),
pos = (audio.currentTime / audio.duration) * 100,
mins = Math.floor(rem/60,10),
secs = rem - mins*60;
timeleft.text('-' + mins + ':' + (secs > 9 ? secs : '0' + secs));
if (!manualSeek) { positionIndicator.css({left: pos + '%'}); }
if (!loaded) {
loaded = true;
$('.player #gutter').slider({
value: 0,
step: 0.01,
orientation: "horizontal",
range: "min",
max: audio.duration,
animate: true,
slide: function() {
manualSeek = true;
},
stop:function(e,ui) {
manualSeek = false;
audio.currentTime = ui.value;
}
});
}
});

```

唯一剩下的就是调用播放/暂停按钮功能。

```html
$(audio).bind('play',function() {
$("#playtoggle").addClass('playing');
}).bind('pause ended', function() {
$("#playtoggle").removeClass('playing');
});
$("#playtoggle").click(function() {
if (audio.paused) { audio.play(); }
else { audio.pause(); }
});

```

### 风格和内容

在创建了简单的标记和详细的 JavaScript 来创建 Ben 定制的 HTML5“音频”播放器之后，唯一剩下的就是对其进行样式设置：

```html
.player {
display: block;
height: 48px;
width: 400px;
position: absolute;
top: 349px;
left: -1px;
-webkit-box-shadow: 0 -1px 0 rgba(20, 30, 40, .75);
-moz-box-shadow: 0 -1px 0 rgba(20, 30, 40, .75);
-o-box-shadow: 0 -1px 0 rgba(20, 30, 40, .75);
box-shadow: 0 -1px 0 rgba(20, 30, 40, .75);
border-top: 1px solid #c2cbd4;
border-bottom: 1px solid #283541;
background: #939eaa;
background: -webkit-gradient(linear, 0% 0%, 0% 100%, from(rgba(174, 185, 196, .9)), to(rgba(110, 124, 140, .9)), color-stop(.5, rgba(152, 164, 176, .9)), color-stop(.501, rgba(132, 145, 159, .9)));
background: -moz-linear-gradient(top, rgba(174, 185, 196, .9), rgba(152, 164, 176, .9) 50%, rgba(132, 145, 159, .9) 50.1%, rgba(110, 124, 140, .9));
background: linear-gradient(top, rgba(174, 185, 196, .9), rgba(152, 164, 176, .9) 50%, rgba(132, 145, 159, .9) 50.1%, rgba(110, 124, 140, .9));
cursor: default;
}
#playtoggle {
position: absolute;
top: 9px;
left: 10px;
width: 30px;
height: 30px;
background: url(../img/player.png) no-repeat -30px 0;
cursor: pointer;
}
#playtoggle.playing {background-position: 0 0;}
#playtoggle:active {top: 10px;}
#timeleft {
line-height: 48px;
position: absolute;
top: 0;
right: 0;
width: 50px;
text-align: center;
font-size: 11px;
font-weight: bold;
color: #fff;
text-shadow: 0 1px 0 #546374;
}
#wrapper #timeleft {right: 40px;}
#gutter {
position: absolute;
top: 19px;
left: 50px;
right: 50px;
height: 6px;
padding: 2px;
-webkit-border-radius: 5px;
-moz-border-radius: 5px;
-o-border-radius: 5px;
border-radius: 5px;
background: #546374;
background: -webkit-gradient(linear, 0% 0%, 0% 100%, from(#242f3b), to(#516070));
background: -moz-linear-gradient(top, #242f3b, #516070);
background: linear-gradient(top, #242f3b, #516070);
-webkit-box-shadow: 0 1px 4px rgba(20, 30, 40, .75) inset, 0 1px 0 rgba(176, 187, 198, .5);
-moz-box-shadow: 0 1px 4px rgba(20, 30, 40, .75) inset, 0 1px 0 rgba(176, 187, 198, .5);
-o-box-shadow: 0 1px 4px rgba(20, 30, 40, .75) inset, 0 1px 0 rgba(176, 187, 198, .5);
box-shadow: 0 1px 4px rgba(20, 30, 40, .75) inset, 0 1px 0 rgba(176, 187, 198, .5);
}
#wrapper #gutter {right: 90px;}
#loading {
background: #fff;
background: #939eaa;
background: -webkit-gradient(linear, 0% 0%, 0% 100%, from(#eaeef1), to(#c7cfd8));
background: -moz-linear-gradient(top, #eaeef1, #c7cfd8);
background: linear-gradient(top, #eaeef1, #c7cfd8);
-webkit-box-shadow: 0 1px 0 #fff inset, 0 1px 0 #141e28;
-moz-box-shadow: 0 1px 0 #fff inset, 0 1px 0 #141e28;
-o-box-shadow: 0 1px 0 #fff inset, 0 1px 0 #141e28;
box-shadow: 0 1px 0 #fff inset, 0 1px 0 #141e28;
-webkit-border-radius: 3px;
-moz-border-radius: 3px;
-o-border-radius: 3px;
border-radius: 3px;
display: block;
float: left;
min-width: 6px;
height: 6px;
}
#handle {
position: absolute;
top: -5px;
left: 0;
width: 20px;
height: 20px;
margin-left: -10px;
background: url(../img/player.png) no-repeat -65px -5px;
cursor: pointer;
}
.player a.popup {
position: absolute;
top: 9px;
right: 8px;
width: 32px;
height: 30px;
overflow: hidden;
text-indent: -999px;
background: url(../img/player.png) no-repeat -90px 0;
}
.player a.popup:active {background-position: -90px 1px;}Content matters

```

当包装内容引人入胜时，花时间创造有趣的东西会更容易和更有回报。The Box 音频采访总是很有趣——只是可惜作者 Tim Van Damme 不经常发布它们。希望将来会有所改变。在[`thebox.maxvoltar.com`](http://thebox.maxvoltar.com)上查看。

### 注意细节

当页面上一次只有一个新的 HTML5“音频”或“视频”元素时，这种方法效果很好。如果您需要多个，您将不得不修改 JavaScript 以连接到标记中的多个“挂钩”。

## 另请参阅

SublimeVideo 采用了一种不同的方法来进行 HTML5 在线视频播放：在这种情况下，播放器不是由您创建或托管的，而是由云中播放器的制造商创建的。好处是您始终拥有可能的最新、最新鲜的播放器版本。这样，当新功能可用或错误被修复时，您无需做任何事情。您自动拥有最新的功能。在[`sublimevideo.net`](http://sublimevideo.net)上查看。

# 为移动设备嵌入音频和视频

到目前为止，我们只是触及了移动体验，但随着越来越智能的移动设备的开发增加，我们需要将注意力转向如何在这些设备上显示我们的新 HTML5“音频”和“视频”。以下是方法。

## 如何做...

现在我们知道如何为我们的目标受众选择 HTML5“音频”或“视频”文件格式，我们现在可以将注意力转向确保他们不仅可以在台式电脑和笔记本电脑上听到或观看，还可以在移动设备上听到或观看。

我们将首先在[`vimeo.com`](http://vimeo.com)上创建一个免费帐户。注册完成后，选择主菜单中的上传|视频功能。您将选择要上传的文件，添加可选的元数据，然后让 Vimeo 服务器设置您的文件。接下来真正的激动时刻开始了：嵌入“视频”。从 Vimeo 主菜单中选择**工具**|**嵌入此视频**。

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_08_21.jpg)

## 它是如何工作的...

Vimeo 过去使用我们之前看过的老式 Flash 嵌入方法。现在它使用基于 iFrame 的方法，可以在 iPhone、iPad 和其他移动设备上播放 HTML5“视频”。以下是一个示例，基于作者上传的一个“视频”：

```html
<iframe src="img/20958090" width="400" height="300" frameborder="0"></iframe><p><a href="http://vimeo.com/20958090">Untitled</a> from <a href="http://vimeo.com/user6281288">Dale Cruse</a> on <a href="http://vimeo.com">Vimeo</a>.</p>

```

## 还有更多...

一旦您将基于 iFrame 的代码片段复制并粘贴到网页上，并在 iPhone 或 iPad 上查看它，您应该会看到一个移动友好的 HTML5“视频”，您可以像这样使其全屏：

![还有更多...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_08_22.jpg)

### Vimeo 提供了更多

Vimeo 还允许您从电子邮件联系人列表中添加朋友，创建“视频”订阅，制作小部件等等。他们现在甚至提供视频学校，以帮助用户了解捕捉、编辑和分享视频的最有效方法。

### 循环回来。

YouTube，世界上最受欢迎的在线视频观看网站，现在也采用基于 iFrame 的嵌入视频的方法。我们可以采用本章开头使用的“Neutraface”视频，使用新的基于 iFrame 的嵌入方法，得到更语义化和友好的结果。它也通过了验证！

```html
<iframe title="YouTube video player" width="1280" height="750" src="img/xHCu28bfxSI?rel=0&amp;hd=1" frameborder="0" allowfullscreen></iframe>

```

看看这有多漂亮！

我们已经完全转变了我们的视频捕捉、编辑和播放能力，以在现代浏览器中运行，同时支持依赖辅助技术和移动设备的用户。这是一个不断发展的过程。

## 另请参阅

Adobe 是否在自掘坟墓？并非如此。2011 年初，Adobe 推出了一个免费的 Flash 转 HTML5 转换器，代号“Wallaby”。不幸的是，许多设计师和开发人员认为 Adobe 在声称 Wallaby 可以使用 Web 标准将 Flash 转换为 HTML5 时过于夸大其词。事实上，它只是将 Flash CS5 或更高版本中创建的最简单的动画转换为简单的标记和样式。它没有能力将 ActionScript 转换为 JavaScript，这种能力才真正使该工具有价值。请查看 John Nack 的博客上关于 Wallaby 发布的公告[`blogs.adobe.com/jnack/2011/03/wallaby-flash-to-html5-conversion-tool-now-available.html`](http://blogs.adobe.com/jnack/2011/03/wallaby-flash-to-html5-conversion-tool-now-available.html)。


# 第九章：数据存储

在本章中，我们将涵盖：

+   测试浏览器是否支持数据存储

+   使用浏览器开发者工具来监视 web 存储

+   设置和获取会话存储变量

+   设置和获取本地存储变量

+   将本地存储字符串转换为数字使用`parseInt`

+   创建一个 web SQL 数据库

+   使用 web SQL 数据库

+   创建一个缓存清单并离线使用站点

+   使用地理位置 API 和`geo.js`显示当前位置

# 介绍

HTML5 引入了一种新的存储信息的方式，而不使用 cookies。这使得设计师和开发人员在处理和显示动态内容时具有更大的灵活性。我们将从测试浏览器是否支持三种主要的数据存储方法开始，最后创建一个使用本地存储来存储和访问视频的 HTML5 页面。虽然这些配方都是基于彼此构建的，但你不必按照它们呈现的顺序完成它们。本章的示例文件可在[`www.packtpub.com/support?nid=7940`](http://www.packtpub.com/support?nid=7940)下载。

# 测试浏览器是否支持数据存储

知道如何快速测试浏览器是否支持你想要使用的数据存储方法将使开发页面和应用程序变得更容易。在这个配方中，我们将创建一个脚本，查询浏览器的 DOM，以测试不同数据存储方法的支持。

## 准备工作

你需要访问一个现代浏览器，如 Firefox 3.6，或者流行浏览器的最新版本，如 Google Chrome，Opera，Safari 或 Internet Explorer。

## 如何做...

首先，我们将创建一个简单的 html 页面。打开一个 HTML 编辑程序或文本编辑器，并输入一个基本的 HTML5 页面的起始代码：

```html
<!doctype html><html lang="en"><head><title>Client-side Storage Test for HTML5</title>
<meta charset="utf-8">

```

现在测试页面的外观需要进行样式设置。我们将在 HTML 页面的`<head>`标签中使用`<style>`标签，但你也可以将它们放在一个单独的 CSS 文件中。

```html
<style>
#results { background-color: #ffcc99; border: 1px #ff6600 solid; color: #ff6600; padding: 5px 20px; margin-bottom: 10px; }
#results .value { font-weight: bold; }
#results h3 { color: #333333; }
</style>

```

输入一个闭合的`head`标签，然后创建一个如下所示的`body`标签。注意，一个很大的区别是我们在页面加载时调用了一个`RunTest()`函数来激活。

```html
</head><body onload="RunTest();">

```

创建一个带有类似下面所示的描述性文本的段落标签。关闭标签，并创建一个包含结果标题的`<h3>`标题标签。

```html
<p>Does your browser support all storage methods?</p>
<div id="results"><h3>Browser Data Storage Support Results</h3>

```

现在，输入每种存储方法，后面跟一个由类值样式化的 span 标签。输入存储方法的 ID 和文本“不支持”。关闭 span 标签，并添加一个换行标签，以便在浏览器窗口中将结果分开显示在单独的行上。结果的显示区域应该如下所示的代码块：

```html
Session Storage: <span class="value" id="session">not supported</span><br/>
Local Storage: <span class="value" id="local">not supported</span> <br />
Database Storage: <span class="value" id="db">not supported</span> <br /></div>

```

我们几乎完成了创建我们的测试页面。创建一个段落来解释测试的目的。用一个`<footer>`标签来包含我们接下来要添加的脚本块。描述性文本应该如下所示的代码：

```html
<p>The test above shows whether the browser you are currently using supports a data storage method.</p> <footer>

```

现在，我们将添加`script`标签，以便浏览器处理一个小的测试程序：

```html
<script language="javascript">
function RunTest() {
for (var mydata in window)
{

```

接下来，我们将创建一个包含每种数据存储方法的代码块的 case 语句，我们将要测试：

```html
switch (mydata) {
case "sessionStorage": document.getElementById("session").innerHTML = "supported";
break;
case "localStorage": document.getElementById("local").innerHTML = "supported";
break;
case "openDatabase": document.getElementById("db").innerHTML = "supported";
break;
} }} </script> </footer> </body> </html>

```

将文件保存为`data-storage-support-test.html`，并在浏览器窗口中打开它。你应该看到类似以下截图的结果：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_09_01.jpg)

## 它是如何工作的...

我们创建的 HTML5 测试页面使用了一小段 JavaScript 代码来查询浏览器是否支持特定的存储方法。我们首先编写了一个标准的 HTML5 页面，包括适当的`<html>`、`<head>`和其他文档标签。如果需要复习它们，可以在本书的早期章节中找到。接下来，我们使用简化的`<script>`标签设置了 JavaScript 代码片段的开头块。HTML5 JavaScript API 在本书的其他地方有更详细的介绍。我们创建了一个名为`RunTest()`的函数来包含变量和代码。然后创建了两个变量。变量 supp 被赋予了一个空字符串的值。这将包含每种存储方法的最终支持结果。我们正在循环遍历 window 对象的属性。在每次迭代中，当前属性暂时存储在`mydata`变量中。这使我们能够测试属性是否符合三种情况。

接下来，我们使用 switch 语句来测试`mydata`变量与我们感兴趣的特定属性。因为我们一次只测试一个值，而且列表很短，这是测试每种存储方法支持的好方法。switch 语句的主体包含三种情况，每种情况都包含一个必须评估的表达式。如果支持存储方法，则每种情况的最终操作是，如果表达式评估为 true，则将文档主体中结果文本的值从“不支持”更改为“支持”。如果情况评估为 false，则页面结果部分显示的文本将保持不变。

创建代码后，我们使用 CSS 样式控制了结果的呈现。使用名为 results 的 div 标签创建了一个显示框的容器，并指定了背景颜色、字体颜色和字体粗细。这是 html 页面头部的最后一块代码。

然后创建了页面的主体部分。测试被设置为在浏览器中加载页面时激活，使用`onload`命令。编写了结果框的开头文本和标题，并将每个结果的显示文本与唯一的 ID 绑定。然后输入了闭合标签以完成页面。保存页面后，在浏览器窗口中查看测试页面时，结果就会显示在屏幕上。截图中使用的浏览器是 Firefox 3.6.13。我们看到的结果反映了 Firefox 在 3.6 和 4.0.3 版本中提供的当前支持。这帮助我们确定，我们可以期望 Firefox 访问者在依赖本地存储和会话存储方法的网页上轻松查看和使用任何功能。他们将无法利用任何依赖于 WebSQL 的功能。

## 还有更多...

测试网站和在线应用程序从未如此简单。有许多可用的工具和服务，可用于在不同平台和各种浏览器上进行测试。

### 移动测试

您可以在智能设备上下载多个浏览器，如 iPod Touch 或 iPad，从而可以测试富媒体内容在移动设备和不同浏览器上的响应性。

### Adobe 浏览器实验室

不需要 Adobe CS5 即可尝试 Adobe BrowserLab，这是一个与 Adobe CS5 产品集成的在线跨浏览器测试工具。访问[`browserlab.adobe.com`](https://browserlab.adobe.com)了解更多信息。

### 使用 BrowserShots 进行免费的跨浏览器和操作系统测试

对于预算有限且有时间的人来说，[BrowserShots.org](http://BrowserShots.org)是一个替代选择。该网站允许访问者输入其网站的 URL，然后从大量的浏览器和操作系统中进行选择。在免费版本的服务中，结果可能需要几分钟才能出现。

# 使用浏览器开发者工具监视 Web 存储

Web 存储可能很具有挑战性。使用浏览器中的开发人员工具，如 Safari 或 Firefox 附加组件，如 Firebug，可以更容易地诊断问题并跟踪变量的值。在本教程中，我们将使用 Google Chrome 浏览器中的本机开发人员工具来探索浏览器本地存储区域中存储的键/值对。

## 准备工作

您需要一个最新版本的 Google Chrome 浏览器和本章的一个本地存储代码文件。

## 如何做...

在 Google Chrome 浏览器窗口中打开本章中的一个本地存储练习文件。

单击**查看**，从**查看**菜单中选择**开发人员**，然后从**开发人员**弹出菜单中选择**开发人员工具**。

当**开发人员**窗口出现在当前页面上时，选择**资源**选项卡，单击 Google Chrome 开发人员工具窗口导航区域中的**本地存储**，然后单击其中的子菜单。您应该看到类似以下截图的结果：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_09_02.jpg)

Google 开发人员工具窗口的资源选项卡下的本地存储部分为我们提供了对每个页面的本地存储区域的访问。它在屏幕右侧显示键和它们对应的值。如果您右键单击一个对象，您将有删除它的选项。

## 它是如何工作的...

我们加载了一个我们知道使用本地存储的页面，以测试 Google Chrome 浏览器中的 Google 开发人员工具窗口如何显示键/值对。

当我们在开发人员工具的左侧菜单中导航时，我们可以选择不同的 Web 存储方法和其他资源。

## 还有更多...

有许多免费的插件和本机浏览器工具，开发人员可以利用。

### 即使您不使用 Firefox，也可以使用 Firebug 附加组件

Firefox 用户长期以来一直在使用 Firebug 附加组件([`getfirebug.com/downloads`](http://getfirebug.com/downloads))来调试和浏览网站和其他在线应用程序。Opera、Google Chrome、Safari 和 IE 6+的用户可以使用 Firebug Lite([`getfirebug.com/firebuglite`](http://getfirebug.com/firebuglite))，并通过轻量级的书签工具体验类似的功能。

### Safari 开发人员工具是 Safari 浏览器的本机工具

打开 Safari 浏览器，单击**Safari**，选择**首选项**，然后单击**高级**选项卡。点击“在菜单栏中显示**开发菜单**”旁边的复选框，开始使用本机开发人员工具。

# 设置和获取会话存储变量

会话存储和本地存储都共享 Web 存储 API。在本教程中，我们将定义两个会话存储变量，然后在屏幕上显示它们。

## 准备工作

您需要一个支持会话存储的最新浏览器。如果您在本地计算机上测试文件，Safari 和 Google Chrome 会有最佳响应。

## 如何做...

首先，我们将创建一个 HTML5 页面的头部区域和一个开放的`body`标签：

```html
<!DOCTYPE HTML><html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8"><title>Show me the session storage</title></head><body>

```

添加一个`section`和一个`article`标签。给文章标签一个 ID 为"aboutyou"。

```html
<section><article id="aboutyou"><p></p></section>

```

接下来，我们将使用`setItem`方法创建两个会话存储变量，如下面的代码块所示：

```html
<footer><script>sessionStorage.setItem('nickname', 'Jumpin Joseph'); sessionStorage.setItem('interest', 'bike ramps and bmx racing');

```

现在我们将使用`getElementByID`和`getItem`方法在屏幕上显示我们刚刚设置的会话存储变量：

```html
document.getElementById('aboutyou').innerHTML = ("Your nickname is: " + sessionStorage.getItem('nickname') + "." + " You are interested in: " + sessionStorage.getItem('interest') + "."); </script></footer></body></html>

```

结果应该在浏览器的 HTML 页面上显示，类似于以下截图中显示的方式：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_09_03.jpg)

## 它是如何工作的...

在这个例子中，我们为两个会话变量设置了唯一的值。会话存储使用键/值对，因此每个变量在创建时必须设置一个值。默认情况下，这些值是字符串。

我们通过输入`sessionStorage.setItem('`为人的昵称定义了一个会话变量，然后为我们的变量添加了一个名称。

我们为变量`"nickname"`命名，并赋予它值"Jumpin Joseph": `'nickname', 'Jumpin Joseph')`;。

当我们创建第二个会话变量来包含名为`"interest"`的变量及其值时，我们使用了与设置第一个会话变量时相同的语法格式。

尽管通常这些变量将由表单中的值填充，但在示例中我们专注于使用正确的语法。`sessionStorage`关键字标识了存储方法的类型。然后我们跟着一个句号，将`setItem`动作附加到关键字上。然后声明了变量`nickname`并赋予了`Jumpin Joseph`的值。当使用时，这将告诉浏览器创建一个名为`nickname`的新会话存储变量，并将`Jumpin Joseph`的值存储在其中。然后我们创建了第二个会话存储变量，只是因为我们可以。在本章的本地存储示例中，我们将使用表单来获取变量值，以完整地展示存储方法的创建、使用和销毁的生命周期视图。

## 还有更多...

会话存储为我们提供了一种更强大的方式来提供短期客户端存储。

### 一个浏览器，一个会话

会话存储最适用于不需要访问者使用多个浏览器标签来浏览网站的情况，以及存储是临时的情况。虽然 HTML5 规范的数据存储区域仍在不断发展，安全性在金融机构或其他需要高度安全信息的网站中并没有长期的使用记录，但仍然有许多有用的方法可以利用会话存储。

## 另请参阅

*设置和获取本地存储变量的教程*。

# 设置和获取本地存储变量

尽管会话存储是临时的，只在浏览器会话处于活动状态时持续。本地存储甚至在关闭浏览器后仍然存在。在这个教程中，我们将使用 HTML5 的`contenteditable`属性和本地存储来创建一个写故事的应用程序。

## 准备工作

您应该使用最近更新的浏览器。这个教程在 Google Chrome 和 Safari 中效果最好，但在 Firefox 中也可以正常使用。

## 如何做...

首先创建一个基本的 HTML5 页面，然后在打开和关闭`head`标签之间添加一个脚本标记。脚本应链接到[`ajax.googleapis.com/ajax/libs/jquery/1.5.2/jquery.min.js`](http://ajax.googleapis.com/ajax/libs/jquery/1.5.2/jquery.min.js)上的 1.5.2 最小化的 jQuery 库。您的代码现在应该类似于以下代码块：

```html
<!DOCTYPE html><html lang="en"><head><script src="img/ jquery.min.js"></script> <meta http-equiv="Content-Type" content="text/html; charset=utf-8"> <title>Local Storage: Storywriter</title>

```

接下来，我们将添加 CSS 样式来设置文章标记的`background-color`和文本`color`，以及`font-family`。

```html
<style> article{background-color: #9F6;color:#333; font-family:Verdana, Geneva, sans-serif} p{} </style>

```

关闭`head`标记并为`body`和`header`元素创建开放标记。添加一个`h1`标记来显示页面标题为`Storywriter`，然后关闭`header`标记。

```html
</head><body> <header> <h1>Storywriter</h1> </header>

```

为`section`和`article`元素创建开放标记。将`article`元素的 id 设置为“mypage”，并将`contenteditable`属性设置为“true”。

```html
<section><article id="mypage" contenteditable="true">

```

接下来，创建一个包含占位文本`type something`的段落标记，然后关闭段落、`article`和`section`标记。在两个`em`标记之间添加描述性的指令文本。您刚刚输入的内容应该看起来像以下代码：

```html
<p>type something</p> </article> </section><em>And then what happened? I'll remember next time you open this browser. </em>

```

创建一个`script`标记，然后键入`$(function(){`声明 jQuery 函数。

使用参数字符串“mypage”调用`document.getElementById`方法，并将其分配给变量'edit'。

接下来，我们需要添加一个事件处理程序，该处理程序由“edit”元素上的模糊事件触发。键入`$(edit).blur(function(){`，然后键入`localStorage.setItem('storyData", this.innerHTML);})`; 完成函数。

现在本地存储可以使用`setItem`存储字符串，我们可以使用`getItem`将存储的字符串内容推送回页面，方法是键入`if ( localStorage.getItem('storyData') ) { edit.innerHTML = localStorage.getItem('storyData'); } })`;

脚本代码块现在应该看起来像以下代码块：

```html
<script>$(function() { var edit = document.getElementById('mypage'); $(edit).blur(function() { localStorage.setItem('storyData', this.innerHTML); }); if ( localStorage.getItem('storyData') ) { edit.innerHTML = localStorage.getItem('storyData'); } });</script>

```

关闭 body 和 HTML 标签，并保存文件。在浏览器窗口中打开它。现在，您应该能够开始输入自己的故事，并在页面上看到输入的文本，即使您关闭浏览器并稍后重新打开它。它应该类似于以下截图：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_09_04.jpg)

## 工作原理...

当我们将`article`标签的`contenteditable`属性设置为`true`时，我们告诉浏览器允许用户输入文本。大多数 HTML5 元素都可以声明`contenteditable`属性，然后将其设置为`true`或`false`。然后，我们使用`document.getElementById`捕获输入的内容，使用 id`mypage`。`getElementById` jQuery 方法搜索文档，查找其参数中列出的特定 ID 名称。然后，我们在`blur`事件上添加了一个事件处理程序，以平滑地显示输入的文本。我们同时使用本地存储方法`setItem`和变量`storyData`存储文本。最后，我们使用`getItem`本地存储方法检查`storyData`是否存在，如果存在，则将其加载到可编辑的 HTML 元素中，使用`edit.innerHTML`和`getItem`。

## 另请参阅

本书中关于 HTML5 元素和 PACKT jQuery 书籍的早期章节。

# 使用 parseInt 将本地存储字符串转换为数字

在这个示例中，我们将从本地存储中获取一个字符串值，并将其转换为整数，以便我们可以使用`parseInt`对其进行数学运算。

## 准备工作

我们将使用 Modernizr（[`www.modernizr.com`](http://www.modernizr.com)）来检测本地存储是否可用，将其托管在名为"js"的子文件夹中。您还需要至少一个最近更新的浏览器。

## 如何做...

创建一个新的 html 页面，直到标题标签，如下面的代码块所示：

```html
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"> <title>Using numbers with local storage</title>

```

接下来，添加样式以指定`h1`和`h2`标签的字体族、文本颜色，以及`h2`标签的背景颜色和高度。

```html
<style>body{font-family:Verdana, Geneva, sans-serif;} h1{color:#333; }h2{color:#C30;background-color:#6CF; height:30px;}</style>

```

添加一个由 Google 托管的 IE HTML5 shiv，以及一个链接到本地 Modernizr JavaScript 文件：

```html
<!--[if IE]><script src="img/html5.js"></script> <![endif]--><script type="text/javascript" src="img/ modernizr-1.7.min.js"></script>

```

通过 Modernizr 脚本的帮助，执行检查以查看浏览器是否支持本地存储：

```html
<script>if (Modernizr.localstorage) {
// window.localStorage is available!}
else {// the browser has no native support for HTML5 storage document.getElementByID('yayanswer').innerHTML = "Local Storage is not supported by your browser. Maybe it's time for an update?";}

```

创建一个名为`storemyradius()`的函数，声明一个名为`myradiusToSave`的变量，并将其赋值为`document.getElementById('myradius').value`；当访问者点击保存时，将值传递到文本字段中。

```html
function storemyradius() {var myradiusToSave = document.getElementById('myradius').value;

```

添加一个`if`语句，检查`myradiusToSave`是否为 null。在此之下，创建一个本地存储`setItem`方法，键为"myradius"，值为"myradiusToSave"。在`if`语句和`storemyradius`函数的闭合括号之前，放置一个对`displaymyradius()`的函数调用，如下面的代码块所示：

```html
if (myradiusToSave != null) { localStorage.setItem('myradius', myradiusToSave);displaymyradius();}}

```

创建一个名为`displaymyradius`的函数，不接受任何参数，然后添加一个名为`myradius`的变量。将 JavaScript 函数`parseInt`赋值给它，其中包含一个本地存储`getItem`方法，参数为"myradius"，基数为 10。到目前为止，函数应该看起来像以下代码块：

```html
function displaymyradius() { var myradius = parseInt(localStorage.getItem('myradius'),10);

```

在同一个函数中，创建一个 if 语句，检查`myradius`变量是否不为 null 且大于零。创建变量`diameter`，并将其值赋为`2`乘以`myradius`的结果。使用`document.getElementById`和`innerHTML`来显示直径变量的值，以及在 HTML 页面的`h2`标签之间显示消息"The `diameter of the circle is"`。

```html
if (myradius != null && myradius > 0) {var diameter = 2 * myradius;document.getElementById('yayanswer').innerHTML = "The diameter of the circle is: " + diameter + "!";}}

```

创建一个名为`clearmyradius`的函数，不接受任何参数，然后创建一个`if`语句，检查本地存储`getItem`方法是否包含一个不为 null 的值。在`if`语句的括号之间，放置本地存储`removeItem`方法，参数为"myradius"，并调用本地存储`clear`方法。关闭脚本和头标签。我们刚刚编写的代码应该类似于以下代码块：

```html
function clearmyradius() {if (localStorage.getItem('myradius') != null) {localStorage.removeItem('myradius'); window.localStorage.clear();}}</script></head>

```

创建开头的 body、section、`hgroup`和`h1`标签，并在闭合的`h1`标签前输入`"localStorage Number Conversion"`。创建一个`h2`标签，并给它一个 ID 为`"yayanswer"`。关闭`hgroup`标签，然后为`myradius`文本字段添加一个标签标签。将`"Enter the radius of the circle:"`作为标签文本。创建一个带有 ID 为`"myradius"`和`maxlength`为`"4"`的输入表单字段标签。创建两个输入按钮，一个带有`onclick`值调用函数`storemyradius()`；另一个带有`onclick`值调用函数`clearmyradius();`。关闭 section、body 和 html 标签，并保存页面。最终的代码块应该如下所示：

```html
<body ><section><hgroup><h1>localStorage Number Conversion</h1> <h2 id="yayanswer"></h2></hgroup><label for="myradius">Enter the radius of the circle:</label><input id="myradius" maxlength="4" /> <input onclick="storemyradius();" name="save" type="button" value="save"><input onclick="clearmyradius();" name="clear" type="button" value="clear"></section></body></html>

```

在 Google Chrome 浏览器窗口中，完成的 HTML 页面应该如下所示：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_09_05.jpg)

## 它是如何工作的...

HTML 页面中显示的文本字段接受访问者输入并将其作为值传递给`storemyradius()`函数。我们声明了一个名为`myradiusToSave`的变量，并将其赋值为`document.getElementById('myradius').value`；它存储了`myradius`中包含的值。然后它将文本字段"myradius"中输入的值传递给本地存储的`setItem`方法。在将值传递给本地存储之前，我们需要验证`myradiusToSave`实际包含一个不为空的值。如果不为空，那么就有数据可以保存到本地存储中。然后，使用`setItem`将该值保存到本地存储中，作为键/值对的一部分。为了将`myradius`值作为数字使用，我们需要将其从字符串转换回整数。这是通过调用`parseInt` JavaScript 函数来完成的。接下来，我们创建了一个名为`diameter`的变量，用于保存我们的直径公式的结果，即半径值乘以 2。最后，我们使用`getElementbyId`方法将结果返回到屏幕上。

页面上的另一个选项是清除本地存储变量的值。虽然我们可以使用`removeItem`方法，但同时使用 clear 方法也可以确保没有其他本地存储变量潜伏。打开 Google 开发者工具刷新页面，验证本地存储区域为空。

## 还有更多...

目前，默认情况下，`localStorage`将所有数据存储为字符串。我们刚刚练习了将`localStorage`变量转换为整数，但它们也可以转换为数组等对象。

### 在 localStorage 中存储和检索数组

在许多情况下，您会希望使用`localStorage`与数组一起保存游戏中的进度或保留用户数据或消息。您可以使用 Douglas Crockford 的 JSON 库来简化数组的存储和检索。访问[`github.com/douglascrockford/JSON-js`](http://https://github.com/douglascrockford/JSON-js)下载代码并了解更多关于 JSON 的信息。

创建一个新的 HTML5 页面，在两个页脚标签之间添加脚本标签。声明一个名为"horsedef"的新变量数组，并将以下键/值对分配给它，如下所示：

```html
var horsedef = {"species":"equine","legs":4,"ears":2, "purposes":{"front":"neigh","behind":"flick"}};

```

现在，在本地存储中设置一个名为"describehorse"的新项目，同时使用`JSON`将我们的数组`horsedef`转换为字符串，如下所示：

```html
window.localStorage.setItem('describehorse', JSON.stringify(horsedef));

```

使用 JSON 解析从本地存储中检索值：

```html
console.log( alert('A horse is a horse of course! ' + JSON.parse (localStorage.getItem('describehorse')) ); // => Object { species="equine", more...} </script>

```

保存页面，并打开浏览器窗口。您应该看到一个警报框，显示了传递给`describehorse`的`horsedef`数组中的键/值对，如下面的屏幕截图所示：

![在 localStorage 中存储和检索数组](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_09_06.jpg)

### 提示

在使用 JSON 时要注意跨站点回调。通常最好从自己的服务器下载并使用文件。始终直接从源下载您的 JSON 副本。不要上当受骗，比如 JSONP。

# 创建 Web SQL 数据库

在这个示例中，我们将创建一个 Web SQL 数据库，并为其定义版本、名称、大小和描述等属性。

## 准备工作

您需要使用支持 Web SQL 数据库的当前浏览器。

## 如何做...

创建一个新的 HTML5 文件，在两个页脚标签之间放置开头和结尾的脚本标签。声明一个名为`db`的变量，然后将`openDatabase()`赋给它。给`openDatabase`传递以下参数：`'mymotodb', '1.0', 'Motocross Rider List DB', 2 * 1024 * 1024`，然后关闭声明。代码应该如下所示：

```html
<script>var db = openDatabase('mymotodb', '1.0', 'Motocross Rider List DB', 2 * 1024 * 1024);</script>

```

保存文件。

## 它是如何工作的...

所有 Web SQL 数据库都使用`openDatabase`方法来为数据库分配值。第一个参数“mymotodb”是数据库的名称。接下来是必需的版本号参数。这里的数字必须与用户尝试使用 Web SQL 数据库时匹配。接下来，我们定义了数据库的描述，然后是估计的大小。一旦为请求的`openDatabase`方法定义了所有参数，数据库就被创建，并且第一个（不可见的）事务发生了——数据库本身的创建。

## 更多信息...

浏览器对规范的实现，如 Web SQL 数据库，一直非常不可预测，同样在 Web 开发社区内对这些规范本身的支持也是如此。

### Web SQL 可能会被 SQLite 替代

Web SQL 数据库规范本身已不再由 W3C 维护，但在大多数浏览器中它仍然运行得相当好。在未来一年左右的时间内，足够多的主要利益相关者可能会就如何实现不同的客户端数据库解决方案达成一致，比如 SQLite，但这样的事情很难预测。请关注[`www.w3.org/TR/webdatabase/`](http://www.w3.org/TR/webdatabase/)上的规范，以获取有关使用客户端数据库的当前选项的更新。

# 使用 Web SQL 数据库

在这个示例中，我们将使用前一个示例中创建的数据库，并向其中添加表和数据，然后在 HTML 页面上显示结果。

## 准备工作

您需要一个当前的浏览器和一个带有基本标签的 HTML5 页面，用于头部区域和正文区域。

## 如何做...

在一个基本的 HTML5 页面上，添加一个`h1`标签来显示页面标题，然后创建一个 ID 为“status”的`div`标签来保存我们的结果，如下面的代码块所示：

```html
<!DOCTYPE HTML><html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8"><title>Using WEB SQL Databases</title></head><body><article><section><header><h1>Today's Riders</h1></header><div id="status" name="status"></div> </section></article><footer>

```

开始脚本，如前一个示例所示，以创建数据库（如果尚未创建）。创建一个名为 info 的新变量，然后创建一个包含接受参数的函数的新事务。使用传递的参数，创建一个名为 RIDERS 的表，其中包含唯一 ID 和名为`ridername`的行。代码应该类似于以下代码块：

```html
var info;db.transaction(function (tx) { tx.executeSql('CREATE TABLE IF NOT EXISTS RIDERS (id unique, ridername)');

```

将数据添加到表行中，使用唯一 ID 和每个名称的文本字符串：

```html
tx.executeSql('INSERT INTO RIDERS (id, ridername) VALUES (1, "Joe Fly")'); tx.executeSql('INSERT INTO RIDERS (id, ridername) VALUES (2, "Gira Ettolofal")'); });

```

执行查询以从数据库中提取数据：

```html
db.transaction(function (tx) { tx.executeSql('SELECT * FROM RIDERS', [], function (tx, results) {

```

创建一个新变量和`for`循环来循环遍历结果并将其打印到屏幕上：

```html
var len = results.rows.length, i; for (i = 0; i < len; i++){ info = "<p><b>" + results.rows.item(i).ridername + "</b></p>"; document.querySelector('#status').innerHTML += info; } }, null);});

```

关闭脚本和 HTML 页面。

```html
</script></footer></body></html>

```

## 它是如何工作的...

当我们在浏览器中打开我们刚创建的页面时，我们将看到我们使用数据库来显示的信息。这是因为查询和循环一起工作，通过数据库并显示适当的信息。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_09_07.jpg)

## 更多信息...

HTML5 中的安全性和数据库事务可能执行不佳。在生产环境中，应该注意保护接受 SQL 查询的任何页面。

### 将脚本代码保存在单独的文件中

为了使这个示例保持简单，我们没有将 SQL 查询代码和 JavaScript 存储在单独的文件中。这可以通过将代码保存在子文件夹中来实现，例如`../js/myCode.js`。注意使用 Web SQL、Indexed DB 或任何其他类型的基于浏览器的查询 API 来获取安全信息。

### 在生产服务器上防止 SQL 注入

每当有可编辑字段时，都有可能会有一些机器人来尝试进行 SQL 注入攻击。可以通过在事务请求中使用“?”来采取基本预防措施。以下代码显示了一个例子。

```html
store.db.transaction(function(tx) { tx.executeSql( "insert into bmxtricks " + "(time, latitude, longitude, trick) values (?,?,?,?);", [bmxtricks.time, bmxtricks.latitude, bmxtricks.longitude, bmxtricks.trick], handler, store.onError );});

```

## 另请参阅

SQL 的 Packt 图书，任何覆盖客户端数据库的 Packt HTML5 图书。

# 为离线存储创建缓存清单

在这个配方中，我们将创建一个缓存清单文件，以便我们可以离线存储一个 HTML5 页面，并仍然查看页面上显示的图像和视频。

## 准备工作

您将需要一个 HTML5 页面，比如本配方的代码文件中提供的页面，并且可以上传文件到服务器，然后在计算机、智能手机或其他具有浏览器的网络设备上查看这些文件。

## 如何做...

首先，我们将创建缓存清单文件。这应该在一个简单的文本编辑器中创建。它应该包含用户在离线状态下访问所需的所有文件和支持代码。首先列出的是当前文件类型（CACHE MANIFEST）。清单的版本号也应包括在内。请注意，我们在以下代码块中添加了所有要让用户访问的文件的路径：

```html
CACHE MANIFEST
# version 0.1
itsallgooed.html
css/Brian Kent Font License.txt
css/exact-css-from-tutorial.css
css/font-stylesheet.css
css/plasdrip-webfont.eot
css/plasdrip-webfont.svg
css/plasdrip-webfont.ttf
css/plasdrip-webfont.woff
css/plasdrpe-webfont.eot
css/plasdrpe-webfont.svg
css/plasdrpe-webfont.ttf
css/plasdrpe-webfont.woff
css/style.css
images/gooed-science-logo.jpg
images/promo-bg.jpg
images/gakposter.png
movie/GakHowTo.mp4
movie/GakHowTo.ogv
movie/GakHowTo.webm

```

在`index.html`页面的`DOCTYPE`标签和`head`标签之间添加一个 manifest 属性，如下所示：

```html
<!DOCTYPE html> <html lang="en" manifest="gooed.manifest"> <head>

```

最后，创建一个`.htaccess`文件来创建正确的 mime 类型：

```html
AddType text/cache-manifest .manifest

```

页面应该显示类似于以下内容：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_09_08.jpg)

## 它是如何工作的...

创建缓存清单为浏览器提供了一个在离线加载页面时使用的清单。虽然离线存储页面的想法是它不需要频繁更新，但使用版本号允许作者在用户下次连接到互联网时推送更新。

并非所有浏览器或系统都能正确解释清单文件类型，因此包含一个`.htaccess`文件可以确保正确识别缓存清单。

您可以排除您认为不重要的文件，以降低离线页面的大小并减少加载时间。

# 使用地理位置和 geo.js 显示当前位置

在这个配方中，我们将使用地理位置规范和`geo.js`来显示活跃用户的当前位置在地图上，并显示他们当前的纬度和经度。

## 准备工作

访问[`code.google.com/p/geo-location-javascript/`](http://code.google.com/p/geo-location-javascript/)下载最新版本的`geo.js`，或者直接从 wiki (http://code.google.com/p/geo-location-javascript/wiki/JavaScriptAPI)获取链接 URL 在线链接到它。

## 如何做...

首先，我们将创建 HTML5 开头页面标签：<head></head>。

然后，在 meta 标签中，我们将把 name 属性设置为"viewport"，并为 content 属性定义以下值：`width = device-width; initial-scale=1.0; maximum-scale=1.0; user-scalable=no`;

现在，声明一个带有 src 属性的脚本标签：[`code.google.com/apis/gears/gears_init.js`](http://code.google.com/apis/gears/gears_init.js)

然后，调用`geo.js`脚本：`src="img/geo.js"`。

到目前为止，代码块应该如下所示：

```html
<html><head><meta name = "viewport" content = "width = device-width; initial-scale=1.0; maximum-scale=1.0; user-scalable=no;"> <script src="img/gears_init.js" type="text/javascript" charset="utf-8"></script><script src="img/geo.js" type="text/javascript" charset="utf-8"></script>

```

为 Google Maps API 添加一个脚本标签：`<script type="text/javascript" src="img/js?sensor=false"></script>`。

现在，我们将创建一个初始化地图的函数`initialize_map()`，然后创建一个名为`myOptions`的数组来存储地图属性。这些属性基于 Google Maps API。它们应该看起来类似于以下代码块：

```html
<script>function initialize_map(){ var myOptions = { zoom: 4, mapTypeControl: true, mapTypeControlOptions: {style: google.maps.MapTypeControlStyle.DROPDOWN_MENU}, navigationControl: true, navigationControlOptions: {style: google.maps.NavigationControlStyle.SMALL}, mapTypeId: google.maps.MapTypeId.ROADMAP }

```

使用`google.maps.Map()`方法向页面添加一个名为 map 的新地图，该方法以`document.getElementById`元素作为参数，而`document.getElementById`又传递了 id 为"map_canvas"。`google.maps.Map`接受的另一个方法是`myOptions`。

```html
map = new google.maps.Map(document.getElementById("map_canvas"), myOptions);}

```

创建`initialize()`函数，并添加一个`if`语句来检查`geo_position_js.init()`函数是否处于活动状态。使用`document.getElementById`和`innerHTML`为 id 为"current"的 div 输入一个新的状态。状态文本为"Receiving…"。

```html
function initialize(){ if(geo_position_js.init()){ document.getElementById('current').innerHTML="Receiving...";

```

如果我们无法获取位置或者由于某种原因浏览器不支持获取当前位置，可以在 helper 消息文本中添加文本以显示，如下所示的代码块：

```html
geo_position_js.getCurrentPosition(show_position,function(){document. getElementById('current').innerHTML="Couldn't get location"}, {enableHighAccuracy:true}); } else{document.getElementById('current').innerHTML="Functionality not available"; }}
function show_position(p){ document.getElementById('current').innerHTML= "latitude="+p.coords.latitude.toFixed(2)+" longitude="+p.coords.longitude.toFixed(2); var pos=new google.maps.LatLng( p.coords.latitude,p.coords.longitude); map.setCenter(pos); map.setZoom(14);

```

创建一个名为`infowindow`的新变量来显示`google.maps InfoWindow`，这是一个在单击标记时显示的气泡。给它一个文本字符串“yes”来显示。创建一个新的与用户当前位置相关联的标记，以及标记的标题文本，该文本将在鼠标悬停时显示。添加一个事件侦听器来检测标记何时被点击。

```html
var infowindow = new google.maps.InfoWindow({ content: "<strong>yes</strong>"}); var marker = new google.maps.Marker({ position: pos, map: map, title:"Here I am!" }); google.maps.event.addListener(marker, 'click', function() { infowindow.open(map,marker);});}</script >

```

样式页面以控制字体系列，填充以及标题和当前 div 的外观。

```html
<style>body {font-family: Helvetica;font-size:11pt; padding:0px;margin:0px} #title {background-color:#0C3;padding:5px;} #current {font-size:10pt;padding:5px;}</style></head>

```

在 body 标签中创建一个`onLoad`命令，初始化`initialize_map()`和`initialize()`函数以在页面加载时运行。创建一个新的`div`来显示页面标题，以及一个 id 为“current”的第二个`div`来显示位置获取过程的当前状态。最后，创建一个 id 为`map_canvas`的`div`来包含地图一旦显示，并使用内联样式设置`div`的宽度和高度。关闭标签并保存页面。

```html
<body onLoad="initialize_map();initialize()"><div id="title">Where am I now?</div> <div id="current">Initializing...</div> <div id="map_canvas" style="width:320px; height:350px"></div></body></html>

```

在浏览器窗口中打开页面，您应该看到类似以下截图的结果：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mtmd-dev-cb/img/1048_09_09.jpg)

## 它是如何工作的...

使用`geo.js`简化了在多个设备上使用地理位置信息。它提供了准备好的错误消息，并遵循 W3C 的实现标准，以及“回退”到诸如 Google Gears 之类的工具的能力。首先，我们需要创建一个包含地图显示和处理选项数组的变量脚本，实例化一个新的地图对象，并绘制一个标记以将用户的当前位置固定到屏幕上。悬停在标记上会显示一个带有标题文本的气泡窗口。这个文本也可以包含一个链接，用于获取并显示驾驶方向、评论或笔记。当页面加载时，地图选项创建函数`map_initialize()`和主要的触发函数`initialize()`被调用。在使用`geo.js`的帮助下确定用户的当前位置并绘制地图时，会显示一个临时状态消息。
