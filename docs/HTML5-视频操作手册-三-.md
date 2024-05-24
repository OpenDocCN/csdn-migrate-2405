# HTML5 视频操作手册（三）

> 原文：[`zh.annas-archive.org/md5/E8CC40620B67F5E68B6D72199B86F6A9`](https://zh.annas-archive.org/md5/E8CC40620B67F5E68B6D72199B86F6A9)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：使用 JavaScript 进行交互

在本章中，我们将涵盖：

+   使用 JavaScript 播放音频文件

+   使用拖放 API 与文本

+   使用`vid.ly`和 jQuery 实现跨浏览器视频支持

+   使用 jQuery 动态显示视频

+   使用 jQuery 创建可移动的视频广告

+   使用`Easel.js`和`canvas`标签控制图像的显示

+   使用`Easel.js`和`canvas`标签来制作图像序列的动画

+   使用`canvas`标签和 JavaScript 进行随机动画播放音频

# 介绍

虽然 HTML5 可能会结束对 Flash 的使用，但它使 JavaScript 比以前更受欢迎。有许多库和插件可用于增强和扩展 HTML5 和 CSS3，以创建丰富的交互体验。

本章包含了一些示例，展示了 JavaScript 如何与 HTML5 标签一起使用，例如音频、视频和画布，以及 CSS3 选择器和元素。

# 使用 JavaScript 播放音频文件

HTML5 在互联网上使用音频文件方面引入了更多的灵活性。在这个示例中，我们将创建一个游戏来练习使用音频标签和 JavaScript 加载和播放声音。

## 准备工作

您需要一个音频文件来播放，一张图片和一个支持 HTML5 的现代浏览器。本章的示例文件可以从[`www.packtpub.com/support?nid=7940`](http://www.packtpub.com/support?nid=7940)下载。Free Sound Project ([`freesound.org`](http://freesound.org))有您可以使用的音频文件，只要给予制作人信用，照片可以在[`www.Morguefile.com`](http://www.Morguefile.com)找到，用于您的个人项目。

## 如何做...

现在我们准备创建一系列按钮和一个简短的 JavaScript 程序，当其中一个按钮被按下时，将播放一个随机的音频文件。

打开您的 HTML 编辑器并创建一个 HTML5 页面的开头部分。

```html
<!DOCTYPE html><html lang="en"><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"> <title>Playing a sound file with JavaScript</title>

```

因为我们只有几种样式，所以我们将它们添加到 HTML 页面的头部区域。

```html
<style>h1{font-family:"Comic Sans MS", cursive; font-size:large; font-weight:bold;}
button{ padding:5px;margin:5px;}
button.crosshair { cursor: crosshair; }
button.crosshairthree {margin-left:40px;
cursor:crosshair;} </style>

```

脚本需要创建三个变量。开头的脚本标签和变量应该看起来像以下代码块：

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

现在我们已经为脚本创建了全局变量，我们可以创建函数。键入`function whackmole(){`开始函数，然后在新行上键入`var i = Math.floor(Math.random() * 5)`;使用 JavaScript 数学库生成一个相对随机的数字。接下来，键入`soundChoice = mySounds[i]`;将数组值分配给`soundChoice`。使用`soundElements[soundChoice].play();}`关闭函数。您的函数代码目前应该看起来像以下内容：

```html
function whackmole() {
var i = Math.floor(Math.random() *5);
soundChoice = mySounds[i];
soundElements[soundChoice].play();}

```

键入`function init(){`开始函数。在新行上，键入`soundElements = document.getElementsByTagName("audio");} </script>`来完成我们的 JavaScript 代码块。它应该看起来像以下代码块：

```html
function init(){
soundElements = document.getElementsByTagName("audio");}
</script>

```

关闭头标签并键入 body 标签，添加一个`init()`函数调用，使其看起来像：

```html
</head><body onLoad="init();">

```

使用`<header>`标签为页面的页眉区域创建一个标题区域。使用标题标签`<h1>`显示页面的标题：

```html
<header><h1>Whack A Mole!</h1></header>

```

有五个按钮来创建一个平衡的外观，它们都被分配了一个类。

```html
<section> <p> <button class="crosshair" onclick="whackmole();"> <img src="img/downmole.png" width="37" height="24" alt="Mole peeping out of hole"></button>
<button class="crosshair" onclick="whackmole();"> <img src="img/downmole.png" width="37" height="24" alt="Mole peeping out of hole"></button></p>

```

第三个按钮的类名为`crosshairthree`，以便更好地控制其在屏幕上的位置。

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

用关闭标签完成页面：

```html
</section></body></html>

```

将文件保存为`playing-audio-files-with-javascript.html`并在浏览器中查看。它应该看起来类似于以下屏幕截图：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_07_01.jpg)

## 它是如何工作的...

首先，我们创建了一个基本的 HTML5 页面的开头。然后，我们添加了 CSS 样式，为按钮添加背景图像，并在鼠标或指针设备移动到按钮上时将鼠标图标更改为十字准线。这给了我们一个视觉上的模拟目标武器，比默认的鼠标图标更有趣。

创建了三个变量供脚本使用：`mySounds, soundElements`和`soundch`。我们创建的第一个函数名为`whackmole()`包含一个内部变量`i`，它保存了一个随机生成的数字的结果。`Math.random()`导致生成一个伪随机数。然后我们将其乘以`5`，我们的音频文件数量，并使用`Math.floor()`的结果创建一个值范围从零到五的整数。然后将该值分配给临时变量`i`，然后用于使用随机生成的数组值填充变量`mySounds`。这个新的数组值存储在变量`soundChoice`中，`soundChoice = mySounds[i]`。这使我们能够在按下按钮时使用`soundElements[soundChoice].play()`触发`audio`标签的`play()`动作。

我们创建的第二个函数是`init()`，稍后我们将其与`body`标签绑定，使用`onLoad`，这样我们就可以使用`audio`标签及其数组值，通过`getElementsByTagName`获取音频文件，如`soundElements`变量中所包含的。

接下来，我们添加了`<body onLoad="init();">`标签，以及一系列包含我们可爱的鼹鼠图像的按钮到页面上。每个按钮都包含一个`onClick()`事件，调用了`whackmole()`函数。我们的第三个按钮与其他按钮的类不同，`crosshairthree`，它在按钮左侧添加了额外的边距，使其看起来更加居中。

### 注意

火狐目前有一个怪癖，如果你不先列出`.ogg`音频源，它就找不到。

最后，我们使用`<audio>`和`<source>`标签将声音文件添加到页面。使用源标签列出了每个文件的`ogg`和`mp3`格式。因为源标签被认为是其所包围的父音频标签的“子”标签，所以根据使用的浏览器，任何文件格式都会播放，因为不同的浏览器目前更喜欢不同的声音文件格式。

## 还有更多...

您可以看到，通过为不同的图像播放不同的声音文件，非常容易创建一个儿童的形状或动物朗读页面等应用程序。

### 使用 jQuery 控制音频剪辑的外观

jQuery 中的`.animate`函数打开了新的方式，当访问者采取行动或作为丰富媒体体验的一部分时，可以使音频控件出现、淡出和消失。以下是一个示例，演示了如何使音频控件淡出，然后迅速重新出现：

```html
<script> $(document).ready(function(){
$('audio').delay(500).hide('fade', {}, 1000 ).slideDown('fast'); }); </script>
<!- - the HTML -- ><audio id ="boing" autobuffer> <source src="img/cartoonboing.ogg" /> <source src="img/cartoonboing.mp3" /></audio>

```

我们将在本章的一个示例中使用视频文件执行类似的技巧。

## 另请参阅

第八章，“拥抱音频和视频”将涵盖更多关于音频标签及其使用方式的信息。

# 使用文本的拖放 API

虽然所有浏览器都可以原生地拖放图像或链接，但放置对象以前需要复杂的 JavaScript 或第三方库。拖放 API 旨在提供一种更简单、标准化的方式，使用户能够将任何类型的对象拖放到标识区域中。实际上，在各种浏览器中使用该 API 是一项挑战。目前主要支持此 API 的浏览器是 Firefox、Chrome 和 Safari。

## 准备工作

在[`www.packtpub.com/support?nid=7940`](http://www.packtpub.com/support?nid=7940)下载本教程的代码。本教程标题中使用的字体来自[`www.fontsquirrel.com`](http://www.fontsquirrel.com)，您也可以在该网站下载其他字体。本教程可能无法在 Internet Explorer 中使用。我们将创建一个井字棋游戏，演示拖放 API 的工作原理。

## 如何做...

打开您的 HTML 编辑器，首先创建一个基本的 HTML5 页面。我们将添加两个样式表链接，一个用于支持我们将加载到页面标题的`@fontface`字体，另一个是我们的主样式表。输入如下所示的代码，然后将文件保存为`using-drag-drop-api.html`。

```html
<!DOCTYPE html><html lang="en"> <head> <meta charset="utf-8"> <title>Using the drag-and-drop API element</title> <link rel="stylesheet" href="fonts/specimen_files/specimen_stylesheet.css" type="text/css" charset="utf-8" /> <link rel="stylesheet" href="stylesheet.css" type="text/css" charset="utf-8" />

```

让我们继续对页面进行样式设置。创建或打开名为`stylesheet.css`的 CSS 文件。将页面的整体`margin`设置为`100px`，默认颜色设置为`#666`。

```html
@charset "UTF-8";/* CSS Document */body { margin:100px; color:#666; }

```

页面的内容标签应该都设置为`display:block`，如下所示的代码：

```html
article, aside, figure, footer, header, hgroup, menu, nav, section { display:block; }

```

现在，我们要指定`@fontface`信息。代码和字体文件来自`www.fontsquirrel.com`字体包，已包含在本教程的代码文件中。

```html
@font-face { /* This declaration targets Internet Explorer */ font- family: '3DumbRegular';src: url('3dumb-webfont.eot');}@font-face {/* This declaration targets everything else */font-family: '3DumbRegular';src: url(//:) format('no404'), url('fonts/3dumb- webfont.woff') format('woff'), url('fonts/3dumb-webfont.ttf') format('truetype'), url('fonts/3dumb-webfont.svg#webfontlNpyKhxD') format('svg');font-weight: normal;font-style: normal;}

```

为`h1`标签添加颜色，并将`font-family`属性设置为`3DumbRegular`，这是我们字体的名称。

```html
h1{color:#C60;font-family: '3DumbRegular';}

```

创建一个名为`gametilebox`的新 div，用于容纳组成游戏瓷砖的字母。将盒子的`float`属性设置为`left`，宽度和高度设置为`280px`。根据以下代码片段设置`padding, margin-right, border`和`background-color`。

```html
#gametilebox{ float:left;width:280px; height:280px; padding:10px; margin-right:30px; border:1px solid #000; background-color:#ccc; }

```

游戏板将共享许多与瓷砖框相同的属性，因此复制`gametilebox`的样式，然后粘贴并命名为"gameboard"。添加一个`background-image`属性，url 为`images/tictactoegrid.jpg`，并将`background-color`设置为`aa`。

`gameboard div`应该如下所示代码：

```html
#gameboard { float:left; width:280px; height:280px; padding:10px; margin-right:30px;border:1px solid #000; background-image:url(images/tictactoegrid.jpg); background-color:#aaa;}

```

让我们对`div`块进行样式设置，用于放置我们的字母。所有`block` div 的`float`应设置为`left`。`width`不应大于`85px`，`height`不应大于`80px`。它们将位于 3x3 的网格上，因此第二行和第三行的第一个块也需要具有`clear:both`属性。第二行和第三行的第三个块应该具有较低或没有`padding`和`margin-right`属性。因为有九个，所以这里只显示了一个块代码的示例：

```html
#blockA {float:left; width:75px; height:75px; padding:5px 5px 5px 2px; margin-right:10px; border:none; background-color:red;}
#blockB {float:left; width:75px; height:75px; padding:5px; margin-right:10px; border:none; background-color:blue;}

```

现在，我们将为字母游戏瓷砖设置样式。在样式表中创建一个名为`lettertile`的新类，然后按照这里显示的属性设置类的属性：

```html
.lettertile { width:60px; height:60px; padding:5px; margin:5px; text-align:center; font-weight:bold;font-size:36px;color:#930; background-color:transparent;display:inline-block;}

```

我们将添加的最后一个样式是`draggable`属性。创建下面的样式以帮助跨浏览器兼容性：

```html
*[draggable=true] { -moz-user-select:none; -khtml-user-drag: element; cursor: move;}

```

样式表已经完成，现在我们可以开始编写脚本来拖动字母瓷砖并放置它们。

打开之前创建的 html 页面`using-drag-drop-api.html`，并为 IE 浏览器输入以下代码：

```html
<!--[if IE]><script src="img/html5.js"> </script><![endif]-->

```

在样式表链接的下方直接添加一个开头的`<script>`标签，并输入第一个函数`dragDefine(ev)`，该函数接受一个事件参数，并在后面加上`{`。在大括号后面，输入`ev.dataTransfer.effectAllowed ='move'`；然后，在新的一行上，输入`ev.dataTransfer.setData("text/plain", ev.target.getAttribute('id'))`；以设置数据类型和目标属性。最后，输入`return true`；并加上一个闭合的`}`来完成函数。

```html
function dragDefine(ev) {ev.dataTransfer.effectAllowed = 'move'; ev.dataTransfer.setData("text/plain", ev.target.getAttribute('id')); return true;}

```

现在，我们需要定义`dragOver`函数。输入`dragOver(ev)`和一个开头的`{`，然后通过添加`ev.preventDefault()`来调用`preventDefault()`函数。函数块应该类似于下面的代码：

```html
function dragOver(ev) { ev.preventDefault();}

```

我们需要的下一个函数是指示拖动完成的函数。输入`function dragEnd(ev)`，然后一个开头的`{`。输入`return true; }`来完成函数。

输入`function dragDrop(ev)`并加上一个开头的`{`，然后换行添加我们的第一个方法。输入`var idDrag = ev.dataTransfer.getData("Text")`来创建一个将保存文本字符串的拖动变量，然后输入`ev.target.appendChild (document.getElementById(idDrag))`。完成函数后，输入`ev.preventDefault()`。函数块应该如下所示代码：

```html
function dragDrop(ev) {
var idDrag = ev.dataTransfer.getData("Text");
ev.target.appendChild(document.getElementById(idDrag));
ev.preventDefault();} </script>

```

关闭页面的头部部分。输入`<body><header>`，然后`<h1>拖放井字棋</h1></header>`来完成页面的标题。

```html
</head><body><header><h1>Drag and Drop Tic Tac Toe</h1></header>

```

接下来，输入`<section><h3>将字母从灰色框拖到游戏板上（然后再拖回去！）</h3>`。

创建一个 ID 为`"gametilebox"`的 div，并设置`ondragover ="dragOver(event)"`和`ondrop="dragDrop(event)"`。它应该如下所示：

```html
<div id="gametilebox" ondragover="dragOver(event)" ondrop="dragDrop(event)">

```

现在，我们将为每个游戏瓷砖创建一个`div`。创建六个**"X"**瓷砖和六个**"O"**瓷砖，每个都以从`1-12`的数字结尾的`id`开始。每个`div`将包含类`"lettertile"`，每个`draggable`属性将包含值`"true"`。每个瓷砖还将包含`ondragstart="return dragDefine(event)"`和`ondragend="dragEnd(event)"`。`div`块应该看起来像以下代码：

```html
<div id="lettertile1" class="lettertile" draggable="true" ondragstart="return dragDefine(event)" ondragend="dragEnd(event)">X</div>
<div id="lettertile2" class="lettertile" draggable="true" ondragstart="return dragDefine(event)" ondragend="dragEnd(event)">X</div>
<div id="lettertile3" class="lettertile" draggable="true" ondragstart="return dragDefine(event)" ondragend="dragEnd(event)">X</div>

```

现在，我们可以为我们在**stylesheet.css**中创建的块样式创建实际的`divs`。首先键入`<div id= "gameboard">`。应该为每个块 id 创建一个`div`，从"blockA"到"blockI"。它们每个都将包含一个`ondragover="return dragOver(event)"`和一个`ondrop="dragDrop(event)"`。它们应该看起来像以下代码块。

```html
<div id="blockA" ondragover="return dragOver(event)" ondrop="dragDrop(event)"></div>
<div id="blockB" ondragover="return dragOver(event)" ondrop="dragDrop(event)"></div>
<div id="blockC" ondragover="return dragOver(event)" ondrop="dragDrop(event)"></div>

```

用`body`和`html`的闭合标签关闭页面，将文件命名为`"using-drag-drop-api.html"`，然后在浏览器窗口中查看结果。拖动几个字母，结果应该类似于以下截图：

![如何使用拖放 API，使用文本](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_07_02.jpg)

## 它是如何工作的...

首先，我们创建了一个基本的 HTML5 页面，并使用`@fontface`添加了一个草图字体作为标题，以使我们的游戏具有有趣的视觉效果。接下来，我们通过将`margin`设置为`body`和所有块级元素的`display:block`来为页面设置样式，以便更好地控制这些元素的呈现。在样式化标题字体后，我们为游戏瓷砖框定义了`width`和`height`。这将是容纳组成游戏瓷砖的字母的容器。

我们通过在 IE 浏览器中键入一个特殊的注释标签来开始我们的脚本，以指向一个额外的脚本文件来触发 HTML5 元素：`<!--[if IE]><script src="img/html5.js"></script><![endif]-->`。这是由 Remy Sharp（http://remysharp.com/html5-enabling-script/）根据 MIT 许可证提供的，以在处理 Internet Explorer 时保持我们的理智。

当用户开始拖动物品时，`dragDefine()`函数被调用。它首先检查物品是否可拖动，使用`dataTransfer.effectAllowed='move'`。然后，它将要传输的数据类型设置为`text`，并使用`dataTransfer.setData("text/plain")`和`target.getAttribute('id'))`来识别目标的`id`。该函数返回 true，表示可以拖动对象。

接下来，我们定义了`dragOver`函数，当拖动的物品位于另一个物品上时调用，接受一个名为`ev`的事件参数，然后使用它来调用`preventDefault()`以允许放置物品。拖放 API 规范明确规定，我们必须取消拖动，然后准备放置。

然后创建了`dragEnd()`函数，当拖动完成时返回 true。它还接受一个事件参数。

完成所有拖动功能后，我们准备创建代码来放置物品。`dragDrop()`函数接受一个事件参数，并使用该值获取文本对象的值，然后将其传递给一个新变量`var idDrag`来保存文本字符串，然后再使用`getElementById`来识别正确的元素 ID 进行放置。就像`dragEnd()`一样，我们必须调用拖放 API 中的`preventDefault()`函数来指示可以放置对象。

在关闭页面的头部区域后，在 body 中放置了内容框来容纳我们的字母瓷砖和游戏板块。这些由两个父 div 容器组成，每个容器都包含包含字母瓷砖或游戏板网格部分的子 div。

游戏瓷砖框在拖动字母瓷砖时调用了`dragOver()`函数。字母瓷砖 div 本身通过`draggable="true"`变得可拖动，并在拖动时返回`dragDefine()`。当拖动停止时，它们调用`dragEnd()`函数。

因为我们希望字母块能够被放下并停留在游戏板的特定区域，我们为网格上的每个单独的块创建了 div，以便在它们被放到板上时保持我们的字母在那里，并在对象被拖动到它们上方时返回`dragOver`事件，并在对象被放到它们上时调用`dragDrop()`。

为什么要费心设置块 div？我们本可以在左边设置我们的游戏块盒子，右边设置游戏板，然后就完成了。结果会是，当我们从左边的盒子拖动块到游戏板时，它们会被放下并按照它们被放下的顺序排列，而不是我们想要放置它们的地方。这种默认行为在你想要对列表进行排序时很好，但当需要精确控制对象放置位置时就不行了。

我们需要覆盖当对象被放下时产生的默认行为。我们创建了九个游戏板块，都是相同的基本大小。每个块的主要变化是`padding`和`margin`。

花几分钟时间阅读[`www.whatwg.org/specs/web-apps/current-work/multipage/dnd.html`](http://www.whatwg.org/specs/web-apps/current-work/multipage/dnd.html)上的拖放规范，你会注意到他们明确表示他们只定义了一个拖放机制，而不是你必须执行的操作。为什么？因为使用智能手机或其他触摸屏设备的用户可能没有鼠标等指针设备。

## 还有更多...

这个拖放 API 的演示可以通过多种方式构建成一个完整的游戏，包括计分、游戏板重置按钮和其他交互元素。

### 创建一个基于画布的井字棋游戏

可以使用两个画布，一个用于游戏块盒子，另一个用于游戏板。可以使用画布动态绘制板和游戏块，然后在屏幕上写入分数或消息，比如“你赢了”。

### 在用户玩游戏时显示响应消息

Remy Sharp 在[`html5demos.com/drag-anything`](http://html5demos.com/drag-anything)上有一个很棒的演示，展示了当一个对象被放下时如何在屏幕上显示消息。

要被放下的对象的源标签类似于：

```html
<div id="draggables"><img src="img/picean.png" alt="Fish" data-science-fact="Fish are aquatic vertebrates (animals with backbones) with fins for appendages." /> </div>

```

当对象被拖动到时，“放置区”框可能如下所示：

```html
<div class="drop" id="dropnames" data-accept="science-fact"> <p>Learn a science fact!</p> </div>

```

当图像被放入框中时，你会看到包含在“data-science-fact”中的文本，而不是图像。

## 另请参见

jQuery 的 Packt 书籍，本书中的其他配方，以及高级 HTML5 的 Packt 书籍。

# 使用 vid.ly 和 jQuery 支持跨浏览器视频

支持大多数浏览器需要将视频编码为多种格式，然后将正确的格式提供给浏览器。在这个配方中，我们将使用一个名为 vid.ly 的在线视频显示库([`www.vid.ly`](http://www.vid.ly))，在多个浏览器上可靠地准备和分享视频，并在页面上改变背景颜色。

## 准备工作

你需要一个视频上传到[`www.vid.ly`](http://www.vid.ly)。一些浏览器不允许本地提供文件，所以你可能也需要一个地方来上传你的文件和测试页面。

## 如何做...

输入`<!DOCTYPE html> <html lang="en"> <head>`，然后开始添加样式声明，输入`<style type="text/css"> h2{color:#303;}`。

样式一个 div 来包含特色内容：`#featured {position:relative; padding: 40px; width: 480px; background-color:#000000; outline: #333 solid 10px; }`。

输入`video {padding: 3px;background-color:black;}`来创建视频标签的样式，然后添加一个闭合的`</style>`标签。

在页面中声明使用的脚本。键入`<script src="img/jquery.min.js" type="text/javascript" charset="utf-8"></script>`来引用主要 jQuery 库的最小化版本。然后，键入`<script type="text/javascript" src="img/jquery-ui.min.js"></script>`来引用用于颜色变化效果的 jQuery UI 库。最后，我们将通过在关闭`</head>`标签之前键入`<script type="text/javascript" src="img/mycolor.js"></script>`来引用我们自己的脚本。

输入一个开放的`<body>`和`<section>`标签，然后键入`<header> <h2>Featured Video</h2></header>`来显示页面标题。

现在，我们可以创建包含我们之前样式化的特色内容的 div。键入`<div id="featured"> <p>此视频已通过<a href="http://vid.ly">vid.ly</a>转换为跨浏览器格式</p>`。

下一步是将视频剪辑上传到[`vid.ly`](http://vid.ly)进行多文件格式转换。转换过程完成后，您将收到一封电子邮件，然后可以获取视频的代码片段，如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_07_03.jpg)

复制网站上的代码，然后粘贴到您的页面中。视频和脚本标签中的`src`值应该是 vid.ly 给出的 URL。代码块应该如下所示：

```html
<video id= "vidly-video" controls="controls" width="480" height="360"> <source src="img/7m5x7w?content=video"/> <script id="vidjs" language="javascript" src="img/html5.js"></script> </video>

```

为了增加一些额外的乐趣，让我们在页面上添加另一个视频标签。键入以下代码：`<p>哎呀，这是一个宝宝视频！</p>`，为视频标签使用不同的 id，并按照以下方式调整大小：`<video id="tinymovie1" controls="controls" width="190" height="120">`，然后使用相同的源标签：`<source src="img/7m5x7w?content=video"/><script id="vidjs" language="javascript" src="img/html5.js"></script></video>`，并关闭页面：`</div> </section></body></html>`。将文件保存为`display-videos-using-videly.html`。

我们要做的最后一件事是创建一个 jQuery 脚本来改变`#featured` div 的背景颜色。打开您的编辑器，创建一个名为`myColor.js`的新文件。

键入`$(document).ready(function() {`，然后转到新的一行，键入调用动画函数并改变背景颜色的代码：`$('#featured').animate({'backgroundColor':'#ff3333', 'color': '#ffffff'}, 6000);})`;。

在浏览器中加载页面，观察主视频加载时颜色的变化。您可以看到以下截图显示的效果：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_07_04.jpg)

## 工作原理...

首先，我们创建了一个标准的 HTML5 页面，并开始添加样式声明。我们将`featured` div 的位置设置为相对位置，以便在将来如果决定添加额外的 jQuery 效果时具有更大的灵活性。通过将`padding`设置为`40px`，将`outline`颜色设置为深灰色并加粗为`10px`，创建了强烈的视觉效果。默认的背景颜色设置为黑色`(#000000)`，以便与最终的红色背景进行高对比度的比较。

接下来，我们样式化了`video`标签，使其在加载时具有黑色的`background-color`。我们还可以在这里添加一个背景图像作为海报。

接下来，使用`<script src="img/jquery.min.js" type="text/javascript" charset="utf-8"></script>`声明了基本的 jQuery 脚本。因为它不包含`animate()`等效果，我们还需要引用用于颜色变化效果的 jQuery UI 库的最小化版本。然后，通过键入`<script type="text/javascript" src="img/mycolor.js"></script>`来添加对我们自己脚本的引用。进一步减小脚本文件大小的另一种方法是创建一个仅包含来自 jQueryUI 库的动画效果的自定义脚本。

接下来，我们创建了主页面内容，包括指向 vid.ly 上的视频的链接。vid.ly 提供的默认代码会将 ID`'vidley video'`应用到`video`标签，但如果您想使用自己的样式 ID 或将为每个视频使用不同的 ID，则可以省略该代码。另一个选择是将所有视频分配相同的类，然后根据需要为它们分配唯一的 ID。

## 另请参阅

第八章，*拥抱音频和视频*，更详细地介绍了视频元素。

# 使用 jQuery 动态显示视频

视频元素使我们能够像处理图像一样处理视频，并以有趣和令人兴奋的方式操纵它们。

## 准备工作

您需要一个以多种文件格式提供的视频（这些文件在本书的章节代码中提供）。建议上传文件的服务器，因为并非所有浏览器都以可预测的方式本地播放文件。

## 操作步骤

首先，我们必须准备一个 HTML5 页面来放置它。输入我们页面的开放标签：`<!DOCTYPE html> <html lang="en"> <head> <meta charset="utf-8" /> <title>Video Explosion</title>`。

打开下载的代码文件中的`stylesheet.css`文件，或创建一个同名的新文件。

输入以下内容来设置 body 样式：`body {background: white;color:#333333; }`，然后按照以下方式设置 div 标签的样式：`div {float:left; border:1px solid #444444;padding:5px;margin:5px; background:#999999;}`。

我们需要创建和设置的第一个独特的 div 是`#featured`。输入`#featured {position:relative; width: 480px; background-color:#f2f1f1;}`来创建样式。

现在创建一个名为`details`的 div 来容纳一个小的信息框。输入`#details{ position:relative;display:block;background-color:#6CF;color:#333333; padding:10px;}`以创建一个将显示在`featured` div 旁边的 div。

保存`css`文件，并在 html 页面的头部引用它，方法是使用链接标签输入`<link rel="stylesheet" href="css/stylesheet.css"type="text/css" media="screen" charset="utf-8"/>`。

在样式表链接下方输入以下链接到主 jQuery 库：`<script src="img/jquery-latest.js" type="text/javascript" charset="utf-8"></script>`，然后通过输入`<script type="text/javascript" src="img/jquery-ui.min.js"></script>`来链接到 jQuery UI 库。最后，通过输入`<script type="text/javascript" src="img/explode.js"></script>`来添加对即将创建的脚本的引用。

创建一个新文件并命名为`explode.js`，并将其存储在一个名为`js`的新子文件夹中。输入`$(document).ready(function(){}`。在两个大括号（{}）之间输入`$('h1').effect('shake', {times:5}, 200)`；创建将导致 featured div 标签中包含的内容爆炸的语句。在新行上，输入`$('#featured').effect('shake', {times:3}, 100).delay(500).hide('explode',{}, 2000).slideDown('fast');)`；以完成脚本。您的代码块应该类似于以下代码块：

```html
$(document).ready(function(){ $('h1').effect('shake', {times:5}, 200); $('#featured').delay(2000).hide('explode', {}, 2000 ).slideDown('fast'); });

```

保存文件并返回 html 页面。

为 HTML 文件添加`</head>`闭合标签和`<body>`开放标签。接下来，输入一个开放的`<header>`标签和标题文本：`<h1>Featured Moto Video</h1>`，然后输入`</header>`标签来完成标题区域。

创建一个开放的`<section>`标签，然后输入`<div id="featured">`来创建一个 div，用于容纳我们的视频标签和相关元素。输入`<video id="movie" width="480" height="360" preload controls>`，然后为三种视频文件类型的每一个添加一个 source 标签：`<source src='motogoggles.ogv' type='video/ogg; codecs="theora, vorbis"'/> <source src='motogoggles.mp4' type='video/mp4; codecs="avc1.42E01E, mp4a.40.2"'/> <source src='motogoggles.webm' type='video/webm; codecs="vp8, vorbis"'/>`，然后使用`</video>`标签和`</div>`标签来关闭 featured div。

最终的内容块包含在`details` div 中。要创建它，输入`<div id="details">`，然后添加一个带有文本的标题标签`<h1>Details</h1>`，最后是一个简短的解释性文本段落：`<p>视频将爆炸然后再次出现！</p>`。关闭`</div></section> </body></html>`标签。将 HTML 文件保存为`exploding-video-dynamically.html`，在浏览器中打开它以查看结果。它们应该与以下截图类似，显示视频分成几部分并爆炸。

![如何操作...视频操作，使用 jQuery](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_07_05.jpg)

## 它是如何工作的...

`stylesheet.css`文件包含了特色 div 的样式，确定了页面上视频对象的位置。要注意的第一件重要的事情是`position`设置为`relative`。这使我们能够移动视频对象并使用 jQuery 执行其他操作。

我们创建了一个名为`details`的 div，其`position`也是`relative`，但`background-color`设置为`浅蓝色(#6CF)`。不同的颜色将有助于在视觉上将其与视频对象区分开来。

接下来，我们添加了 jQuery 库脚本。为了让我们能够访问`animate`类中包含的方法和函数，需要引用 jQuery UI 库。在这个例子中，我们是在本地引用它，但您也可以像我们访问主要的 jQuery 库一样链接到它。

最后，我们能够编写自己的脚本，使页面上的元素摇晃和爆炸！我们创建了一个语句来验证页面是否准备好接受我们的代码，方法是键入`$(document).ready(function(){}`。这个函数查询 DOM 并询问页面是否已加载并准备好接受脚本。在创建 jQuery 脚本时，使用这个包装函数是最佳实践。我们使用别名符号`$`来调用 jQuery 函数，以抓取`h1`选择器，并对其应用包含`shake`参数的`effect`动作，使元素向侧面移动，其中又包含了一个关于摇动元素的次数的参数。摇动应持续的时间间隔以毫秒定义，本例中为`200`。我们使用选择器`$('#featured')`来抓取特色 div 元素，并像对`h1`标签所做的那样，对其进行摇动（只摇动三次以增加变化），每次摇动持续`100`毫秒。现在我们添加了一些新的动作。在`shakes`和爆炸之间添加了`500`毫秒的`delay`，并使用`.delay(500)`命令附加到该命令。然后我们附加了`hide`动作，参数为`explode`，默认情况下将发生一次，持续时间为`2000`毫秒。视频爆炸后，`slidedown`动作将其以`fast`参数滑回屏幕上。请注意，爆炸所用的时间有点长，这样我们可以更容易地看到它。`100-500`毫秒的时间间隔会产生更真实的爆炸效果。如果您只想要视频本身而不是特色标签提供的背景或边框，也可以直接使用`$('video')`来抓取视频标签。

回到 HTML 文件，我们将视频放在一个名为`featured`的容器 div 中，并创建了一个父`video`标签，它将`preload`并包含默认的`controls`。在关闭`video`标签之前，我们在其中嵌套了三种视频文件类型的`source`标签，以便不同浏览器的用户都可以观看视频：我们没有提供 FLASH 回退，但我们可以使用 JavaScript 库，比如`Video.js`。然后我们关闭了`</video>`标签和特色 div 标签`</div>`。

最后，我们创建了一个 div 来保存关于用户可以期待在`details` div 中发生的事情的信息。

## 还有更多...

视频元素、JavaScript 和画布标签还有很多可以做的事情。继续阅读更多实验。

### 使用视频和画布进行更多交互式爆炸

Sean Christmann 在[`www.craftymind.com`](http://www.craftymind.com)上进行了一项令人惊叹的实验，使您能够在视频播放时实时爆炸多个视频部分。您可以在此处查看：[`www.craftymind.com/2010/04/20/blowing-up-html5-video-and-mapping-it-into-3d-space/`](http://www.craftymind.com/2010/04/20/blowing-up-html5-video-and-mapping-it-into-3d-space/)，但请注意 - 在 Firefox 中资源消耗非常大。

### 所有这些爆炸是怎么回事？

起初似乎没有任何真正实际的理由来分解视频。然而，这对于模仿独特的过渡效果或对游戏中用户操作的响应可能非常有用。

### 实时 Chroma 键背景替换

Firefox 开发人员一直在尝试操纵视频元素。他们创建了一个教程，解释了他们如何使用画布、JavaScript 和视频元素的属性执行 Chroma 键替换。您可以在以下网址阅读有关此内容并查看演示：[`developer.mozilla.org/En/Manipulating_video_using_canvas`](http://https://developer.mozilla.org/En/Manipulating_video_using_canvas)。

想象一下在网站上显示视频，您可以显示异国情调的背景或创建产品和人物的互动混搭。

## 另请参阅

视频元素在本书的第八章*拥抱音频和视频*中进行了深入探讨。

# 使用 jQuery 创建可移动视频广告

我们将在网站上创建一个视频广告，当用户向下滚动页面时，它将移动使用 jQuery 和视频标签。

## 准备工作

您将需要多种格式的视频文件，如`.ogg/.ogv, .mp4`和`.webm`，或者使用视频服务，如[`www.vid.ly.com`](http://www.vid.ly.com)来提供跨浏览器视频。此示例未在 Internet Explorer 中进行测试，但应在 Safari、Google Chrome、Opera 和 Firefox 的最新版本中正常工作。

## 如何做...

我们将首先创建一个典型的网页。在编辑器中打开一个新文件，并将其保存为`movable-video-ad.html`。键入`<!DOCTYPE html> <html lang="en"><head><meta charset="utf-8" /><title>Movable Video Ad</title>`以在页面上放置第一个标签。

现在，为我们的默认样式表创建一个引用链接`<link rel="stylesheet" href="css/main.css" type="text/css" media="screen" charset="utf-8" />`和一个名为`<link rel="stylesheet" href="css/scroll.css" type="text/css" media="screen" charset="utf-8" />`的辅助样式表。

接下来，为 jQuery 脚本创建引用链接。键入`<script src="img/jquery-1.4.min.js" type="text/javascript" charset="utf-8"></script>`来引用核心 jQuery 代码。添加链接语句`<script type="text/javascript" src="img/jquery-ui-1.7.2.custom.min.js"></script>`。我们将链接到的最终脚本是我们为名为`myAd.js`的配方创建的自己的脚本，它将存储在我们创建的名为"js"的子文件夹中。键入`<script type="text/javascript" src="img/myAd.js"></script>`来链接到该文件。

键入`</head><body><div id="container">`开始页面的内容区域。通过键入`<header> <h1>Motocross Mania</h1></header>`来显示页面标题。

通过键入`<div id="content"> <h2>No dirt = no fun</h2>`来开始添加页面内容。现在可以通过输入文本`<div id="motoad"><h3>Buy this movie!</h3>`，然后在段落元素标签中包含电影标题`<p><strong>MotoHelmet</strong></p>`来向页面添加包含广告的 div。

然后应添加一个视频标签`<video width="190" height="143" preload controls>`。键入包含每种视频格式的源标签，如下面的代码块所示：

```html
<source src='video/motohelmet.ogv' type='video/ogg; codecs="theora, vorbis"'/> <source src='video/motohelmet.mp4' type='video/mp4; codecs="avc1.42E01E, mp4a.40.2"'/> <source src='video/motohelmet.webm' type='video/webm; codecs="vp8, vorbis"'/></video>

```

关闭`</div>`标签并保存到目前为止的进度。

创建一个带有 id 为 intro 的段落`<p id="intro">`来包含文本`We review the best motorcross gear ever!!!`。在段落标签和文本后面，加上一个虚拟链接列表：`<ul><li><a href="#">Helmets</a></li> <li><a href="#">Gloves</a></li><li><a href="#">Goggles</a></li></ul>`，用`</p>`关闭段落，然后创建一个新的 div 来包含一个虚拟新闻内容块，然后是另外两个虚拟 div 块，一个页脚标签，以及关闭页面元素，如下面的代码块所示：

```html
<div id="news"><h2>Latest News</h2> <p>Trip Ousplat admits he doesn't do his own stunts! "My mom makes
me use a stunt double sometimes," The shy trick-riding sensation explains.</p> <p>Gloria Camshaft smokes the competition for a suprise win at the Hidden Beverage Playoffs</p> <p>Supercross competitors report more injuries; jumps more extreme than ever</p><p>James Steward still polite, reporters bored</p>
</div><div id="filler"><h2>On Location</h2> <p>Grass is not greener as there is no grass on most motorcross trails experts claim </p></div> <p id="disclaimer">Disclaimer! Anything you choose to do is at your own risk. Got it? Good.</p><footer><p>&copy; Copyright 2011 Motocross Extreme Publications, Inc.</p></footer></div></body></html>

```

现在，我们将在`main.css`文件中为页面元素设置样式。第一个关键样式是`#container` div。它应该有一个`0 auto`的边距和`650px`的宽度。接下来，`#motoad` div 应该被设置为`右浮动`，并包含一个`200px`的宽度来容纳视频元素。最后，`#intro` div 应该包含一个较短的`450px`宽度。这三个样式应该看起来类似于下面显示的代码块：

```html
#container{ margin:0 auto;text-align:left; width: 650px;}
#motoad{ float:right;width:200px;}
#intro{width:450px;}

```

其余的样式是对填充和颜色或其他标准声明的微小调整。

现在，打开`scroll.css`文件来定义样式，以帮助我们的广告滚动。我们将级联`#motoad`的属性，形成一个可以移动的 div 块。接下来，定义`#content`属性的`height`，以及段落和`h2`元素的宽度。`scroll.css`中的样式现在应该如下所示：

```html
#motoad {display:block;position: relative; background-color:#FC0;width:200px;padding:10px;}
#content { height:1000px;}
p {width:450px;}h2 {width:460px;}

```

保存文件，并准备创建我们的 jQuery 脚本。

打开或创建`myAd.js`，并开始输入文档就绪函数`$(document).ready(function(){}`和花括号。在花括号之间点击 enter，并输入滚动函数`$(window).scroll(function() {`。在该函数的开头花括号后键入命令：`$('#motoad').stop().animate({top: $(document).scrollTop()},'slow','easeOutBack')`;。也要关闭脚本：" });});"。我们的 jQuery 脚本现在应该看起来像以下代码块：

```html
$(document).ready(function(){ $(window).scroll(function() { $('#motoad').stop().animate({top: $(document).scrollTop()},'slow','easeOutBack'); }); });

```

保存所有文件，并在浏览器窗口中加载 HTML 页面。在开始滚动页面之前，页面应该看起来像下面的截图。

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_07_06.jpg)

尝试向上和向下滚动页面。广告也应该随着页面一起上下移动。结果应该看起来类似于以下截图：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_07_07.jpg)

## 工作原理...

在创建了一个包含不同内容元素的典型 HTML 页面后，我们准备好为 CSS 页面设置样式。我们将 CSS 分成两个文件，`main.css`和`scroll.css`，这样当我们在 jQuery 脚本中调用滚动函数并积极应用它时，页面上的内容元素会收缩，以便我们的广告可以轻松移动，而不会阻挡页面上的任何信息。

我们希望在调用窗口滚动事件时，使`#motoad` div 标签移动。为此，我们使用别名符号`$`来调用 jQuery 函数，从 DOM 中获取`window`选择器，并将默认滚动动作参数应用于它。使用这个函数，我们然后创建了控制`#motoad` div 块行为的命令。我们给它了`stop`的动作，这样它就准备好进行动画。`animate`动作链接到了`stop`命令。我们应用到`#motoad` div 的`animate`的第一个参数是，当文档窗口中的滚动条移动时，div 会移动。`slow`参数控制了广告上下移动的速度，`easeOutBack`参数引用了一个缓动命令，以创建流畅的动画运动，而不是突然开始或停止。

## 还有更多...

在这个示例中，我们通过使自定义 HTML 元素对页面上的用户操作做出响应来实现了动画效果。这只是我们可以微妙地添加效果的一种方式，可以用于实际解决方案。

### 有 HTML 元素，就会移动

探索 jQuery UI 库，你会被许多可以操纵和样式化任何 HTML 元素的方式所启发。访问[`jqueryui.com`](http://jqueryui.com)查看演示和文档。

## 另请参阅

学习 jQuery：使用简单的 JavaScript 技术实现更好的交互设计和 Web 开发，Packt Publishing 出版。

# 使用 Easel.js 和 canvas 标签控制图像的显示

JavaScript 库`Easel.js`减少了使用`canvas`标签创建动画和丰富交互环境的复杂性。在这个配方中，我们将使用单个文件中名为"sprites"的一系列图像，以展示如何使用`Easel.js`来控制精灵中选择性显示的图形图像。

## 准备工作

您需要下载`Easel.js`库，或者使用此配方的代码文件中的副本。

## 如何做...

创建一个 HTML5 文件的开放标签。您的代码应该类似于以下代码块：

```html
<!DOCTYPE HTML><html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8"><title> Animating images using BitmapSequence and SpriteSheet</title>

```

接下来，链接到此配方中使用的主样式表`styles.css`：<link href="styles.css" rel="stylesheet" type="text/css" />。

接下来，我们将通过插入以下脚本文件的链接来导入`Easel.js`框架库：`UID.js, SpriteSheetUtils.js, SpriteSheet.js, DisplayObject.js, Container.js, Stage.js, BitmapSequence.js`和`Ticks.js`。您可以在这里看到每个脚本文件的路径和链接：

```html
<script src="img/UID.js"></script><script src="img/SpriteSheetUtils.js"></script><script src="img/SpriteSheet.js"></script><script src="img/DisplayObject.js"></script><script src="img/Container.js"></script><script src="img/Stage.js"></script><script src="img/BitmapSequence.js"></script><script src="img/Tick.js"></script>

```

接下来，创建并打开`<script>`标签，并声明以下三个变量：`var canvas; var stage; var critterSheet = new Image()`; 用于我们的脚本。

输入`function init(){`开始函数，然后输入`canvas = document.getElementById("testCanvas")`;将页面主体中的 canvas 与 canvas 变量绑定。准备加载一个新的`spriteSheet`，输入`critterSheet.onload = handleImageLoad`;。`critterSheet`变量存储精灵图像的来源。输入`critterSheet.src = "images/moles.png"`;来加载我们自己的一系列鼹鼠图像。函数块应如下代码块所示：

```html
function init() {
canvas = document.getElementById("testCanvas");
critterSheet.onload = handleImageLoad;
critterSheet.src = "images/moles.png";}

```

我们将创建的第二个函数是`handleImageLoad()`。输入`function handleImageLoad() {`然后输入`stage = new Stage(canvas)`;来创建一个新的舞台实例。输入`var spriteSheet = new SpriteSheet(critterSheet, 76, 80);`来创建一个新的`spriteSheet`。创建一个名为`critter1`的新位图序列变量，并定义它在舞台上的位置，使用 x 和 y 坐标来输入：`var critter1 = new BitmapSequence(spriteSheet); critter1.y = 85; critter1.x = 85`;。通过输入`critter1.gotoAndStop(1)`，从我们的精灵表`moles.png`中添加一个小动物。接下来，使用命令`stage.addChild(critter1)`将其添加到舞台上。

克隆我们创建的第一个`critter1`变量，并通过输入`var critter2 = critter1.clone()`将其值传递给一个新的 critter 变量。通过添加到其当前位置值来将新变量定位在第一个 critter 的右侧，使用`critter2.x += 120`。

输入`critter2.gotoAndStop(0)`来为`critter2`变量赋值。克隆 critter 1 和 critter 2 的代码块应如下所示：

```html
var critter2 = critter1.clone();
critter2.x += 120;
critter2.gotoAndStop(0);
stage.addChild(critter2);

```

Tick 间隔`Tick.setInterval(300)`;和监听器`Tick.addListener(stage)`;是我们将添加到脚本的最后两个语句。关闭`handleImageLoad()`函数的大括号（}），然后输入一个闭合的脚本标签。

关闭`</head>`标签，然后输入带有`onload`属性的开放`body`标签，调用`init()`函数。创建一个名为"description"的 div 用于内容。添加一个名为`canvasHolder`的 div 来包含 canvas 元素。在页面底部显示图像文件`moles.png`。

```html
<body onload="init();">
<div class="description">Using <strong>BitmapSequence</strong> to animate images from a <strong>SpriteSheet</strong>.
</div>
<div class="canvasHolder">
<canvas id="testCanvas" width="980" height="280" style="background-color:#096"></canvas> </div> </p><p>The original moles.png spritesheet file with all the images:<br/><img src="img/moles.png"/></p> </body></html>

```

将文件保存为`whack-mole-easel-test-single.html`。结果可以在以下截图中看到：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_07_08.jpg)

## 工作原理...

在我们设置好 HTML5 页面的开头之后，我们准备好导入`Easel.js`框架并创建我们的主要脚本。

我们创建了一个开放的`<script>`标签，并声明了以下全局变量：`var canvas; var stage; var critterSheet = new Image()`; 用于我们的脚本。

创建的`init()`函数将在页面加载时被调用。它包含了正在被分配选择器`testCanvas`的`canvas`变量的过程，使用`document.getElementById("testCanvas");`将页面主体中的 canvas 与 canvas 变量绑定。接下来，我们准备通过输入`critterSheet.onload = handleImageLoad`加载一个新的`spriteSheet`。`critterSheet`变量存储了精灵图像的来源。输入`critterSheet.src = "images/moles.png"`；让我们可以访问我们自己的一系列鼹鼠图像。

我们创建的第二个函数是`handleImageLoad()`。在这个函数中，我们做了大部分工作，首先是使用`stage = new Stage(canvas)`创建了一个舞台的新实例；接下来，我们使用`var spriteSheet = new SpriteSheet(critterSheet, 76, 80)`创建了一个新的`spriteSheet`。

现在我们有了一个精灵图实例，我们可以创建一个新的位图序列变量，称为`critter1`，并定义它在舞台上的位置，使用 x 和 y 坐标来输入：`var critter1 = new BitmapSequence(spriteSheet);critter1.y = 85;critter1.x = 85`；。接下来，我们按数字引用要添加的帧，以便首先将正确的动作应用于 critter，然后应用于舞台。我们通过输入`critter1.gotoAndStop(1)`将`critter1`变量链接到我们精灵图`moles.png`上的第二个图像。我们使用命令`stage.addChild(critter1)`将图像添加到舞台上。

我们克隆了我们创建的第一个`critter1`变量，并通过输入`var critter2 = critter1.clone()`将其值传递给一个新的 critter 变量。我们通过使用`critter2.x += 120`将新变量定位在第一个 critter 的右侧，将其当前位置值添加到其中。我们通过命令`BitSequence`去到`moles.png`上的第一个图像的位置并在那里停止，并将其分配给`critter2`变量。

我们添加了`Tick.setInterval(300)`；，这样就在`Ticks`之间应用了`300`毫秒的时间间隔。Tick 接口充当全局定时设备，如果需要，可以返回每秒帧数（FPS）。我们向舞台添加了一个监听器`Tick.addListener(stage)`；，它的行为类似于其他类型的监听器，它监听`Ticks`。这可以用来在指定的时间重新绘制舞台，或执行其他与时间相关的操作。

我们使用`onload`属性在`body`标签中调用`init()`函数。这会导致在页面加载时调用`init()`函数。

## 另请参阅

*动画序列*教程。

# 使用 Easel.js 和 canvas 标签来制作图像序列的动画

我们可以通过创建数组和使用`Easel.js` JavaScript 库的函数来制作称为精灵的图像条，然后使用`canvas`元素对它们进行操作。在这个教程中，我们将对同一条图像条进行动画处理，但显示两个不同时间序列。

## 准备工作

下载此教程的代码文件，以使用`Easel.js`框架库以及支持文件。您需要一个能够正确显示 HTML5 元素并测试本教程中使用的代码的最新浏览器。

## 操作步骤

创建一个 HTML5 文件的开头标签。您的代码应该类似于以下代码块：

```html
<!DOCTYPE HTML><html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8"><title> Animating images using BitmapSequence and SpriteSheet</title>

```

链接到本教程中使用的主样式表`styles.css`：<link href="styles.css" rel="stylesheet" type="text/css" />。

通过插入以下脚本文件的链接来导入`Easel.js`框架库：`UID.js, SpriteSheetUtils.js, SpriteSheet.js, DisplayObject.js, Container.js, Stage.js, BitmapSequence.js`和`Ticks.js`。参考前面的示例，了解框架块应该是什么样子的。

创建一个开头的`<script>`标签，并声明以下三个变量：`var canvas;var stage;var critterSheet = new Image()`；用于我们的脚本。

输入`function init(){`开始函数，然后输入`canvas = document.getElementById("testCanvas")`。

准备通过输入`critterSheet.onload = handleImageLoad`;来加载一个新的`spriteSheet`。输入`critterSheet.src = "images/moles.png"`;来加载我们自己的一系列鼹鼠图像。函数块应该如下所示的代码块：

```html
function init() {
canvas = document.getElementById("testCanvas");
critterSheet.onload = handleImageLoad;
critterSheet.src = "images/moles.png";}

```

我们将创建的第二个函数是`handleImageLoad()`。输入`function handleImageLoad() {`然后`stage = new Stage(canvas)`;创建舞台的新实例。输入`var spriteSheet = new SpriteSheet(critterSheet, 80, 80)`;创建一个新的`spriteSheet`。现在我们有了一个精灵表，创建一个新的位图序列变量名为`critter1`，并使用 x 和 y 坐标定义其在舞台上的位置，输入：`var critter1 = new BitmapSequence(spriteSheet)`;然后`critter1.y = 100;critter1.x = 90`;。接下来，我们将创建一个数组，将其映射到原始`spritesheet`文件上的每个图像，输入`var frameData = {shymole:0, upmole:1, downmole:2, whacked:3, whackedow:4, clouds:5,tinycloud:6, cloudgroup:7}`;以便我们有八个名称值，每个名称值都与一个数组 ID 相关联。

到目前为止，`handleImageLoad()`的代码块应该如下所示：

```html
function handleImageLoad() {
stage = new Stage(canvas);
var spriteSheet = new SpriteSheet(critterSheet, 80, 80);
var critter1 = new BitmapSequence(spriteSheet);
critter1.y = 100;
critter1.x = 90;
var frameData = {shymole:0, upmole:1, downmole:2, whacked:3, whackedow:4, clouds:5,tinycloud:6, cloudgroup:7};

```

通过输入：`spriteSheet = new SpriteSheet(critterSheet, 80, 80, frameData)`;创建一个新的`spriteSheet`并将其用作参数。

创建一个名为`critter1`的新位图序列变量，并通过输入`critter1gotoAndStop(0)`;应用图像精灵。使用`stage.addchild(critter1)`;将`critter1`添加到`stage`。

通过输入`var critter2 = critter1.clone()`;克隆第一个`critter1`变量，并将其值传递给一个新的小动物变量。使用`critter2.x += 120`;定义新变量的`x`值。通过输入`critter2.gotoAndStop(5)`;为小动物分配其自己的图像，来自`moles.png`图像文件。添加一个新的`spriteSheet`，创建`critter 1`和克隆`critter 2`的代码块应该如下所示的代码块：

```html
spriteSheet = new SpriteSheet(critterSheet, 80, 80, frameData);
critter1.gotoAndStop(0);
stage.addChild(critter1);
var critter2 = critter1.clone();
critter2.x += 120;critter2.gotoAndStop(5);

```

输入：`var critter3 = critter2.clone(); critter3.spriteSheet = spriteSheet`;。就像我们之前创建的其他小动物变量一样，通过将`10`添加到其当前值来重新定义`critter3`的`x`值：`critter3.x += 10`;。以下代码块显示了我们到目前为止所做的事情：

```html
var critter3 = critter2.clone();
critter3.spriteSheet = spriteSheet;
critter3.x += 10;

```

通过输入`critter3.gotoAndStop("upmole")`;按名称引用`moles.png`中的图像`frames`。通过克隆一个新变量并引用一个新帧，将当前的`upmole`帧图像替换为不同的帧：`var critter4 = critter3.clone(); critter4.gotoAndStop("downmole")`;。通过输入`critter4.x += 10`;将该帧向右移动`10`像素。

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

通过输入以下内容循环播放我们的`moles.png`文件中的帧：

```html
var critter6 = critter1.clone(); critter6.x = critter5.x + 100; critter6.gotoAndPlay(3);stage.addChild(critter6);.

```

在舞台上添加第二个动画序列，通过引用不同的起始帧来改变动画的时序，当新的小动物精灵被添加到舞台上时：`var critter7 = critter1.clone(); critter7.x = critter6.x + 100; critter7.gotoAndPlay(1); stage.addChild(critter7)`;。

我们的两个动画序列现在应该包含以下代码：

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

Tick 间隔`Tick.setInterval(200)`;和监听器`Tick.addListener(stage)`;是我们将添加到脚本中的最后两个语句。关闭`handleImageLoad()`函数的大括号（}）并输入一个闭合的脚本标签。

输入`</head>`，然后`<body onload="init()">`。创建一个名为`"description"`的 div 来容纳内容。最后一个 div 是`canvasHolder`，包含 canvas 元素。将宽度设置为`600`，高度设置为`280`，背景颜色设置为浅灰色`(#ccc)`。添加指向图像文件`moles.png`的链接，以便用户可以看到`moles.png`中引用的图像精灵。

保存文件，并在浏览器窗口中打开它。你应该在左侧看到一个静止的帧（闭着眼睛的鼹鼠头像），并在屏幕右侧看到两个动画序列循环播放。以下截图显示了两个序列如何加载相同的帧，但时间不同。

![如何操作...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_07_09.jpg)

## 它是如何工作的...

创建 HTML 页面和引用画布的配方的第一步与上一个配方相同。

创建`spriteSheet`后，我们创建了一个新变量来保存我们的精灵帧，称为`critter1`，并通过输入以下内容定义了帧位置的`x`和`y`坐标：`var critter1 = new BitmapSequence(spriteSheet); critter1.y = 100;critter1.x = 90`;。

我们创建了数组`var frameData`来声明八个键/值对。然后，我们能够创建一个新的`spriteSheet`，它接受了`spriteSheet`名称的参数，每个帧的默认高度和宽度，并使用`frameData`一次性加载`moles.png`中的所有帧到`spriteSheet`中。

接下来，我们尝试使用`frameData`通过数字值和名称键引用帧，创建一系列位图序列，然后用它们的克隆替换它们。

我们对序列进行了动画处理，并将它们放在了舞台上。它们都遵循相同的格式，但通过更改`gotoAndPlay`操作中的数字参数，它们在不同的帧上开始它们的动画序列。

最后，我们添加了`Tick.setInterval(200)`;，它在 Ticks 之间应用了 200 毫秒的时间间隔。Tick 接口充当全局定时设备，如果需要，可以返回每秒帧数（FPS）。我们向舞台添加了一个监听器`Tick.addListener(stage)`;，它像其他类型的监听器一样监听 Ticks。这可以用来在指定时间重新绘制舞台，或执行其他与时间相关的操作。我们使用`onload`属性在`body`标签中调用`init()`函数。这会导致在页面加载时调用`init()`函数。

## 还有更多...

`Easel.js`和其他类似的库使控制 HTML5 元素变得更加容易。不过要小心使用它们，因为有些可能不够稳定，不能在生产环境中使用。

### 海盗爱雏菊，你也应该爱

`Easel.js`的创建者被微软要求创建一个名为 Pirates love daisies 的概念性网络游戏（[`www.pirateslovedaisies.com`](http://www.pirateslovedaisies.com)），完全使用 HTML5 和 JavaScript，并且严重依赖于`Easel.js`库来操作`canvas`元素。你可以在任何网络浏览器中玩这个游戏，也许有些讽刺的是，它还为使用 Internet Explorer 9 浏览器的访问者提供了特殊功能。

### 老派计算机动画技术的回归

当我第一次开始在计算机上玩游戏时，游戏屏幕上有 256 种颜色和 8 位动画是一件大事。计算机动画师使用了许多技巧来复制水流动等效果。重新体验那些日子（或者第一次通过 effect games 的演示发现它们：[`www.effectgames.com/demos/canvascycle/`](http://www.effectgames.com/demos/canvascycle/)。

## 另请参阅

本书中有一整章关于 canvas 的配方。如果你跳过了它们，现在就去吞食它们。

# 使用 canvas 标签和 JavaScript 进行随机动画和音频

在这个配方中，我们将使用 canvas 标签来绘制和动画一系列形状。我们还将使用音频标签循环播放音频文件，同时显示动画。我们正在改编 Michael Nutt 创建的原始动画。我们将创建一个更慢、更轻松的动画，看起来像是摇曳的草。

## 做好准备

您将需要一个最近更新的浏览器，如 Firefox 3.6 或 Google Chrome，以及多种格式的音频文件。在 Opera 浏览器 9 和 10 中，它显示的大小会有所不同（更小）。在那些版本的 Opera 中，音频也不会播放。

## 如何做...

首先，打开一个新的 HTML5 页面，并命名为`random-animation-with-audio.html`。输入一个 HTML5 页面的开头，包括页面标题：

```html
<!DOCTYPE html> <html lang="en"> <head><meta charset="utf-8" /> <title>Canvas Reggae</title>.

```

然后，添加链接到 JavaScript 和 CSS 文件，这些文件将在页面加载时导入：`<script type="text/javascript" src="img/animatedlines.js"></script><link rel="stylesheet" href="css/stylesheet.css" type="text/css" media="screen" charset="utf-8" />`，并使用`</head>`关闭 head 标签。

输入`<body onLoad="init();">`来在页面加载时激活`init()`函数。

接下来，我们创建页面的标题`<header><h1>CANVAS Reggae</h1></header>`，然后通过输入`<canvas id="tutorial" width="480" height="360"></canvas>`来添加 canvas 元素。

创建一个新的 div，其中包含一个`id`为 credits 的链接到 Michael 的网站：`<div id="credits">Based on Canvas Party by <a href="http://nuttnet.net/">Michael Nutt</a>&nbsp;&nbsp`;。然后向 div 添加一个链接，以抓取音频元素并在单击链接时应用`pause()`函数来暂停音乐。`<a href="#" onClick="document.getElementsByTagName('audio')[0].pause();">[OFF]</a></div>`。

现在，输入音频标签，并将 autoplay 设置为 true，loop 设置为 loop：`<audio autoplay="true" loop="loop">`创建两个 source 标签来包含音频格式：`<source type="audio/ogg" src="img/randomreggae.ogg" /><source type="audio/mpeg" src="img/randomreggae.mp3" />`。

在关闭音频标签之前，我们将添加一串文本，如果不支持音频标签，则会显示：`Your browser doesn't recognize the HTML5 audio tag`。

关闭音频、body 和 html 标签，并保存页面。

在创建脚本之前，打开`stylesheet.css`页面，并输入以下内容：

```html
body { margin: 0; background-color: #000; color: #FFF; font-family: Helvetica, sans-serif; }
a { color: #FFF; }
h1 { position: absolute; top: 0; margin: auto; z-index: 50; padding: 10px; background-color: #000; color: #FFF; }
div#credits { position: absolute; bottom: 0; right: 0; padding: 10px; }
audio { position: absolute; visibility: hidden; }

```

现在 HTML 和 CSS 页面已经构建完成，我们将着手处理动画脚本。创建一个新的 JavaScript 文件并命名为`animatedLines.js`。我们将把它放在一个名为`js`的新子文件夹中。

首先，我们将声明 flatten 变量并创建一个新的数组函数：`var flatten = function(array) { var r = []`。接下来，在函数内部，我们将创建一个`for`语句来声明一个以一个对象开始的数组（`var i = 0`），然后在数组长度大于`i`的情况下增加数组的大小。`for(var i = 0; i < array.length; i++) {`。使用`push`函数，我们将通过输入以下内容向数组添加新值：`r.push.apply(r, array[i]);}`，最后通过返回数组来结束函数：`return r; }`。

到目前为止，我们的脚本应该看起来像以下代码块：

```html
var flatten = function(array) { var r = [];
for(var i = 0; i < array.length; i++) {
r.push.apply(r, array[i]); }
return r; }

```

接下来，我们将创建一个名为 shuffle 的函数，它接受一个数组作为参数。输入`function shuffle(array) { var tmp, current, top = array.length`。在函数内部，我们有一个 if/while 循环来遍历数组中的值。通过输入以下内容将其添加到脚本中：`var tmp, current, top = array.length; if(top) while(--top) { current = Math.floor(Math.random() * (top + 1)); tmp = array[current]; array[current] = array[top]; array[top] = tmp; }`。在函数末尾返回数组的值。我们的随机洗牌数组值的函数现在应该看起来像以下代码块：

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

现在，我们准备创建一个全局的`canvas`变量和一个`context`变量，输入：`var canvas`;和`var ctx;`。

有了这些变量，我们可以向脚本添加`init()`函数，所有的动作都从这里开始。输入`function init() {`，然后输入语句将我们的 canvas 变量与 canvas 元素关联起来：`canvas = document.getElementById('tutorial')`。

现在，我们将创建一个`if`语句来设置我们的画布变量的宽度和高度属性：`if (canvas.getContext) {canvas.width = window.innerWidth; canvas.height = window.innerHeight - 100; ctx = canvas.getContext('2d'); ctx.lineJoin = "round"; setInterval("draw()", 300); }。这`完成了`init()`函数。

接下来，我们为浏览器窗口添加一个监听器，以便在调整大小时检测：`window.addEventListener('resize', function() {canvas.width = window.innerWidth;canvas.height = window.innerHeight - 100; });}`。

我们脚本的最新添加现在应该是：

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

我们终于准备好创建一个函数来在画布上绘制形状。这个函数将包含大部分驱动形状动画的脚本。输入`function draw(){ctx.globalCompositeOperation = "darker"; ctx.fillStyle = '#000'; ctx.fillRect(0, 0, canvas.width, canvas.height);ctx.globalCompositeOperation = "lighter";`来设置画布背景的外观。

现在，我们将输入动画中要使用的颜色。我们将创建一个包含`rgba`值的数组的数组。类型：`var colors = ["rgba(134, 154, 67, 0.8)", "rgba(196, 187, 72, 0.8)", "rgba(247, 210, 82, 1)", "rgba(225, 124, 20, 0.8)"];。我们`颜色已经定义好了，现在我们将使用一个包含宽度和高度值的单独数组的数组来设置形状的宽度和高度：`var data = [ [ [5, 20], [15, 2] ], [ [50, 12], [10, 14], [3, 21] ], [ [60, 8]], [ [30, 24], [15, 4], [10, 17] ], [ [5, 10] ], [ [60, 5], [10, 6], [3, 26] ], [ [20, 18] ], [ [90, 11], [40, 13], [15, 10] ], [ [70, 19] ], ]`。

现在，我们可以通过使用`data = shuffle(data)`来改变它们的宽度和高度来使形状动画化。

为了使形状上下以及左右移动，我们需要"压扁"或压缩它们的高度。创建一个新变量来包含`var flatData = flatten(data)`；

现在，我们将扭曲线条，使它们看起来像是在不同方向上拉动并使用`bezierCurve`。这是一个大的函数块，包含在我们之前创建的`draw()`函数中，所以输入`link()`函数如下所示：

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

现在，当我们仍然在`draw()`函数中时，让我们添加一个新变量来表示形状的起始点，然后添加一个`for`循环来创建一个可以容纳数据值集合的新变量。以下是变量和循环代码：`Var topStartingPoint = 0; for(var i in data) { var group = data[i]; var color = colors[ i % colors.length ];ctx.strokeStyle = color`。

通过创建一个嵌套的`for`循环，将一组数据值传递给一个名为`line`的新变量来进一步操作：`for(var j in group) { var line = group[j]`；然后我们可以在创建一个初始值为零的`bottomStartingPoint`变量后进行操作：`var bottomStartingPoint = 0`。

第三个嵌套的`for`循环将允许我们进一步控制形状的定位和移动：`for(var k in flatData) { if(flatData[k][1] < line[1]) { bottomStartingPoint += flatData[k][0] + 11;} }`。

最后，我们使用 link 来设置线条的顶部和底部起始点，`link(topStartingPoint, bottomStartingPoint, line[0])`；，然后将`topStartingPoint`赋值为其当前值加上线条数组。最后的语句将`topStartingPoint`值设置为其当前值加上五：`topStartingPoint += line[0]; } topStartingPoint += 5; }}`。保存脚本文件。

在浏览器中打开文件`random-animation-with-audio.html`，您应该会看到线条来回摆动，类似于以下截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_07_10.jpg)

## 它是如何工作的...

首先，我们创建了一个 HTML5 页面，其中包含指向在页面加载时导入的 JavaScript 和 CSS 文件的链接：`<script type="text/javascript" src="img/animatedlines.js"></script><link rel="stylesheet" href="css/stylesheet.css" type="text/css" media="screen" charset="utf-8" />`。为了激活我们的动画序列，我们将`init()`函数放在 HTML 页面的 body 标签中。当页面加载时，`animatedLines.js` JavaScript 文件中的`init()`函数将通过`<body onLoad="init();">`进行初始化。

我们使用`body`样式来设置页面的全局默认`margin`为`0`，`background-color`，`font color`和`font-family`。我们为基本链接颜色设置了样式，然后对`h1`标题标签进行了样式设置，以便它以`position: absolute; top: 0`的方式显示在`top`位置，并通过将`z-index`设置为`50`始终显示在大多数其他内容块的上方。`#credits` div 被定位在页面的右下角，音频标签使用`visibility: hidden`进行隐藏。

我们创建了一个名为`animatedLines.js`的新脚本，并首先定义了一系列变量和函数来控制形状的行为。

我们设置了一个名为`flatten`的数组，它会将新值添加到自身。接下来，我们需要一个函数来随机旋转数组的值。我们使用了`Math.floor(Math.random()`语句来计算一个随机数，并将结果乘以变量`top + 1`的当前值的总和。然后我们将一个整数值返回给变量`current`。

我们通过使用`document.getElementById`在页面加载时获取`canvas`元素的 ID 来定义`canvas`变量的尺寸值。我们使用 DOM 的帮助设置了`canvas`变量的`width`和`height`属性：`canvas.height = window.innerHeight - 100; ctx = canvas.getContext('2d')`；然后创建了一个语句，对`canvas`的`2d`上下文应用了`lineJoin`，参数为`round`。我们使用`setInterval()`函数将线条在画布上绘制的速度设置为`300`毫秒。数字越大，动画看起来越慢。我们为浏览器窗口添加了一个监听器，以便检测窗口的大小和画布。

然后使用`draw()`函数将形状绘制到画布上。使用`globalCompositeOperation = "darker"`来使线条在相互移动时变暗。线条在画布舞台前部重叠时，使用`globalCompositeOperation = "lighter"`来设置画布背景的外观。

用于装饰线条的颜色需要以`rgba`格式。rgba 中的'a'指的是 alpha 值，控制每种颜色的可见性。每个 rgba 值集合都包含在一个数组中，然后成为数组列表。我们需要与线条相匹配的宽度和高度值集合。这些存储在数组`var data`中。

接下来，我们将`data`数组分配给从我们的`shuffle()`函数返回的值，以便我们可以随机化屏幕上线条的外观。然后，我们将从`flatten()`函数返回的值分配给变量`flatData`。为每条线分配一个拉动值使我们能够将其移动指定数量的像素。我们将这与`bezierCurve`结合起来，使线条弯曲。

## 还有更多...

将音频标签、画布动画和 JavaScript 结合起来，听起来像是一种有趣的方式来创建酷炫的可视化效果。然而，这些效果在很大程度上依赖于浏览器的支持，因此许多网络浏览器用户目前无法正确查看它们。我的意思是，大多数标准浏览器在一两年内都无法播放它们。

### 使用尖端浏览器可视化您的音频

如果您已经下载了测试版的 Firefox 4，您就可以访问 Firefox 音频和视频 API。您将能够使用类似 Spectrum Visualizer 的工具查看和创建自己的音频可视化效果：

[`www.storiesinflight.com/jsfft/visualizer/index.html`](http://www.storiesinflight.com/jsfft/visualizer/index.html)

### 推动 HTML5 中音频的实现

Alexander Chen 一直在尝试使用音频和画布来移植基于 Flash 的应用程序。他在博客中详细介绍了使用多个音频文件时遇到的一些问题：

[`blog.chenalexander.com/2011/limitations-of-layering-html5-audio/`](http://blog.chenalexander.com/2011/limitations-of-layering-html5-audio/)

## 另请参阅

画布和


# 第八章：拥抱音频和视频

在这一章中，我们将涵盖：

+   对 Flash 说不

+   了解“音频”和“视频”文件格式

+   为每个人显示“视频”

+   创建可访问的“音频”和“视频”

+   打造时髦的“音频”播放器

+   为移动设备嵌入“音频”和“视频”

# 介绍

> “Flash 是在 PC 时代创建的-为 PC 和鼠标。Flash 对 Adobe 来说是一个成功的业务，我们可以理解他们为什么想要将其推广到 PC 之外。但移动时代是关于低功耗设备，触摸界面和开放的网络标准，这些都是 Flash 的短板。提供其内容给苹果移动设备的媒体机构的大量增加表明 Flash 不再是观看视频或消费任何类型的网络内容的必要条件。”- 史蒂夫·乔布斯

就像我们已经看过的许多其他新技术一样，在开源 HTML5 标准中，新的“音频”和“视频”元素比以往任何时候都更加成熟和可用。这是一件好事，因为用户对多媒体的期望比以往任何时候都要高。在过去，我们使用 300 比特每秒的调制解调器下载一张照片需要 10 分钟。后来，我们使用 Napster 非法下载 MP3“音频”文件。现在，我们在移动设备上播放电视和色情内容。由于带宽管道变得越来越宽，我们对互动娱乐的需求几乎是无法满足的。现在是金钱的时刻。

多年来，QuickTime、RealPlayer 和 Flash 之间的战斗是为了在网络上播放视频的统治地位。这些浏览器插件很容易安装，*通常*能产生预期的结果。

随着时间的推移，QuickTime 和 RealPlayer 继续作为播放平台，但专有 Flash 工具的制造商也创建了一个强大的开发环境，不仅让设计师，还让开发人员将其视为一个可行的平台。

虽然 QuickTime 和 RealPlayer 仍然存在，但 Flash 已经赢得了这场战争。对于动画和卡通来说，Flash 是理想的工具。但它是否仍然是最好的“音频”和“视频”播放工具呢？史蒂夫·乔布斯肯定不这么认为。

2010 年，苹果电脑的负责人乔布斯划定了界限，并表示 Flash 永远不会出现在他最畅销的 iPhone 和 iPad 上。相反，他强烈支持开放的 HTML5 标准，并引发了一场在线圣战。

很快，“Flash 的死亡”宣言成为媒体和整个博客圈的头条新闻。有些人写得如此恶毒，好像一座大坝决堤，所有积累的污秽和淤泥都被允许淹没我们的集体多媒体对话。

很快，即使非网页设计师和开发人员也开始注意到，比如 C.C.查普曼，著名书籍《内容*规则》的作者，表达了他对《今日秀》在 iPad 上不可用的不满：

![介绍](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_08_01.jpg)

这个问题迅速渗透到我们的在线娱乐讨论中。你不再需要成为网页设计师或开发人员才知道这里有一个真正的问题。

C.C.简单而直接地说话，但作者知道当谈到史蒂夫创造的 Flash/HTML5“视频”战争时，他已经说错了话。有时他争论自己的观点时过于热情和勇气，但事实是像网页设计师杰西卡·邦恩这样头脑清晰的人在提醒我们时是正确的，Flash 和 HTML5“视频”可以和平共存。

自史蒂夫发表声明以来不到一年的时间，像 ABC、CBS、CNN、ESPN、Facebook、Fox News、MSNBC、国家地理、Netflix、《纽约时报》、NPR、《人物》、《体育画报》、《时代》、Vimeo、《华尔街日报》、YouTube 等网站都采用了新的 HTML5“音频”和“视频”元素。截至目前，超过 60%的网络视频现在都支持 HTML5。可以说，新的 HTML5“音频”和“视频”功能是一些最令人兴奋和期待的新发展！

支持新 HTML5“音频”和“视频”元素的浏览器包括：

![介绍](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_08_02.jpg)

在本章中，我们将看一些现实生活中的例子，拒绝 Flash，了解新的“视频”和“音频”文件格式，为所有人显示“视频”，创建可访问的“音频”和“视频”，打造时尚的“音频”播放器，以及为移动设备嵌入“音频”和“视频”。

现在，让我们开始吧！

# 对 Flash 说不

作者的妈妈过去常说，万事都有其时机和地点，我们相信 Flash 也有其时机和地点。只是现在，随着技术的成熟，这位作者认为 Flash 的时间和地点越来越少。

![对 Flash 说不](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_08_03.jpg)

在过去的坏日子里，如果我们想在网页中使用 YouTube 视频，比如“Neutraface”，这是排版世界对 Lady Gaga 的“Pokerface”的回应，我们必须使用一些丑陋的代码，如下所示：

```html
<object width="640" height="390">
<param name="movie" value="http://www.youtube.com/v/xHCu28bfxSI?fs=1&amp;hl=en_US"> </param>
<param name="allowFullScreen" value="true"></param>
<param name="allowscriptaccess" value="always"></param>
<embed src="img/xHCu28bfxSI?fs=1&amp;hl=en_US" type="application/x-shockwave-flash" allowscriptaccess="always" allowfullscreen="true" width="640" height="390"></embed>
</object>

```

那段代码又长又丑陋，复杂，而且无法通过验证测试。它还依赖于第三方插件。呃。

多年来，我们忍受了那些垃圾，但不再了。现在我们可以重建它——我们有技术。

## 如何做...

现在我们可以使用更加优雅的东西，而不是臃肿的`object`代码：

```html
<video src="img/videosource.ogv"></video>

```

这就是所需的全部。它很简短，漂亮，而且验证通过。最重要的是，它不需要插件。再告诉我，为什么我们认为 Flash 是个好主意。

为了增加一些样式和功能，让我们再加入一点代码。

```html
<video src="img/videosource.ogv" controls height="390" width="640"></video>

```

## 它是如何工作的...

那段代码应该很简单。您可能会猜到，`src`是指源“视频”文件，`controls`表示“视频”应该使用标准的播放和音量控件播放，`height`和`width`是不言自明的。

现代浏览器现在具有自己的本机 HTML5“音频”和“视频”播放控件。让我们来看看每一个，从苹果 Safari 开始：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_08_04.jpg)

这是 Google Chrome 显示播放控件的方式：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_08_05.jpg)

微软 Internet Explorer 9 显示方式不同：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_08_06.jpg)

然后，Mozilla Firefox 以不同的方式显示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_08_07.jpg)

毫无疑问，Opera 以另一种方式显示播放控件：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_08_08.jpg)

每一个看起来都不同。如果每一个不同的外观都满足您的需求，那太好了！如果不是，那肯定需要更多的工作来使它们行为和外观相似。

## 还有更多...

还有一些可选属性我们可以包括。它们是：

+   `autobuffer` - 这个布尔属性告诉浏览器在用户点击播放按钮之前就开始下载歌曲或电影。

+   `autoplay` - 可以猜到，这告诉浏览器自动播放 HTML5“音频”或“视频”。

+   `loop` - 也是一个布尔属性，它会一遍又一遍地播放 HTML5“音频”或“视频”文件。

+   preload - preload 属性在播放之前开始加载文件。

+   `poster` - `poster`属性是在新的 HTML5“视频”加载时显示的静态占位图像。显然，这个属性不适用于 HTML5“音频”文件。

无论您添加了这些可选属性中的哪些，最终您都将得到一种更漂亮、更语义化、更可访问的显示“音频”和“视频”的方法，而不是依赖 Flash 为您提供它。

### 一些好消息

与`canvas`章节不同，关于新的 HTML5“音频”和“视频”元素的好消息是它们是可访问的。新的 HTML5“音频”和“视频”元素具有键盘可访问性。由于浏览器现在本地处理新的 HTML5“音频”和“视频”元素，它可以像有按钮而不是键一样支持您的键盘。这一点本身就可能大大促进对这项新技术的接受。

### 带有样式的视频

新的 HTML5 `音频`和`视频`元素可以使用 CSS 进行视觉样式设置。我们可以使用 CSS 不仅控制播放器的大小，还可以添加`:hover`和`:transform`效果。此外，我们可以使用 JavaScript 来控制新的 HTML5 `音频`和`视频`的行为。酷！

### Cover your assets

Flash 确实提供优势的一个领域是保护您的`音频`和`视频`内容。请记住，根据性质，新的 HTML5 `音频`和`视频`元素是开源的，没有数字版权管理。如果保护您的`音频`或`视频`文件不被下载对您来说是一个不可接受的条件，那么新的 HTML5 `音频`和`视频`元素不适合您 - Flash 可能仍然适合。这并不是说 Flash 提供了绝对的防盗保护 - 只是说，Flash 默认隐藏了查找媒体轨道的能力，而新的 HTML5 `<audio>`和`<video>`元素则将这些文件留在了公开的地方供任何人查看。然而，Flash Media Server 可以完全保护您的资产。

还不确定是选择 HTML5 音频和视频还是 Flash？试试这个实用提示列表。

HTML5 的好处包括：

+   **可访问性：** 如果可访问性对您很重要（而且应该重要），那么新的 HTML5 `音频`和`视频`元素是您最好的选择。

+   **iOS：** 如果您希望您的`音频`和`视频`能在 iPhone 或 iPad 上显示，那么 HTML5 是您唯一的选择。

+   **移动设备：** 除了苹果之外的移动设备对新的 HTML5 `音频`和`视频`元素有很好的支持。

+   `视频/音频` **流媒体：** 如果您正在流媒体的内容不是专有的，并且不需要版权管理，那么 HTML5 是您的完美选择。

Flash 的好处包括：

+   **可访问性：** 如果您不关心盲人或聋人，就不要支持他们。谁在乎你是否被起诉呢？

+   **动画：** 毫无疑问，使用 Flash 的最好理由是如果您的网站上有复杂的动画。像[`jibjab.com`](http://jibjab.com)这样的网站如果没有 Flash 就无法存在。

+   **仅桌面开发：** 如果您不需要支持移动用户。那只是一个时尚而已。

+   `视频/音频` **流媒体：** 如果您不想分享并且必须锁定您的`音频`或`视频`，使其不容易被人们下载，那就坚持使用 Flash。

+   **网络摄像头：** 如果您使用网络摄像头（除了[`chatroulette.com`](http://chatroulette.com)之外，还有谁这样做？），那么 Flash 是最好的选择。

这*真的*是使用 Flash 的最具说服力的理由吗？

![Cover your assets](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_08_09.jpg)

## 另请参阅

想要在所有主要浏览器中播放新的 HTML5 `音频`和`视频`元素，包括一直到 Internet Explorer 6？谁不想呢？如果是这种情况，请查看免费的开源 Projekktor 项目，网址为[`projekktor.com`](http://projekktor.com)。Projekktor 是 Sascha Kluger 的创意，使用 JavaScript 来确保各种支持的浏览器都能正确解释和显示特定的 HTML5 `视频`文件格式。

# 了解音频和视频文件格式

有很多不同的`音频`和`视频`文件格式。这些文件不仅可以包括`视频`，还可以包括`音频`和元数据 - 都在一个文件中。这些文件类型包括：

+   `.avi` - 这是一个过去的文件格式，音频视频交错文件格式是由微软发明的。不支持今天大多数现代的`音频`和`视频`编解码器。

+   `.flv` - Flash `视频`。这曾经是 Flash 完全支持的唯一`视频`文件格式。现在它还包括对`.mp4`的支持。

+   `.mp4`或`.mpv` - MPEG4 基于苹果的 QuickTime 播放器，并需要该软件进行播放。

## 它是如何工作的...

之前提到的每种`视频`文件格式都需要浏览器插件或某种独立软件进行播放。接下来，我们将看看不需要插件或特殊软件以及支持它们的浏览器的新开源`音频`和`视频`文件格式。

+   H.264 已经成为最常用的高清视频格式之一。它被用于蓝光光盘以及许多互联网视频流媒体网站，包括 Flash、iTunes 音乐商店、Silverlight、Vimeo、YouTube、有线电视广播和实时视频会议。此外，H.264 有专利，因此从定义上来说，它不是开源的。支持 H.264 视频文件格式的浏览器包括：![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_08_10.jpg)

### 提示

谷歌现在部分拒绝了 H.264 格式，更倾向于支持新的 WebM 视频文件格式。

+   Ogg 可能听起来很滑稽，但我向你保证，它的潜力是非常严肃的。Ogg 实际上是两个东西：Ogg Theora，这是一个视频文件格式；和 Ogg Vorbis，这是一个音频文件格式。Theora 实际上更多地是一个视频文件压缩格式，而不是一个播放文件格式，尽管它也可以用于播放。它没有专利，因此被认为是开源的。我们将在下一节讨论 Ogg Vorbis。

### 提示

有趣的事实：根据维基百科，“Theora 是以 Max Headroom 电视节目中 Edison Carter 的控制器 Theora Jones 命名的。”

支持 Ogg 视频文件格式的浏览器包括：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_08_11.jpg)

+   WebM 是在线视频文件格式竞赛中最新的参与者。这种开源的音频/视频文件格式开发是由谷歌赞助的。WebM 文件包含了 Ogg Vorbis 音频流和 VP8 视频流。它得到了许多媒体播放器的支持，包括 Miro、Moovidia、VLC、Winamp 等，包括 YouTube 的初步支持。Flash 的制造商表示未来将支持 WebM，Internet Explorer 9 也将支持。目前支持 WebM 的浏览器包括：![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_08_12.jpg)

## 还有更多...

到目前为止，这似乎是一个音频和视频文件格式的清单，最多只有零星的浏览器支持。如果你开始有这种感觉，那么你是对的。

事实上，没有一个音频或视频文件格式被确定为统治所有的真正格式。相反，我们开发人员经常不得不以多种格式提供新的音频和视频文件，让浏览器决定它最舒适和能够播放的格式。目前这是一个麻烦，但希望未来我们能够确定更少的格式，获得更一致的结果。

### 音频文件格式

还有许多音频文件格式。让我们来看看那些。

+   AAC - 高级音频编码文件更为人所知为 AAC。这种音频文件格式是为了在相同比特率下比 MP3 更好地发声而设计的。苹果使用这种音频文件格式来销售 iTunes 音乐商店的音乐。由于 AAC 音频文件格式支持数字版权管理，苹果提供受保护和未受保护格式的文件。由于 AAC 有专利，因此从定义上来说，我们不能完全称其为开源的音频文件格式。所有苹果硬件产品，包括他们的移动 iPhone 和 iPad 设备以及 Flash，都支持 AAC 音频文件格式。支持 AAC 的浏览器包括：![音频文件格式](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_08_13.jpg)

+   MP3 - MPEG-1 音频层 3 文件更为人所知为 MP3。除非你一直躲在石头下，你知道 MP3 是今天最普遍使用的音频文件格式。这些文件可以播放两个声道的声音，并且可以使用多种比特率进行编码，最高可达 320。一般来说，比特率越高，音频文件的声音就越好。这也意味着更大的文件大小，因此下载速度更慢。MP3 有专利，因此从定义上来说，我们也不能完全称其为开源的音频文件格式。支持 MP3 的浏览器包括：![音频文件格式](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_08_14.jpg)

+   Ogg - 我们之前讨论过 Ogg Theora 视频文件格式。现在，让我们来看看 Ogg Vorbis 音频格式。如前所述，Ogg 文件没有专利，因此被认为是开源的。

### 提示

另一个有趣的事实：根据维基百科，“Vorbis”是以《蓝色星球》中的角色 Exquisitor Vorbis 命名的，由特里·普拉切特的《小神灵》中的角色 Exquisitor Vorbis 命名的。

![音频文件格式](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_08_15.jpg)

### 文件格式不可知论

我们花了很多时间来研究这些不同的`video`和`audio`文件格式。每种格式都有其优点和缺点，并且受到各种浏览器的支持（或不支持）。有些比其他的更好，有些听起来和看起来比其他的更好。但好消息是：新的 HTML5 `<video>`和`<audio>`元素本身是文件格式不可知的！这些新元素不在乎您引用的是什么类型的`video`或`audio`文件。相反，它们提供您指定的任何内容，并让每个浏览器做它最擅长的事情。

### 我们能不能有一天停止这种疯狂？

最重要的是，直到一个新的 HTML5 `audio`和一个新的 HTML5 `video`文件格式成为所有浏览器和设备的明确选择，`audio`和`video`文件将不得不被编码多次进行播放。不要指望这种情况很快会改变。

# 为所有人显示视频

根据作者马克·皮尔格里姆的说法，您的 HTML5 网络`video`工作流程将如下所示：

+   制作一个使用 WebM（VP8 和 Vorbis）的版本。

+   制作另一个版本，使用 H.264 基准`video`和 AAC“低复杂度”`audio`在 MP4 容器中。

+   制作另一个版本，使用 Theora `video`和 Vorbis `audio`在 Ogg 容器中。

+   从单个`<video>`元素链接到所有三个`video`文件，并回退到基于 Flash 的`video`播放器。

Kroc Camen 在创建“面向所有人的视频”时确实做到了这一点，这是一段 HTML 代码，如果用户的浏览器可以处理它，就会显示新的 HTML5 `video`元素，如果不能，就会显示 Flash 电影 —— 这一切都不需要 JavaScript。让我们看看 Kroc 是如何做到的：[`camendesign.com/code/video_for_everybody`](http://camendesign.com/code/video_for_everybody)。

![为所有人显示视频](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_08_16.jpg)

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

仔细看，很容易看出 Kroc 做了什么。首先，他调用了浏览器本地播放的`controls`，以及新的 HTML5 `video`元素关联的`height`和`width`。

```html
<video controls height="360" width="640">

```

接下来，Kroc 依次调用每个新的 HTML5 `video`源，从 MP4 文件开始。桌面浏览器不太在乎 HTML5 `video`文件的包含顺序，但 iPad 对于想要首先指定 MP4 文件很挑剔，所以好吧。又是你赢了，史蒂夫·乔布斯。

```html
<source src="img/__VIDEO__.MP4" type="video/mp4" />
<source src="img/__VIDEO__.OGV" type="video/ogg" />

```

然后，Kroc 通过调用相同文件的 Flash `video`版本来为无法处理新的 HTML5 `video`元素的软弱浏览器打赌。

```html
<object width="640" height="360" type="application/x-shockwave-flash" data="__FLASH__.SWF">
<param name="movie" value="__FLASH__.SWF" />
<param name="flashvars" value="controlbar=over&amp; image=__POSTER__.JPG&amp;file=__VIDEO__.MP4" />
<img src="img/__VIDEO__.JPG" width="640" height="360" alt="__TITLE__" title="No video playback capabilities, please download the video below" />
</object>

```

最后，Kroc 通过提示用户选择下载新的 HTML5 `video`文件本身，无论是封闭的（MP4）还是开放的（Ogg）格式，增加了一个不错的额外功能。分享就是关怀。

```html
<p><strong>Download Video:</strong>
Closed Format: <a href="__VIDEO__.MP4">"MP4"</a>
Open Format: <a href="__VIDEO__.OGV">"Ogg"</a>
</p>

```

### 提示

当然，您会用自己文件的路径替换诸如“_VIDEO_.MP4”之类的东西。

这种方法非常成功，因为无论您使用什么网络浏览器，您都可以看到*某些东西* —— 而无需使用 JavaScript 或下载 Flash。

## 它是如何工作的...

这个概念实际上非常简单：如果您的浏览器能够播放新的 HTML5 `video`元素文件，那么您将会看到它。如果它不能支持，代码堆栈中还包括了 Flash 电影，所以您应该会看到它。如果由于某种原因，您的浏览器无法原生支持新的 HTML5 `video`元素，Flash 播放器崩溃或不可用，您将会看到一个静态图像。每个人都有所涵盖。

使用这种方法显示新的 HTML5 `video`元素的浏览器包括：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_08_17.jpg)

使用这种方法显示 Flash `video`的浏览器包括：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_08_18.jpg)

## 还有更多...

所有其他 Flash `video`嵌入方法都会提示用户下载 Flash（如果尚未安装）。而“面向所有人的视频”独特之处在于它不会这样做。作者 Kroc Camen 出于设计目的这样做，他说：

> “用户已经有足够的安全问题了，而不需要随机的网站提示他们安装东西-对于那些不想要或不能使用 Flash 的人来说，这更加恼人。”

### 浪费一个艺术家是一件可怕的事情

Kroc 提醒我们确保我们的服务器使用正确的`mime-types`，并建议将这些行放在你的`.htaccess`文件中：

```html
AddType video/ogg .ogv
AddType video/mp4 .mp4
AddType video/webm .webm

```

### 外部“Video for Everybody”

现在 WordPress 有一个“Video for Everybody”插件，网址是[`wordpress.org/extend/plugins/external-video-for-everybody`](http://wordpress.org/extend/plugins/external-video-for-everybody)。现在你也可以在你的博客上轻松使用 Kroc 的方法。

### 灵活处理你的方法

稍后，我们将研究一种方法，该方法与 Kroc 的方法实现了几乎相同的效果，但这次是使用 JavaScript。记住：做对你、你的项目和最重要的是你的客户最有意义的事情。

## 另请参阅

Humanstxt.org 是一个项目，旨在让网站背后的开发人员更加知名。该网站鼓励开发人员包含一个小文本文件，其中包含有关为创建和构建网站做出贡献的每个团队成员的信息。请访问：[`humanstxt.org`](http://humanstxt.org)。

# 创建可访问的音频和视频

我们已经非常广泛地研究了如何向人们提供在线 HTML5`video`，而不管他们的浏览器是什么，但是对依赖辅助技术的人却没有给予太多关注。现在结束了。

## 如何做到…

首先，我们将从 Kroc Camen 的“Video for Everybody”代码块开始，并研究如何使其具有可访问性，最终看起来像这样：

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

## 它是如何工作的…

你会注意到的第一件事是，我们将新的 HTML5`video`元素包装在一个包装器`div`中。虽然从语义上讲这并不是严格必要的，但它将为我们的 CSS 提供一个很好的“钩子”。

```html
<div id="videowrapper">

```

下一部分的大部分内容应该是从前一部分中可以识别的。这里没有改变：

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

到目前为止，我们仍在使用向能够处理它的浏览器提供新的 HTML5`video`元素的方法，并将 Flash 作为我们的第一个备用选项。但是，如果 Flash 不是一个选择，接下来会发生什么很有趣：

```html
<track kind="captions" src="img/videocaptions.srt" srclang="en" />

```

你可能会想，那是什么鬼。 

> “`track`元素允许作者为媒体元素指定显式的外部定时文本轨道。它本身不代表任何东西。”- W3C HTML5 规范

现在我们有机会使用 HTML5 规范的另一个新部分：新的`<track>`元素。现在，我们可以引用`kind="captions"`中指定的外部文件类型。你可以猜到，`kind="captions"`是用于字幕文件，而`kind="descriptions"`是用于`audio`描述。当然，`src`调用特定文件，`srclang`设置新的 HTML5`track`元素的源语言。在这种情况下，`en`代表英语。不幸的是，目前没有浏览器支持新的`track`元素。

最后，我们允许最后一点备用内容，以防用户无法使用新的 HTML5`video`元素或 Flash 时，我们给他们一些纯文本内容。

```html
<p>Final fallback content</p>

```

现在，即使用户看不到图像，他们至少会得到一些描述性内容。

接下来，我们将创建一个容器`div`来容纳我们基于文本的字幕。因此，目前没有浏览器支持新的 HTML5`audio`或`video`元素的闭合字幕，我们必须留出空间来包含我们自己的：

```html
<div id="captions"></div>

```

最后，我们将包括 Kroc 的文本提示，以下载 HTML5`video`的封闭或开放文件格式：

```html
<p><strong>Download Video:</strong>
Closed Format: <a href="__VIDEO__.MP4">"MP4"</a>
Open Format: <a href="__VIDEO__.OGV">"Ogg"</a>
</p>

```

## 还有更多…

除了新的 HTML5`audio`和`video`元素的可选`controls`属性之外，还有可选的`loop`属性。你可能会猜到，这个例子将允许 HTML5`video`一直播放：

```html
<video controls height="360" loop width="640">

```

### 始终考虑可访问性

我们默认的最终描述性内容可能是为使用辅助技术的人提供可下载链接的替代位置。这将使能够看到或听到的人无法下载，因此您应确定这种方法是否适合您。

### 浏览器支持

对于新的 HTML5“音频”和“视频”元素，具有最佳辅助功能支持的网络浏览器包括：

![浏览器支持](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_08_19.jpg)

### 查看更多

您可以在[`html5accessibility.com`](http://html5accessibility.com)上跟踪 HTML5 的可访问性。该网站跟踪新的 HTML5 功能，如“音频”和“视频”，以及在哪些浏览器中可用。您可能会惊讶地发现，截至目前，Opera 是最不友好的可访问性网络浏览器，甚至低于微软 Internet Explorer 9。令人惊讶。

## 另请参阅

Video.Js 是另一个免费的开源 HTML5 视频播放器。它轻巧，不使用图像，但仍然可以通过 CSS 完全定制。它看起来很棒，并支持苹果 Safari，谷歌 Chrome，微软 Internet Explorer 9，Mozilla Firefox 和 Opera，同时还支持 IE 6-8 的回退。它甚至适用于 iPhone，iPad 和 Android 等移动设备。在[`videojs.com`](http://videojs.com)上查看。

# 打造时尚的音频播放器

Neutron Creations 的负责人兼联合创始人兼前端开发人员 Ben Bodien 为 Tim Van Damme 的 The Box 播客创建了定制的 HTML5“音频”播放器，网址为[`thebox.maxvoltar.com`](http://thebox.maxvoltar.com)。Ben 的创作快速，直观且时尚。让我们更深入地了解他是如何做到的。

![打造时尚的音频播放器](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_08_20.jpg)

Ben 的自定义 HTML5“音频”播放器具有被采访者（在这种情况下是 Shaun Inman）的吸引人照片，播放/暂停按钮，显示播放进度的轨道，以及如果您选择的话，将 HTML5“音频”播放器弹出到单独的窗口的能力。就是这样。没有更多的需要。作为一个额外的触摸，注意 HTML5“音频”播放器栏的轻微透明度的细节。平滑。

## 如何做...

起初，Ben 的标记似乎看起来简单欺骗人：

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

等一下，我听到你在想，“HTML5`音频`标签在哪里？！”别担心。Ben 是个聪明人，对此有计划。但首先让我们看看他到目前为止做了什么。

```html
<p class="player">

```

到目前为止，这很简单。Ben 创建了一个包装元素（在这种情况下是`<p>`）来放置他的播放器。他可以使用`<div>`代替吗？也许。做对你和你的项目最有意义的事情。

```html
<span id="playtoggle" />

```

然后，Ben 使用这个自闭合的（注意末尾的斜杠）`span`来进行播放/暂停切换按钮。

```html
<span id="gutter">
<span id="loading" />
<span id="handle" class="ui-slider-handle" />
</span>

```

现在，事情变得有趣起来。Ben 的“gutter”`span`容纳了时间轴跟踪，其中有一个指示 HTML5“音频”文件加载或缓冲进度的条形元素，以及指示播放头的圆形元素，如果您选择，可以来回“擦洗”。

```html
<span id="timeleft" />

```

最后，Ben 使用另一个自闭合的`span`来显示剩余时间，以分钟和秒为单位。

### 提示

`<span>`元素可以胜任，但它并不是非常语义化，是吗？Patrick H. Lauke 迅速指出，使用可聚焦元素将大大提高这种方法对依赖辅助技术的人的可访问性。

## 它是如何工作的...

Ben 使用 jQuery 来检测对 HTML5“音频”的支持。

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

在这段代码中，我们可以看到，如果浏览器支持 HTML5“音频”，它将提供完整的 HTML5`<audio>`标签，包括对`.ogg，.mp3`和`.wav`的回退，这是我们尚未使用过的文件格式。由于新的 HTML5`<audio>`和`<video>`元素是文件格式不可知的，因此`.wav`文件也应该可以正常工作。

Ben 创建了一个简单的 JavaScript 代码，允许浏览器做他们感觉最舒适的事情。如果这种方法对您和您的项目有意义，请考虑这种方法，但请记住，您依赖 JavaScript 来完成繁重的工作，而不是我们已经看过的其他不依赖它的方法。

### 提示

请注意，如果您使用`<div>`来包含 HTML5 的`video`播放器，那么 JavaScript 也必须进行调整。简单地说，`<p class="player">` … `</p>`将被更改为`<div class="player">` … `</div>`。

## 还有更多...

到目前为止，我们已经为播放器设置了标记，并“嗅探”了任何特定浏览器想要的文件格式。现在，我们需要添加一些功能。

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

然后添加一个函数来计算播放头的位置，以确定剩余时间，注意如果剩余时间需要，要包括前导零。

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

唯一剩下的就是调用播放/暂停按钮的功能。

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

在简单的标记和详细的 JavaScript 之后，创建本的定制 HTML5 `audio`播放器，唯一剩下的就是对其进行样式设置：

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

当包裹的内容引人入胜时，花时间创造有趣的东西会更容易且更有意义。Box 音频采访总是很有趣——只是遗憾的是作者 Tim Van Damme 并不经常发布它们。希望将来会有所改变。请访问[`thebox.maxvoltar.com`](http://thebox.maxvoltar.com)查看。

### 注意细节

当页面上一次只有一个新的 HTML5 `audio`或`video`元素时，这种方法效果很好。如果您需要多个，您将需要修改 JavaScript 以连接到标记中的多个“挂钩”。

## 另请参阅

SublimeVideo 采用了一种不同的方法来进行 HTML5 在线`video`播放：在这种情况下，播放器不是由您创建或托管的，而是由播放器制造商自己在云中创建的。好处是您始终拥有可能的最新、最新鲜的播放器版本。这样，当新功能可用或错误修复时，您无需做任何操作。您自动拥有最新的功能。请访问[`sublimevideo.net`](http://sublimevideo.net)查看。

# 为移动设备嵌入音频和视频

到目前为止，我们只是简单地涉及了移动体验，但随着对越来越智能的移动设备的开发增加，我们需要把注意力转向如何在这些设备上显示我们的新 HTML5 `audio`和`video`。以下是方法。

## 如何做...

既然我们知道如何为目标受众选择 HTML5 `audio`或`video`文件格式，现在我们可以把注意力转向确保他们不仅可以在台式电脑和笔记本电脑上听到或观看，还可以在移动设备上听到或观看。

我们将从[`vimeo.com`](http://vimeo.com)创建一个免费账户。注册完成后，在主菜单中选择上传|视频功能。您将选择要上传的文件，添加可选的元数据，然后让 Vimeo 服务器设置您的文件。接下来就是真正的激动人心的时刻：嵌入`video`。从 Vimeo 主菜单中选择**工具**|**嵌入此视频**。

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_08_21.jpg)

## 它是如何工作的...

Vimeo 以前使用的是我们之前看过的老式 Flash 嵌入方法。现在它使用基于 iFrame 的方法，可以让 HTML5 `video`在 iPhone、iPad 和其他移动设备上播放。以下是一个示例，基于作者上传的`video`：

```html
<iframe src="img/20958090" width="400" height="300" frameborder="0"></iframe><p><a href="http://vimeo.com/20958090">Untitled</a> from <a href="http://vimeo.com/user6281288">Dale Cruse</a> on <a href="http://vimeo.com">Vimeo</a>.</p>

```

## 还有更多...

一旦您将基于 iFrame 的代码片段复制并粘贴到网页上，并在 iPhone 或 iPad 上查看它，您应该会看到一个移动友好的 HTML5 `video`，您可以像这样使其全屏：

![还有更多...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_08_22.jpg)

### Vimeo 提供了更多

Vimeo 还允许您从电子邮件联系人列表中添加朋友，创建`video`订阅，制作小部件等等。他们现在甚至提供视频学校，帮助用户了解捕捉、编辑和分享`video`的最有效方法。

### 全方位的

YouTube，世界上最受欢迎的在线视频观看网站，现在也使用基于 iFrame 的嵌入视频的方法。我们可以采用本章开头使用的“Neutraface”视频，使用新的基于 iFrame 的嵌入方法，最终得到更具语义和友好性的结果。它也通过了验证！

```html
<iframe title="YouTube video player" width="1280" height="750" src="img/xHCu28bfxSI?rel=0&amp;hd=1" frameborder="0" allowfullscreen></iframe>

```

看看这样多漂亮！

我们已经完成了一整个循环，并完全改变了我们在现代浏览器中捕捉、编辑和播放视频的能力，同时支持那些依赖辅助技术和移动设备的人。这是一个可以发展的方向。

## 另请参阅

Adobe 是否在自掘坟墓？几乎没有。2011 年初，Adobe 推出了一个名为“Wallaby”的免费 Flash 到 HTML5 转换器。不幸的是，许多设计师和开发人员认为 Adobe 在声称 Wallaby 可以使用 Web 标准将 Flash 导出到 HTML5 时过于夸大其词。事实上，它所做的只是将在 Flash CS5 或更高版本中创建的最简单的动画转换为简单的标记和样式。它没有能力将 ActionScript 转换为 JavaScript，这种能力才会真正使该工具有价值。在 John Nack 的博客上查看有关 Wallaby 公告的信息[`blogs.adobe.com/jnack/2011/03/wallaby-flash-to-html5-conversion-tool-now-available.html`](http://blogs.adobe.com/jnack/2011/03/wallaby-flash-to-html5-conversion-tool-now-available.html)。


# 第九章：数据存储

在本章中，我们将涵盖：

+   测试浏览器是否支持数据存储

+   使用浏览器开发工具监视 Web 存储

+   设置和获取会话存储变量

+   设置和获取本地存储变量

+   将本地存储字符串转换为数字使用`parseInt`

+   创建 Web SQL 数据库

+   使用 Web SQL 数据库

+   创建缓存清单并离线使用站点

+   使用 Geolocation API 和`geo.js`显示当前位置

# 介绍

HTML5 引入了一种新的存储信息的方式，而不使用 cookie。这为设计师和开发人员提供了更多的灵活性，以处理和显示动态内容。我们将从测试浏览器是否支持三种主要数据存储方法开始，并最终创建一个使用本地存储来存储和访问视频的 HTML5 页面。尽管这些示例都是基于彼此构建的，但您不必按照它们呈现的顺序完成它们。本章的示例文件可在[`www.packtpub.com/support?nid=7940`](http://www.packtpub.com/support?nid=7940)上下载。

# 测试浏览器是否支持数据存储

知道如何快速测试浏览器是否支持您想要使用的数据存储方法将使页面和应用程序的开发更加容易。在这个示例中，我们将创建一个脚本，查询浏览器的 DOM，以测试对不同数据存储方法的支持。

## 做好准备

您将需要访问现代浏览器，如 Firefox 3.6，或流行浏览器的最新版本，如 Google Chrome，Opera，Safari 或 Internet Explorer。

## 如何做...

首先，我们将创建一个简单的 html 页面。打开一个 HTML 编辑程序或文本编辑器，并输入基本 HTML5 页面的起始代码：

```html
<!doctype html><html lang="en"><head><title>Client-side Storage Test for HTML5</title>
<meta charset="utf-8">

```

现在需要对测试页面的外观进行样式设置。我们将在 HTML 页面的`<head>`标记中使用`<style>`标记，但您也可以将它们放在单独的 CSS 文件中。

```html
<style>
#results { background-color: #ffcc99; border: 1px #ff6600 solid; color: #ff6600; padding: 5px 20px; margin-bottom: 10px; }
#results .value { font-weight: bold; }
#results h3 { color: #333333; }
</style>

```

输入一个关闭的`head`标记，然后创建一个`body`标记如下所示。请注意，主要区别在于我们在页面加载时调用`RunTest()`函数来激活。

```html
</head><body onload="RunTest();">

```

创建一个段落标记，其中包含类似下面所示的描述性文本。关闭标记，并创建一个包含结果标题的`<h3>`标题标记。

```html
<p>Does your browser support all storage methods?</p>
<div id="results"><h3>Browser Data Storage Support Results</h3>

```

现在，输入每种存储方法，然后输入一个由类值样式化的 span 标记。输入存储方法的 ID 和文本“不支持”。关闭 span 标记并添加一个换行标记，以便在浏览器窗口中将结果分开显示在单独的行上。结果显示区域应该如下代码块所示：

```html
Session Storage: <span class="value" id="session">not supported</span><br/>
Local Storage: <span class="value" id="local">not supported</span> <br />
Database Storage: <span class="value" id="db">not supported</span> <br /></div>

```

我们几乎完成了创建我们的测试页面。创建一个段落来解释测试的目的。用`<footer>`标记结束内容区域，以包含我们接下来要添加的脚本块。描述性文本应如下代码所示：

```html
<p>The test above shows whether the browser you are currently using supports a data storage method.</p> <footer>

```

现在，我们将添加`script`标记，以便浏览器处理一个小型测试程序：

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

将文件保存为`data-storage-support-test.html`，并在浏览器窗口中打开它。您应该看到类似以下截图的结果：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_09_01.jpg)

## 它是如何工作的...

我们创建的 HTML5 测试页面使用了一小段 JavaScript 代码来查询浏览器是否支持特定的存储方法。我们首先编写了一个标准的 HTML5 页面，包括适当的`<html>`，`<head>`和其他文档标签。如果您需要复习它们，它们在本书的早期章节中有介绍。接下来，我们使用简化的`<script>`标签设置了 JavaScript 代码片段的开头块。HTML5 JavaScript API 在本书的其他地方有更详细的介绍。我们创建了一个名为`RunTest()`的函数来包含变量和代码。然后创建了两个变量。变量`supp`被赋予了一个空字符串的值。这将包含每种存储方法的最终支持结果。我们正在循环遍历 window 对象的属性。在每次迭代中，当前属性暂时存储在`mydata`变量中。这使我们能够测试属性与三种情况进行比较。

接下来，我们使用 switch 语句来测试`mydata`变量与我们感兴趣的特定属性。因为我们一次只测试一个值，而且列表很短，这是测试每种存储方法支持的好方法。`switch`语句的主体包含三种情况，每种情况对应一种存储方法。每种情况都包含一个必须评估的表达式。如果支持存储方法，则每种情况的最终操作是将文档主体中结果文本的值从“不支持”更改为“支持”，如果表达式评估为真。如果情况评估为假，则页面结果部分显示的文本将保持不变。

创建代码后，我们使用 CSS 样式控制了结果的呈现。使用一个名为 results 的 div 标签创建了一个用于显示框的容器，并指定了背景颜色、字体颜色和粗细。这是 html 页面头部的最后一个代码块。

然后创建了页面的主体部分。使用`onload`命令设置了页面在浏览器中加载时激活测试。编写了结果框的开头文本和标题，并将每个结果的显示文本与唯一的 ID 相关联。然后输入了闭合标签以完成页面。保存页面后，当在浏览器窗口中查看测试页面时，结果将显示在屏幕上。截图中使用的浏览器是 Firefox 3.6.13。我们看到的结果反映了 Firefox 在 3.6 和 4.0.3 版本中对存储方法的当前支持。这帮助我们确定我们可以期望 Firefox 访问者轻松查看和使用依赖本地存储和会话存储方法的网页上的任何功能。他们将无法利用任何依赖于 WebSQL 的功能。

## 还有更多...

测试网站和在线应用程序从未如此简单。有许多可用的工具和服务可用于在不同平台和浏览器上进行测试。

### 移动测试

您可以在智能设备上下载多个浏览器，如 iPod Touch 或 iPad，从而可以测试移动设备和不同浏览器上丰富媒体内容的响应性。

### Adobe 浏览器实验室

不需要 Adobe CS5 即可尝试 Adobe BrowserLab，这是一个与 Adobe CS5 产品集成的在线跨浏览器测试工具。访问[`browserlab.adobe.com`](https://browserlab.adobe.com)了解更多信息。

### 使用 BrowserShots 进行免费的跨浏览器和操作系统测试

对于预算有限且有时间的人来说，[BrowserShots.org](http://BrowserShots.org)是一个替代选择。该网站允许访问者输入其网站的 URL，然后从庞大的浏览器和操作系统列表中进行选择。使用免费版本的服务可能需要几分钟才能看到结果。

# 使用浏览器开发工具监视 Web 存储

Web 存储可能很难测试。使用浏览器中的开发者工具，如 Safari 或 Firefox 附加组件，如 Firebug，可以更容易地诊断问题并跟踪变量的值。在这个示例中，我们将使用 Google Chrome 浏览器中的原生开发者工具来探索浏览器本地存储区中存储的键/值对。

## 准备工作

您需要一个最新版本的 Google Chrome 浏览器和本章的一个本地存储代码文件。

## 如何操作...

在 Google Chrome 浏览器窗口中打开本章中的一个本地存储练习文件。

点击**查看**，从**查看**菜单中选择**开发者**，然后从**开发者**弹出菜单中选择**开发者工具**。

当**开发者**窗口出现在当前页面上时，选择**资源**选项卡，点击 Google Chrome 开发者工具窗口导航区域中的**本地存储**，然后选择其中的子菜单。您应该看到类似以下截图的结果：

![如何操作...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_09_02.jpg)

在 Google 开发者工具窗口的资源选项卡下的本地存储部分，我们可以访问每个页面的本地存储区域。它在屏幕右侧显示键和它们对应的值。如果右键单击对象，您将有删除它的选项。

## 工作原理...

我们加载了一个我们知道使用本地存储的页面，以测试 Google Chrome 浏览器中的 Google 开发者工具窗口如何显示键/值对。

当我们在开发者工具的左侧菜单中导航时，我们可以选择不同的 Web 存储方法和其他资源。

## 还有更多...

有许多免费的插件和原生浏览器工具供开发人员利用。

### 即使不使用 Firefox，也可以使用 Firebug 附加组件

Firefox 用户长期以来一直在使用 Firebug 附加组件（[`getfirebug.com/downloads`](http://getfirebug.com/downloads)）来调试和浏览网站和其他在线应用程序。Opera、Google Chrome、Safari 和 IE 6+的用户可以使用 Firebug Lite（[`getfirebug.com/firebuglite`](http://getfirebug.com/firebuglite)），并通过轻量级的书签工具体验类似的功能，他们可以轻松地添加到他们的浏览器中。

### Safari 开发者工具是 Safari 浏览器的原生工具

在打开 Safari 浏览器时，点击**Safari**，选择**首选项**，然后点击**高级**选项卡。点击“在菜单栏中显示**开发菜单**”旁边的复选框，开始使用原生开发者工具。

# 设置和获取会话存储变量

会话存储和本地存储都共享 Web 存储 API。在这个示例中，我们将定义两个会话存储变量，然后在屏幕上显示它们。

## 准备工作

您需要一个支持会话存储的最新版本的浏览器。如果您在本地计算机上测试文件，Safari 和 Google Chrome 会有最佳响应。

## 如何操作...

首先，我们将创建一个 HTML5 页面的头部区域和一个开放的`body`标签：

```html
<!DOCTYPE HTML><html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8"><title>Show me the session storage</title></head><body>

```

添加一个`section`和一个`article`标签。给 article 标签一个 ID 为“aboutyou”。

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

结果应该在浏览器中的 HTML 页面上显示，类似于以下截图中显示的方式：

![如何操作...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_09_03.jpg)

## 工作原理...

在这个示例中，我们为两个会话变量设置了唯一的值。会话存储使用键/值对，因此在创建时必须为每个变量设置一个值。默认情况下，这些值都是字符串。

我们通过输入`sessionStorage.setItem('`为人的昵称定义了一个会话变量，然后为我们的变量添加了一个名称。

我们将变量命名为`"nickname"`，并赋予它值“Jumpin Joseph”：`'nickname', 'Jumpin Joseph')`。

当我们创建第二个会话变量来包含名为`"interest"`的变量及其值时，我们使用了与设置第一个会话变量时相同的语法格式。

尽管通常这些变量将由表单中的值填充，但我们在示例中专注于使用正确的语法。`sessionStorage`关键字标识了存储方法的类型。我们在关键字后面加上一个句点，附加了`setItem`动作到关键字上。然后声明了变量`nickname`并赋予了值`Jumpin Joseph`。当使用时，这将告诉浏览器创建一个名为`nickname`的新会话存储变量，并将`Jumpin Joseph`的值存储在其中。然后我们创建了第二个会话存储变量，只是因为我们可以。在本章的本地存储示例中，我们将使用表单来获取本地存储变量的值，以便全面了解存储方法的创建、使用和销毁的完整生命周期视图。

## 还有更多...

会话存储为我们提供了一种更强大的方式来提供短期客户端存储。

### 一个浏览器，一个会话

会话存储最适合于不需要访问者使用多个浏览器标签来浏览网站，并且需要存储是临时的情况。虽然 HTML5 规范的数据存储区域仍在不断发展，安全性在金融机构或其他需要高度安全信息的网站使用方面并没有长期的记录，但仍然有许多有用的方法可以利用会话存储。

## 另请参阅

*设置和获取本地存储变量的教程*。

# 设置和获取本地存储变量

尽管会话存储是临时的，只在浏览器会话处于活动状态时持续。本地存储甚至在关闭浏览器后仍然存在。在这个教程中，我们将使用 HTML5 的`contenteditable`属性和本地存储创建一个故事写作应用程序。

## 准备工作

您应该使用最近更新的浏览器。这个教程在 Google Chrome 和 Safari 中效果最佳，但在 Firefox 中也可以正常运行。

## 如何做...

首先创建一个基本的 HTML5 页面，然后在开放和关闭的`head`标签之间添加一个脚本标签。脚本应该链接到 1.5.2 最小化的 jQuery 库，网址为[`ajax.googleapis.com/ajax/libs/jquery/1.5.2/jquery.min.js`](http://ajax.googleapis.com/ajax/libs/jquery/1.5.2/jquery.min.js)。您的代码现在应该类似于以下代码块：

```html
<!DOCTYPE html><html lang="en"><head><script src="img/ jquery.min.js"></script> <meta http-equiv="Content-Type" content="text/html; charset=utf-8"> <title>Local Storage: Storywriter</title>

```

接下来，我们将添加 CSS 样式来设置文章标签的`background-color`和文本`color`，以及`font-family`。

```html
<style> article{background-color: #9F6;color:#333; font-family:Verdana, Geneva, sans-serif} p{} </style>

```

关闭`head`标签并为`body`和`header`元素创建开放标签。添加一个`h1`标签来显示页面标题为`Storywriter`，然后关闭`header`标签。

```html
</head><body> <header> <h1>Storywriter</h1> </header>

```

为`section`和`article`元素创建开放标签。将`article`元素的 id 设置为“mypage”，并将`contenteditable`属性设置为“true”。

```html
<section><article id="mypage" contenteditable="true">

```

接下来，创建一个包含占位文本`type something`的段落标签，然后关闭段落、`article`和`section`标签。在两个`em`标签之间添加描述性的指令文本。您刚刚输入的内容应该如下所示的代码：

```html
<p>type something</p> </article> </section><em>And then what happened? I'll remember next time you open this browser. </em>

```

创建一个`script`标签，然后通过键入`$(function(){`声明 jQuery 函数。

使用参数字符串“mypage”调用`document.getElementById`方法，将其分配给变量'edit'。

接下来，我们需要添加一个由“edit”元素的模糊事件触发的事件处理程序。键入`$(edit).blur(function(){`，然后键入`localStorage.setItem('storyData", this.innerHTML);})`;以完成函数。

现在，由于本地存储可以使用`setItem`存储字符串，我们可以使用`getItem`通过键入`if ( localStorage.getItem('storyData') ) { edit.innerHTML = localStorage.getItem('storyData'); } })`将存储的字符串内容推送回页面。

脚本代码块现在应该如下所示：

```html
<script>$(function() { var edit = document.getElementById('mypage'); $(edit).blur(function() { localStorage.setItem('storyData', this.innerHTML); }); if ( localStorage.getItem('storyData') ) { edit.innerHTML = localStorage.getItem('storyData'); } });</script>

```

关闭 body 和 HTML 标签，并保存文件。在浏览器窗口中打开它。现在，您应该能够开始输入自己的故事，并在页面上看到输入的文本，即使您关闭浏览器，稍后再次打开它。它应该看起来类似于以下的屏幕截图：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_09_04.jpg)

## 它是如何工作的...

当我们将`article`标签的`contenteditable`属性设置为`true`时，我们告诉浏览器允许用户输入文本。大多数 HTML5 元素都可以声明`contenteditable`属性，然后将其设置为`true`或`false`。然后，我们使用`document.getElementById`使用 ID`mypage`捕获输入的内容。`getElementById` jQuery 方法会在其参数中搜索特定 ID 名称的文档。然后，我们在`blur`事件上添加了一个事件处理程序，以使输入的文本看起来更加平滑。同时，我们还使用本地存储方法`setItem`和变量`storyData`存储文本。最后，我们使用`getItem`本地存储方法来检查`storyData`是否存在，如果存在，则将其加载到可编辑的 HTML 元素中，使用`edit.innerHTML`和`getItem`。

## 另请参阅

本书的前几章介绍了 HTML5 元素和 PACKT jQuery 书籍。

# 使用`parseInt`将本地存储的字符串转换为数字

在这个示例中，我们将从本地存储中获取一个字符串值，并将其转换为整数，以便我们可以使用`parseInt`进行数学运算。

## 准备工作

我们将使用 Modernizr ([`www.modernizr.com`](http://www.modernizr.com))来检测本地存储是否可用，将其托管在名为"js"的子文件夹中。您还需要至少一个最近更新的浏览器。

## 如何做...

按照下面的代码块创建一个新的 html 页面的开始，直到标题标签为止：

```html
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"> <title>Using numbers with local storage</title>

```

接下来，添加样式来指定`h1`和`h2`标签的字体族、文本颜色，以及`h2`标签的背景颜色和高度。

```html
<style>body{font-family:Verdana, Geneva, sans-serif;} h1{color:#333; }h2{color:#C30;background-color:#6CF; height:30px;}</style>

```

添加一个由 Google 托管的 IE HTML5 shiv，并添加一个指向本地 Modernizr JavaScript 文件的链接：

```html
<!--[if IE]><script src="img/html5.js"></script> <![endif]--><script type="text/javascript" src="img/ modernizr-1.7.min.js"></script>

```

使用 Modernizr 脚本来检查浏览器是否支持本地存储：

```html
<script>if (Modernizr.localstorage) {
// window.localStorage is available!}
else {// the browser has no native support for HTML5 storage document.getElementByID('yayanswer').innerHTML = "Local Storage is not supported by your browser. Maybe it's time for an update?";}

```

创建一个名为`storemyradius()`的函数，声明一个名为`myradiusToSave`的变量，并将其赋值为`document.getElementById('myradius').value`；以便在访问者点击保存时将输入的数值传递到文本字段中。

```html
function storemyradius() {var myradiusToSave = document.getElementById('myradius').value;

```

添加一个`if`语句来检查`myradiusToSave`是否为 null。在此之下，创建一个本地存储`setItem`方法，键为"myradius"，值为"myradiusToSave"。在`if`语句的闭合括号和`storemyradius`函数的闭合括号之前，放置一个对`displaymyradius()`的函数调用，如下面的代码块所示：

```html
if (myradiusToSave != null) { localStorage.setItem('myradius', myradiusToSave);displaymyradius();}}

```

创建一个名为`displaymyradius`的函数，不接受任何参数，然后添加一个名为`myradius`的变量。将其赋值为包含一个本地存储`getItem`方法的 JavaScript 函数`parseInt`，参数为"myradius"，基数为 10。到目前为止，函数应该如下面的代码块所示：

```html
function displaymyradius() { var myradius = parseInt(localStorage.getItem('myradius'),10);

```

在同一个函数中，创建一个`if`语句，用于检查`myradius`变量是否不为 null 且大于零。创建变量`diameter`，并将其值赋为`2`乘以`myradius`的结果。使用`document.getElementById`和`innerHTML`来显示直径变量的值，以及在 HTML 页面的`h2`标签之间显示消息"The `diameter of the circle is`"。

```html
if (myradius != null && myradius > 0) {var diameter = 2 * myradius;document.getElementById('yayanswer').innerHTML = "The diameter of the circle is: " + diameter + "!";}}

```

创建一个名为`clearmyradius`的函数，不接受任何参数，然后创建一个`if`语句，检查本地存储`getItem`方法是否包含一个不为 null 的值。在`if`语句的括号之间，放置本地存储`removeItem`方法，参数为字符串"myradius"，以及对本地存储`clear`方法的调用。关闭脚本和头标签。我们刚刚写的代码应该看起来类似于以下的代码块：

```html
function clearmyradius() {if (localStorage.getItem('myradius') != null) {localStorage.removeItem('myradius'); window.localStorage.clear();}}</script></head>

```

创建开放的 body、section、`hgroup`和`h1`标签，在关闭的`h1`标签之前输入`"localStorage Number Conversion"`。创建一个`h2`标签，并为其分配一个 ID 为`"yayanswer"`。关闭`hgroup`标签，然后为`myradius`文本字段添加一个标签标签。输入标签文本为`"输入圆的半径:"`。创建一个带有 ID 为`"myradius"`和`maxlength`为`"4"`的输入表单字段标签。创建两个输入按钮，一个带有`onclick`值调用函数`storemyradius()`；另一个带有`onclick`值调用函数`clearmyradius()`。关闭 section、body 和 html 标签，并保存页面。最终的代码块应该如下所示：

```html
<body ><section><hgroup><h1>localStorage Number Conversion</h1> <h2 id="yayanswer"></h2></hgroup><label for="myradius">Enter the radius of the circle:</label><input id="myradius" maxlength="4" /> <input onclick="storemyradius();" name="save" type="button" value="save"><input onclick="clearmyradius();" name="clear" type="button" value="clear"></section></body></html>

```

在 Google Chrome 浏览器窗口中，完成的 HTML 页面应该如下所示：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_09_05.jpg)

## 它是如何工作的...

在 HTML 页面中显示的文本字段接受访问者输入并将其作为值传递给`storemyradius()`函数。我们声明了一个名为`myradiusToSave`的变量，并将其分配为`document.getElementById('myradius').value`；它存储了`myradius`中包含的值。然后，它将传递到本地存储的`setItem`方法中。在将值传递到本地存储之前，我们需要验证`myradiusToSave`实际上包含的值不是 null。如果不是 null，则有数据保存到本地存储。然后，该值作为键/值对的一部分保存到本地存储中，使用`setItem`。为了将`myradius`值作为数字使用，我们需要将其从字符串转换为整数。这是通过调用`parseInt` JavaScript 函数来完成的。接下来，我们创建了一个名为`diameter`的变量，用于保存我们的直径公式的结果，即半径值的两倍。最后，我们使用`getElementbyId`方法将结果返回到屏幕上。

另一个页面上的选项是清除本地存储变量的值。虽然我们本可以使用`removeItem`方法，但同时使用 clear 方法可以确保没有其他潜在的本地存储变量。通过打开 Google 开发者工具刷新页面，可以验证本地存储区域为空。

## 还有更多...

当前，默认情况下`localStorage`将所有数据存储为字符串。我们刚刚练习了将`localStorage`变量转换为整数，但它们也可以转换为数组等对象。 

### 在 localStorage 中存储和检索数组

在许多情况下，您会希望使用`localStorage`与数组一起保存游戏中的进度或保留用户数据或消息。您可以使用 Douglas Crockford 的 JSON 库来简化数组的存储和检索。访问[`github.com/douglascrockford/JSON-js`](http://https://github.com/douglascrockford/JSON-js)下载代码并了解更多关于 JSON 的信息。

创建一个新的 HTML5 页面，并在两个页脚标签之间添加脚本标签。声明一个名为"horsedef"的新变量数组，并将其分配为以下键/值对，如下所示：

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

保存页面，打开浏览器窗口。您应该看到一个警报框，显示传递给`describehorse`的`horsedef`数组中的键/值对，如下面的屏幕截图所示：

![在 localStorage 中存储和检索数组](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_09_06.jpg)

### 提示

在使用 JSON 时要注意跨站点回调。通常最好从自己的服务器下载并使用文件。始终直接从源下载 JSON 的副本。不要上当受骗，比如 JSONP。

# 创建 Web SQL 数据库

在这个示例中，我们将创建一个 Web SQL 数据库，并赋予它定义版本、名称、大小和描述的属性。

## 准备工作

您需要使用支持 Web SQL 数据库的当前浏览器。

## 如何操作...

创建一个新的 HTML5 文件，并在两个页脚标签之间放置打开和关闭脚本标签。声明一个名为`db`的变量，然后将`openDatabase()`赋给它。给`openDatabase`以下参数：`'mymotodb', '1.0', 'Motocross Rider List DB', 2 * 1024 * 1024`，然后关闭声明。代码应该看起来像以下代码片段：

```html
<script>var db = openDatabase('mymotodb', '1.0', 'Motocross Rider List DB', 2 * 1024 * 1024);</script>

```

保存文件。

## 它是如何工作的...

所有 Web SQL 数据库都使用`openDatabase`方法来为数据库分配值。第一个参数“mymotodb”是数据库的名称。下一个必需的参数是版本号。这里的数字必须与用户尝试使用 Web SQL 数据库时匹配。接下来，我们定义了数据库的描述，然后是估计的大小。一旦为请求的`openDatabase`方法定义了所有参数，数据库就被创建了，并且进行了第一次（不可见的）事务——数据库本身的创建。

## 还有更多...

诸如 Web SQL 数据库之类的规范的浏览器实现一直非常不可预测，同样，Web 开发社区对这些规范本身的支持也是如此。

### Web SQL 可能会被 SQLite 取代

Web SQL 数据库规范本身已不再由 W3C 维护，但在大多数浏览器中运行得相当好。可能在接下来的一年左右，足够多的主要利益相关者将会就如何实现不同的客户端数据库解决方案达成一致，比如 SQLite，但这样的事情很难预测。关注[`www.w3.org/TR/webdatabase/`](http://www.w3.org/TR/webdatabase/)上的规范，了解使用客户端数据库的当前选项的更新。

# 使用 Web SQL 数据库

在这个步骤中，我们将使用前面步骤中创建的数据库，并向其中添加表和数据，然后在 HTML 页面上显示结果。

## 准备工作

您需要一个当前的浏览器和一个带有基本标签的 HTML5 页面，用于头部区域和主体区域。

## 如何操作...

在一个基本的 HTML5 页面上，添加一个`h1`标签来显示页面标题，然后创建一个 ID 为“status”的`div`标签来保存我们的结果，如下面的代码块所示：

```html
<!DOCTYPE HTML><html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8"><title>Using WEB SQL Databases</title></head><body><article><section><header><h1>Today's Riders</h1></header><div id="status" name="status"></div> </section></article><footer>

```

如果尚未创建数据库，请按照前面的步骤开始脚本以创建数据库。创建一个名为 info 的新变量，然后创建一个包含接受参数的函数的新事务。使用传递的参数，创建一个名为 RIDERS 的带有唯一 ID 和名为`ridername`的行的表。代码应该类似于以下代码块：

```html
var info;db.transaction(function (tx) { tx.executeSql('CREATE TABLE IF NOT EXISTS RIDERS (id unique, ridername)');

```

将数据添加到表行中，使用唯一 ID 的数字和每个名称的文本字符串：

```html
tx.executeSql('INSERT INTO RIDERS (id, ridername) VALUES (1, "Joe Fly")'); tx.executeSql('INSERT INTO RIDERS (id, ridername) VALUES (2, "Gira Ettolofal")'); });

```

执行查询以从数据库中提取数据：

```html
db.transaction(function (tx) { tx.executeSql('SELECT * FROM RIDERS', [], function (tx, results) {

```

创建一个新变量和`for`循环，循环遍历结果并将其打印到屏幕上：

```html
var len = results.rows.length, i; for (i = 0; i < len; i++){ info = "<p><b>" + results.rows.item(i).ridername + "</b></p>"; document.querySelector('#status').innerHTML += info; } }, null);});

```

关闭脚本和 HTML 页面。

```html
</script></footer></body></html>

```

## 它是如何工作的...

当我们在浏览器中打开我们刚创建的页面时，我们将看到我们使用数据库来显示的信息。这是因为查询和循环一起查看数据库并显示适当的信息。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_09_07.jpg)

## 还有更多...

在 HTML5 中，安全性和数据库事务可能执行不佳。在生产环境中，应该注意保护接受 SQL 查询的任何页面。

### 在单独的文件中保存脚本代码

为了简化本步骤，我们没有将 SQL 查询代码和 JavaScript 保存在单独的文件中。可以通过将代码保存在子文件夹中，如`../js/myCode.js`来完成。谨慎使用 Web SQL、Indexed DB 或任何其他类型的基于浏览器的查询 API 来获取安全信息。

### 在生产服务器上防范 SQL 注入

每当有可编辑字段时，都可能会有一些机器人尝试执行 SQL 注入攻击。可以通过在事务请求中使用“?”来采取基本预防措施。以下代码显示了一个例子。

```html
store.db.transaction(function(tx) { tx.executeSql( "insert into bmxtricks " + "(time, latitude, longitude, trick) values (?,?,?,?);", [bmxtricks.time, bmxtricks.latitude, bmxtricks.longitude, bmxtricks.trick], handler, store.onError );});

```

## 另请参阅

SQL 的 Packt 图书，任何覆盖客户端数据库的 Packt HTML5 图书。

# 为离线存储创建缓存清单

在这个示例中，我们将创建一个缓存清单文件，以便我们能够离线存储 HTML5 页面，并仍然查看页面上显示的图像和视频。

## 准备工作

您将需要一个 HTML5 页面，例如本示例的代码文件中提供的页面，并且可以上传文件到服务器，然后在计算机、智能手机或其他具有浏览器的网络设备上查看它们。

## 如何做...

首先，我们将创建缓存清单文件。这应该在一个简单的文本编辑器中创建。它应该包含用户在离线时需要访问的所有文件和支持代码。首先列出的是当前文件类型（CACHE MANIFEST）。清单的版本号也应包括在内。请注意，我们在以下代码块中添加了所有我们希望用户在离线时访问的文件的路径：

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

最后，创建一个`.htaccess`文件来创建正确的 MIME 类型：

```html
AddType text/cache-manifest .manifest

```

页面应该显示类似于以下内容：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_09_08.jpg)

## 它是如何工作的...

创建缓存清单为浏览器提供了一个加载离线页面时使用的清单。虽然离线存储页面的想法是它不需要频繁更新，但使用版本号允许作者在用户下次连接到互联网时推送更新。

并非所有浏览器或系统都能正确解释清单文件类型，因此包括一个`.htaccess`文件可以确保缓存清单被正确识别。

您可以排除您认为不重要的文件，以减小离线页面的大小并减少加载时间。

# 使用地理位置和 geo.js 显示当前位置

在这个示例中，我们将使用地理位置规范和`geo.js`来显示地图上活动用户的当前位置，并显示他们当前的纬度和经度。

## 准备工作

访问[`code.google.com/p/geo-location-javascript/`](http://code.google.com/p/geo-location-javascript/)下载最新版本的`geo.js`，或者从 wiki (http://code.google.com/p/geo-location-javascript/wiki/JavaScriptAPI)获取链接 URL 以直接在线链接到它。

## 如何做...

首先，我们将创建 HTML5 开头页面标签：<head></head>。

然后，在 meta 标签中，我们将把 name 属性设置为“viewport”，并为 content 属性定义以下值：`width = device-width; initial-scale=1.0; maximum-scale=1.0; user-scalable=no`;

现在，声明一个带有 src 属性的脚本标签：[`code.google.com/apis/gears/gears_init.js`](http://code.google.com/apis/gears/gears_init.js)

然后，调用`geo.js`脚本：`src="img/geo.js"`。

到目前为止，代码块应该如下所示：

```html
<html><head><meta name = "viewport" content = "width = device-width; initial-scale=1.0; maximum-scale=1.0; user-scalable=no;"> <script src="img/gears_init.js" type="text/javascript" charset="utf-8"></script><script src="img/geo.js" type="text/javascript" charset="utf-8"></script>

```

为 Google Maps API 添加一个脚本标签：`<script type="text/javascript" src="img/js?sensor=false"></script>`。

现在，我们将创建一个初始化地图的函数，命名为`initialize_map()`，然后创建一个名为`myOptions`的数组来存储地图属性。这些属性基于 Google Maps API。它们应该类似于以下代码块：

```html
<script>function initialize_map(){ var myOptions = { zoom: 4, mapTypeControl: true, mapTypeControlOptions: {style: google.maps.MapTypeControlStyle.DROPDOWN_MENU}, navigationControl: true, navigationControlOptions: {style: google.maps.NavigationControlStyle.SMALL}, mapTypeId: google.maps.MapTypeId.ROADMAP }

```

使用`google.maps.Map()`方法向页面添加一个名为 map 的新地图，该方法将`document.getElementById`元素作为参数，该元素又传递了 id“map_canvas”。`google.maps.Map`接受的另一个方法是`myOptions`。

```html
map = new google.maps.Map(document.getElementById("map_canvas"), myOptions);}

```

创建`initialize()`函数，并添加一个`if`语句来检查`geo_position_js.init()`函数是否激活。使用`document.getElementById`和`innerHTML`为 id 为“current”的 div 输入一个新状态。状态文本为“接收中…”。

```html
function initialize(){ if(geo_position_js.init()){ document.getElementById('current').innerHTML="Receiving...";

```

添加帮助消息文本，以显示如果我们无法获取位置或者由于某种原因浏览器不支持获取当前位置，如下所示的代码块：

```html
geo_position_js.getCurrentPosition(show_position,function(){document. getElementById('current').innerHTML="Couldn't get location"}, {enableHighAccuracy:true}); } else{document.getElementById('current').innerHTML="Functionality not available"; }}
function show_position(p){ document.getElementById('current').innerHTML= "latitude="+p.coords.latitude.toFixed(2)+" longitude="+p.coords.longitude.toFixed(2); var pos=new google.maps.LatLng( p.coords.latitude,p.coords.longitude); map.setCenter(pos); map.setZoom(14);

```

创建一个名为`infowindow`的新变量，用于显示`google.maps InfoWindow`，即在点击标记时显示的气泡。给它一个文本字符串“yes”来显示。创建一个新的标记，与用户当前位置相关联，并为标记添加标题文本，以便在鼠标悬停时显示。添加一个事件监听器来检测标记何时被点击。

```html
var infowindow = new google.maps.InfoWindow({ content: "<strong>yes</strong>"}); var marker = new google.maps.Marker({ position: pos, map: map, title:"Here I am!" }); google.maps.event.addListener(marker, 'click', function() { infowindow.open(map,marker);});}</script >

```

样式化页面以控制字体系列、填充和标题和当前 div 的外观。

```html
<style>body {font-family: Helvetica;font-size:11pt; padding:0px;margin:0px} #title {background-color:#0C3;padding:5px;} #current {font-size:10pt;padding:5px;}</style></head>

```

在 body 标签中创建一个`onLoad`命令，初始化`initialize_map()`和`initialize()`函数。创建一个新的`div`来显示页面标题，以及一个 id 为“current”的第二个`div`来显示位置获取过程的当前状态。最后，创建一个 id 为`map_canvas`的`div`来包含地图一旦显示，并使用内联样式设置`div`的宽度和高度。关闭标签并保存页面。

```html
<body onLoad="initialize_map();initialize()"><div id="title">Where am I now?</div> <div id="current">Initializing...</div> <div id="map_canvas" style="width:320px; height:350px"></div></body></html>

```

在浏览器窗口中打开页面，您应该会看到类似以下截图的结果：

![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_09_09.jpg)

## 工作原理...

使用`geo.js`简化了在多个设备上使用地理定位的过程。它提供了准备好的错误消息，并遵循 W3C 的实现标准，以及“回退”到诸如 Google Gears 之类的工具的能力。首先，我们需要创建一个包含地图显示和处理选项数组的变量的脚本，实例化一个新的地图对象，并绘制一个标记以将用户的当前位置固定到屏幕上。在标记上悬停会显示一个带有标题文本的气泡窗口。这个文本也可以包含一个链接，用于拉取和显示驾驶方向、评论或笔记。当页面加载时，地图选项创建函数`map_initialize()`和主要的触发函数`initialize()`被调用。在使用`geo.js`的帮助下确定用户的当前位置并绘制地图时，会显示一个临时状态消息。
