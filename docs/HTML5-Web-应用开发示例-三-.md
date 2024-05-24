# HTML5 Web 应用开发示例（三）

> 原文：[`zh.annas-archive.org/md5/F338796025D212EF3B95DC40480B4CAD`](https://zh.annas-archive.org/md5/F338796025D212EF3B95DC40480B4CAD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：钢琴人

> “音乐不仅是艺术，不仅是文学，它是普遍可及的。” – 比利·乔尔

*在本章中，我们将通过创建一个虚拟钢琴应用程序来学习如何使用音频。首先，我们将学习 HTML5 音频元素和 API。然后，我们将创建一个音频管理器，以异步加载音频文件并缓存它们以供以后播放。我们将使用 HTML 元素创建一个键盘，并使用 CSS 进行样式设置。*

在本章中，我们将学习以下内容：

+   HTML5 `<audio>` 元素及其属性

+   如何使用音频 API 来控制应用程序中的音频

+   如何动态加载音频文件

+   如何处理键盘事件，将计算机键盘转换为钢琴键盘

+   如何使用范围输入来控制音频元素的音量

+   如何检查您的浏览器是否支持范围输入类型

# HTML5 音频概述

在我们开始编写钢琴应用程序之前，我们需要学习如何使用 HTML5 音频的基础知识。因此，让我们从 `<audio>` 元素及其 API 的概述开始。

## HTML5 <audio> 元素

HTML5 `<audio>` 元素用于定义在网页或应用程序中播放的音频文件。`audio` 元素可以在页面上具有可见控件，也可以保持隐藏并且可以通过 JavaScript 进行控制。以下是它支持的一些最有用的属性：

+   `src`: 要加载的音频文件的 URL。

+   `autoplay`: 用于指定文件在加载后立即开始播放。

+   `controls`: 告诉浏览器在页面上显示音频控件。否则，元素不会显示任何内容。

+   `loop`: 指定音频将循环播放。

+   `muted`: 指定音频将被静音。

+   `preload`: 定义音频文件的加载方式。

+   `auto`: 页面加载时加载音频文件。这是默认设置。

+   `none`: 不预加载文件，等待播放。

+   `metadata`: 页面加载时仅加载有关文件的元数据。

以下在页面加载后自动播放 `audioFile.mp3` 并在页面上显示音频控件：

```html
<audio src="img/audioFile.mp3" autoplay controls>
    Your browser doesn't support audio.
</audio>
```

在 Chrome 上显示在页面上时的样子如下：

![HTML5 <audio> 元素](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947_06_05.jpg)

如果浏览器不支持 `<audio>` 元素，它将显示元素内的任何内容。

虽然您可以使用 `src` 属性指定要加载的文件，但不建议这样做。不同的浏览器支持不同的文件类型，因此如果您只指定一个文件，它可能在所有浏览器上都无法工作。相反，您应该在 `<audio>` 元素内指定 `<source>` 子元素，以定义要使用的不同音频文件的列表。浏览器将使用它支持的第一个文件：

```html
<audio controls>
    <source src="img/audioFile.mp3">
    <source src="img/audioFile.ogg">
    <source src="img/audioFile.wav">
</audio>
```

支持的三种主要音频类型是 MP3、Ogg 和 WAV。您至少应提供 MP3 和 Ogg 文件，因为所有主要浏览器都支持其中一种。如果您还想包括 WAV 文件，请将其放在列表的最后，因为 WAV 文件未经压缩，因此需要大量带宽来下载。

## HTML5 音频 API

如果您只能使用 HTML5 音频在网页上放置一个元素让用户听音乐，那将会很无聊，这一章将结束。但是像 `<canvas>` 元素一样，`<audio>` 元素有一个完整的 API 支持它。我们可以使用音频 API 来控制何时以及如何从 JavaScript 播放音频剪辑。

音频 API 包含大量的方法和属性。以下是其中一些最有用的方法：

+   `play()`: 开始播放音频剪辑。

+   `pause()`: 暂停音频剪辑的播放。

+   `canPlayType(type)`: 用于确定浏览器是否支持某种音频类型。传入音频 MIME 类型，如 `"audio/ogg"` 或 `"audio/mpeg"`。它返回以下值之一：

+   `"probably"`: 很可能支持

+   `"maybe"`: 浏览器可能能够播放它

+   `""`（空字符串）：不支持

+   `currentTime`：用于获取或设置当前播放时间（以秒为单位）。这使我们能够在播放之前将声音定位到某个特定点。通常我们会将其设置为`0`以重新开始播放声音。

+   `volume`：用于获取或设置音量。可以是`0`到`1`之间的任何值。

+   `ended`：用于确定声音是否已完全播放。

### 注意

请注意，`<audio>`和`<video>`元素都共享相同的 API。因此，如果你知道如何使用 HTML 音频，你也知道如何使用视频。

我们可以使用音频 API 来做一些有趣的事情。在本章中，我们将创建一个虚拟钢琴，用户可以通过在屏幕上点击钢琴键来在网页上演奏。

# 加载音频文件

你可以通过在 HTML 文件中为每个音频文件添加`<audio>`元素来定义应用程序的所有音频文件。但是，我们也可以从 JavaScript 动态加载音频文件，以控制它们的加载方式和时间。我们可以像在上一章中动态加载图像文件一样加载它们。首先，我们创建一个新的`<audio>`元素，并将`src`属性设置为音频文件的名称：

```html
var audio = $("<audio>")[0];
audio.src = "2C.mp3";
```

接下来，我们添加一个事件处理程序，以便在音频文件加载完成时收到通知。我们可以使用两个事件。`canplay`事件在浏览器有足够的数据开始播放音频时触发。`canplaythrough`事件在文件完全加载后触发：

```html
audio.addEventListener("canplaythrough", function()
{
    audio.play();
});
```

# 行动时间 - 创建 AudioManager 对象

让我们将加载音频文件封装到一个可重用的对象中。我们将创建一个名为`AudioManager`的新对象，并将其放在名为`audioManager.js`的文件中。该对象将抽象出加载、缓存和访问音频文件所需的所有代码。

我们对象的构造函数接受一个名为`audioPath`的参数，这是存储音频文件的路径：

```html
function AudioManager(audioPath)
{
    audioPath = audioPath || "";
    var audios = {},
        audioExt = getSupportedFileTypeExt();
```

如果未定义`audioPath`，我们将其默认为一个空字符串。然后我们添加一个名为`audios`的变量，它是一个对象，将用于缓存所有已加载的`<audio>`元素。最后，我们定义一个变量来保存浏览器支持的音频文件扩展名，我们将通过调用`getSupportedFileTypeExt()`方法来确定：

```html
    function getSupportedFileTypeExt()
    {
        var audio = $("<audio>")[0];
        if (audio.canPlayType("audio/ogg")) return ".ogg";
        if (audio.canPlayType("audio/mpeg")) return ".mp3";
        if (audio.canPlayType("audio/wav")) return ".wav";
        return "";
    };
```

首先，我们在内存中创建一个新的`<audio>`元素，并使用它调用`canPlayType()`方法来确定浏览器支持的文件类型。然后我们返回该类型的文件扩展名。

接下来，我们需要一种从`AudioManager`对象获取音频文件的方法。让我们添加一个公共的`getAudio()`方法：

```html
    this.getAudio = function(name, onLoaded, onError)
    {
        var audio = audios[name];
        if (!audio)
        {
            audio = createAudio(name, onLoaded, onError);
            // Add to cache
            audios[name] = audio;
        }
        else if (onLoaded)
        {
            onLoaded(audio);
        }
        return audio;
    };
```

`getAudio()`方法接受三个参数。第一个是没有扩展名的音频文件的名称。在加载文件时，我们稍后将为其添加音频路径和默认扩展名。接下来的两个参数是可选的。第二个参数是在文件加载完成时将被调用的函数。第三个是在加载文件时将被调用的函数。

`getAudio()`的第一件事是检查`audios`对象，看看我们是否已经加载并缓存了该文件。在这种情况下，`audios`对象被用作关联数组，其中键是文件名，值是音频元素。这样可以很容易地通过名称查找`<audio>`元素。

如果文件尚未添加到缓存中，那么我们将创建一个新的`audio`元素，并通过调用`createAudio()`方法来加载它，接下来我们将实现。然后将新元素添加到`audios`对象中以进行缓存。

如果文件名已经在缓存中，那么我们立即调用传递的`onLoaded()`处理程序函数，因为文件已加载。

现在让我们编写私有的`createAudio()`方法。它接受与上一个方法相同的参数：

```html
    function createAudio(name, onLoaded, onError)
    {
        var audio = $("<audio>")[0];
        audio.addEventListener("canplaythrough", function()
        {
            if (onLoaded) onLoaded(audio);
            audio.removeEventListener("canplaythrough",
                arguments.callee);
        });
        audio.onerror = function()
        {
            if (onError) onError(audio);
        };
        audio.src = audioPath + "/" + name + audioExt;
        return audio;
    }
}
```

首先，我们使用 jQuery 创建一个新的`<audio>`元素。然后我们为`canplaythrough`添加一个事件监听器。当事件触发时，我们检查方法中是否传入了`onLoaded`函数。如果是，我们调用它并传递新的`<audio>`元素。我们还需要删除事件监听器，因为有些浏览器会在每次播放音频时调用它。

我们还为`<audio>`元素添加了一个`onerror`处理程序，以检查加载文件时是否出现错误。如果出现错误，它将调用`onError`函数（如果已定义）。

接下来，我们将`<audio>`元素的`src`属性设置为音频文件的 URL。我们通过组合`audioPath`、名称参数和`audioExt`来构建 URL。这将导致音频文件开始加载。最后，我们返回新的`<audio>`元素。

## *刚刚发生了什么？*

我们创建了一个名为`AudioManager`的对象来加载和缓存音频文件。当我们第一次请求音频文件时，它会被加载和缓存。下一次它将使用缓存的音频。例如，如果我们的浏览器支持 Ogg 文件，以下代码将加载`audio/2C.ogg`音频文件：

```html
var audioManager = new AudioManager("audio");
var audio = audioManager.getAudio("2C");
```

# HTML5 钢琴应用程序

现在让我们创建我们的 HTML5 钢琴应用程序。我们将拥有两个八度的钢琴键，包括黑色和白色，并且我们将使用一些样式使其看起来像一个真正的键盘。当用户用鼠标点击键时，它将播放相应的音符，该音符在音频文件中定义。

您可以在`chapter6/example6.1`中找到此部分的代码。

# 行动时间-创建虚拟钢琴

我们将像往常一样，复制我们在第一章中创建的应用程序模板，*手头的任务*，并将文件重命名为`piano.html`、`piano.css`和`piano.js`。我们还需要`touchEvents.js`，这是我们在上一章中创建的。

在`piano.js`中，我们将应用程序对象更改为`PianoApp`：

```html
function PianoApp()
{
    var version = "6.1",
        audioManager = new AudioManager("audio");
```

我们创建了一个`AudioManager`的实例，并传入了我们音频文件的路径，这将是`audio`文件夹。现在让我们打开我们的 HTML 文件并添加所有的钢琴键：

```html
<div id="keyboard">
    <div id="backboard"></div>
    <div class="keys">
        <div data-note="2C" class="piano-key white"></div>
        <div data-note="2C#" class="piano-key black"></div>
        <div data-note="2D" class="piano-key white"></div>
        <div data-note="2D#" class="piano-key black"></div>
        <div data-note="2E" class="piano-key white"></div>
        <div data-note="2F" class="piano-key white"></div>
        <div data-note="2F#" class="piano-key black"></div>
        <div data-note="2G" class="piano-key white"></div>
        <div data-note="2G#" class="piano-key black"></div>
        <div data-note="2A" class="piano-key white"></div>
        <div data-note="2A#" class="piano-key black"></div>
        <div data-note="2B" class="piano-key white"></div>
        <!-- third octave not shown -->
        <div data-note="4C" class="piano-key white"></div>
    </div>
</div>
```

在“main”元素内，我们添加一个`<div>`标签，`id`设置为`keyboard`。在里面，我们有一个`<div>`标签，它将成为背板，以及一个包含所有键的`<div>`标签。每个键由一个包含`piano-key`类和`white`或`black`类的元素定义，具体取决于键的颜色。每个键元素还有一个`data-note`自定义数据属性。这将设置为钢琴键音符的名称，也将是匹配音频文件的名称。

我们的钢琴有两个完整的八度钢琴键。每个键都有自己的音频文件。由于每个八度有 12 个音符，并且我们在键盘末尾有一个额外的 C 音符，我们将有 25 个音频文件，命名为`2C`到`4C`。我们希望提供 Ogg 和 MP3 格式的音频文件以支持所有浏览器，因此总共有 50 个音频文件：

![行动时间-创建虚拟钢琴](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947_06_01.jpg)

让我们打开`piano.css`并为应用程序设置样式。首先，我们将通过将`position`设置为`absolute`并将所有`position`值设置为`0`来使应用程序占据整个浏览器窗口。我们将给它一个从白色到蓝色的线性渐变：

```html
#app
{
    position: absolute;
    top: 0;
    bottom: 0;
    left: 0;
    right: 0;
    margin: 4px;
    background-color: #999;
    /* browser specific gradients not shown */
    background: linear-gradient(top, white, #003);
}
```

我们还将`footer`选择器的`position`属性设置为`absolute`，`bottom`设置为`0`，这样它就贴在窗口底部了：

```html
#app>footer
{
    position: absolute;
    bottom: 0;
    padding: 0.25em;
    color: WhiteSmoke;
}
```

在主要部分，我们将`text-align`设置为`center`，这样键盘就居中在页面上了：

```html
#main
{
    padding: 4px;
    text-align: center;
}
```

现在让我们为键盘设置样式，使其看起来像一个真正的钢琴键盘。首先，我们给整个键盘一个从深棕色到浅棕色的渐变和一个阴影，使其具有一定的深度：

```html
#keyboard
{
    padding-bottom: 6px;
    background-color: saddlebrown;
    /* browser specific gradients not shown */
    background: linear-gradient(top, #2A1506, saddlebrown);
    box-shadow: 3px 3px 4px 1px rgba(0, 0, 0, 0.9);
}
```

接下来，我们样式化背板，隐藏键的顶部。我们给它一个深棕色，使其高度为`32`像素，并给它一个阴影以增加深度。为了使阴影绘制在钢琴键上方，我们需要将`position`设置为`relative`：

```html
#backboard
{
    position: relative;
    height: 32px;
    background-color: #2A1506;
    border-bottom: 2px solid black;
    box-shadow: 3px 3px 4px 1px rgba(0, 0, 0, 0.9);
}
```

所有钢琴键共享一些基本样式，这些样式是使用`piano-key`类定义的。首先，我们将`display`设置为`inline-block`，这样它们就可以保持在同一行，并且具有宽度和高度。然后我们给底部设置了边框半径，使它们看起来圆润。我们还将`cursor`属性设置为`pointer`，这样用户就可以知道它们可以被点击：

```html
#keyboard .piano-key
{
    display: inline-block;
    border-bottom-right-radius: 4px;
    border-bottom-left-radius: 4px;
    cursor: pointer;
}
```

最后，我们来到黑白键的样式。白键比黑键稍微宽一些，高一些。我们还给它们一个象牙色和阴影。最后，我们需要将`z-index`设置为`1`，因为它们需要显示在黑键的后面：

```html
#keyboard .piano-key.white
{
    width: 50px;
    height: 300px;
    background-color: Ivory;
    box-shadow: 3px 3px 4px 1px rgba(0, 0, 0, 0.7);
    z-index: 1;
}
```

黑键比白键小一点。为了使黑键显示在白键的上方，我们将`z-index`设置为`2`。为了使它们看起来在白键之间，我们将它们的`position`属性设置为`relative`，并使用负`left`偏移将它们移动到白键的上方。我们还需要一个负的`right-margin`值，这样下一个白键就会被拉到它的上方和下方：

```html
#keyboard .piano-key.black
{
    position: relative;
    width: 40px;
    height: 200px;
    left: -23px;
    margin-right: -46px;
    vertical-align: top;
    background-color: black;
    box-shadow: 2px 2px 3px 1px rgba(0, 0, 0, 0.6);
    z-index: 2;
}
```

这就是我们的钢琴会是什么样子的：

![行动时间-创建虚拟钢琴](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947_06_03.jpg)

第一张图片显示了没有设置边距的键。看起来不太像一个真正的键盘，是吧？下一张图片显示了设置了`left`边距的样子。它变得更好了，但是白键还没有移动过来。设置右边距就解决了这个问题。

## *刚刚发生了什么？*

我们从我们的应用程序模板开始创建了一个新的 HTML5 钢琴应用程序。我们在 HTML 中定义了所有的键，然后使用负偏移和边距对它们进行了样式化，使键能够像真正的键盘一样排列。

就是这样！我们现在有一个看起来非常逼真的两个八度键盘：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947_06_02.jpg)

# 行动时间-加载音符

我们有一个键盘，但还没有声音。让我们回到 JavaScript，加载所有的音频文件。我们将创建一个名为`loadAudio()`的新方法，并从应用程序的`start()`方法中调用它。

我们可以通过两种方式加载所有文件。我们可以通过为每个文件调用`audioManager.getAudio()`来一次加载它们，这将非常冗长并且需要大量输入。或者我们可以迭代所有的`piano-key`元素，并从它们的`data-note`属性中获取文件名。通过使用这种方法，我们可以在 HTML 中添加更多的钢琴键，甚至不需要触及 JavaScript：

```html
function loadAudio()
{
    var count = 0,
        loaded = 0,
        error = false;

    $(".keyboard .piano-key").each(function()
    {
        count++;
        var noteName = escape($(this).data("note"));
        audioManager.getAudio(noteName,
            function()
            {
                if (error) return;
                if (++loaded == count) setStatus("Ready.");
                else setStatus("Loading " +
                        Math.floor(100 * loaded / count) + "%");
            },
            function(audio)
            {
                error = true;
                setStatus("Error loading: " + audio.src);
            }
        );
    });
}
```

我们要做的第一件事是定义一些变量来跟踪正在加载的音频文件的数量和已加载的数量。我们将使用它们来计算完成百分比。我们还需要一个变量来设置如果加载文件时出现错误。

接下来，我们要使用 jQuery 选择所有的`piano-key`元素，并调用`each()`来对它们进行迭代。对于每一个，我们要做以下事情：

1.  将`count`变量加 1，以跟踪文件的总数。

1.  从`data-note`属性中获取音符名称，这也是文件名。请注意，我们必须使用`escape()`函数，因为一些音符包含 sharp 符号`#`，这在 URL 中是非法的。

1.  调用`audioManager.getAudio()`，传入音符名称。这将导致音频文件被加载和缓存。下次我们为这个音符调用`getAudio()`时，它将被加载并准备好播放。

1.  `getAudio()`的第二个参数是一个在每个文件成功加载完成时调用的函数。在这个函数中，我们增加了加载变量。然后我们检查是否所有文件都已加载，如果是，则显示准备好的消息。否则，我们通过调用`setStatus()`计算加载文件的完成百分比并显示在页脚中。

1.  `getAudio()`的最后一个参数是一个在加载文件时出错时调用的函数。当发生这种情况时，我们将`error`变量设置为`true`，并显示一个显示无法加载的文件的消息。

### 注意

请注意，如果您通过 IIS 等 Web 服务器运行此应用程序，您可能需要将`.ogg`文件类型添加到站点的 MIME 类型列表中（`.ogg`，`audio/ogg`）。否则，您将收到文件未找到的错误。

## *刚刚发生了什么？*

我们使用`AudioManager`对象动态加载每个键盘键的所有声音，使用它们的`data-note`属性作为文件名。现在我们已经加载、缓存并准备好播放所有的音频文件。

# 行动时间-播放音符

接下来我们需要做的是为钢琴键添加事件处理程序，当点击或触摸钢琴键时播放`<audio>`元素。我们将为所有的钢琴键连接事件处理程序，并在它们被触发时播放相关的音符。

### 注意

在撰写本文时，移动设备上的音频状态并不是很好。尽管触摸设备非常适合钢琴应用，但由于移动浏览器缓存音频的方式（或者没有缓存），声音并不总是正确播放。

让我们创建一个名为`initKeyboard()`的方法，它将从应用程序的`start()`方法中调用：

```html
function initKeyboard()
{
    var $keys = $(".keyboard .piano-key");
    if ($.isTouchSupported)
    {
        $keys.touchstart(function(e) {
            e.stopPropagation();
            e.preventDefault();
            keyDown($(this));
        })
        .touchend(function() { keyUp($(this)); })
    }
    else
    {
        $keys.mousedown(function() {
            keyDown($(this));
            return false;
        })
        .mouseup(function() { keyUp($(this)); })
        .mouseleave(function() { keyUp($(this)); });
    }
}
```

首先，我们使用 jQuery 选择键盘上所有的`piano-key`元素。然后，我们使用触摸事件的 jQuery 扩展来检查浏览器是否支持触摸事件。如果是，我们将触摸事件处理程序连接到钢琴键。否则，我们将连接鼠标事件处理程序。

当按下键或点击鼠标时，它调用`keyDown()`方法，传入用 jQuery 对象包装的键元素。

### 注意

请注意，在这种情况下，`this`是被点击的元素。当键被释放或鼠标释放，或鼠标离开元素时，我们调用`keyUp()`方法。

让我们首先编写`keyDown()`方法：

```html
function keyDown($key)
{
    if (!$key.hasClass("down"))
    {
        $key.addClass("down");
        var noteName = $key.data("note");
        var audio = audioManager.getAudio(escape(noteName));
        audio.currentTime = 0;
        audio.play();
    }
}
```

在`keyDown()`方法中，我们首先检查键是否已经被按下，通过检查它是否具有`down`类。如果没有，我们将`down`类添加到键元素。我们将使用这个来为键添加样式，使其看起来像是被按下。然后，我们从`data-note`自定义属性中获取键的音符名称。我们将其传递给`audioManager.getAudio()`方法以获取`<audio>`元素。为了开始播放音频剪辑，我们首先将`currentTime`属性设置为`0`，以在开始时排队声音。然后，我们调用 Audio API 的`play()`方法来开始播放它。

```html
function keyUp($key)
{
    $key.removeClass("down");
}
```

`keyUp()`方法只是从元素中移除`down`类，这样键就不会再以按下状态进行样式设置。

我们需要做的最后一件事是为按下状态添加样式。我们将使用渐变来使其看起来像是按下了键的末端。我们还会使阴影变小一点，因为按下时键不会那么高：

```html
.keyboard .piano-key.white.down
{
    background-color: #F1F1F0;
    /* Browser-specific gradients not shown */
    background: linear-gradient(top, Ivory, #D5D5D0);
    box-shadow: 2px 2px 3px 1px rgba(0, 0, 0, 0.6);
}
.keyboard .piano-key.black.down
{
    background-color: #111;
    /* Browser-specific gradients not shown */
    background: linear-gradient(top, Black, #222);
    box-shadow: 1px 1px 2px 1px rgba(0, 0, 0, 0.6);
}
```

## *刚刚发生了什么？*

我们连接了事件处理程序到钢琴键，当它们被鼠标点击或在触摸设备上被触摸时，播放相关的音符。我们添加了一些样式来给出视觉指示，表明键被按下。现在我们有一个使用 HTML5 音频的功能钢琴。请在浏览器中打开它，并弹奏一些曲调。

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947_06_04.jpg)

# 键盘事件

在我们的钢琴上使用鼠标弹奏音符效果还可以，但如果我们可以同时播放多个音符会更好。为此，我们可以使用计算机键盘来弹奏音符。为此，我们将在 JavaScript 中向 DOM`document`添加键盘事件处理程序，并将键盘键映射到钢琴键。

键盘的前两行将用于第一个八度，后两行将用于第二个八度。例如，按下*Q*键将播放最低的 C 音符。按下*2*键将播放 C#，*W*将播放 D，依此类推。对于第二个八度，按下*Z*将播放中央 C，*S*将播放 C#，依此类推：

![键盘事件](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947_06_06.jpg)

您可以在`chapter6/example6.2`中找到本节的代码。

# 行动时间-添加键盘事件

我们需要做的第一件事是将`keycodes.js`添加到我们的应用程序中。该文件包含一个名为`keyCodes`的全局静态对象，将键盘上的键映射到它们关联的键码。例如，`keyCodes.ENTER`等于`13`。使用这个将使我们的代码比使用键码数字更易读。

我们需要做的下一件事是打开 HTML 并向`piano-key`元素添加一个新的自定义数据属性。我们将其称为`data-keycode`，并将其设置为我们想要与钢琴键关联的`keyCode`对象中的值：

```html
<div data-note="2C" data-keycode="Q" class="piano-key white" title="C2"></div>
<!—elements not shown -->
<div data-note="4C" data-keycode="COMMA" class="piano-key white" title="C4"></div>
```

现在我们需要将按键代码映射到音符。我们将在我们的应用程序中添加一个名为`keyCodesToNotes`的对象来保存我们的映射。我们将在`initKeyboard()`方法中对其进行初始化：

```html
function initKeyboard()
{
    // Code not shown...
    $keys.each(function() {
        var $key = $(this);
        var keyCode = keyCodes[$key.data("keycode")];
        keyCodesToNotes[keyCode] = $key.data("note");
    });
}
```

在这里，我们遍历所有`piano-key`元素，获取每个元素的`data-keycode`自定义属性，并使用它来从`keyCodes`对象中获取键码。然后，我们通过将其设置为元素的`data-note`自定义属性来将映射添加到`keyCodesToNotes`中。例如，*Q*键的键码为 81，关联的钢琴键音符为 2C。因此，`keyCodesToNotes[81]`将设置为`2C`。

现在让我们添加键盘事件处理程序。在检查按下、释放或按下事件时，您需要将事件处理程序附加到 HTML 文档上。让我们在应用程序的`start()`方法中添加`keydown`和`keyup`事件处理程序：

```html
this.start = function()
{
  // Code not shown... 
    $(document).keydown(onKeyDown)
               .keyup(onKeyUp);
}
```

`keydown`事件处理程序调用`onKeyDown()`方法。`keyup`处理程序调用`onKeyUp()`：

```html
function onKeyDown(e)
{
    var note = keyCodesToNotes[e.which];
    if (note)
    {
        pressPianoKey(note);
    }
}
```

在`onKeyDown()`方法中，我们使用`keyCodesToNotes`对象查找按下的键对应的音符。jQuery 在键事件对象上定义了一个`which`字段，其中包含键码。如果键码与我们键盘上的音符匹配，那么我们调用`pressPianoKey()`方法，将`note`参数传递给它：

```html
function onKeyUp(e)
{
    var note = keyCodesToNotes[e.which];
    if (note)
    {
        releasePianoKey(note);
    }
}
```

`onKeyUp()`方法的工作方式相同，只是调用了`releasePianoKey()`方法。

```html
function pressPianoKey(note)
{
    var $key = getPianoKeyElement(note);
    keyDown($key);
}
```

在`pressPianoKey()`方法中，我们将要播放的音符名称作为参数。然后，我们调用`getPianoKeyElement()`来获取与该音符相关联的钢琴键元素。最后，我们将该元素传递给我们在添加鼠标和触摸事件时已经实现的`keyDown()`方法。通过这种方式，我们模拟了用户在屏幕上点击钢琴键元素。

```html
function releasePianoKey(note)
{
    var $key = getPianoKeyElement(note);
    keyUp($key);
}
```

`releasePianoKey()`方法的工作方式完全相同，只是调用了现有的`keyUp()`方法。

```html
function getPianoKeyElement(note)
{
    return $(".keyboard .piano-key[data-note=" + note + "]");
}
```

在`getPianoKeyElement()`方法中，我们通过使用 jQuery 选择器匹配`data-note`自定义属性来找到与音符相关联的`piano-key`元素。

## *刚刚发生了什么？*

我们在应用程序的 HTML 文档中添加了键盘按键事件处理程序。当按下键盘上的键时，我们将键码映射到钢琴键，以便用户可以按下键盘上的键来弹奏钢琴。通过将`piano-key`元素传递给`keyDown()`和`keyUp()`，我们模拟了用户点击这些键。它们被添加了`down`类，看起来就像它们真的被按下了。

自己试一试。尝试同时按下两个或三个键，弹奏一些和弦。

# 音量和延音控制

让我们在钢琴上添加一些控件，允许用户更改音量和延音。你可能还记得，`audio`元素的音量可以设置为`0`到`1.0`之间的任何值。我们将使用一个范围输入控件，允许用户通过滑块来控制音量。

延音控制允许音符在释放钢琴键后继续播放。当关闭延音时，音符将在释放键时立即停止播放。我们将添加一个复选框来打开和关闭这个功能。

您可以在`chapter6/example6.3`中找到本节的源代码。

# 行动时间-添加延音控制

让我们继续在应用程序中添加一个延音控件。我们将使用复选框输入控件来打开和关闭延音。在我们的 HTML 文件中，我们将在键盘下方添加一个带有`controls`类的新`<div>`元素来容纳我们的控件：

```html
<div id="main">
    <!-- keyboard not shown... -->
    <div class="controls">
        <label for="sustain">Sustain: </label>
        <input type="checkbox" id="sustain" checked /><br />
    </div>
</div>
```

我们使用`id`属性定义一个标签和一个复选框，名称为`sustain`。我们还将其默认设置为选中状态。

现在让我们在`PianoApp`应用程序对象中实现复选框的代码。首先，我们需要添加一个名为`sustain`的变量，并将其设置为`true`：

```html
function PianoApp()
{
    var version = "6.3",
    // Code not shown...
    sustain = true;
```

接下来，我们将添加一个`change`事件处理程序，以便在复选框更改时收到通知。我们将在应用程序的`start()`方法中执行此操作：

```html
$("#sustain").change(function() { sustain = $(this).is(":checked"); });
```

复选框更改时，我们使用 jQuery 的`is()`过滤器方法来确定它是否被选中，传递给它`:checked`过滤器。如果选中，`sustain`变量将设置为`true`。

现在我们需要对`keyUp()`方法进行一些更改。该方法现在的作用只是从`piano-key`元素中移除`down`类。我们需要添加代码来检查`sustain`变量，并且如果该变量设置为`true`，则停止播放声音：

```html
function keyUp($key)
{
    $key.removeClass("down");
    if (!sustain)
    {
        var noteName = $key.data("note");
        var audio = audioManager.getAudio(escape(noteName));
        audio.pause();
    }
}
```

删除`down`类后，我们检查`sustain`变量。如果未设置延音，我们从`piano-key`元素的`data-note`自定义属性中获取音符名称，并使用它来从`audioManager`对象中获取`<audio>`元素。然后我们调用`pause()`方法来停止播放声音。

## *刚刚发生了什么？*

我们添加了一个复选框，允许用户打开和关闭延音控制。当延音关闭并且用户释放钢琴键时，我们调用音频 API 的`pause()`方法来停止播放音符。

# 行动时间-添加音量控制

回到 HTML 中，让我们添加一个范围输入控件，允许用户更改音量。我们将它放在刚刚添加的延音标签和控件下面：

```html
<label for="volume">Volume: </label>
<input type="range" id="volume" min="1" max="100" value="100" step="1" />
```

我们使用`volume`属性定义一个标签和一个范围输入。我们将控件的范围设置为`1`到`100`，步长值为`1`。我们还将默认值设置为`100`。

回到我们的`PianoApp`对象中，我们添加了另一个名为`volume`的全局变量，并将其默认设置为`1.0`，即最大音量：

```html
function PianoApp()
{
    var version = "6.3",
    // Code not shown...
    sustain = true,
    volume = 1.0;
```

与`sustain`复选框一样，我们需要为应用程序的`start()`方法添加一个`change`事件处理程序，用于范围控制：

```html
$("#volume").change(function() {
    volume = parseInt($(this).val()) / 100;
});
```

您可能已经注意到，我们的范围输入控件的范围为`1`到`100`，而`audio`元素的音量定义为`0`到`1.0`。因此，在我们的事件处理程序中，我们将`volume`变量设置为范围控件的值除以`100`。

现在我们只需要在`keyDown()`方法中添加一行代码，以在播放之前设置`audio`元素的`volume`属性：

```html
audio.currentTime = 0;
audio.volume = volume;
audio.play();
```

现在让我们在 CSS 中为页面的`controls`部分进行一些样式设置：

```html
.controls
{
    margin-top: 2em;
    color: white; 
}
.controls input
{
    vertical-align: middle;
}
.controls input[type=range]
{
    width: 10em;
}
```

我们设置顶部边距，为控件留出一些空间，为控件设置垂直对齐，使标签居中对齐，并设置音量范围控件的宽度。

我们还应该做一件事，使我们的应用程序更加动态。范围输入控件并不被所有浏览器广泛支持，因此让我们添加一些代码来检查它是否被支持。我们将添加一个`isInputTypeSupported()`方法：

```html
function isInputTypeSupported(type)
{
    var $test = $("<input>");
    // Set input element to the type we're testing for
    $test.attr("type", type);
    return ($test[0].type == type);
}
```

首先，我们在内存中创建一个新的`<input>`元素。然后我们将`type`属性设置为我们正在测试的类型。在我们的情况下，那将是`range`。然后我们检查`type`属性，看它是否被固定。如果元素保留了该类型，则表示浏览器支持它。

在`start()`方法中，我们将添加一个检查范围类型的检查。如果您还记得第三章中的内容，*细节中的魔鬼*，如果一个输入类型不受支持，它将显示为文本输入字段。因此，如果范围类型不受支持，我们将更改字段的宽度，使其变小。我们不希望一个宽度为`10em`的文本输入字段输入从`0`到`100`的数字：

```html
if (!isInputTypeSupported("range")) $("#volume").css("width", "3em");
```

## *刚刚发生了什么？*

我们添加了一个范围输入控件，允许用户使用滑块更改声音的音量。在播放声音之前，我们将音量设置为用户选择的值。我们还编写了一个方法，用于检查浏览器是否支持某些 HTML5 输入类型。以下是我们创建的内容：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947_06_07.jpg)

## 尝试一下

为`<audio>`元素创建一个包装器对象，该对象将元素作为构造函数，并包含公共方法来访问音频 API 方法。添加一些便利方法，例如`rewind()`，它设置`audio.currentTime = 0`，或`stop()`，它调用`pause()`和`rewind()`。

## 快速测验

Q1\. `<audio>`元素支持哪种音频类型？

1.  Ogg

1.  MP3

1.  Wav

1.  以上所有内容

Q2\. 你将键盘事件附加到哪个对象？

1.  `窗口`

1.  `文档`

1.  `div`

1.  `音频`

# 音频工具

在我们离开本章之前，我想告诉你一些免费音频工具，你可以用它们来获取和处理应用程序的音频文件。

## FreeSound.org

[FreeSound.org](http://FreeSound.org)是一个网站，你可以在那里获取以知识共享许可发布的音频文件。这意味着你可以在各种使用限制下免费使用它们。有一些公共领域的声音，你可以无需做任何事情就可以使用。还有一些声音，只要你给作者以信用，你就可以做任何事情。还有一些声音，你可以用于任何目的，除了商业用途。FreeSound 数据库庞大，具有出色的搜索和浏览功能。你几乎可以在这个网站上找到任何你需要的声音。

## Audacity

Audacity 是一个免费的开源音频编辑器，用于录制、切割和混合音频，可在许多不同的操作系统上运行。Audacity 非常适合在不同文件类型之间转换，这对我们来说非常重要，因为我们需要支持不同浏览器的不同音频类型。它支持主要网络浏览器使用的所有主要音频类型，包括 Ogg、MP3 和 WAV。

# 总结

在本章中，我们学习了如何使用 HTML5 的`audio`元素和 API 来为 Web 应用程序添加声音。我们看到了如何通过创建可重用的音频管理器对象来加载和缓存音频文件。然后我们使用 HTML5 音频在网页中创建了一个虚拟钢琴应用程序。我们使用键盘事件允许用户通过键盘弹奏钢琴键。我们添加了控件来改变音量和延长音符。

在本章中，我们涵盖了以下概念：

+   如何将 HTML5 的`<audio>`元素添加到网页中并使用其属性来控制它

+   使用 JavaScript 从音频 API 来编程控制音频元素的播放

+   如何加载音频文件并缓存以供以后播放

+   如何播放、暂停和重置音频文件

+   如何将键盘事件连接到文档并在我们的应用程序中处理它们

+   如何使用范围输入控件改变`audio`元素的音量

+   如何检查浏览器是否支持任何 HTML5 输入类型

在下一章中，我们将把我们的钢琴应用程序变成一个叫做钢琴英雄的游戏。我们将学习关于时间、动画元素和通过创建音频序列器播放音乐。


# 第七章：钢琴英雄

> "音乐的一大好处是，当它打动你时，你感觉不到痛苦。"
> 
> - 鲍勃·马利

*在本章中，我们将把上一章的钢琴应用程序转变成一个游戏，玩家必须在音符按下屏幕时以正确的时间演奏歌曲的音符。我们将创建一个启动页面，用于跟踪图像加载并允许玩家选择游戏选项。我们将创建一个音频序列以播放音乐数据中的歌曲。在游戏过程中，我们将收集钢琴键盘输入并验证以确定玩家的得分。*

在本章中我们将学到以下内容：

+   如何使用 HTML5 进度条元素跟踪资源的加载

+   如何使用 JavaScript 定时器来控制音频播放以播放歌曲

+   如何使用 DOM 元素动画来移动它们在屏幕上

+   如何在游戏状态之间过渡

+   如何获取用户输入并验证它

# 创建钢琴英雄

我们的钢琴英雄游戏将从我们在上一章中构建的 HTML5 钢琴应用程序开始。我们将添加一个音频序列到其中以播放预先录制的歌曲。为了得分，玩家需要跟着演奏歌曲的音符，并在正确的时间演奏。还将有一个练习模式，只播放歌曲，以便玩家能听到它。

我们的游戏将有两个不同的主面板。第一个将是启动面板，这是游戏的起点。当应用程序首次启动时，它将显示一个进度条，因为音频正在加载。加载完成后，它将显示游戏的选项。当玩家点击播放按钮时，他们将转到游戏面板。

游戏面板包含钢琴键盘和一个显示要演奏的音符从上面掉下来的区域。如果用户在正确的时间演奏了正确的音符，他们会得到积分。在歌曲结束时，玩家的得分和一些统计数据将被显示。游戏结束后，应用程序将转回到启动面板，用户可以选择选项并再次游戏。

通常有助于绘制一个流程图，显示游戏如何从一个状态过渡到另一个状态。

![创建钢琴英雄](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_07_03.jpg)

# 行动时间-创建启动面板

让我们从上一章创建的钢琴应用程序开始，并将文件重命名为`pinaoHero.html`，`pianoHero.js`和`pianoHero.css`。我们还将主应用程序对象重命名为`PianoHeroApp`。您可以在`第七章/example7.1`中找到本节的代码。

现在让我们创建启动面板。首先我们将在`pianoHero.html`中定义 HTML。我们将在键盘元素上方添加一个新的`<div>`元素来容纳启动面板：

```html
<div id="splash">
    <h1>Piano Hero</h1>
    <section class="loading">
        Loading audio...<br/>
        <progress max="100" value="0"></progress>
    </section>
```

首先，我们添加一个带有`"loading"`类的部分，显示应用程序首次启动时加载音频的状态。请注意，我们正在使用新的 HTML5`<progress>`元素。该元素用于在应用程序中实现进度条。它有一个`max`属性，定义最大值，和一个`value`属性来设置当前值。由于我们显示百分比完成，我们将`max`设置为`100`。随着音频文件的加载，我们将从 JavaScript 更新`value`属性。

然后我们添加一个带有`"error"`类的部分，如果加载音频时出错将显示错误消息。否则它将被隐藏：

```html
    <section class="error">
        There was an error loading the audio.
    </section>
```

最后，我们添加一个显示游戏选项和按钮的部分。这个面板在所有音频加载完成后显示：

```html
    <section class="loaded hidden">
        <label>Choose a song</label>
        <select id="select-song">
            <option value="rowBoat">Row Your Boat</option>
            <option value="littleStar">
              Twinkle, Twinkle, Little Star</option>
            <option value="londonBridge">London Bridge</option>
            <option value="furElise">Fur Elise</option>
        </select><br/>
        <label>Choose difficulty</label>
        <select id="select-rate">
            <option value="0.5">Slow (60bpm)</option>
            <option value="1" selected>Normal (120bpm)</option>
            <option value="1.5">Fast (180bpm)</option>
        </select>
        <p>
            <button id="start-game">Start Game</button>
            <button id="start-song">Play Song</button>
        </p>
    </section>
</div>
```

在这里，用户从下拉列表中选择歌曲和难度。难度是以歌曲播放速度的比率来表示。值为 1 是默认速度，即每分钟 120 拍。小于 1 的值是更慢的，大于 1 的值是更快的。

现在我们需要为启动面板设置样式。请查看所有样式的源代码。一个值得注意的样式是**PIANO HERO**标题，我们将其放在`<h1>`标题元素中：

```html
#splash h1
{
    font-size: 6em;
    color: #003;
    text-transform: uppercase;
    text-shadow: 3px 3px 0px #fff, 5px 5px 0px #003;
}
```

我们将文本的颜色设置为深蓝色。然后我们使用`text-shadow`来产生有趣的块文本效果。在使用`text-shadow`时，您可以通过逗号分隔指定任意数量的阴影。阴影将按照从后到前的顺序绘制。所以在这种情况下，我们首先绘制一个偏移为 5 像素的深蓝色阴影，然后是一个偏移为 3 像素的白色阴影，最后深蓝色文本将被绘制在其上方：

![行动时间-创建闪屏面板](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_07_02.jpg)

现在让我们创建一个名为`splashPanel.js`的新 JavaScript 文件，并在其中定义一个名为`SplashPanel`的新对象，该对象将包含控制闪屏面板的所有代码。构造函数将接受一个参数，即对`audioManager`的引用：

```html
function SplashPanel(audioManager)
{
    var $div = $("#splash"),
    error = false;
```

我们定义了一个`$div`对象来保存对闪屏面板根`<div>`元素的引用，并设置了一个`error`变量来设置是否在加载音频时出现错误。接下来，我们定义了公共的`show()`和`hide()`方法。这些方法将由主应用程序对象调用以显示或隐藏面板。

```html
    this.show = function()
    {
        $div.fadeIn();
        return this;
    };
    this.hide = function()
    {
        $div.hide();
        return this;
    };
}
```

接下来，我们将`loadAudio()`方法从`PianoHeroApp`移动到`SplashPanel`。在这个方法中，我们需要对`audioManager.getAudio()`的调用进行一些小的更改：

```html
audioManager.getAudio(noteName,
    function()
    {
        if (error) return;
        if (++loaded == count) showOptions();
        else updateProgress(loaded, count);
    },
    function(audio) { showError(audio); }
);
```

在我们每次加载音频文件时调用的函数中，我们首先检查是否有错误，如果有，则将其取出。然后我们检查是否已加载所有音频文件（`loaded == count`），如果是，则调用`showOptions()`方法。否则，我们调用`updateProgress()`方法来更新进度条：

```html
function updateProgress(loadedCount, totalCount)
{
    var pctComplete = parseInt(100 * loadedCount / totalCount);
    $("progress", $div)
        .val(pctComplete)
        .text(pctComplete + "%");
}
```

`updateProgress()`方法将加载计数和总计数作为参数。我们计算完成的百分比，并使用它来更新`<progress>`元素的值。我们还设置了`<progress>`元素的内部文本。这只会在不支持`<progress>`元素的浏览器中显示。

```html
function showOptions()
{
    $(".loading", $div).hide();
    $(".options", $div).fadeIn();
}
```

在加载完所有音频后，将调用`showOptions()`方法。首先隐藏具有`"loading"`类的元素，然后淡入具有`"options"`类的元素。这将隐藏进度部分并显示包含游戏选项的部分。

我们的错误处理程序调用`showError()`，将失败的音频元素传递给它：

```html
function showError(audio)
{
    error = true;
    $(".loading", $div).hide();
    $(".error", $div)
        .append("<div>" + audio.src + "<div>")
        .show();
}
```

在`showError()`方法中，我们将`error`标志设置为`true`，以便我们知道不要在`getAudio()`调用中继续。首先隐藏加载部分，然后将失败的文件名附加到错误消息中，并显示错误部分。

我们闪屏面板中的最后一件事是将事件处理程序连接到按钮。有两个按钮，**开始游戏**和**播放歌曲**。它们之间唯一的区别是**播放歌曲**按钮会播放歌曲而不计分，因此用户可以听歌曲并练习：

```html
$(".options button", $div).click(function()
{
    var songName = $("#select-song>option:selected", $div).val();
    var rate = Number($("#select-rate>option:selected", $div).val());
    var playGame = ($(this).attr("id") == "start-game");
    app.startGame(songName, rate, playGame);
});
```

我们为两个按钮使用相同的事件处理程序。首先获取用户选择的选项，包括歌曲和播放速率。您可以使用 jQuery 的`:selected`选择器找到所选的`<option>`元素。我们通过查看按钮的`id`属性来确定用户按下了哪个按钮。然后我们在全局`app`对象上调用`startGame()`方法，传入所选的选项。我们稍后将编写该方法。

![行动时间-创建闪屏面板](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_07_01.jpg)

## *刚刚发生了什么？*

我们创建了一个闪屏面板，使用 HTML5 的`<progress>`元素显示音频文件的加载进度。加载完成后，它会显示游戏选项，然后等待用户选择选项并开始游戏。

# 行动时间-创建游戏面板

接下来，我们将创建游戏面板。我们已经有了钢琴键盘，它将是其中的一部分。我们还需要在其上方添加一个区域来显示下降的音符，并在游戏结束时显示结果的地方。让我们将这些添加到我们的 HTML 文件中的`game`元素内部和键盘上方：

```html
<div id="game">
    <div id="notes-panel">
        <div class="title">PIANO HERO</div>
    </div>
```

`<div id="notes-panel">`元素将用于容纳代表要演奏的音符的元素。现在它是空的。在游戏进行时，`note`元素将动态添加到这个元素中。它有一个带有标题的`<div>`元素，将显示在音符的后面。

```html
    <div id="results-panel">
        <h1>Score: <span class="score"></span></h1>
        <p>
            You got <span class="correct"></span>
            out of <span class="count"></span> notes correct.
        </p>
        <p>
            Note accuracy: <span class="note-accuracy"></span>%<br/>
            Timing accuracy: <span class="timing-accuracy"></span>%
        </p>
    </div>
```

`<div id="results-panel">`元素将在游戏完成时显示。我们添加`<span>`占位符来显示得分，音符的总数以及正确的数量，以及一些准确度统计。

```html
    <div class="keyboard">
        <div class="keys">
            <!-- Code not shown... -->
        </div>
        <div class="controls">
            <button id="stop-button">Stop</button>
            <button id="restart-button">Restart</button>
            <button id="quit-button">Quit</button><br/>
            <label for="sustain">Sustain: </label>
            <input type="checkbox" id="sustain" checked /><br />
            <label for="volume">Volume: </label>
            <input type="range" id="volume" min="1" max="100"
                value="100" step="1" />
        </div>
    </div>
</div>
```

我们还在键盘下方的`<div class="controls">`元素中添加了一些按钮。**停止**按钮将停止游戏，**重新开始**将从头开始播放当前歌曲，**退出**将把玩家带回到启动面板。

现在让我们在一个名为`gamePanel.js`的文件中创建一个`GamePanel`对象，以包含实现游戏所需的所有代码。构造函数将接受对`audioManager`对象的引用：

```html
function GamePanel(audioManager)
{
    var $panel = $("#game"),
        $notesPanel = $("#notes-panel"),
        $resultsPanel = $("#results-panel"),
        practiceMode = false,
        noteCount = 0,
        notesCorrect = 0,
        score = 0,
        keyCodesToNotes = {},
        sustain = true,
        volume = 1.0;
```

在这里，我们定义了一些变量来跟踪游戏状态。`practiceMode`变量确定我们是在玩游戏还是练习。`noteCount`、`notesCorrect`和`score`用于跟踪玩家的表现。

我们将所有支持键盘的代码从`PianoHeroApp`对象移动到`GamePanel`对象。这包括`keyCodesToNotes`、`sustain`和`volume`变量。我们还移动了`initKeyboard()`、`keyDown()`、`keyUp()`、`pressPianoKey()`、`releasePianoKey()`、`getPianoKeyElement()`和`isInputTypeSupported()`方法。最后，我们移动了`onKeyDown()`和`onKeyUp()`事件处理程序。

现在让我们为应用程序与游戏面板交互添加一些公共方法。与启动面板一样，我们需要方法来显示和隐藏它：

```html
this.show = function()
{
    $panel.fadeIn(startGame);
    return this;
};
this.hide = function()
{
    $panel.hide();
    return this;
};
```

`show()`公共方法将游戏面板淡入。我们传入一个对`startGame()`方法的引用，我们将在下一节中编写该方法，以在淡入完成时调用。

## *刚刚发生了什么？*

我们通过添加标记来创建游戏面板，用于容纳动画`note`元素的区域，以及显示得分的区域。这些是我们在上一章中创建的键盘之外的内容。然后，我们创建了一个 JavaScript 对象来保存游戏面板的所有代码，包括我们之前为键盘编写的所有代码。

# 行动时间-创建控制器

此时在我们的主应用程序对象`PianoHeroApp`中剩下的不多了。我们将所有加载音频的代码移到了`SplashPanel`对象中，将使键盘工作的所有代码移到了`GamePanel`对象中。

`PianoHeroApp`对象现在只作为状态控制器来隐藏和显示正确的面板。首先，我们需要添加一些变量来保存对面板的引用：

```html
function PianoHeroApp()
{
    var version = "7.1",
        audioManager = new AudioManager("audio"),
        splashPanel = new SplashPanel(audioManager),
        gamePanel = new GamePanel(audioManager),
        curPanel = undefined;
```

我们定义变量来保存音频管理器、启动面板和游戏面板对象。我们还有一个`curPanel`变量，它将被设置为当前显示的面板。一开始我们将把它设置为`undefined`。

接下来，我们将创建一个私有的`showPanel()`方法，它将隐藏当前显示的面板（如果有的话），并显示另一个面板：

```html
    function showPanel(panel)
    {
        if (curPanel) curPanel.hide();
        curPanel = panel;
        curPanel.show();
    }
```

这个方法以要显示的面板作为参数。这将是对`SplashPanel`或`GamePanel`的引用。首先，我们检查是否正在显示面板，如果是，我们调用它的`hide()`方法。然后我们将`curPanel`设置为新面板，并调用它的`show()`方法。

接下来，我们定义公共的`startGame()`方法。如果你还记得我们为`SplashPanel`对象编写的代码，这个方法将在用户点击**开始游戏**或**播放歌曲**按钮时从事件处理程序中调用。它会传入玩家选择的游戏选项：

```html
    this.startGame = function(songName, rate, playGame)
    {
        gamePanel.setOptions(songName, rate, playGame);
        showPanel(gamePanel);
    };
```

`startGame()`方法接受三个参数；要播放的歌曲的名称，播放速率（控制游戏进度的快慢），以及一个布尔值（确定用户是否点击了**开始游戏**按钮）。

首先，我们调用`GamePanel`对象的`setOptions()`方法，稍后我们将编写。我们通过与启动面板获得的相同参数进行传递。然后我们调用`showPanel()`方法，传入`GamePanel`对象。这将开始游戏。

接下来，我们将定义公共的`quitGame()`方法。当用户点击**退出**按钮时，这将从游戏面板中调用：

```html
    this.quitGame = function()
    {
        showPanel(splashPanel);
    };
```

在这个方法中，我们所做的就是调用`showPanel()`，将`SplashPanel`对象传递给它。

我们需要定义的最后一件事是应用程序的`start()`方法：

```html
    this.start = function()
    {
        $(document).keydown(function(e) { curPanel.onKeyDown(e); })
                   .keyup(function(e) { curPanel.onKeyUp(e); });

        showPanel(splashPanel);
        splashPanel.loadAudio();
    };
```

首先，在文档上设置键盘事件处理程序，就像我们在创建钢琴应用程序时所做的那样。但是，在这个应用程序中，我们将键盘事件转发到当前面板。通过在应用程序对象中集中处理键盘事件处理程序，我们不必在每个面板中编写大量代码来订阅和取消订阅来自文档的键盘事件处理程序，当面板显示或隐藏时。

我们做的最后一件事是显示启动面板，然后调用它的`loadAudio()`方法来启动应用程序。

### 音符

我们的启动和游戏面板实现了`show()`、`hide()`、`keydown()`和`keyup()`方法。由于 JavaScript 是无类型的，我们无法通过接口来强制执行这一点。因此，我们改为按照约定进行编程，假设所有面板都将实现这些方法。

## *刚刚发生了什么？*

我们在主应用程序对象中添加了代码来控制游戏的状态。当玩家点击启动面板上的按钮之一时，游戏就会开始，当他们从游戏中点击**退出**时，它会显示启动面板。

# 创建音频序列

在我们玩游戏之前，我们需要一种方法来通过按照特定顺序、在正确的时间和以正确的速度播放音符来在钢琴上演奏歌曲。我们将创建一个名为`AudioSequencer`的对象，它接受一个音乐事件对象数组并将它们转换为音乐。

为了实现我们的音频序列，我们需要定义音乐事件的格式。我们将大致遵循 MIDI 格式，但简化得多。MIDI 是记录和回放音乐事件的标准。每个事件包含有关何时以及如何演奏音符或关闭音符的信息。

我们的事件对象将包含三个字段：

+   `deltaTime`：执行事件之前等待的时间量。

+   `事件`：这是一个整数事件代码，确定事件的操作。它可以是以下之一：

+   打开音符

+   关闭音符

+   提示点将在歌曲的开头

+   曲目结束将表示歌曲结束。

+   `注意`：这是要演奏的音符。它包含了八度和音符，并且与我们的音频文件名称匹配，例如，3C。

音频序列将通过查看每个事件中的`deltaTime`字段来确定在触发事件之前等待多长时间。客户端将传递一个事件处理程序函数，当事件触发时将调用该函数。然后客户端将查看事件数据并确定要演奏哪个音符。这个循环会一直持续，直到没有更多的事件为止。

![创建音频序列](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_07_07.jpg)

# 行动时间 - 创建 AudioSequencer

让我们在一个名为`audioSequencer.js`的文件中创建我们的`AudioSequencer`对象。我们将首先定义一些变量：

```html
function AudioSequencer()
{
    var _events = [],
        _playbackRate = 1,
        _playing = false,
        eventHandler = undefined,
        timeoutID = 0;
```

首先，我们定义了一个`_events`数组来保存所有要播放的音乐事件。`_playbackRate`变量控制歌曲播放的速度。值为`1`时是正常速度，小于`1`时是较慢，大于`1`时是较快。`_playing`变量在播放歌曲时设置为`true`。`eventHandler`将设置为一个在事件触发时调用的函数，`timeoutID`将包含从`setTimeout()`返回的句柄，以防用户停止游戏，我们需要取消超时。

现在让我们定义一些公共属性方法。第一个是`events()`。它用于获取或设置`_events`数组：

```html
    this.events = function(newEvents)
    {
        if (newEvents) {
            _events = newEvents;
            return this;
        }
        return _events;
    };
```

接下来是`playbackRate()`。它用于获取或设置`_playbackRate`：

```html
    this.playbackRate = function(newRate)
    {
        if (newRate) {
            _playbackRate = newRate;
            return this;
        }
        return _playbackRate;
    };
```

最后，我们有`isPlaying()`，用于确定歌曲当前是否正在播放：

```html
    this.isPlaying = function()
    {
        return _playing;
    };
```

现在我们将编写公共的`startPlayback()`方法。该方法接受两个参数；事件处理程序函数和可选的起始位置，即`_events`数组的索引：

```html
    this.startPlayback = function(callback, startPos)
    {
        startPos = startPos || 0;

        if (!_playing && _events.length > 0)
        {
            _playing = true;
            eventHandler = callback;
            playEvent(startPos);
            return true;
        }
        return false;
    };
```

首先，我们将`startPos`参数默认设置为`0`，如果没有提供的话。接下来，我们检查歌曲是否已经在播放，并确保我们实际上有一些事件要播放。如果是这样，我们将`_playing`标志设置为`true`，存储事件处理程序的引用，然后为第一个事件调用`playEvent()`。如果成功开始播放，则返回`true`。

现在让我们编写`playEvent()`方法。它接受一个参数，即要触发的下一个事件的索引：

```html
    function playEvent(index)
    {
        var event = _events[index];
        eventHandler(event.event, event.note, index);

        index++;
        if (index < _events.length)
        {
            timeoutID = setTimeout(function()
            {
                playEvent(index);
            },
            _events[index].deltaTime * (1 / _playbackRate));
        }
        else _playing = false; // all done
    }
```

我们首先要做的是在`_events`数组中获取指定索引处的事件。然后立即调用`startPlayback()`方法中提供的事件处理程序的回调函数，传递事件代码、要播放的音符和事件索引。

接下来，我们增加索引以获取下一个事件。如果还有其他事件，我们将调用`setTimeout()`来等待事件的`deltaTime`字段中指定的时间量，然后再次调用`playEvent()`，传递下一个事件的索引。我们通过将`deltaTime`乘以播放速率的倒数来计算等待的时间量。例如，如果播放速率为 0.5，则等待时间将是 1，0.5 或 2 倍于正常速率。这个循环将继续进行，直到没有更多的事件要播放。

我们最后需要一个公共的`stopPlayback()`方法。调用此方法将停止事件循环，从而停止音频事件的播放：

```html
    this.stopPlayback = function()
    {
        if (_playing)
        {
            _playing = false;
            if (timeoutID) clearTimeout(timeoutID);
            eventHandler = undefined;
        }
    };
```

首先，我们检查`_playing`标志，以确保歌曲实际上正在播放。如果是这样，我们将标志设置为`false`，然后调用`clearTimeout()`来停止超时。这将阻止再次调用`playEvent()`，从而停止播放循环。

我们最后需要做的是定义播放事件代码，这样我们就不必记住事件代码编号。我们将使用`AudioSequencer`上的对象定义一个伪枚举，称为`eventCodes`：

```html
AudioSequencer.eventCodes =
{
    noteOn: 1,
    noteOff: 2,
    cuePoint: 3,
    endOfTrack: 4
};
```

## *刚刚发生了什么？*

我们创建了一个音频序列对象，它接受一个音乐事件数组，类似于 MIDI 事件，并使用`setTimeout()`函数在正确的时间调用它们。当事件被触发时，它会调用游戏面板传入的事件处理程序函数。

### 注意

虽然我们编写了这段代码来播放音乐，但你可以在任何需要在预定时间发生事情的地方使用相同的技术。

# 播放歌曲

现在我们有了一个音频序列，我们可以进入游戏面板并添加一些代码以在练习模式下播放歌曲。当歌曲播放时，它将在屏幕上按下正确的键，就像玩家钢琴一样。稍后我们将添加代码来检查玩家的互动，看他们跟着歌曲的节奏有多好。

# 行动时间-添加音频序列

让我们将音频序列添加到游戏面板中。我们将进入`GamePanel`对象，并在其中添加一个`AudioSequencer`的实例：

```html
function GamePanel(audioManager)
{
    var sequencer = new AudioSequencer();
```

接下来让我们编写公共的`setOptions()`方法，该方法从`PianoHeroApp`的`startGame()`方法中调用。它接受三个参数；歌曲名称，播放速率，以及是否在练习模式下播放游戏或歌曲：

```html
    this.setOptions = function(songName, rate, playGame)
    {
        sequencer.events(musicData[songName])
                 .playbackRate(rate);
        practiceMode = !playGame;
        return this;
    };
```

我们首先将音频序列的`events()`属性设置为要播放的歌曲的数据。我们从`musicData.js`中定义的`musicData`对象中获取歌曲数据。然后，我们设置音频序列的`playbackRate()`属性。最后，我们设置`practiceMode`变量。

`musicData`对象包含了音序器可以为用户在闪屏页面上选择的所有歌曲播放的事件数据。每首歌曲都被定义为一个音乐事件对象的数组。以下是韵律“Twinkle, Twinkle Little Star”数据的示例：

```html
var musicData =
{
    littleStar: [
        { deltaTime: 0, event: 3, note: null },
        { deltaTime: 0, event: 1, note: "3C" },
        { deltaTime: 500, event: 2, note: "3C" },
        { deltaTime: 0, event: 1, note: "3C" },
        { deltaTime: 500, event: 2, note: "3C" },
        { deltaTime: 0, event: 1, note: "3G" },
        { deltaTime: 500, event: 2, note: "3G" },
        // ...
        { deltaTime: 0, event: 4, note: null }
    ]
};
```

它以一个提示点事件（`event: 3`）开始，然后打开 3C 音符（`event: 1`）。500 毫秒后，关闭 3C 音符（`event: 2`）。它一直持续到最后一个事件，即曲目结束（`event: 4`）。

接下来让我们编写`startGame()`方法，该方法从`show()`方法中调用：

```html
function startGame()
{
    $resultsPanel.hide();
    $notesPanel.show();
    // Reset score
    noteCount = 0;
    notesCorrect = 0;
    score = 0;
    // Start interval for notes animation
    intervalId = setInterval(function() { updateNotes(); },
        1000 / framesPerSecond);
    // Start playback of the song
    sequencer.startPlayback(onAudioEvent, 0);
}
```

我们首先隐藏结果面板并显示音符面板。然后重置分数和统计信息。

接下来，我们通过调用 JavaScript 的`setInterval()`函数并将`intervalId`变量设置为返回的句柄来启动一个间隔计时器。我们稍后将使用它来在游戏结束或玩家停止游戏时停止间隔。此间隔用于动画播放从页面顶部下落的音符面板中的元素。我们通过将 1000 毫秒除以每秒帧数来设置间隔以以恒定速率触发。我们将使用每秒 30 帧的帧速率，这足以产生相对平滑的动画，而不会拖慢游戏。在计时器的每个间隔处，我们调用`updateNotes()`方法，我们将在下一节中编写。

在此方法中的最后一件事是调用音频顺序器的`startPlayback()`方法，将音频事件处理程序方法`onAudioEvent()`的引用和起始位置零传递给它：

```html
function onAudioEvent(eventCode, note)
{
    switch (eventCode)
    {
        case AudioSequencer.eventCodes.noteOn:
            addNote(note);
            break;
        case AudioSequencer.eventCodes.endOfTrack:
            sequencer.stopPlayback();
            break;
    }
}
```

此方法接受两个参数：音频事件代码和要播放的音符。我们使用`switch`语句以及我们的`eventCodes`枚举来确定如何处理事件。如果事件代码是`noteOn`，我们调用`addNote()`方法向音符面板添加一个`note`元素。如果是`endOfTrack`事件，我们在音频顺序器上调用`stopPlayback()`。我们现在可以忽略所有其他事件。

## *刚刚发生了什么？*

我们将音频顺序器添加到游戏面板中，并连接一个处理音符事件触发的函数。我们添加了一个`startGame()`方法，用于启动动画间隔以动画播放`note`元素。

# 创建动画音符

现在我们将实现音符面板的代码。这是音符从页面顶部下落的动画发生的地方。它的工作方式如下：

+   音频顺序器发送一个事件，指示应该播放一个音符（请参阅上一节中的`onAudioEvent()`）。

+   此时实际上并没有播放音符。相反，表示音符的矩形元素被添加到音符面板的顶部。

+   每当我们的动画间隔计时器触发时，`note`元素的 y 位置会递增，使其向下移动。

+   当元素触及音符面板的底边（以及键盘的顶边）时，它会播放与音符相关的音频剪辑。

+   当元素完全离开音符面板时，它将从 DOM 中移除。

![创建动画音符](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_07_04.jpg)

# 行动时间-添加音符

让我们编写`addNote()`方法，该方法在上一节中由`onAudioEvent()`引用。此方法接受一个参数，要添加的音符的名称：

```html
function addNote(note)
{
    noteCount++;
    // Add a new note element
    var $note = $("<div class='note'></div>");
    $note.data("note", note);
    $notesPanel.append($note);

    var $key = getPianoKeyElement(note);
    // Position the note element over the piano key
    $note.css("top", "0")
         .css("left", $key.position().left)
         .css("width", $key.css("width"));

    if ($key.hasClass("black"))
    {
        $note.addClass("black");
    }
}
```

首先，我们更新`noteCount`变量以跟踪统计信息。然后，我们使用 jQuery 创建一个新的音符`<div>`元素，并给它一个`"note"`类。我们将`data-note`自定义属性设置为音符的名称。当它到达面板底部时，我们将需要它来知道要播放哪个音符。最后，我们使用 jQuery 的`append()`方法将其添加到音符面板中。

接下来我们要做的是将`note`元素定位在它所代表的钢琴键上。我们通过调用现有的`getPianoKeyElement()`方法来获取与音符关联的钢琴键元素。我们提取钢琴键的左侧位置和宽度，并将`note`元素设置为相同的值，使其对齐。

我们最后要做的是检查钢琴键是黑键还是白键，方法是检查它是否定义了`"black"`类。如果是，则我们也给`note`元素添加`"black"`类。这将使元素以不同的颜色显示。

让我们为`note`元素添加样式：

```html
#notes-panel .note
{
    position: absolute;
    display: block;
    width: 50px;
    height: 20px;
    background-color: cyan;
    /* browser specific gradients not shown */
    background: linear-gradient(left, white, cyan);
    box-shadow: 0 0 4px 4px rgba(255, 255, 255, 0.7);
}
```

我们将`position`设置为`absolute`，因为我们需要移动它们并将它们放在我们想要的任何位置。我们给它们一个从左到右的线性渐变，从白色渐变到青色。我们还给它一个没有偏移的白色阴影。这将使它看起来像是在黑色背景上发光：

```html
#notes-panel .note.black
{
    background-color: magenta;
    /* browser specific gradients not shown */
    background: linear-gradient(left, white, magenta);
}
```

具有``"black"``类的音符将覆盖背景颜色，从白色渐变为品红色。

## *刚刚发生了什么？*

我们创建了一个方法，向音符面板添加代表音符的元素。我们将这些音符定位在它们所属的钢琴键的正上方。

# 到了行动的时候-为音符添加动画

之前，我们在`startGame()`方法中使用`setInterval()`开始了一个间隔。`updateNotes()`方法在间隔到期时被调用。该方法负责更新所有`note`元素的位置，使它们看起来向下移动屏幕：

```html
function updateNotes()
{
    $(".note", $notesPanel).each(function()
    {
        var $note = $(this);
        var top = $note.position().top;
        if (top <= 200)
        {
            // Move the note down
            top += pixelsPerFrame;
            $note.css("top", top);
            if (top + 20 > 200)
            {
                // The note hit the bottom of the panel
                currentNote.note = $note.data("note");
                currentNote.time = getCurrentTime();
                currentNote.$note = $note;
                if (practiceMode) pressPianoKey($note.data("note"));
            }
        }
        else
        {
            // Note is below the panel, remove it
            if (practiceMode) releasePianoKey($note.data("note"));
            $note.remove();
        }
    });

    // Check if there are any notes left
    if ($(".note", $notesPanel).length == 0)
    {
        // No more notes, game over man
        if (!practiceMode) showScore();
        endGame();
    }
}
```

首先，我们选择音符面板中的所有`note`元素并对它们进行迭代。对于每一个，我们执行以下操作：

+   获取顶部位置并检查是否小于 200，这是音符面板的高度。

+   如果元素仍然在音符面板内，我们将元素向下移动`pixelsPerFrame`变量定义的像素数。每秒 30 帧，即 2 像素。

+   接下来，我们检查`note`元素的底部是否击中了音符面板的底部，方法是检查底部是否大于 200。

+   如果是，我们将`currentNote`对象的`note`变量设置为音符，这样我们可以稍后检查用户是否演奏了正确的音符。我们还获取音符击中底部的确切时间，以确定玩家离按时演奏有多近。

+   如果我们处于练习模式，还可以通过调用`pressPianoKey()`并将`note`元素传递给它来演奏音符。

+   如果`note`元素在音符面板之外，那么我们调用`releasePianoKey()`并将其从 DOM 中移除。

我们要做的最后一件事是检查音符面板中是否还有任何音符元素。如果没有，游戏结束，我们调用`showScore()`来显示结果面板。然后我们调用`endGame()`，停止动画间隔。

## *刚刚发生了什么？*

我们对`note`元素进行了动画处理，使它们看起来在键盘上的键上下落。当音符击中音符面板底部时，如果处于练习模式，我们会演奏音符。当`note`元素移出面板时，我们将其从 DOM 中移除。

## 试一试英雄

尝试调整帧速率，看看它如何影响动画的质量。什么是可以接受的最低帧速率？什么是可以察觉到的最高帧速率？

# 处理用户输入

用户已经开始了游戏，音符正在屏幕上下落。现在我们需要检查玩家是否在正确的时间按下了正确的钢琴键。当他们这样做时，我们将根据他们的准确性给他们一些分数。

# 行动时间-检查音符

我们将在`keyDown()`方法中添加对`checkNote()`方法的调用。`checkNote()`方法以音符的名称作为参数，并检查音符面板底部是否有与之匹配的`note`元素：

```html
function checkNote(note)
{
    if (currentNote.note == note)
    {
        var dif = getCurrentTime() - currentNote.time;
        if (dif < gracePeriod)
        {
            notesCorrect++;
            score += Math.round(10 * (gracePeriod - dif) / gracePeriod);
            currentNote.$note.css("background", "green");
            addHitEffect();
        }
    }
}
```

首先检查之前在`updateNotes()`中设置的`currentNote`对象。如果它的音符与用户演奏的音符相同，那么他们可能会因在正确时间演奏而得到一些分数。要找出他们是否得分，我们首先找出音符击中面板底部的时间与当前时间之间的毫秒时间差。如果在允许的宽限期内，我们将其设置为 200 毫秒，那么我们计算得分。

我们首先增加了正确音符的数量。然后，我们通过计算他们的偏差百分比并乘以 10 来确定分数。这样，每个音符的分数在 1 到 10 之间。最后，为了给用户一些指示他们做对了，我们将元素的背景颜色改为绿色，并调用`addHitEffect()`：

```html
function addHitEffect()
{
    var $title = $(".title", $notesPanel);
    $title.css("color", "#012");
    setTimeout(function() { $title.css("color", "black"); }, 100);
}
```

`addHitEffect()`方法通过改变颜色在音符面板的背景中闪烁**PIANO HERO**标题，使用`setTimeout()`调用等待 100 毫秒，然后将其改回黑色。

![行动时间-检查音符](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_07_06.jpg)

## *刚刚发生了什么？*

我们添加了一个方法来检查是否在“音符”元素的正确时间按下了正确的钢琴键。如果是这样，我们根据音符的演奏时间来添加分数，并改变音符的颜色以指示成功。

# 结束游戏

现在玩家可以玩游戏，我们可以跟踪分数和他们正确演奏的音符数量。游戏结束时，我们需要显示结果面板，显示分数和一些统计信息。

# 行动时间-创建结果面板

在歌曲的所有音符都被演奏后，`updateNotes()`方法调用`showScore()`，在那里我们将显示玩家的分数和一些统计信息：

```html
function showScore()
{
    $notesPanel.hide();
    $resultsPanel.fadeIn();
    $(".score", $resultsPanel).text(score);
    $(".correct", $resultsPanel).text(notesCorrect);
    $(".count", $resultsPanel).text(noteCount);
    $(".note-accuracy", $resultsPanel).text(
        Math.round(100 * notesCorrect / noteCount));
    $(".timing-accuracy", $resultsPanel).text(
        Math.round(10 * score / notesCorrect));
}
```

首先，我们隐藏音符面板，并在其位置淡入分数面板。然后，我们在 DOM 中的占位符中填入分数和统计信息。我们显示分数、正确音符的数量和总音符数量。此外，我们使用`notesCorrect`和`noteCount`变量计算他们正确演奏的音符的百分比。

我们通过从分数和正确音符的数量中计算来获得时间准确度百分比。请记住，每个音符可能获得的总分数是 10 分，所以如果他们正确演奏了 17 个音符，那么可能获得的总分数是 170。如果分数是 154，那么 154/170≈91%。

![行动时间-创建结果面板](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_07_05.jpg)

## *刚刚发生了什么？*

当游戏结束时，我们显示了结果面板，并填充了玩家的分数和统计信息。我们的游戏现在已经完成。试一试，成为钢琴英雄！

## 尝试一试

尝试编写一个音频记录器类，记录用户在键盘上演奏音符的时间，并将其保存到可以由音频序列器播放的数据对象数组中。

## 小测验

Q1. 哪个 JavaScript 函数可以用来创建一个定时器，直到清除为止？

1.  `setTimeout()`

1.  `setRate()`

1.  `setInterval()`

1.  `wait()`

Q2. `<progress>`元素的哪些属性控制标记为完成的进度条的百分比？

1.  `value`和`max`

1.  `currentValue`和`maxValue`

1.  `start`和`end`

1.  `min`和`max`

# 摘要

我们创建了一个基于我们在上一章中编写的钢琴应用程序的游戏。我们使用 JavaScript 计时器来实现音频序列器以播放歌曲并创建动画循环。我们创建了闪屏和游戏面板，并学会了在它们之间过渡游戏状态。

本章中我们涵盖了以下概念：

+   如何创建一个闪屏面板并使用文本阴影产生有趣的文本效果

+   如何使用 HTML5 进度条元素显示动态资源的加载进度

+   使用 JavaScript 计时器函数创建音频序列器，控制音频播放以播放歌曲

+   如何使用 JavaScript 计时器来动画 DOM 元素

+   如何在游戏状态和面板之间过渡

+   如何收集用户输入，验证它，并在游戏结束时显示结果

在下一章中，我们将学习如何使用 Ajax 来动态加载资源并通过构建天气小部件调用 Web 服务。


# 第八章：天气的变化

> "气候是我们所期望的，天气是我们得到的。"
> 
> -马克·吐温

*在本章中，我们将构建一个天气小部件，以了解如何使用 Ajax 异步加载内容并与 Web 服务通信。我们将学习 Ajax 以及如何使用 jQuery 的 Ajax 方法加载包含 XML 或 JSON 格式数据的文件。然后我们将从 Web 服务获取天气状况以在小部件中显示。我们还将使用 HTML 地理位置 API 来查找用户的位置，以便显示他们当地的天气。*

在本章中，我们将学到以下内容：

+   如何使用 jQuery 的 Ajax 方法获取 XML 和 JSON 数据

+   解析从服务返回的 JSON 与 XML

+   什么是 Web 服务以及如何使用 Ajax 异步与它们通信

+   跨站脚本的问题，以及解决方案 JSONP

+   如何使用 HTML5 地理位置 API 获取用户的位置

+   如何连接到 Web 服务以获取当前天气报告

# Ajax 简介

Ajax 是 JavaScript 用于向服务器发送数据和接收数据的技术。最初**Ajax**代表**异步 JavaScript 和 XML**，但现在这个含义已经丢失，因为 JSON（我们在第一章中学到的，*手头的任务*）已经开始取代 XML 作为打包数据的首选格式，而 Ajax 请求不需要是异步的。

使用 Ajax 将使您的应用程序更加动态和响应。与其在每次需要更新网页的部分时都进行回发，您可以仅加载必要的数据并动态更新页面。通过 Ajax，我们可以从服务器检索几乎任何东西，包括要插入到网页中的 HTML 片段和应用程序使用的静态数据。我们还可以调用提供对服务器端唯一可用的数据和服务的 Web 服务。

## 发出 Ajax 请求

jQuery 提供了一些方法，可以轻松访问 Web 资源并使用 Ajax 调用 Web 服务。`ajax()`方法是其中最原始的方法。如果你想对服务调用有最大的控制，可以使用这个方法。大多数情况下，最好使用`get()`或`post()`等更高级的方法。

`get()`方法使使用 Ajax 进行 HTTP GET 请求变得更加容易。最简单的情况下，您传入要获取的资源或服务的 URL，它会异步发送请求并获取响应。完成后，它会执行您提供的回调函数。

例如，以下代码片段对服务器上的 XML 文件进行 GET 请求，并在对话框中显示其内容：

```html
$.get("data/myData.xml", function(data) {
    alert("data: " + data);
});
```

所有的 jQuery Ajax 方法都返回一个对象，您可以附加`done()`、`fail()`和`always()`回调方法。`done()`方法在请求成功后调用，`fail()`在出现错误时调用，`always()`在请求成功或失败后都会调用：

```html
$.get("data/myData.xml")
    .done(function(data) { alert("data: " + data); })
    .fail(function() { alert("error"); })
    .always(function() { alert("done"); });
```

传递给`done()`方法的数据将根据响应中指定的 MIME 类型，要么是 XML 根元素，要么是 JSON 对象，要么是字符串。如果是 JSON 对象，您可以像引用任何 JavaScript 对象一样引用数据。如果是 XML 元素，您可以使用 jQuery 来遍历数据。

您可以通过传入一个名称/值对的对象文字来为请求提供查询参数：

```html
$.get("services/getInfo.php", {
    firstName: "John",
    lastName: "Doe"
})
.done(function(data) { /* do something */ });
```

这将发出以下请求：

```html
services/getInfo.php?firstName=John&lastName=Doe
```

如果您更喜欢进行 POST 请求而不是 GET 请求，则可以使用`post()`方法，如果您使用安全协议（如 HTTPS）并且不希望在请求中看到查询参数，则可能更可取：

```html
$.post("services/getInfo.php", {
    firstName: "John",
    lastName: "Doe"
});
```

### 注意

在一些浏览器中，包括 Chrome，您无法使用`file://`协议通过 Ajax 请求访问文件。在这种情况下，您需要通过 IIS 或 Apache 运行您的应用程序，或者使用其他浏览器。

# 行动时间-创建一个天气小部件

在本章中，我们将演示如何通过实现一个显示天气报告的小部件来进行各种 Ajax 调用。让我们从定义小部件的 HTML 标记开始：

```html
<div id="weather-widget">
  <div class="loading">
    <p>Checking the weather...</p>
    <img src="img/loading.gif" alt="Loading..."/>
  </div>
  <div class="results">
    <header>
      <img src="img/" alt="Condition"/>Current weather for
      <div class="location"><span></span></div>
    </header>
    <section class="conditions">
      Conditions: <span data-field="weather"></span><br/>
      Temperature: <span data-field="temperature_string"></span><br/>
      Feels Like: <span data-field="feelslike_string"></span><br/>
      Humidity: <span data-field="relative_humidity"></span><br/>
      Wind: <span data-field="wind_string"></span><br/>
    </section>
  </div>
  <div class="error">
    Error: <span></span>
  </div>
</div>
```

小部件由三个不同的面板组成，任何时候只有一个面板会显示。`<div class="loading">`面板在从服务器检索天气数据时可见。它里面有一个动画图像，向用户指示正在加载某些内容。

`<div class="results">`面板将显示从服务器返回的天气数据。它包含占位符字段，用于放置天气数据。请注意，我们在占位符`<span>`元素上使用了自定义数据属性。稍后将使用这些属性从服务器返回的 XML 文档或 JSON 对象中提取正确的数据。

`<div class="error">`面板将在 Ajax 请求失败时显示错误消息。

现在让我们创建 JavaScript 代码来控制小部件，命名为`weatherWidget.js`。我们将创建一个`WeatherWidget`对象，其构造函数接受一个包装在 jQuery 对象中的小部件根元素的引用：

```html
function WeatherWidget($widget)
{
    this.update = function()
    {
        $(".results", $widget).hide();
        $(".loading", $widget).show();
        getWeatherReport();
    };

    function getWeatherReport() {
        // not implemented
    }
}
```

在我们的对象中，我们创建了一个名为`update()`的公共方法。这将从页面调用，告诉小部件更新天气报告。在`update()`方法中，我们首先隐藏结果面板，显示加载面板。然后我们调用`getWeatherReport()`方法，它将进行 Ajax 调用并在完成时更新小部件。在接下来的几节中，我们将编写此方法的不同版本。

## *刚刚发生了什么？*

我们创建了一个可以放置在网站任何页面上的天气小部件。它有一个公共的`update()`方法，用于告诉小部件更新其信息。

# 行动时间-获取 XML 数据

首先让我们创建一个从 XML 文件中获取数据并从其数据更新天气小部件的示例。我们将创建一个名为`weather.html`的新网页，并将天气小部件的标记放入其中。该页面将有一个**检查天气**按钮。单击时，它将调用天气小部件的`update()`方法。您可以在`第八章/示例 8.1`中找到此示例的代码。

接下来，我们需要创建一个包含一些天气信息的 XML 文件。我们将文件命名为`weather.xml`，并将其放在`data`文件夹中：

```html
<weather>
    <location>Your City</location>
    <current_observation>
        <weather>Snow</weather>
        <temperature_string>38.3 F (3.5 C)</temperature_string>
        <feelslike_string>38 F (3 C)</feelslike_string>
        <relative_humidity>76%</relative_humidity>
        <wind_string>From the WSW at 1.0 MPH</wind_string>
        <icon_url>images/snow.gif</icon_url>
    </current_observation>
</weather>
```

现在让我们在`WeatherWidget`对象中编写`getWeatherReport()`方法：

```html
function getWeatherReport()
{
    $.get("data/weather.xml")
        .done(function(data) {
            populateWeather(data);
       })
        .fail(function(jqXHR, textStatus, errorThrown) { 
            showError(errorThrown);
        });
}
```

在这个方法中，我们使用 jQuery 的`get()`方法执行 Ajax 请求，并将 XML 文件的路径传递给它。如果服务器调用成功，我们调用`populateWeather()`方法，将请求返回的数据传递给它。这将是表示我们的 XML 文件的 DOM 的根元素。如果请求失败，我们调用`showError()`方法，将错误消息传递给它。

接下来让我们编写`populateWeather()`方法。这是我们将从 XML 文档中提取数据并插入到页面中的地方：

```html
function populateWeather(data)
{
    var $observation = $("current_observation", data);

    $(".results header img", $widget)
        .attr("src", $("icon_url", $observation).text());
    $(".location>span", $widget)
        .text($("location", data).text());

    $(".conditions>span").each(function(i, e)
    {
        var $span = $(this);
        var field = $span.data("field");
        $(this).text($(field, $observation).text());
    });

    $(".loading", $widget).fadeOut(function ()
    {
        $(".results", $widget).fadeIn();
    });
}
```

我们需要一种方法来从服务器检索到的 XML 文档中提取数据。幸运的是，jQuery 可以用来选择任何 XML 文档中的元素，而不仅仅是网页的 DOM。我们所要做的就是将我们的 XML 的根元素作为第二个参数传递给 jQuery 选择器。这正是我们在方法的第一行中所做的，以获取`current_observation`元素并将其存储在`$observation`变量中。

接下来，我们使用 jQuery 从`icon_url`元素中获取文本，并将图像的`src`属性设置为它。这是表示当前天气的图像。我们还从`location`元素中获取文本，并将其插入到小部件的标题中。

然后，我们遍历小部件条件部分中的所有`<span>`元素。对于每个元素，我们获取其`data-field`自定义数据属性的值。我们使用它来查找`current_observation`元素中具有相同名称的元素，获取其文本，并将其放入`<span>`元素中。

我们做的最后一件事是淡出加载面板并淡入结果面板，以在页面上显示当前天气。加载的数据如下所示：

![执行操作-获取 XML 数据](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_08_02.jpg)

## 发生了什么？

我们使用 jQuery 的`get()` Ajax 方法从服务器加载了一个包含天气数据的 XML 文件。然后，我们使用 jQuery 选择从 XML 文档中提取信息，并将其放入小部件的占位符元素中以在页面上显示它。

# 执行操作-获取 JSON 数据

现在让我们做与上一节相同的事情，只是这次我们将从包含 JSON 格式数据的文件中获取数据，而不是 XML。概念是相同的，只是从 Ajax 调用中返回的是 JavaScript 对象，而不是 XML 文档。您可以在`第八章/示例 8.2`中找到此示例的代码。

首先让我们定义我们的 JSON 文件，我们将其命名为`weather.json`，并将其放在`data`文件夹中：

```html
{
    "location": {
        "city":"Your City"
    }
    ,"current_observation": {
        "weather":"Clear",
        "temperature_string":"38.3 F (3.5 C)",
        "wind_string":"From the WSW at 1.0 MPH Gusting to 5.0 MPH",
        "feelslike_string":"38 F (3 C)",
        "relative_humidity":"71%",
        "icon_url":"images/nt_clear.gif"
    }
}
```

这个 JSON 定义了一个匿名包装对象，其中包含一个`location`对象和一个`current_observation`对象。`current_observation`对象包含 XML 文档中`current_observation`元素的所有数据。

现在让我们重写`getWeatherReport()`以获取 JSON 数据：

```html
function getWeatherReport()
{
    $.get("data/weather.json", {
        t: new Date().getTime()
    })
    .done(function(data) { populateWeather(data); })
    .fail(function(jqXHR, textStatus, errorThrown) {
        showError(errorThrown);
    });
}
```

我们仍然使用`get()`方法，但现在我们正在获取 JSON 文件。请注意，这次我们正在向 URL 添加查询参数，设置为当前时间的毫秒数。这是绕过浏览器缓存的一种方法。大多数浏览器似乎无法识别使用 Ajax 请求更改文件时。通过添加每次发出请求时都会更改的参数，它会欺骗浏览器，使其认为这是一个新请求，绕过缓存。请求将类似于`data/weather.json?t=1365127077960`。

### 注意

当通过诸如 IIS 之类的 Web 服务器运行此应用程序时，您可能需要将`.json`文件类型添加到站点的 MIME 类型列表中（`.json`，`application/json`）。否则，您将收到文件未找到的错误。

现在让我们重写`populateWeather()`方法：

```html
function populateWeather(data)
{
    var observation = data.current_observation;

    $(".results header img", $widget).attr("src", observation.icon_url);
    $(".location>span", $widget).text(data.location.city);

    $(".conditions>span").each(function(i, e)
    {
        var $span = $(this);
        var field = $span.data("field");
        $(this).text(observation[field]);
    });

    $(".loading", $widget).fadeOut(function ()
    {
        $(".results", $widget).fadeIn();
    });
}
```

这次 jQuery 认识到我们已经以 JSON 格式加载了数据，并自动将其转换为 JavaScript 对象。因此，这就是传递给方法的`data`参数。要获取观察数据，我们现在可以简单地访问`data`对象的`current_observation`字段。

与以前一样，我们遍历所有的`<span>`占位符元素，但这次我们使用方括号来使用`field`自定义数据属性作为字段名从`observation`对象中访问数据。

## 发生了什么？

我们重写了天气小部件，以从 JSON 格式文件获取天气数据。由于 jQuery 会自动将 JSON 数据转换为 JavaScript 对象，因此我们可以直接访问数据，而不必使用 jQuery 搜索 XML 文档。

# HTML5 地理位置 API

稍后，我们将再次重写天气小部件，以从 Web 服务获取天气，而不是从服务器上的静态文件。我们希望向用户显示其当前位置的天气，因此我们需要某种方式来确定用户的位置。HTML5 刚好有这样的东西：地理位置 API。

地理位置由几乎每个现代浏览器广泛支持。位置的准确性取决于用户设备的功能。具有 GPS 的设备将提供非常准确的位置，而没有 GPS 的设备将尝试通过其他方式（例如通过 IP 地址）尽可能接近地确定用户的位置。

通过使用`navigator.geolocation`对象访问地理位置 API。要获取用户的位置，您调用`getCurrentPosition()`方法。它需要两个参数-如果成功则是回调函数，如果失败则是回调函数：

```html
navigator.geolocation.getCurrentPosition(
    function(position) { alert("call was successful"); },
    function(error) { alert("call failed"); }
);
```

成功调用的函数会传递一个包含另一个名为`coords`的对象的对象。以下是`coords`对象包含的一些更有用的字段的列表：

+   `latitude`：这是用户的纬度，以十进制度表示（例如，44.6770429）。

+   `longitude`：这是用户的经度，以十进制度表示（例如，-85.60261659）。

+   `accuracy`：这是位置的精度，以米为单位。

+   `speed`：这是用户以米每秒为单位的移动速度。这适用于带有 GPS 的设备。

+   `heading`：这是用户移动的方向度数。与速度一样，这适用于带有 GPS 的设备。

例如，如果您想获取用户的位置，您可以执行以下操作：

```html
var loc = position.coords.latitude + ", " + position.coords.longitude);
```

用户必须允许您的页面使用 Geolocation API。如果他们拒绝您的请求，调用`getCurrentPosition()`将失败，并且根据浏览器，可能会调用错误处理程序或静默失败。在 Chrome 中，请求如下所示：

![HTML5 Geolocation API](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_08_01.jpg)

错误处理程序会传递一个包含两个字段`code`和`message`的错误对象。`code`字段是整数错误代码，`message`是错误消息字符串。有三种可能的错误代码：`permission denied`，`position unavailable`或`timeout`。

Geolocation API 还有一个`watchPosition()`方法。它的工作方式与`getCurrentPosition()`相同，只是当用户移动时会调用您的回调函数。这样，您可以实时跟踪用户并在应用程序中更新他们的位置。

### 注意

在某些浏览器中，您必须通过 IIS 或 Apache 等 Web 服务器运行网页才能使地理位置功能正常工作。

# 行动时间-获取地理位置数据

在本节中，我们将向我们的天气小部件示例中添加一些代码，以访问 Geolocation API。您可以在`chapter8/example8.3`中找到本节的代码。

首先让我们进入`weather.html`，并在**检查天气**按钮旁边添加一个显示用户位置的部分：

```html
<div id="controls">
    <div>
        Latitude: <input id="latitude" type="text"/><br/>
        Longitude: <input id="longitude" type="text"/>
    </div>
    <button id="getWeather">Check Weather</button>
    <div class="error">
        Error: <span></span>
    </div>
</div>
```

我们添加了一个带有文本字段的`<div>`元素，以显示我们从 Geolocation API 获取的用户纬度和经度。我们还添加了一个`<div class="error">`元素，以显示地理位置失败时的错误消息。

现在让我们进入`weather.js`，并向`WeatherApp`对象添加一些代码。我们将添加一个`getLocation()`方法：

```html
function getLocation()
{
    if (navigator.geolocation)
    {
        navigator.geolocation.getCurrentPosition(
        function(position)
        {
            $("#latitude").val(position.coords.latitude);
            $("#longitude").val(position.coords.longitude);
        },
        function(error)
        {
            $("#controls .error")
                .text("ERROR: " + error.message)
                .slideDown();
        });
    }
}
```

首先，我们通过检查`navigation`对象中是否存在`geolocation`对象来检查 Geolocation API 是否可用。然后我们调用`geolocation.getCurrentPosition()`。回调函数获取`position`对象，并从其`coords`对象中获取纬度和经度。然后将纬度和经度设置到文本字段中：

![行动时间-获取地理位置数据](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_08_03.jpg)

如果由于某种原因地理位置请求失败，我们从错误对象中获取错误消息，并在页面上显示它：

![行动时间-获取地理位置数据](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_08_05.jpg)

## *刚刚发生了什么？*

我们使用 Geolocation API 获取了用户的位置。我们提取了纬度和经度，并在页面上的文本字段中显示了它们。我们将把这些传递给天气服务，以获取他们所在位置的天气。

## 尝试一下

创建一个 Web 应用程序，使用 Geolocation API 跟踪用户的位置。当用户位置发生变化时，使用 Ajax 调用 Google Static Maps API 获取用户当前位置的地图，并更新页面上的图像。在您的智能手机上打开应用程序并四处走动，看看它是否有效。您可以在[`developers.google.com/maps/documentation/staticmaps/`](https://developers.google.com/maps/documentation/staticmaps/)找到 Google Static Maps API 的文档。

# 使用网络服务

Web 服务是创建大多数企业级 Web 应用程序的重要组成部分。它们提供了无法直接在客户端访问的服务，因为存在安全限制。例如，您可以有一个访问数据库以检索或存储客户信息的 web 服务。Web 服务还可以提供可以从许多不同应用程序访问的集中操作。例如，提供天气数据的服务。

Web 服务可以使用任何可以接收 Web 请求并返回响应的服务器端技术创建。它可以是简单的 PHP，也可以是像.NET 的 WCF API 这样复杂的面向服务的架构。如果您是唯一使用您的 Web 服务的人，那么 PHP 可能足够了；如果 Web 服务是为公众使用而设计的，那么可能不够。

大多数 Web 服务以 XML 或 JSON 格式提供数据。过去，XML 是 Web 服务的首选格式。然而，近年来 JSON 变得非常流行。不仅因为越来越多的 JavaScript 应用程序直接与 Web 服务交互，而且因为它是一种简洁、易于阅读和易于解析的格式。许多服务提供商现在正在转向 JSON。

这本书的范围不在于教你如何编写 web 服务，但我们将学习如何通过使用提供本地天气报告的 web 服务与它们进行交互。

## Weather Underground

在这个例子中，我们将从一个真实的 web 服务中获取天气。我们将使用 Weather Underground 提供的服务，网址为[`www.wunderground.com`](http://www.wunderground.com)。要运行示例代码，您需要一个开发者 API 密钥，可以在[`www.wunderground.com/weather/api/`](http://www.wunderground.com/weather/api/)免费获取。免费的开发者计划允许您调用他们的服务，但限制了您每天可以进行的服务调用次数。

## 跨站脚本和 JSONP

我们可以使用前面讨论过的任何 jQuery Ajax 方法来调用 Web 服务。调用与您的网页位于同一域中的 Web 服务没有问题。但是，调用存在于另一个域中的 Web 服务会带来安全问题。这就是所谓的跨站脚本，或 XSS。例如，位于`http://mysite.com/myPage.html`的页面无法访问`http://yoursite.com`的任何内容。

跨站脚本的问题在于黑客可以将客户端脚本注入到请求中，从而允许他们在用户的浏览器中运行恶意代码。那么我们如何绕过这个限制呢？我们可以使用一种称为**JSONP**的通信技术，它代表**带填充的 JSON**。

JSONP 的工作原理是由于从其他域加载 JavaScript 文件存在安全异常。因此，为了绕过获取纯 JSON 格式数据的限制，JSONP 模拟了一个`<script>`请求。服务器返回用 JavaScript 函数调用包装的 JSON 数据。如果我们将前面示例中的 JSON 放入 JSONP 响应中，它将看起来像以下代码片段：

```html
jQuery18107425144074950367_1365363393321(
{
    "location": {
        "city":"Your City"
    }
    ,"current_observation": {
        "weather":"Clear",
        "temperature_string":"38.3 F (3.5 C)",
        "wind_string":"From the WSW at 1.0 MPH Gusting to 5.0 MPH",
        "feelslike_string":"38 F (3 C)",
        "relative_humidity":"71%",
        "icon_url":"images/nt_clear.gif"
    }
}
);
```

使用 jQuery 进行 Ajax 请求的好处是，我们甚至不需要考虑 JSONP 的工作原理。我们只需要知道在调用其他域中的服务时需要使用它。要告诉 jQuery 使用 JSONP，我们将`dataType`参数设置为`"jsonp"`传递给`ajax()`方法。

`ajax()`方法可以接受一个包含所有请求参数的名称/值对对象，包括 URL。我们将`dataType`参数放在该对象中：

```html
$.ajax({
    url: "http://otherSite/serviceCall", 
    dataType : "jsonp"
});
```

# 行动时间-调用天气服务

现在我们已经获得了用户的位置，我们可以将其传递给 Underground Weather 服务，以获取用户当前的天气。由于服务存在于外部域中，我们将使用 JSONP 来调用该服务。让我们进入`WeatherWidget`对象并进行一些更改。

首先，我们需要更改构造函数以获取 Weather Underground API 密钥。由于我们正在编写一个通用小部件，可以放置在任何站点的任何页面上，页面的开发人员需要提供他们的密钥：

```html
function WeatherWidget($widget, wuKey)
```

接下来我们将更改`getWeatherReport()`方法。现在它获取我们想要获取天气报告的地点的坐标。在这种情况下，我们从地理位置 API 中获取的是用户的位置：

```html
function getWeatherReport(lat, lon)
{
    var coords = lat + "," + lon;
    $.ajax({
        url: "http://api.wunderground.com/api/" + wuKey +
             "/conditions/q/" + coords + ".json", 
        dataType : "jsonp"
    })
    .done(function(data) { populateWeather(data); })
    .fail(function(jqXHR, textStatus, errorThrown) { 
        showError(errorThrown);
    });
}
```

我们使用`ajax()`方法和 JSONP 调用 Weather Underground 服务。服务的基本请求是[`api.wunderground.com/api/`](http://api.wunderground.com/api/)后跟 API 密钥。要获取当前天气状况，我们在 URL 中添加`/conditions/q/`，后跟以逗号分隔的纬度和经度。最后，我们添加`".json"`告诉服务以 JSON 格式返回数据。URL 最终看起来像[`api.wunderground.com/api/xxxxxxxx/conditions/q/44.99,-85.48.json`](http://api.wunderground.com/api/xxxxxxxx/conditions/q/44.99,-85.48.json)。

`done()`和`fail()`处理程序与前面的示例中的处理程序相同。

现在让我们更改`populateWeather()`方法，以提取从服务返回的数据：

```html
function populateWeather(data)
{
    var observation = data.current_observation;

    $(".results header img", $widget).attr("src", observation.icon_url);
    $(".location>span", $widget).text(observation.display_location.full);

    $(".conditions>span").each(function(i, e)
    {
        var $span = $(this);
        var field = $span.data("field");
        $(this).text(observation[field]);
    });

    // Comply with terms of service
    $(".results footer img", $widget)
        .attr("src", observation.image.url);

    $(".loading", $widget).fadeOut(function ()
    {
        $(".results", $widget).fadeIn();
    });
}
```

这个版本的`populateWeather()`方法几乎与我们在 JSON 文件示例中使用的方法相同。唯一的区别是我们在小部件的页脚中添加了一个显示 Weather Underground 标志的图像，这是使用他们的服务的服务条款的一部分。

唯一剩下的事情就是回到网页的主`WeatherApp`对象，并更改对`WeatherWidget`的调用，以提供 API 密钥和位置：

```html
function WeatherApp()
{
    var weatherWidget =
            new WeatherWidget($("#weather-widget"), "YourApiKey"),
        version = "8.3";
```

接下来，我们更改`getCurrentWeather()`，当单击**检查天气**按钮时调用该方法，将用户的坐标传递给小部件的`update()`方法：

```html
function getCurrentWeather()
{
    var lat = $("#latitude").val();
    var lon = $("#longitude").val();
    if (lat && lon)
    {
        $("#weather-widget").fadeIn();
        weatherWidget.update(lat, lon);
    }
}
```

在小部件淡入后，我们从文本输入字段中获取坐标。然后我们调用小部件的`update()`方法，将坐标传递给它。这样，用户位置的天气就显示出来了：

![行动时间-调用天气服务](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_08_04.jpg)

## *刚刚发生了什么？*

我们更改了天气小部件，使用 Weather Underground 服务获取了从地理位置 API 获取的用户位置的当前天气。我们使用 JSONP 调用服务，因为它不在与我们网页相同的域中。

## 快速测验

Q1\. 你使用哪个 jQuery 方法来发出 Ajax 请求？

1.  `ajax()`

1.  `get()`

1.  `post()`

1.  以上所有

Q2\. 何时需要使用 JSONP 进行 Ajax 请求？

1.  调用 web 服务时

1.  在向另一个域发出请求时

1.  在向同一域发出请求时

1.  进行 POST 请求时

Q3\. 地理位置 API 提供什么信息？

1.  用户的纬度和经度

1.  用户的国家

1.  用户的地址

1.  以上所有

# 总结

在本章中，我们创建了一个可以放置在任何页面上的天气小部件。我们使用 Ajax 请求从服务器获取静态 XML 和 JSON 数据。我们学会了如何使用地理位置 API 找到用户的位置，并使用它来调用 web 服务以获取本地化的天气数据。

本章中涵盖了以下概念：

+   如何使用 Ajax 从服务器读取 XML 和 JSON 文件

+   如何使用 jQuery 从服务器调用返回的 XML 中提取数据

+   如何使用 HTML5 地理位置 API 在世界任何地方获取用户的当前位置

+   如何使用 Ajax 异步与 web 服务交互

+   使用 JSONP 绕过跨站点脚本的安全限制

+   如何使用地理位置和 web 服务获取用户当前位置的天气报告

在下一章中，我们将学习如何使用 Web Workers API 创建多线程 JavaScript 应用程序。我们将创建一个应用程序，绘制 Mandelbrot 分形图，而不会锁定浏览器。
