# HTML5 iPhone Web 应用开发（二）

> 原文：[`zh.annas-archive.org/md5/C42FBB1BF1A841DF79FD9C30381620A5`](https://zh.annas-archive.org/md5/C42FBB1BF1A841DF79FD9C30381620A5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：HTML5 音频

在上一章中，我们讨论了媒体分发的重要性，以及 HTML5 如何改变了在浏览器中提供音频和视频内容的方式。我们特别讨论了 HTML5 视频实现，但我们也讨论了`MediaElement`规范，该规范涵盖了视频和音频都使用的常见 API。

在本章中，我们将进一步研究规范并将其抽象化，使其可重用于音频和视频。但在此之前，我们将通过一个简单的示例讨论服务器配置，然后继续进行更高级的实现，包括动态音频播放器和自定义控件。

在本章中，我们将学习以下内容：

+   集成一个简单的 HTML5 音频示例

+   配置我们的服务器

+   `MediaElement`抽象

+   扩展`MediaElement`API 以支持音频

+   创建动态音频播放器

+   自定义音频控件

# 服务器配置

在开始使用 HTML5 音频元素之前，我们需要配置我们的服务器，以允许特定的音频格式适当播放。首先，让我们花点时间了解适当的音频格式。

## 音频格式

对 HTML5 音频播放的支持与视频元素的支持类似，因为每个浏览器出于某种原因支持不同类型的格式。以下是一些展示支持情况的表格：

+   以下是与桌面浏览器相关的细节：

| 桌面浏览器 | 版本 | 编解码器支持 |
| --- | --- | --- |
| Internet Explorer | 9.0+ | MP3，AAC |
| Google Chrome | 6.0+ | Ogg Vorbis, MP3, WAV |
| Mozilla Firefox | 3.6+ | Ogg Vorbis, WAV |
| Safari | 5.0+ | MP3，AAC，WAV |
| Opera | 10.0+ | Ogg Vorbis, WAV |

+   以下是与移动浏览器相关的细节：

| 移动浏览器 | 版本 | 编解码器支持 |
| --- | --- | --- |
| Opera Mobile | 11.0+ | 设备相关 |
| Android | 2.3+ | 设备相关 |
| Mobile Safari（iPhone，iPad，iPod Touch） | iOS 3.0+ | MPEG，MPG，MP3，SWA，AAC，WAV，BWF，MP4，AIFF，AIF，AIFC，CDDA，32G，3GP2，3GP，3GPP |
| Blackberry | 6.0+ | MP3，AAC |

正如我们所看到的，各种浏览器，无论是移动还是桌面，都支持多种格式类型。幸运的是，这本书侧重于 iPhone 网络应用程序，所以对于我们的目的，我们只关注传递大多数浏览器支持的 MP3 格式。现在，我们需要确保我们的服务器可以播放 MP3。

## 音频格式指令

为了提供正确的 MIME 类型，我们需要配置我们的 Apache 服务器。为此，我们希望将以下指令添加到一个`.htaccess`文件中：

```html
AddType audio/mpeg mp3
AddType audio/mp4 m4a
AddType audio/ogg ogg
AddType audio/ogg oga
AddType audio/webm webma
AddType audio/wav wav
```

当然，对于我们的目的，我们只需要 MPEG/MP3，但允许这些格式是个好主意，以便在支持其他浏览器时考虑可扩展性。

# 简单的 HTML5 音频集成

在页面上包含音频非常简单。我们只需在页面中包含以下标记，就可以立即拥有一个音频播放器：

```html
<audio controls>
    <source src="img/mymusic.mp3" type='audio/mpeg; codecs="mp3"'/>
    <p>Audio is not supported in your browser.</p>
</audio>
```

![简单的 HTML5 音频集成](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_03_01.jpg)

音频元素

前面的例子指定了一个带有控件属性的音频元素，告诉浏览器具有用于播放的本机控件的音频播放器。在这个元素内部，有一个源元素和一个段落元素。源元素指定音频的来源和类型。源元素上的`src`属性是音频的相对位置，`type`属性指定了源的 MIME 类型和编解码器。最后，我们有一个段落元素，以防音频元素不受支持。

这个例子非常适合演示在我们的页面上拥有媒体有多么容易，除非它并不总是那么简单。大多数时候，我们希望完全控制我们的组件，有时需要利用指定的 API。我们在上一章中已经讨论过这些概念，并且开发了一个广泛的 Video 类，我们可以在这里使用。在下一节中，我们将退一步，抽象我们迄今为止编写的代码。

# MediaElement 抽象

我们已经讨论过音频和视频在 HTML5 规范中共享相同的 API。在本节中，我们将讨论将我们编写的视频 JavaScript 抽象化，以便我们可以重用它来进行音频播放。

## 创建 App.MediaElement.js

1.  首先，在我们的`js`目录中创建一个新的 JavaScript 文件，命名为`App.MediaElement.js`。

1.  接下来，将`App.Video.js`的内容复制到新的`App.MediaElement.js`文件中。

在这一步中，我们希望确保我们的文件反映了`MediaElement`命名空间，因此我们将把`Video`一词重命名为`MediaElement`。

一旦我们把所有东西都重命名为`MediaElement`，我们可能想要删除默认元素及其名称，因为它们对于这样一个抽象类来说是不必要的。除了这些默认值，我们也不需要公共的`fullscreen`方法或`onFullScreen`回调。

当我们进行以上更改时，我们的文件应该如下所示：

```html
var App = window.App || {};
App.MediaElement = (function(window, document, $){
  'use strict';

  var _defaults = {
'callbacks': {
...
}
  };

  function MediaElement(options) { ... }
  function attachEvents() { ... }

MediaElement.prototype.onCanPlay = function(e, ele) { ... }
MediaElement.prototype.onSeeking = function(e, ele) { ... }
MediaElement.prototype.onSeeked = function(e, ele) { ... }
MediaElement.prototype.onEnded = function(e, ele) { ... }
MediaElement.prototype.onPlay = function(e, ele) { ... }
MediaElement.prototype.onPause = function(e, ele) { ... }
MediaElement.prototype.onLoadedData = function(e, ele) { ... }
MediaElement.prototype.onLoadedMetaData = function(e, ele) { ... }
MediaElement.prototype.onTimeUpdate = function(e, ele) { ... }
MediaElement.prototype.getDefaults = function() { ... ;
MediaElement.prototype.toString = function() { ... };
MediaElement.prototype.play = function() { ... }
MediaElement.prototype.pause = function() { ... }
MediaElement.prototype.stop = function() { ... }
MediaElement.prototype.mute = function() { ... };
MediaElement.prototype.unmute = function() { ... };

  return MediaElement;

}(window, document, Zepto)); 
```

尽管我们之前已经编写了这段代码，让我们简要回顾一下`MediaElement`类的结构。这个类包含可以访问的公开方法，比如`onCanPlay`、`onSeeking`和`onEnded`。当我们传递的元素分派了适当的事件时，这些方法将被调用。我们正在监听的事件在`attachEvents`中，它们包含共享的 API 事件，比如`canplay`、`seeking`、`ended`等等。

这个类基本上只包含在音频和视频媒体之间共享的 API。如果我们想要扩展它以实现特定功能，比如全屏，我们将扩展`MediaElement`的实例，或者使用 JavaScript 继承来为`App.Video`类。

### 提示

在本书中，我们不涵盖真正的 JavaScript 继承。鉴于我们希望全面审查 iPhone 网页应用程序开发的 HTML5，我们不会深入讨论 JavaScript 架构的更高级细节。

## 初始化 App.MediaElement.js

为了初始化`App.MediaElement.js`，我们可以这样做：

```html
new App.MediaElement({
    'element': someElement,
    'callbacks': {
        'onCanPlay': function(){ console.log('onCanPlay'); },
        'onSeeking': function(){ console.log('OVERRIDE :: onSeeking'); },
        'onSeeked': function(){ console.log('OVERRIDE :: onSeeked'); },
        'onEnded': function(){ console.log('OVERRIDE :: onEnded'); },
        'onPlay': function(){ console.log('OVERRIDE :: onPlay'); },
        'onPause': function(){ console.log('OVERRIDE :: onPause'); },
        'onLoadedData': function(){ console.log('OVERRIDE :: onLoadedData'); },
        'onLoadedMetaData': function(){ console.log('OVERRIDE :: onLoadedMetaData'); },
        'onTimeUpdate': function(){ console.log('OVERRIDE :: onTimeUpdate'); }
    }
});
```

在上述代码中，我们创建了一个`MediaElement`的新实例，并传递了一个对象，该对象与`MediaElement`构造函数的默认值合并。请记住，`element`将始终引用音频或视频元素。我们可以选择覆盖默认的回调，也可以不覆盖，因为它们是可选的。

### 注意

请注意，我们正在传递所有的回调。这是因为自从编写本书以来，`Zepto.js`包含一个 bug，如果将布尔值 true 作为第一个参数传递，它不会进行对象的深复制。

现在我们准备在这个页面上使用这个类与我们为此页面开发的音频类一起。

# 扩展音频的 MediaElement API

现在我们有了一个抽象的`MediaElement`类，我们希望在其基础上构建，以实现音频播放。从我们已经建立的基本模板开始，我们将创建一个包含此页面所有功能的`App.Audio`类；从创建一个`MediaElement`的实例，到创建一个下拉菜单来切换曲目和管理每个曲目的音量。

## 基本模板

我们可以通过遵循我们之前建立的模式来建立一个基本模板。以下是一些代码，您可以用作模板的起点：

```html
var App = window.App || {};

App.Audio = (function(window, document, $){
  'use strict';

  var _defaults = {
    'element': 'audio',
    'name': 'Audio'
  };

  function Audio(options) {
    this.options = $.extend({}, _defaults, options);

        this.element = this.options.element;
        this.$element = $(this.element);

        attachEvents.call(this);
  }

    function attachEvents() { }

  Audio.prototype.getDefaults = function() { ... };

  Audio.prototype.toString = function() { ... };

  return Audio;

}(window, document, Zepto));
```

这里没有什么新东西，我们使用了之前使用过的相同模式；建立一个`App.Audio`类，一个包含`Audio`构造函数的 IIFE，包含处理事件的相同`attachEvents`方法，以及一些扩展`Audio`的原型方法（`getDefaults`和`toString`）。我们继续使用`Zepto`并将`window`和`document`传递给 IIFE 作为引用，然后自包含我们的代码。

## 创建一个 MediaElement 的实例

在我们的构造函数中，我们需要做两件事。一是，我们需要获取页面上的音频元素并对其进行缓存。二是，我们需要根据页面上的元素创建或初始化一个基于 MediaElement 的实例。

### 查找和缓存音频元素

要找到音频元素并将其缓存，我们可以这样做：

```html
this.audioElement = document.getElementsByTagName('audio')[0];
this.$audioElement = $(this.audioElement);
```

请记住，`this`关键字是指返回给`App.Audio`的`audio`实例。然后我们在`this`上创建一个名为`audioElement`的属性，该属性设置为页面上找到的第一个音频元素。

### 注意

请注意，`getElementsByTagName`存在于文档中，接受一个参数，即一个字符串。这个方法获取页面上与该标签匹配的所有元素，并以数组的形式返回。在这种情况下，我们在页面上只有一个音频元素，所以我们得到一个包含一个找到的元素的数组。因此，我们使用`[0]`来获取该数组中的第一个实例。

一旦我们有了音频元素，我们将其缓存为`Zepto`对象，以便我们只使用一次`Zepto`，从而提高我们应用程序的性能。我在大多数项目中都这样做，因为我发现自己经常使用 Zepto 的许多内置方法，特别是用于创建事件侦听器。但是，如果在您的情况下发现它没有用处，可以跳过这一步。

### 初始化 MediaElement

现在我们有了音频元素，我们可以按照上一节中编写的代码来初始化`MediaElement`。因此，您不必翻回去，这是我们可以使用的代码：

```html
this.mediaElement = new App.MediaElement({
    'element': this.audioElement,
    'callbacks': {
        'onCanPlay': function(){ ... },
        'onSeeking': function(){ ... },
        'onSeeked': function(){ ... },
        'onEnded': function(){ ... },
        'onPlay': function(){ ... },
        'onPause': function(){ ... },
        'onLoadedData': function(){ ... },
        'onLoadedMetaData': function(){ ... },
        'onTimeUpdate': function(){ ... }
    }
});
```

这与我们之前编写的代码相同，回调中的省略号应包含我们编写的`console.log`。您应该注意到的一件事是，我们将`this.audioElement`，我们缓存的音频元素，传递给`MediaElement`的实例。此外，我们现在已经创建了对`MediaElement`实例的引用，即`this.mediaElement`。现在我们可以从稍后将创建的`App.Audio`实例中公开控制音频。

在这一点上，我们已经建立了一个完全功能的音频播放器，基于我们抽象类`MediaElement`。然而，目前没有太多事情发生；我们只是有一个可以工作和可扩展的设置，但它并不是独一无二的。这就是我们动态音频播放器将发挥作用的地方。

# 动态音频播放器

因此，在这一点上，我们有一个扩展了我们的`MediaElement`对象的音频类，具有公开的事件，因此可以用来创建动态内容。现在，让我们来玩一些，创建一个可以切换曲目的动态音频播放器。

## 选择元素

最初，当我们在第一章中创建这个应用程序时，*应用程序架构*，我们创建了一个由锚点标签和列表元素包含的导航。虽然这在桌面上和可能 iPad 上都可以完美运行，但对于 iPhone 等较小的屏幕设备来说并不适用。因此，`select`元素会弹出一个原生组件，允许您轻松导航并选择选项。

苹果的开发者文档建议我们在应用程序中使用`select`元素，因为它已经被优化为 iOS 中的自定义控件。这非常有用，因为它允许我们遵循 iOS 的 Web 应用程序设计指南。

现在让我们继续实施。首先，我们需要确保将`select`元素添加到我们的页面中。现在，您应该有以下标记：

```html
<div class="audio-container">
    <audio controls preload>
        <source src="img/sample.mp3" type='audio/mpeg; codecs="mp3"'/>
        <p>Audio is not supported in your browser.</p>
    </audio>
</div>
```

我们需要做的是在`audio`标签之后添加`select`元素，如下所示：

```html
<div class="audio-container">
    <audio controls preload>
        <source src="img/nintendo.mp3" type='audio/mpeg; codecs="mp3"'/>
        <p>Audio is not supported in your browser.</p>
    </audio>
    <select>
        <option value="sample1.mp3" selected>Sample1</option>
        <option value="sample2.mp3">Sample2</option>
        <option value="sample3.mp3">Sample3</option>
    </select>
</div>
```

![The select element](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_03_02.jpg)

选择元素

在上述代码中，我们添加了一个包含多个选项的选择元素。这些选项具有`value`属性，而第一个选项还包含一个`selected`属性。value 属性应包含您在资产中拥有的曲目，而 selected 属性告诉`select`在页面加载时自动选择该选项。

### 注意

在这个例子中，我们假设所有的音频都是 MP3 格式。在您的情况下可能会有所不同，如果是这样，我们需要在我们将要编写的代码中构建逻辑来处理这个逻辑。由于这将引入复杂性，我们专注于处理具有 MP3 MIME 类型的音频轨道。

## 切换音轨

现在我们在页面上有一个`select`元素，以 iOS 建议的方式列出了几个音轨，我们现在希望根据用户输入使我们的播放器动态。为此，我们需要创建一个事件监听器来处理`change`事件。

### change 事件监听器

`select`元素有一个特定的事件可以监听，即`change`事件。这在`Zepto`和我们缓存的音频元素实例中相当容易实现。要添加监听器，让我们进入`App.Audio`中的`attachEvents`方法，并添加以下代码：

```html
var that = this;
this.$element
    on('change', 'select', function(e) { onSelectChange.call(that, e); });
```

首先，我们创建了一个名为`that`的变量，它指的是音频的实例。然后，我们获取在构造函数中创建的缓存元素，并委托来自页面上任何`select`元素的`change`事件。当`change`事件触发时，我们调用匿名函数，即`on`方法中的第三个参数。在这个匿名函数内部，我们调用一个方法，我们还没有创建，叫做`onSelectedChange`，并将事件或`e`引用传递给它。

### 注意

我们正在使用 Zepto 的`on`方法。这个方法可以接受类似于 jQuery 的`on`方法的各种参数，但在这种情况下，我们发送我们想要监听的事件，它应该来自哪个元素，最后是应该被调用的函数。除此之外，我们的匿名函数正在调用我们之前讨论过的方法，但本质上它改变了`this`的引用为音频。

### change 事件处理程序

一旦我们为`change`事件创建了监听器，我们需要定义处理程序。我们还没有创建这个，但它涉及一些相当复杂的功能。最初，现在我们通过`MediaElement`实例有了一个 API，这应该相当容易。然而，页面上只有一个音频元素，所以我们需要能够使用该元素进行播放。因此，在我们的处理程序中，我们需要做以下事情：

+   创建对缓存音频元素的临时引用

+   停止音频的播放，即使它没有在播放

+   将缓存的音频元素克隆到临时引用

+   从 DOM 中删除音频元素

+   删除缓存的媒体元素、音频元素和 Zepto 音频元素

+   更改克隆的音频元素的源

+   将克隆的音频元素附加到 DOM

+   重新创建缓存的媒体元素、音频元素和 Zepto 音频元素

是的，这听起来是为了保持页面上的单个音频元素而要做很多工作，但要做到这一点的代码很少，涉及一些复制和粘贴，因为我们已经写过了。所以，让我们写一些魔法！

在事件处理程序部分，我们想要包含以下方法：

```html
function onSelectChange(e) {
    var $tempAudioElement;
    // Stop the song from playing
    this.mediaElement.stop();
    // Store the element temporarily
    $tempAudioElement = this.$audioElement.clone();
    // Now remove the element
    this.$audioElement.remove();
    // Remove from memory
    //-----
    delete this.mediaElement;
    delete this.audioElement;
    delete this.$audioElement;
    //-----

    // Change the temporary audio source
    $tempAudioElement.
        find('source').
            attr('src', '../assets/' + e.target.selectedOptions[0].value);

    // Now attach it to the DOM
    this.$element.prepend($tempAudioElement);
    // Reset the audioElement
    this.audioElement = document.getElementsByTagName('audio')[0];
    this.$audioElement = $(this.audioElement);
    // Reset the mediaElement
    this.mediaElement = new App.MediaElement({
        'element': this.audioElement,
        'callbacks': {
            'onCanPlay': function(){ ... },
            'onSeeking': function(){ ... },
            'onSeeked': function(){ ... },
            'onEnded': function(){ ... },
            'onPlay': function(){ ... },
            'onPause': function(){ ... },
            'onLoadedData': function(){ ... },
            'onLoadedMetaData': function(){ ... },
            'onTimeUpdate': function(){ ... }
        }
    });
}
```

如果我们继续在浏览器中运行代码，我们应该能够在音轨之间切换而没有问题。如果您遇到问题，请参考提供的源代码。

无论如何，前面的代码确实实现了我们想要的效果。如果我们仔细分析代码，我们可以看到当我们停止播放时，我们实质上是在利用`MediaElement`类。这是一个很好的例子，说明了现在通过抽象化处理媒体元素（如音频和视频）是多么容易。还要注意，我们使用了相当多的 Zepto 方法，包括`clone`、`remove`、`prepend`和`attr`。这些都是有用的方法，这正是我们缓存音频元素的原因。

您可能会问自己在我们前面的代码中`delete`部分是做什么的。基本上，这有助于垃圾收集；它告诉 JavaScript 引擎我们不再需要它，所以你可以重新收集它。是的，我们可以在将新音频元素前置之后将它们设置为新值，但这是一种确保从 JavaScript 引擎中重新开始并不留下任何猜测的方法。

我们编写的代码存在一个问题，那就是重复创建`audioElement`、`$audioElement`和`mediaElement`对象。由于我们之前在构造函数中定义了这个功能，我们可以重构以确保我们的功能都位于一个位置——这就是下一节要讨论的内容。如果你已经理解了这段代码的重构意义，你可以跳过这部分。

### 重构我们的代码

由于我们在两个地方有相同的代码，我们开始引入了一些冗余。为了使我们的应用程序更易管理，我们应该将相同的功能集中到一个位置。这样做并不复杂，比你想象的要简单。

对于我们的重构，我们只需要编写一个方法，一个`setAudioElement`方法。这个方法应该是私有的，只能在`Audio`类内部使用，它应该只包含创建对`audioElement`、`$audioElement`和`mediaElement`对象的引用所需的代码。

为此，在我们的私有方法部分创建以下方法：

```html
function setAudioElement() {
    return this;
}
```

现在从构造函数中复制以下代码，并粘贴到`setAudioElement`中：

```html
this.audioElement = document.getElementsByTagName('audio')[0];
this.$audioElement = $(this.audioElement);

this.mediaElement = new App.MediaElement({
        'element': this.audioElement,
        'callbacks': {
            'onCanPlay': function(){ ... },
            'onSeeking': function(){ ... },
            'onSeeked': function(){ ... },
            'onEnded': function(){ ... },
            'onPlay': function(){ ... },
            'onPause': function(){ ... },
            'onLoadedData': function(){ ... },
            'onLoadedMetaData': function(){ ... },
            'onTimeUpdate': function(){ ... }
        }
});
```

一旦我们完成了这个，让我们在构造函数中调用`setAudioElement`：

```html
function Audio(options) {
    // Customizes the option
    this.options = $.extend({}, _defaults, options);
    //Cache the main element
    this.element = this.options.element;
    this.$element = $(this.element);
    // Sets the audio element objects
    setAudioElement.call(this);
    attachEvents.call(this);
}
```

如果我们现在运行我们的应用程序，它应该像平常一样运行，就好像我们没有改变任何东西。现在我们需要替换`select`处理程序中的重复代码，以调用相同的方法：

```html
function onSelectChange(e) {
    ....
    // Now attach it to the DOM
    this.$element.prepend($tempAudioElement);

   setAudioElement.call(this);
}
```

现在我们已经做好了所有需要的重构，让我们在 iPhone 模拟器上运行应用程序。当页面运行并在音轨之间切换时，你不应该遇到任何问题。这里没有什么令人惊讶的，但很酷的是，现在你有一个通用的代码集中在一个位置。这就是重构的本质，它有助于实现可维护的代码库。

### 初始化我们的 Audio 类

到目前为止，我们专注于`Audio`类的开发。这很好，但现在我们需要初始化所有这些代码。

为此，打开`index.html`文件，找到**Audio**页面。它应该位于`/audio/index.html`。一旦打开了该文件，滚动到源代码底部，并在所有其他脚本之后添加以下脚本：

```html
<script>
    new App.Audio({
        'element': document.querySelector('.audio-container')
    });
</script>
```

这与我们初始化`App.Video`的方式有些不同，因为我们现在传入元素，而`App.Video`在其中查找视频元素。这种差异背后的原因是为了展示我们如何以不同的方式初始化我们的类。你可以自行决定如何初始化一个类。每种方式都有其优缺点，但了解替代方案并选择最适合你的代码风格和项目需求的方式是很好的。

现在我们有一个动态音频播放器运行在一个抽象的`MediaElement`类上。除此之外，我们还创建了一个对于这个目的有效的 UI，并执行了预期的操作。但是，如果我们想要更清晰地控制音频，除了默认界面提供的内容之外呢？在下一节中，我们将发现如何使用之前创建的`MediaElement`类来控制我们的音频。

# 自定义 HTML5 音频控件

在这一节中，我们将介绍如何自定义音频播放器的控件。正如我们在上一章讨论的视频播放器中所看到的，创建自定义体验可能非常有用。对于本书来说，我们保持了相当简单的方式，并将继续遵循这种模式，以便我们可以讨论原则并让你快速入门。对于音频，自定义控件甚至更简单，特别是因为我们无法控制音量，这将在下一节中进一步讨论。

## 创建自定义媒体控件

首先，让我们从`audio`元素中删除`controls`属性。这样做后，你应该有以下标记：

```html
<audio preload>
    <source src="img/sample1.mp3" type='audio/mpeg; codecs="mp3"'/>
    <p>Audio is not supported in your browser.</p>
</audio>
```

现在我们需要向标记添加自定义控件。我们可以继续做与上一章相同的事情，只是这次我们用一个 media-controls 类来抽象它，并简单地只有一个播放和暂停按钮。这也应该放在`audio`元素之后。完成后，标记应该是这样的：

```html
<div class="media-controls">
    <div class="mc-state">
        <button class="mc-play mc-state-play">Play</button>
        <button class="mc-pause mc-state-pause">Pause</button>
    </div>
</div>
```

当您在 iPhone 模拟器上查看应用程序时，它应该是这样的：

![创建自定义媒体控件](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_03_03.jpg)

自定义控件

您会注意到的是，现在页面上没有显示音频元素。这是因为我们已经去掉了`controls`属性。不要太担心；这是 iOS 上预期的行为。通常，您会为音频播放器创建所有控件，但现在我们只做播放和暂停。作为奖励，您可能还想要一首曲目，但这是一个更大讨论的内容，不适合本书的范围。

## 为我们的自定义控件添加交互性

这就是所有魔术发生的地方。我们现在将连接我们已经构建的交互性到`MediaElement`类，以定制我们的体验。

首先，让我们去我们的`App.Audio` JavaScript 文件中找到`attachEvents`方法。为了简短和简单起见，让我们在我们的`change`事件监听器之后包含以下代码片段：

```html
this.$element.
    find('.media-controls').
        on('click', '.mc-play', function() { that.mediaElement.play(); }).
        on('click', '.mc-pause', function(){ that.mediaElement.pause(); });
```

前面的代码使用缓存的`$element`来查找媒体控件，然后相应地将时钟事件附加到播放和暂停按钮上。在每个事件监听器内部，我们使用在`setAudioElement`方法中创建的`mediaElement`的实例来调用`play`或`pause`方法。

### 注意

需要注意的一点是，我们的事件监听器使用`that`来引用`mediaElement`的实例。如果您还记得，我们在`attachEvents`方法的顶部创建了`that`变量，以便在事件监听器内部有一个`this`的引用。正如我们之前解释过的，JavaScript 具有函数作用域，因此当我们创建我们的事件监听器时，该函数创建了一个新的作用域，将`this`的关系设置为事件作用域。在幕后，Zepto 将`this`设置为目标元素，这可能是`play`或`pause`元素。

这就是我们需要的一切，以制作自定义控件来播放和暂停我们的音频。如果我们现在测试应用程序，我们应该能够在曲目之间切换，播放我们的曲目，并暂停曲目。

## 顺序播放

在这一部分，我们将看看如何构建一个初步的播放列表。虽然这一部分更多是额外材料，但在创建某种音乐播放器应用程序时，有音乐播放列表是很有用的。起初，可能很难理解我们如何做到这一点，特别是考虑到我们需要用户输入来启用播放，但这实际上并不是问题。因为加载和播放方法是在第一首歌曲上启动的，我们只需切换源，加载它，然后播放曲目。所以让我们一步一步地进行。

### 标记

我们实际上不希望默认按顺序播放音乐，这应该是基于良好的用户体验设计由用户发起的。因此，让我们为用户添加另一个按钮来启用或禁用此功能：

```html
<div class="mc-state">
    <button class="mc-play mc-state-play">Play</button>
    <button class="mc-pause mc-state-pause">Pause</button>
    <button class="mc-sequential mc-sequential-off mc-state-sequential">Sequential Off</button>
</div>
```

在前面的代码中，我们所做的只是在播放和暂停按钮之后添加了另一个按钮。这个按钮包含了我们需要的适当的三个类和文本`Sequential Off`，因为我们只希望用户在需要时启用此功能。

当您的标记都设置好后，您应该有以下界面：

![标记](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_03_04.jpg)

顺序按钮

### JavaScript

这里有一些工作要做，但并不是太复杂。以下是我们要做的清单：

+   为顺序播放创建默认设置，并将其设置为 false

+   创建一个`handleOnAudioEnded`方法，带有`Audio`类的参数

+   在媒体元素初始化的`onEnded`回调中调用`handleOnAudioEnded`方法

+   在`handleOnAudioEnded`方法中，我们应该检查顺序播放是否已启用

+   如果启用了顺序播放，我们希望更新选择菜单并重新加载音频元素

+   最后，我们希望监听新的顺序按钮的点击事件以启用或禁用此功能，同时也更新按钮的状态

所以，首先，让我们创建顺序的默认设置：

```html
var _defaults = {
    'element': 'audio',
    'name': 'Audio',
    'sequential': false
};
```

没有太疯狂的事情，我们只是添加了一个名为`sequential`的默认设置，并将其设置为`false`。接下来，我们想创建包含我们之前列出的功能的`handleOnAudioEnded`方法：

```html
function handleOnAudioEnded(Audio) {
    if(Audio.options.sequential) {
        var $select = Audio.$element.find('select'), $next;

        // Go to next in playlist
        $next = $select.
            find('option[selected]').
                removeAttr('selected').
                    next().
                        attr('selected', 'selected');

        // Change the Selected Index
        $select[0].selectedIndex = $next.index();

        // Must be made on the audio element itself
        Audio.audioElement.src = '../assets/' + $select.val();
        Audio.audioElement.load();
        Audio.audioElement.play();
    }
}
```

如果你不理解前面的代码，不要担心，只需考虑以下几点：

+   我们传递的唯一参数是`Audio`的一个实例

+   然后我们检查`sequential`是否已启用

+   一旦我们确认我们想要顺序播放，我们创建两个变量：`$select`，它缓存了选择元素，和`$next`，它将缓存播放列表中的下一首歌曲。

+   然后我们设置`$next`元素，同时从当前选项中删除`selected`属性

+   通过将`select`的`selectedIndex`设置为`select`中的下一个选项来更新`select`菜单

+   最后，我们直接更新音频元素的源，加载该源，并将状态设置为播放

这个方法处理我们想要播放的下一个源的播放。我们可能可以通过在`MediaElement`类中添加更改源、加载和播放的功能来改进这一点，但我会把这个决定和需要扩展的功能留给你。我们也可能在类级别（`Audio`）缓存`select`，而不是每次想要顺序播放时都这样做。

### 注意

请注意，我们还没有添加任何错误检查。目前，这段代码没有检查我们是否到达列表的末尾。也许我们希望它循环，或者也许我们希望通知用户播放列表已经完成？我们可以在这里执行许多用例，但你明白我的意思，也就是说，如果我们愿意，我们可以在我们的应用程序中拥有一个播放列表。

接下来，当我们将`callbacks`传递给媒体元素的初始化时，我们希望调用我们创建的前面的方法。你可能还记得，我们把这个放在我们的`setAudioElement`中，因此我们希望更新初始化如下：

```html
this.mediaElement = new App.MediaElement({
    'element': this.audioElement,
    'callbacks': {
        ...
        'onEnded': function(){ handleOnAudioEnded(that); },
        ...
    }
});
```

我们在这里所做的就是通过调用`handleOnAudioEnded`来更新`onEnded`方法，并传入`that`，它是对`Audio`类实例的引用。现在，我们只需要为用户想要顺序播放时添加事件监听器，这可以在我们的`attachEvents`方法中添加：

```html
this.$element.
    find('.media-controls').
        on('click', '.mc-play', function() { that.mediaElement.play(); }).
        on('click', '.mc-pause', function() { that.mediaElement.pause(); }).
        on('click', '.mc-sequential', function(e) { handleSequentialClick(e, that); });
```

前面的代码基本上显示了我们已经向我们的顺序按钮添加了一个`click`事件监听器，它所做的就是调用`handleSequentialClick`方法，该方法接受一个事件和我们之前创建的`that`变量的音频实例。注意我们还没有创建`handleSequentialClick`方法吗？好吧，这就是它：

```html
function handleSequentialClick(e, Audio) {
    var $this = $(e.target);

    if(!Audio.options.sequential) {
        Audio.options.sequential = true;
        $this.
            removeClass('mc-sequential-off').
            addClass('mc-sequential-on').
            text('Sequential On');
    } else {
        Audio.options.sequential = false;
        $this.
            removeClass('mc-sequential-on').
            addClass('mc-sequential-off').
            text('Sequential Off');
    }
}
```

简而言之，这个方法只是将默认的`sequential`选项更新为`true`或`false`，根据先前的状态切换值。该方法还切换按钮和内部文本的类，根据用户的交互更新用户。

# iOS 注意事项

到目前为止，我们已经为视频和音频元素定制了许多体验。这对桌面设备来说非常完美，但在处理触摸设备（如 iPhone 和 iPad）时，我们需要考虑一些要点。好消息是，这些是所有 iOS 设备上一致的要点，因此应该是我们需要考虑的事情。

## 音量

我们可以为音频和视频元素设置音量从`0`到`1`，并且我们可以在我们的`MediaElement`库中保持音量的状态。这是整体架构的良好实践。然而，在 iOS 上，音量在用户的物理控制下——几乎任何设备上我们与之交互的音量按钮。

根据苹果的文档（[`developer.apple.com/library/safari/#documentation/AudioVideo/Conceptual/Using_HTML5_Audio_Video/Device-SpecificConsiderations/Device-SpecificConsiderations.html#//apple_ref/doc/uid/TP40009523-CH5-SW11`](http://developer.apple.com/library/safari/#documentation/AudioVideo/Conceptual/Using_HTML5_Audio_Video/Device-SpecificConsiderations/Device-SpecificConsiderations.html)）：

> 在 iOS 设备上，音量始终在用户的物理控制下。音量属性在 JavaScript 中不可设置。读取音量属性始终返回 1。

基本上，我们无法设置音量属性；它将始终返回`1`。这是为了我们不操纵用户的音量，因此只能通过用户的音量控制按钮设置。

## 自动播放

在我们的应用程序中，我们还看到了自动播放的一个例子，在我们的`select`中选择不同的音轨后播放音频。这在桌面上运行得很完美，但在 iOS 上不太好。这是有原因的，基本上是为了保护用户的蜂窝数据使用。这是苹果的设计决定，也是我们在其他设备上可能看到的东西。

根据苹果的文档（[`developer.apple.com/library/safari/#documentation/AudioVideo/Conceptual/Using_HTML5_Audio_Video/Device-SpecificConsiderations/Device-SpecificConsiderations.html#//apple_ref/doc/uid/TP40009523-CH5-SW8`](http://developer.apple.com/library/safari/#documentation/AudioVideo/Conceptual/Using_HTML5_Audio_Video/Device-SpecificConsiderations/Device-SpecificConsiderations.html)）：

> 自动播放被禁用以防止未经请求的蜂窝下载。

它还指出（[`developer.apple.com/library/safari/#documentation/AudioVideo/Conceptual/Using_HTML5_Audio_Video/Device-SpecificConsiderations/Device-SpecificConsiderations.html#//apple_ref/doc/uid/TP40009523-CH5-SW4`](http://developer.apple.com/library/safari/#documentation/AudioVideo/Conceptual/Using_HTML5_Audio_Video/Device-SpecificConsiderations/Device-SpecificConsiderations.html)）：

> 在 iOS 的 Safari 浏览器上（包括 iPad 在内的所有设备），用户可能在蜂窝网络上并且按数据单位收费，预加载和自动播放都被禁用。直到用户启动它，才会加载数据。这意味着 JavaScript 的 play()和 load()方法也在用户启动播放之前无效，除非 play()或 load()方法是由用户操作触发的。换句话说，用户启动的播放按钮有效，但 onLoad="play()"事件无效。

## 同时播放

你可能会问为什么我们没有涉足更复杂的体验，包括同时播放多个视频或音轨。嗯，这也有一个很好的理由，基本上是因为 iOS 限制了一次只能播放一个音频或视频流。这也归结于我们不想在页面上使用比必要更多的蜂窝数据。

根据苹果的文档（[`developer.apple.com/library/safari/#documentation/AudioVideo/Conceptual/Using_HTML5_Audio_Video/Device-SpecificConsiderations/Device-SpecificConsiderations.html#//apple_ref/doc/uid/TP40009523-CH5-SW10`](http://developer.apple.com/library/safari/#documentation/AudioVideo/Conceptual/Using_HTML5_Audio_Video/Device-SpecificConsiderations/Device-SpecificConsiderations.html)）：

> 目前，所有运行 iOS 的设备都限制为一次只能播放一个音频或视频流。在 iOS 设备上，目前不支持同时播放多个视频——并排、部分重叠或完全叠加。同时播放多个音频流也不受支持。

在开发支持音频和视频媒体播放的 iOS Web 应用程序时，应考虑更多因素。我们可以在这里继续讨论这些内容，但我鼓励您访问苹果的文档* iOS 特定注意事项*（[`developer.apple.com/library/safari/#documentation/AudioVideo/Conceptual/Using_HTML5_Audio_Video/Device-SpecificConsiderations/Device-SpecificConsiderations.html`](http://developer.apple.com/library/safari/#documentation/AudioVideo/Conceptual/Using_HTML5_Audio_Video/Device-SpecificConsiderations/Device-SpecificConsiderations.html)）来审查所有必要的注意事项。先前提到的文档片段应该涵盖了您在开发本书的视频和音频部分时遇到的一些问题，但了解所有可能出现的问题总是好的。

# 总结

在本章中，我们从 iOS 上音频播放的角度审查了媒体元素 API。从将先前的代码抽象成`MediaElement`类，使其可重用于音频和视频，到自定义音频元素的控件，我们创建了一个动态音频播放器，它以模块化的方式工作和构建。除了创建音频播放器，我们还审查了在 iOS 设备上必须考虑的注意事项，比如音量控制和同时播放的限制。我希望本章能帮助您开始尝试音频，并帮助您了解，通过抽象化我们的代码，我们可以 consoli 代码并专注于提供在我们的应用程序中至关重要的功能。在下一章中，我们将转向如何使用触摸和手势来创建超越可点击按钮的独特用户体验。


# 第四章：触摸和手势

创建 iPhone 网页应用程序默认涉及触摸交互。这是显而易见的，幸运的是，苹果已经通过默认将点击映射到触摸事件，很好地帮助我们快速上手。然而，如果我们想要一个幻灯片向用户的滑动做出反应怎么办？或者，如果我们想要在用户在应用程序的定义区域内捏合时放大照片，而不影响页面的布局怎么办？嗯，这都取决于我们作为开发者。

在本章中，我们将讨论触摸事件和手势，并利用这项技术构建一个对用户的触摸和手势响应的幻灯片。这里的大部分概念都是基础的，以帮助您理解这些在传统网页开发中不常见的新事件。然而，我们还将深入一些更高级的功能，使用捏合手势来放大和缩小图像。但首先，我们需要对我们的应用进行一些调整，重新组织我们的导航，以便它不会占用大部分屏幕空间，然后我们将开始深入研究触摸和手势。

在本章中，我们将涵盖：

+   简化我们的导航

+   创建响应式相册

+   监听和处理触摸事件

+   解释触摸事件

+   响应手势

+   将触摸事件扩展为插件

# 简化导航

我们的导航目前占据了一些严重的屏幕空间，尽管它对我们之前的示例有效，但它在本书的其余示例中效果不佳。所以，首先我们需要清理这个应用程序，以便专注于我们应用程序的实际内容。我们将清理我们的标记以使用`select`组件。然后我们将添加交互性，使我们的`select`元素实际上在页面之间切换。

在开始编码之前，在我们的 JavaScript 目录中创建一个`App.Nav.js`文件。创建文件后，让我们在页面底部包含它，使用以下脚本标签：

```html
<script src="img/App.Nav.js"></script>
```

## 导航标记和样式

在本章的这一部分，我们将重新设计我们应用程序的导航。在大多数情况下，我们希望确保在设备上使用原生控件，因此这里的目标是为用户提供在 iOS 中使用自定义选择控件的能力，但同时给我们提供相同的灵活性来自定义外观和感觉，同时具有相同的交互。我们将修改标记，查看自定义控件，然后模拟相同的体验。

### 基本模板

首先，让我们摆脱我们在导航中使用的锚标签。一旦我们移除了这些链接，让我们创建一个`select`元素，其中包含选项，并使值指向适当的页面：

```html
<nav>
    <select>
        <option value="../index.html">Application Architecture</option>
        <option value="../video/index.html">HTML5 Video</option>
        <option value="../audio/index.html">HTML5 Audio</option>
        <option value="../touch/index.html" selected>Touch and Gesture Events</option>
        <option value="../forms/index.html">HTML5 Forms</option>
        <option value="../location/index.html">Location Aware Applications</option>
        <option value="../singlepage/index.html">Single Page Applications</option>
    </select>
</nav>
```

在上述代码中，我们用`select`元素的选项替换了锚标签。每个选项都有一个值，指向特定的页面，选项中包含章节名称。由于我们已经移除了锚标签，我们需要调整样式。

### 样式化选择组件

这里我们没有太多需要做的，只需移除我们之前设置的样式。虽然这并非必需，但最佳实践是，您总是希望移除未使用的样式。这有助于通过降低页面加载来提高应用程序的性能。

所以让我们移除以下样式：

```html
/* --- NAVIGATION --- */
nav ul {
    padding: 0;
}
nav li {
    list-style: none;
}
nav a {
    display: block;
    font-size: 12px;
    padding: 5px 0;
}
```

现在，我们需要添加模仿锚标签默认操作的交互性。

## 导航交互

模仿锚标签的默认行为非常简单。让我们从创建一个基本模板开始，就像我们在之前的章节中所做的那样，然后缓存导航并添加切换页面的行为。所以让我们开始吧！

### 基本模板

以下是我们的默认模板。和以前一样，这只是一个简单的 IIFE，为我们的导航建立了一个类。这个闭包接受`window`、`document`和`Zepto`对象，并将`Zepto`对象别名为美元符号。

```html
var App = window.App || {};

App.Nav = (function(window, document, $){

  var _defaults = {};

  function Nav() {}

  return Nav;

}(window, document, Zepto));
```

### 缓存我们的导航

现在，我们可以每次需要时使用 Zepto 在 DOM 中查找导航。但是遵循我们的最佳实践，我们可以缓存导航，并在闭包范围内包含一个变量，该变量可以被私有和公共方法使用。

```html
var _defaults = {},
  $nav;

function Nav() {
  $nav = $('nav');
}
```

在前面的代码中，我们创建了一个`$nav`变量，它包含在闭包范围内，因此我们现在可以在闭包中包含的所有方法中引用它。然后在构造函数中，我们将变量设置为`nav`元素。

### 监听和处理 change 事件

现在开始有趣的部分。我们需要监听`select`元素的 change 事件何时被触发。我们以前为我们的音频播放器做过这个。但是，我们将简要介绍如何在这里做这个，以防您之前没有跟进。

首先，让我们调用一个我们将在下面定义的`attachEvents`方法：

```html
function Nav() {
  $nav = $('nav');

  attachEvents();
}
```

现在我们正在调用`attachEvents`方法，我们需要创建它。在这个方法中，我们想要监听 change 事件，然后处理它：

```html
function attachEvents() {
  $nav.
    on('change', 'select', handleSelectChange);
}
```

在前面的代码中，我们使用 Zepto 的`on`方法告诉缓存的导航监听`select`元素上的 change 事件，该元素包含在导航中。然后我们分配一个我们尚未创建的方法`handleSelectChange`。这个方法是一个处理程序，我们将在下面定义。

最后，我们需要定义我们的处理程序。这个处理程序所需要做的就是根据`select`元素的更改值切换页面。

```html
function handleSelectChange(e) {
  window.location = this.value;
}
```

前面的处理程序接受事件参数，但实际上我们并没有使用它。您可以删除此参数，但通常我喜欢保留处理程序接受的参数。无论如何，我们都在告诉窗口对象通过将`window.location`设置为`select`元素已更改为的值来切换位置。

### 注意

请注意，我们使用`this.value`来设置窗口对象的位置。在这种情况下，`this`指的是选择元素本身或事件目标元素。

### 初始化导航

最后，我们需要做的就是初始化这个类。因为这个导航理论上将出现在我们应用程序的每个页面上，所以我们可以在创建此调用后立即创建一个`App.Nav`的新实例。因此，让我们在`App.Nav.js`的末尾添加以下代码：

```html
new App.Nav();
```

这就是我们需要模仿以前锚标签行为的全部内容。完成这些后，我们现在有足够的屏幕空间来进行触摸事件。接下来，让我们讨论 iPhone 上的触摸事件和手势。

# 触摸和手势事件

在 iPhone 上处理触摸事件很容易；但是，当您开始深入研究事件何时被触发以及在某些情况下如何解释它们时，会有一些“陷阱”。幸运的是，手势也可以很容易地通过`GestureEvent`对象实现。在本节中，我们将总体上讨论触摸和手势，获得对这些用户体验背后技术的基本理解，以便在下一节中，我们可以成功地创建一个可滑动的幻灯片放映。

## 触摸事件

触摸事件包括移动设备接收的一个或多个输入。在本书中，我们将重点放在我们可以以多种方式处理的最多两个手指事件上。iOS 在解释这些输入方面做得很好；但是，元素可以是可点击的或可滚动的，如苹果的开发者文档所述（[`developer.apple.com/library/ios/#documentation/AppleApplications/Reference/SafariWebContent/HandlingEvents/HandlingEvents.html#pageTitle`](http://developer.apple.com/library/ios/#documentation/AppleApplications/Reference/SafariWebContent/HandlingEvents/HandlingEvents.html)）：

> 可点击元素是链接、表单元素、图像映射区域或任何其他具有 mousemove、mousedown、mouseup 或 onclick 处理程序的元素。可滚动元素是任何具有适当溢出样式、文本区域和可滚动的 iframe 元素的元素。由于这些差异，您可能需要将一些元素更改为可点击元素，如“使元素可点击”中所述，以在 iOS 中获得所需的行为。
> 
> 此外，您可以像在“阻止默认行为”中描述的那样关闭 iOS 上 Safari 的默认行为，并直接处理自己的多点触摸和手势事件。直接处理多点触摸和手势事件使开发人员能够实现类似原生应用程序的独特触摸屏界面。阅读“处理多点触摸事件”和“处理手势事件”以了解更多关于 DOM 触摸事件的信息。

这是必须牢记的，因为根据我们需要的功能类型，某些元素的默认行为会有所不同。如果我们想要修改这种功能，我们需要通过将某些事件附加到这些元素来覆盖默认行为，就像之前描述的那样。通过阻止默认功能并用我们自己的功能覆盖它，我们可以创建非常符合我们需求的体验。一个例子是创建一个全屏视差体验，在滚动时播放动画。

一旦我们知道我们想要的行为类型，就有一些重要的事情需要记住。例如，事件是有条件的，因此根据用户交互，某些手势可能不会生成任何事件。让我们来看看其中一些事件。

### 滚动时

一个有条件事件的很好例子是用户滚动页面。在这种交互中，滚动事件只有在页面停止移动并重绘时才会触发。因此，在大多数视差驱动的网站上，页面上的默认行为会被阻止，并实现自定义滚动解决方案。

### 触摸并保持

当用户触摸可点击元素并按住手指时，会显示一个信息气泡。但是如果您希望捕捉此手势，那就没那么幸运了。根据官方苹果文档，在这种类型的交互期间不会分派任何事件。

### 双击缩放

在这种交互中，用户双击屏幕，页面会放大。你可能会认为会有一个针对这种交互的事件，但是我们没有任何可以关联的事件。

如果我们记住了之前讨论的例外情况，我们应该能够正确地开发我们的应用程序并正确处理我们的触摸事件。现在我们需要知道我们可以关联哪些事件进行触摸，以及如何适当地监听和处理它们。

### 支持的触摸事件及其工作原理

苹果官方文档正式列出了在 iOS 上支持的所有事件，包括以下触摸和手势事件以及它们的支持情况：

| 事件 | 生成 | 有条件 | 可用 |
| --- | --- | --- | --- |
| `gesturestart` | 是 | 不适用 | iOS 2.0 及更高版本 |
| `gesturechange` | 是 | 不适用 | iOS 2.0 及更高版本 |
| `gestureend` | 是 | 不适用 | iOS 2.0 及更高版本 |
| `touchcancel` | 是 | 不适用 | iOS 2.0 及更高版本 |
| `touchend` | 是 | 不适用 | iOS 2.0 及更高版本 |
| `touchmove` | 是 | 不适用 | iOS 2.0 及更高版本 |
| `touchstart` | 是 | 不适用 | iOS 2.0 及更高版本 |

根据前面的列表，我们已经拥有了在 iPhone 上使用移动 Safari 制作复杂用户体验所需的一切。如果您担心这些事件是如何处理的，根据苹果的开发文档（[`developer.apple.com/library/ios/#documentation/AppleApplications/Reference/SafariWebContent/HandlingEvents/HandlingEvents.html`](http://developer.apple.com/library/ios/#documentation/AppleApplications/Reference/SafariWebContent/HandlingEvents/HandlingEvents.html)），无需担心，这些事件的传递方式与任何其他浏览器相同。 

> 鼠标事件按照您在其他网络浏览器中期望的顺序传递（...）。如果用户点击一个不可点击的元素，不会生成任何事件。如果用户点击一个可点击的元素，事件按照以下顺序到达：mouseover、mousemove、mousedown、mouseup 和 click。只有在用户点击另一个可点击的项目时，mouseout 事件才会发生。此外，如果页面内容在 mousemove 事件上发生变化，那么序列中的后续事件都不会发送。这种行为允许用户在新内容中点击。

现在我们对单指触摸事件有了很好的理解，包括异常和它们的工作方式，我们应该花一些时间来理解手势。

## 手势

从技术上讲，手势是触摸事件，因此前面的信息也适用于单点触摸事件，因为平移、缩放和滚动都被视为手势。但是，手势也是可以被不同解释的复杂交互。根据苹果的文档（[`developer.apple.com/library/ios/#documentation/AppleApplications/Reference/SafariWebContent/HandlingEvents/HandlingEvents.html`](http://developer.apple.com/library/ios/#documentation/AppleApplications/Reference/SafariWebContent/HandlingEvents/HandlingEvents.html)），我们可以结合多点触摸事件来创建自定义手势；

> 通常，您会实现多点触摸事件处理程序来跟踪一个或两个触摸。但您也可以使用多点触摸事件处理程序来识别自定义手势。也就是说，自定义手势不是已经识别的手势（...）

我们从前面的部分的图表中看到，我们可以监听手势，从而创建自定义体验；然而，关于手势和普通触摸事件的一件令人困惑的事情是它们发生的时间。但这并不是一个谜，因为苹果的文档（[`developer.apple.com/library/safari/#documentation/UserExperience/Reference/GestureEventClassReference/GestureEvent/GestureEvent.html#//apple_ref/javascript/cl/GestureEvent`](http://developer.apple.com/library/safari/#documentation/UserExperience/Reference/GestureEventClassReference/GestureEvent/GestureEvent.html)）为我们提供了以下信息：

（...）对于双指多点触摸手势，事件按照以下顺序发生：

1\. finger 1 的 touchstart。当第一根手指触摸表面时发送。

2\. gesturestart。当第二根手指触摸表面时发送。

3\. finger 2 的 touchstart。当第二根手指触摸表面时立即发送 gesturestart 后发送。

4\. 当前手势的 gesturechange。当两根手指在仍然触摸表面的情况下移动时发送。

5\. gestureend。当第二根手指从表面抬起时发送。

6\. finger 2 的 touchend。当第二根手指从表面抬起时立即发送 gestureend 后发送。

7\. finger 1 的 touchend。当第一根手指从表面抬起时发送。

根据前面的信息，我们可以得出触摸和手势事件是相辅相成的。这使我们能够在前端做一些有趣的事情，而不需要猜测。但是，我们该如何做到这一点呢？好吧，下一节通过创建一个对触摸和手势都有响应的照片库来解决这个问题。

# 创建一个响应式的照片库

如果我们专注于我们在传统移动应用程序中已经看到的小功能片段，比如交互式幻灯片放映，我们将更好地理解触摸和手势事件。我们到处都看到这个，一个带有下一个和上一个按钮的幻灯片放映，但也可以从左到右或从右到左滑动。按钮很容易，附加触摸事件也相当简单；然而，在移动 Safari 中，滑动不是开箱即用的，所以我们需要构建它。所以让我们首先布置我们的画廊，然后进行样式设置。

## 画廊标记和样式

与任何幻灯片画廊一样，创建一个良好的结构是至关重要的。这种结构应该易于遵循，如果我们想要模块化，就不需要太多的元素。

### 基本画廊幻灯片列表

让我们从非常基本的东西开始。首先，让我们创建一个带有`gallery`类的`div`：

```html
<div class="gallery"></div>
```

从这里开始，我们希望有一个内容区域，其中包含所有幻灯片。你可能会问为什么我们不把幻灯片直接放在父画廊容器中，原因是这样我们可以通过其他功能扩展我们的画廊，比如播放和暂停按钮，而不会影响幻灯片本身的结构。

所以让我们在我们的画廊内创建另一个带有`gallery-content`类的`div`，就像这样：

```html
<div class="gallery">
    <div class="gallery-content">
    </div>
</div>
```

现在我们有了一个画廊的内容区域，我们想要创建一个包含我们图像的幻灯片的无序列表。当我们最终这样做时，我们的`gallery`标记应该是这样的：

```html
<div class="gallery">
    <div class="gallery-content">
        <ul>
            <li>
                <img src="img/sample-image1.jpg" alt="…">
            </li>
            <li>
                <img src="img/sample-image2.jpg" alt="…">
            </li>
            <li>
                <img src="img/sample-image3.jpg" alt="…">
            </li>
            <li>
                <img src="img/sample-image4.jpg" alt="… ">
            </li>
        </ul>
    </div>
</div>
```

### 提示

当你看到前面的标记时，可能会震惊于我在`image`标记上留下了`alt`属性的内容。是的，这是一个不好的做法，但我在这里这样做是为了更快地移动。然而，在你的应用程序中不应该这样做，始终为你的图像提供一个带有相关内容的`alt`属性。

现在我们有了一个基本的标记结构，我们应该开始为这个幻灯片秀设置样式，但要记住，前面的标记并不是最终的解决方案。我在其他网站上看到了一些非凡的工作，那很酷，但我们想在这里保持简单，并为你提供一个基础。我鼓励你进行实验和尝试新的东西，但不要让前面的标记成为你的最终解决方案。在我们开始样式化之前，让我们退一步，了解为什么我们有一个内容区域。

### 添加简单的画廊控件

我们不想为内容区域增加复杂的样式。如果我们这样做，这可能会导致一些混乱的样式，"修复我们的标记"。因此，出于这个原因，我们创建了一个内容区域，现在要向我们的幻灯片秀添加一个`controls`组。

所以让我们遵循同样的原则；让我们创建一个带有`gallery-controls`类的`div`，其中包含两个锚标记，一个用于下一个按钮，另一个用于上一个按钮。

```html
<div class="gallery-controls">
    <a href="#next">&raquo;</a>
    <a href="#previous">&laquo;</a>
</div>
```

现在，内容区域和控件是两个可以独立控制的区域。当我们开始为我们的画廊设置样式时，你会看到这样做对我们来说是多么容易。现在，请相信我，这将使你更容易控制你的画廊。但现在，让我们开始样式化！

### 使图像具有响应性

我们在本书的第一章已经介绍了响应式设计，希望你能理解这些原则。但如果你不理解，这一章应该给你一个很好的想法，让我们确保我们的应用程序不仅在 iPhone 上工作，而且在其他触摸设备上也能工作。

所以我们希望我们的画廊存在于我们网站的移动和桌面版本上，这是一个非常理想的功能，因为现在你正在构建一个可重用的、设备无关的组件。但这也会让事情变得困难，不考虑资产管理，我们需要计算我们的图像必须有多大。好吧，对于这个例子，我们希望我们的图像能够缩放到幻灯片的宽度的 100%，我们希望幻灯片占据我们屏幕宽度的 100%，并且两侧有 12 像素的填充。

为了实现这一点，我们可以简单地将所有图像的宽度设置为 100%，并让我们的画廊在两侧应用 12 像素的填充，如下所示：

```html
img {
  width: 100%;
}

.gallery {
  margin: 12px 0 0 0;
  padding: 0 12px;
}
```

### 注意

请注意，我们的画廊已经占据了屏幕宽度的 100%，减去我们在两侧给它的填充。因此你在`.gallery`中看不到`width: 100%`的属性。另外，要考虑到我们在画廊顶部添加了 12 像素的填充，以便给它一些与主导航的空间。最后但同样重要的是，我们在这里使用了简写属性，这样我们就不用使用 padding-left，margin-top 等。这不仅使我们的代码更短，而且更容易理解和维护。

这就是使用 CSS 制作响应式画廊所需的全部内容，其余的样式将通过 JavaScript 应用。有些人可能会对此感到反感，但这是一个相当常用的技术，因为我们需要知道设备的宽度才能正确设置我们的画廊以实现响应式使用。但在开始之前，让我们先完成我们的画廊样式。

### 为我们的画廊添加样式

现在让我们在 CSS 中完成我们画廊的样式。其中一些样式仍然适用于响应式应用，但前面的部分有助于定义原则。不过不用担心，我会逐一介绍这个应用的每个部分的样式，以便你能彻底理解。

首先，让我们确保我们的画廊内容在宽度上扩展到 100%，并且因为最终我们的幻灯片将左浮动，我们希望父容器有一个高度；所以让我们添加一个`overflow: hidden`的属性。当你完成后，你的样式应该是这样的：

```html
.gallery .gallery-content {
  width: 100%;
  overflow: hidden;
}
```

接下来，我们要确保无序列表在幻灯片左浮动时也有一个高度，这样这个高度就会应用到画廊内容上。不仅如此，因为我们想要根据用户交互来动画显示无序列表左右移动，所以我们需要确保位置和起始的`left`值已经定义。当你完成应用这些样式后，它应该看起来像这样：

```html
.gallery .gallery-content > ul {
  left: 0;
  margin: 0;
  overflow: hidden;
  padding: 0;
  position: relative;
}
```

### 提示

在这里，我们还将`margin`和`padding`的值设为`0`。这主要是为了重置，以免以后出现任何布局问题。`Normalize.css`默认为无序列表应用了一些`padding`和`margin`，这是好的，但对于我们的应用来说并不是必要的，所以我们清除了这些值。

现在，让我们专注于样式化我们幻灯片的控件。下一步主要是设置样式，以便我们在容器内浮动元素时不会遇到任何问题；就像我们之前为`gallery`内容和无序列表所做的那样。所以让我们确保我们的控件的`overflow`设置为`hidden`：

```html
.gallery .gallery-controls {
  overflow: hidden;
}
```

由于我们的控件现在设置为`hidden`当元素溢出时，我们可以相应地浮动我们的下一个和上一个按钮，使它们位于幻灯片的适当侧面。

```html
.gallery .gallery-controls a[href="#next"] {
  float: right;
}

.gallery .gallery-controls a[href="#previous"] {
  float: left;
}
```

这就是为你的幻灯片做基本样式所需的全部内容。不幸的是，它看起来仍然不够漂亮，这是因为我们需要使用 JavaScript 来确定屏幕尺寸，为幻灯片应用宽度，并为无序列表应用总体宽度。然而，这里还有一件事情可以带来严重的性能优化，那就是使用 CSS3 过渡。

### 注意

在我们继续之前，重要的是要注意，我们的 CSS 选择器是从`gallery``div`中级联的。这是一个很好的做法，因为它允许你将样式分隔开来。我们所做的基本上是为我们的画廊创建默认样式，如果有人想要自定义它，他们可以在`.gallery`之前添加自己的类来覆盖这些样式，从而使画廊更加可定制。这是一个基本的 CSS 基本原则，但我想指出它的重要性，以显示创建模块化样式的重要性。

### 使用 CSS3 过渡

CSS3 过渡对我们的应用程序非常重要。不仅因为它让我们的工作变得更容易，而且因为它为我们提供了性能优化。默认情况下，移动 Safari 使用硬件加速进行 CSS3 过渡；这意味着硬件将处理这些过渡的渲染，因此我们不需要手动处理。传统上，我们需要使用 JavaScript 来做到这一点，因为这样我们就无法获得性能优化，但现在我们可以通过 CSS3 过渡来实现。所以让我们使用它们！

这是一个基本的画廊，我们希望保持它简单。所以让我们只是将我们的过渡添加到无序列表中。毕竟，无序列表是我们希望在用户滑动或从控件发起操作时进行动画处理的内容。为此，我们将使用`transition`属性，并使用简写来定义我们要动画处理的属性、持续时间以及要使用的过渡时间函数，也就是所谓的缓动方法。

```html
.gallery .gallery-content > ul {
  left: 0;
  margin: 0;
  overflow: hidden;
  padding: 0;
  position: relative;

  -webkit-transition: left 500ms ease;
  -moz-transition: left 500ms ease;
  -ms-transition: left 500ms ease;
  -o-transition: left 500ms ease;
  transition: left 500ms ease;
}
```

我们在这里做的唯一一件事就是向我们的无序列表添加了`transition`属性。这个属性告诉无序列表在 500 毫秒内动画处理`left`属性，并使用默认的缓动方法。

### 提示

在这里，我们定义了五个过渡属性，每个属性都添加了浏览器厂商的前缀，而最后一个是支持的标准属性。这样做是为了使我们的画廊可以在各种设备上使用。是的，这有点复杂和混乱，但鉴于浏览器厂商已经给这个属性添加了前缀，并且现在才开始使用非前缀版本，这是一个必要的恶。

## 画廊互动

我们幻灯片秀的核心在于它的互动性；从下一个和上一个按钮、可滑动的内容和富有动画的显示——我们的幻灯片秀依赖于 JavaScript。在这一部分，我们深入探讨了我们的幻灯片秀是如何工作的；使用我们的基本框架，我们将构建一个高效的`Gallery`类，实现之前所述的目标。实际上，我们的画廊应该只具有允许其在某个方向上调整大小和播放的功能。但是，像往常一样，这需要一些设置工作，然后我们将一切连接起来。所以让我们开始吧！

### 基本模板

首先，我们将创建我们的`Gallery`类。这个类应该设置与我们构建的任何其他类的方式相同。但是，如果你没有按顺序阅读本书，我们只需要检查`App`命名空间，然后在其下创建一个`Gallery`类。包裹在闭包中，我们将有一些默认值和一个`Gallery`函数，并在闭包声明的末尾返回它。正如我们之前提到的，我们将有以下内容：

```html
var App = window.App || {};

App.Gallery = (function($) {

    var _defaults = {};

    function Gallery() {}

    return Gallery;

}(Zepto));
```

这里唯一不同的是我们只传入了`Zepto`对象。以前，我们传入了`window`和`document`，但对于这个类，我们不需要这两个对象，所以我们将它限制在 Zepto 库中。

现在我们所需要的就是缓存我们将要重复使用的元素，而且它们需要在闭包中可用，以便它们在私有和公共方法中可用。

### 缓存画廊

在我们的应用程序中，缓存对象非常有帮助，特别是因为它提高了性能，使我们的应用程序非常高效。通过减少我们在 DOM 中需要做的查找次数，我们可以加快处理速度，并创建一个不太容易出错的应用程序。

不仅我们想要缓存某些元素，而且我们希望它们也在闭包中可用，以便所有方法都可以访问它们。要做到这一点，我们只需要在上面的构造函数中添加缓存变量，就像这样：

```html
var _defaults = {},
    $gallery,
    $slides,
    $slidesContainer,
    $slidesLength,
    $galleryControls,
    slidesWidth,
    galleryWidth;
```

在上面的代码中，我们可以看到画廊、它的幻灯片、幻灯片容器、幻灯片数量、画廊控件、幻灯片和画廊宽度将被缓存。然而，此时我们还没有缓存任何东西。所以让我们开始给它们分配应该有的值。

初始化值的最佳位置应该是在构造函数中，或者在创建一个画廊的实例时。构造函数应该先缓存我们在整个运行应用程序中需要的值。此外，每个变量在语义上描述了它应该持有的内容，这样可以更容易地理解发生了什么。让我们来看看下面的函数：

```html
function Gallery() {
    $gallery = this.$el = $('.gallery');

    $slides = $gallery.find('li');

    $slidesContainer = $gallery.find('.gallery-content > ul');

    $galleryControls = $gallery.find('.gallery-controls');

    $slidesLength = $slides.length;
}
```

从这个函数中，我们可以得出结论，我们缓存了画廊，然后从中确定了所有其他值。例如，我们使用`$gallery`来查找所有幻灯片或列表项。这非常有用，因为我们所做的是告诉我们的应用程序从`gallery`元素开始，然后深入其中找到适当的值。否则，我们通常会从文档的顶部开始，然后向下进行，这在 DOM 查找方面非常昂贵。

这是过程中的一个关键步骤，因为其他所有事情都应该很容易。所以让我们开始连接一些交互！

### 连接我们的控件

首先，我们希望用户能够点击下一个和上一个按钮。但是，我们现在不希望发生任何事情，我们只是想捕获这些事件。和往常一样，让我们从小处开始，然后逐步扩大，我们想要的是有一个可以使用的基础。

#### 附加事件

我们之前已经讨论过如何附加事件，在本章中也是一样。首先创建一个`attachEvents`方法，从画廊中查找下一个和上一个按钮，然后调用`play`方法。当你写完代码时，你应该有类似这样的东西：

```html
function attachEvents() {
    $galleryControls
        on('click', 'a[href="#next"]', play).
        on('click', 'a[href="#previous"]', play);
}
```

这里没有什么不同。我们使用缓存的`$galleryControls`变量，并告诉它监听来自下一个和上一个按钮的`click`事件。当`click`事件来自指定的元素时，然后调用我们的`play`方法。如果我们现在运行我们的代码，除了可能会因为`play`不存在而出现错误之外，什么也不会发生。但我们不要这样做；相反，在所有设置代码完成后，我们将在构造函数中调用我们的`attachEvents`方法：

```html
function Gallery() {
  // our previous code 

    attachEvents();
}
```

这里没有什么疯狂的，我们只是调用`attachEvents`，一个私有方法。你是否注意到，即使它是一个私有方法，我们仍在使用`$galleryControls`？这是因为该变量存在于闭包范围内，因此这样可以更容易地管理变量，而不会污染程序的全局范围。如果你还不明白这里发生了什么，不要担心。随着时间和实践，这将变得清晰，事情将变得更容易。

现在，我们还有一个问题。没有`play`方法，所以让我们创建它！

#### 处理我们的事件

因为我们的`play`方法不存在，所以我们的应用程序失败了；所以我们需要编写它。但它应该做什么？对于这个应用程序，我们希望它确定画廊应该播放的方向。然后我们希望它根据画廊当前位置的左右动画。你可能会说，这听起来比你想象的要容易。但实际上是这样的。所以让我们一步一步来。

##### 再次缓存变量

是的，我们希望尽可能缓存。再次强调，我们正在为 iPhone 创建一个移动应用程序，由于移动设备的性质，我们需要尽可能进行优化。但我们应该缓存什么？好吧，我们将首先检查方向，然后操作无序列表的当前左侧位置。为了防止查找这些值，让我们在方法的顶部声明一个`currentLeftPos`和方向，如下所示：

```html
function play(e) {
    var currentLeftPos, direction;
}
```

简单！现在，让我们确定这些值。确定方向的简单方法是基于所点击元素的值。在这种情况下，我们可以检查#next 或#previous，即`href`属性的值。为了使其更简单，我们可能还想删除井号，以防我们将来想公开此方法并允许自己传递`next`或`previous`。所以让我们这样做：

```html
function play(e) {
    var currentLeftPos, direction;

    direction = $(this).attr('href');

    direction = direction.substr(1, direction.length);
}
```

### 提示

不要太担心这里的细节，但基本上，由于`play`是一个事件处理程序，`this`已经成为目标事件，这将是我们的锚标签。这是我们如何可以从这些元素中获取`href`值的方式。同时，不要对那里进行的字符串操作太紧张。基本上，我们使用了`substr`，这是一个内置的`string`方法，并传递了`1`，这样它就从位置 1 开始获取字符串的其余部分。这就是我们如何能够从`href`属性中获取单词“next”或“previous”的方式。

很好，到这一点上我们已经确定了方向。现在我们想要获取无序列表的最新左位置。为了做到这一点，我们可以在设置方向之后添加以下代码：

```html
function play(e) {

  // Previous code

    currentLeftPos = parseInt($slidesContainer.css('left'), 10);
}
```

### 注意

请注意，我们使用了`parseInt`，这是一个内置的数字方法，它接受一个整数作为其第一个参数，然后将基数作为其第二个参数。我们这样做是因为当我们请求`left`属性的值时，我们得到类似`0px`的东西，而我们希望我们使用的值是一个整数，而不是一个字符串。因此，`parseInt`通过将`0px`解释为`0`的整数来帮助我们。

现在是时候创建我们应用程序的神奇部分了。这部分有点复杂，但最终将帮助我们实现我们想要的效果。但首先让我们专注于让我们的应用程序在下一个行动呼叫时移动。为了做到这一点，我们希望将无序列表的左位置设置为当前左位置减去单个幻灯片的宽度。为了做到这一点，我们可以在设置`currentLeftPos`之后简单地编写以下代码：

```html
function play(e) {
    // Previous code

    // Next
    $slidesContainer.css({ 
    'left': currentLeftPos + -(slidesWidth) + 'px' });
}
```

前面的代码将完全按照我们的要求执行；但是，我们遇到了一些问题。首先，这将始终运行，即使点击了“previous”按钮。其次，没有检查当你到达画廊的最末端时。这可以很容易地添加到我们的应用程序中，就像这样：

```html
function play(e) {
    // Previous code

    // Next
    if (direction === 'next') {
        if (Math.abs(currentLeftPos) < (galleryWidth - slidesWidth)) {
            $slidesContainer.css({
                'left': currentLeftPos + -(slidesWidth) + 'px'
            });
        }
    }
}
```

### 提示

您可能已经注意到我们在`currentLeftPos`上使用了`Math.abs`。这是因为我们将得到一个负数作为我们的值，而且由于我们不想使数学或比较复杂化，我们只需使用`Math.abs`将其转换为正整数。保持简单！

在这个调整后的代码中，我们检查方向，寻找`next`，然后检查当前左位置是否小于画廊宽度减去单个幻灯片的宽度。这有助于防止可能出现的任何错误。

现在开始实现我们的`previous`功能。在这一步中，我们将按照相同的步骤进行；我们将确保我们要向`previous`方向前进，然后我们将进行比较，以确保我们不会低于`0`标记，最后我们将在条件满足时执行代码。当我们完成实现这个功能时，我们应该有以下代码：

```html
function play(e) {
    // Previous code

    // Previous
    if (direction === 'previous') {
        if (Math.abs(currentLeftPos) > 0) {
            $slidesContainer.css({
                'left':  currentLeftPos + slidesWidth + 'px'
            });
        }
    }
}
```

唯一的区别是我们正在与静态数字`0`进行比较。这是为了防止任何会在我们的画廊中引起视觉错误的正值。然后，我们不是对我们的数字取反，而是使用正确的值以便将其加到负数上，从而呈现`Previous`操作的外观。

最后，我们的`play`方法应该是这样的：

```html
function play(e) {
    var currentLeftPos, direction;

    direction = $(this).attr('href');

    direction = direction.substr(1, direction.length);

    currentLeftPos = parseInt($slidesContainer.css('left'), 10);

    // Next
    if (direction === 'next') {
        if (Math.abs(currentLeftPos) < (galleryWidth - slidesWidth)) {
            $slidesContainer.css({
                'left': currentLeftPos + -(slidesWidth) + 'px'
            });
        }
    }

    // Previous
    if (direction === 'previous') {
        if (Math.abs(currentLeftPos) > 0) {
            $slidesContainer.css({
                'left':  currentLeftPos + slidesWidth + 'px'
            });
        }
    }
}
```

我们完成了吗？是的！尽管我们只是在切换无序列表的左位置值，但我们实际上是在进行动画，因为如果你记得，我们已经告诉我们的元素在 CSS 中过渡左属性。看看使用 CSS3 属性是多么简单和有效？通过简单的声明，我们已经能够最小化代码，并制作出高度优化的版本。

现在，我们的画廊的核心已经完成，让我们使其响应式！

### 画廊响应性

我们要稍微绕个弯，但这是值得的努力！在这一步中，我们将研究如何使我们的画廊对用户设备的宽度做出响应。所以让我们开始设置我们的样式。

#### 设置画廊样式

在这里，我们将设置所有必要的样式，使我们的画廊具有响应性。我们需要做一些事情。首先，让我们使用`Gallery`函数的`prototype`创建一个公共的`setStyles`方法：

```html
Gallery.prototype.setStyles = function() {

    return this;
};
```

如你可能已经注意到的，前面的方法返回了`Gallery`的实例，因此允许你链接你的方法。接下来，获取单个幻灯片的宽度。这个宽度是其所在容器的 100%，因此应该与画廊本身的宽度相同。为了获取这个宽度，我们可以在`setStyles`中进行以下操作：

```html
Gallery.prototype.setStyles = function() {

    slidesWidth = $slides.width();

    return this;
};
```

现在，我们可以通过将幻灯片的数量乘以每个幻灯片设置的宽度来确定画廊的完整宽度，这是我们在上一步中已经确定的。当我们这样做时，我们得到以下代码：

```html
Gallery.prototype.setStyles = function() {

    slidesWidth = $slides.width();

    galleryWidth = slidesWidth * $slidesLength;

    return this;
};
```

以下步骤可能会令人困惑，但它非常重要，因为我们需要手动设置每个幻灯片的宽度，以便将它们浮动在一起。因此，我们现在需要做的是将`slideWidth`值应用到每个幻灯片上，如下所示：

```html
Gallery.prototype.setStyles = function() {

    slidesWidth = $slides.width();

    galleryWidth = slidesWidth * $slidesLength;

    $slides.width(slidesWidth);

    return this;
};
```

现在，我们还可以使用计算画廊宽度来设置幻灯片容器的宽度。同样，我们需要这样做，以便保持一个具有左浮动幻灯片的画廊。因此，我们将设置幻灯片容器的宽度，然后将所有幻灯片左浮动。当我们编写这些要求时，你的`setStyles`方法将如下所示：

```html
Gallery.prototype.setStyles = function() {

    slidesWidth = $slides.width();

    galleryWidth = slidesWidth * $slidesLength;

    $slides.width(slidesWidth);

    $slidesContainer.css({'width': galleryWidth});

    $slides.css({'float': 'left'});

    return this;
};
```

这就是以响应式方式设置我们的画廊样式所需的全部步骤。然而，这里有一个问题；样式无法重置，这是为了在设备的方向或宽度发生变化时适当地确定幻灯片和容器的宽度而需要的。让我们进行一些设置工作，以便进行重置。

为了做到这一点，我们将简单地将我们的功能包装在一个方法中，然后将其传递给一个公共的`resetStyles`方法。在这种技术中，我们实质上是在发送一个`回调`，当`resetStyles`功能完成时将被执行。目前，你的代码应该产生以下结果：

```html
Gallery.prototype.setStyles = function() {

    this.resetStyles(function(){
        slidesWidth = $slides.width();

        galleryWidth = slidesWidth * $slidesLength;

        $slides.width(slidesWidth);

        $slidesContainer.css({'width': galleryWidth});

        $slides.css({'float': 'left'});
    });

    return this;
};
```

正如你所看到的，我们最初为`setStyles`创建的所有功能都被包装在一个匿名函数中，也被称为`回调`，当`resetStyles`运行完成时将被调用。为了全面了解情况，让我们继续创建我们的`resetStyles`函数。

#### 重置画廊样式

重置元素的样式实际上并不复杂，所以我们将直接进入这个方法。查看下面应该在你的`reset`方法中的代码。

```html
Gallery.prototype.resetStyles = function(callback) {
    $slides.attr('style', null);

    $slidesContainer.attr('style', null);

    $slides.attr('style', null);

    if (typeof callback !== 'undefined') {
        callback.call(this);
    }

    return this;
};
```

不会太疯狂吧？我们基本上只是删除 Zepto 在我们使用 JavaScript 设置元素样式时应用的内联样式，或者我们在`setStyles`方法中所做的事情。当我们删除这些样式时，然后检查是否有`回调`方法并执行该方法。这是一个很好的做法，因为假设我们需要出于任何其他原因重置我们画廊的样式；我们不想无缘无故地创建不必要的函数。

#### 初始化画廊样式

我们需要做的最后一件事是初始化我们的样式。为此，让我们在`Gallery`构造函数中初始化代码时调用`setStyles`。

```html
function Gallery() {
  // our previous code 

   this.setStyles();
    attachEvents();
}
```

当我们最终设置好我们的样式时，我们的应用程序在纵向模式下应该如下所示：

![初始化画廊样式](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_04_01.jpg)

响应式画廊

在横向模式下，我们的应用程序应该如下所示：

![初始化画廊样式](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_04_02.jpg)

响应式画廊

### 提示

不幸的是，你的应用程序不会看起来或行为像这些截图中显示的应用程序；这是因为现在没有任何连接，我们甚至还没有初始化我们的任何代码。但是，如果你确实想立即进行操作并查看我们是如何做的，你可以在本章的最后一节之前查看我们的结论。如果你按照这些步骤，你应该会得到一个类似于我们刚刚看到的应用程序。

从技术上讲，我们的画廊现在已经完全构建好了，我们现在可以使用下一个和上一个按钮完全与之交互。但现在，让我们开始等待已久的有趣的触摸事件！

## 扩展触摸功能的画廊

默认情况下，我们可以将触摸交互包含在`Gallery`类中，但这不具有可重用性，也无法应用于应用程序的其他部分。因此，在本节中，我们将创建一个名为`Swipe`的新类，它将包含检测特定模块上滑动手势所需的一切。

### 基本模板

与以往编写的其他类似，我们始终希望从基本框架开始。我们可以编写以下基本模板来开始：

```html
var App = window.App || {};

App.Swipe = (function(window, document, $){

  var _defaults = {};

  function Swipe(options) {
    this.options = $.extend({}, _defaults, options);
  }

    return Swipe;

}(window, document, Zepto));
```

`Swipe`类与我们的`Gallery`类有些不同，它接受`window`、`document`和`Zepto`对象。另一个不同之处在于`Swipe`构造函数接受一个名为`options`的参数，用于覆盖我们即将设置的默认值。

### 默认选项和模块化滑动事件

`Swipe`类内部有几件事情要做。首先，我们希望确保它仅适用于特定容器，而不是整个文档。然后，我们希望能够缓存某些值，如触摸的初始 x 位置和结束 x 位置。这些缓存的值也应该在闭包作用域中可用，以便它们在所有方法中都可用。

以下是我们想要的默认值和将在闭包作用域中可用的缓存值：

```html
var _defaults = {
  'el': document.body,
  '$el': $(document.body)
},
el,
$el,
delta,
initXPos,
endXPos,
threshold = 30;
```

在前面的代码中，我们基本上是在说默认元素，滑动功能，应该附加到文档的`body`元素。从这里开始，我们确保可以在闭包作用域中访问这些缓存的元素。最后，我们设置一些变量，将存储关于我们将要监听的触摸手势的信息。

现在在我们的构造函数中，我们要覆盖这些默认值，并确保一些这些初始值将存在于全局作用域中：

```html
function Swipe(options) {
  this.options = $.extend({}, _defaults, options);
  $el = this.$el = this.options.$el = $(this.options.el);
  threshold = this.options.threshold || threshold;

  this.init();
}
```

在这里，我们使用 Zepto 的`extend`方法创建一个新对象，其中包含将选项参数合并到默认对象中。然后，我们确保闭包作用域包含了滑动类将附加到的缓存元素。最后，我们检查是否传递了自定义阈值，并覆盖默认的 30。在所有这些之后，我们在构造函数的末尾调用一个初始化方法，以便`Swipe`类自动启动。

### 监听触摸事件

现在我们需要将适当的事件附加到`Swipe`类。这些事件将基于我们之前介绍的触摸事件，但它们将以模拟滑动手势的方式使用。为了实现这一点，我们首先需要监听`touchstart`、`touchend`和`touchmove`事件，并为每个事件分配事件处理程序。我们可以在我们从构造函数调用的`init`方法中完成所有这些。

因此，首先让我们在`Swipe`的`prototype`上创建我们的`init`方法，并确保在方法的末尾返回实例：

```html
Swipe.prototype.init = function() {

  return this;
};
```

在这个方法中，我们希望监听前面提到的触摸事件，并确保它们有事件处理程序。为此，我们将使用 Zepto 的`on`方法，并将事件附加到我们缓存的元素上：

```html
Swipe.prototype.init = function() {
  this.options.$el.
    on('touchstart', handleTouchStart).
    on('touchend', handleTouchEnd).
    on('touchmove', handleTouchMove);

  return this;
};
```

在前面的代码中，我们将事件作为字符串传递给`on`方法的第一个参数，然后分配一个尚未创建的事件处理程序。您还会注意到这些方法是可链接的，允许我们一次附加多个事件。这就是为什么我们在公共方法的末尾返回`this`，以便我们可以允许自己同步调用的原因。

### 处理触摸事件

现在我们需要创建我们分配给每个监听器的事件处理程序。我们将逐个处理处理程序，以便解释如何从这些触摸事件中创建滑动手势。我们首先要看的是`touchstart`处理程序。

当我们把手指放在手机上时，我们想要做的第一件事是存储手指的初始 x 位置。要访问这些信息，事件触发时会有一个`touches`数组。因为我们只想使用第一个触摸，所以我们需要访问`touches`数组中的第一个触摸。一旦我们得到第一个触摸，我们就可以使用该对象上的`pageX`属性来获取 x 位置。这就是`handleTouchStart`的功能将会是什么样子：

```html
function handleTouchStart(e) {
    initXPos = e.touches[0].pageX;
}
```

正如你所看到的，`handleTouchStart`方法接受一个参数，即事件对象。然后我们将`initXPos`设置为事件对象上`touches`数组中第一个触摸的`pageX`属性。这可能听起来很混乱，但基本上我们只是访问我们需要的对象，以便保存您触摸的初始 x 值。

接下来，我们想要创建`handleTouchMove`事件处理程序。这个处理程序将包含与`handleTouchStart`相同的概念，但我们想要更新结束的 x 位置，而不是初始的 x 位置。可以在以下代码中看到：

```html
function handleTouchMove(e) {
  e.preventDefault();
    endXPos = e.changedTouches[0].pageX;
}
```

这里有一些我将解释的不同之处。首先，我们阻止了触摸移动的默认行为。这是为了阻止发生任何奇怪的行为，通常建议在我们想要创建独特体验时使用，比如可滑动的画廊。

你会注意到的另一个区别是我们正在查看事件的`changedTouches`对象。这是因为`move`事件不包含`touches`对象。尽管有点有争议，但这有助于跟踪每次触摸和该特定触摸的更改属性。因此，如果我有多次触摸，那么我的`changedTouches`对象将适当地包含每次更改的触摸。

到目前为止，我们所做的只是设置初始和结束的 x 位置。现在我们需要使用这些值来创建一个`delta`值，然后使用它来触发左右方向的滑动。这就是我们的`handleTouchEnd`事件处理程序将为我们做的事情。

这是`handleTouchEnd`应该包含的代码：

```html
function handleTouchEnd(e) {
    endXPos = e.changedTouches[0].pageX;
    delta = endXPos - initXPos;

    if(delta > threshold) {
        $el.trigger('SwipeLeft');
    }

    // The *-1 converts the threshold to a negative integer
    if(delta < threshold*-1) {
        $el.trigger('SwipeRight');
    }
}
```

现在让我们逐行查看这段代码。首先我们做的和`handleTouchMove`一样，就是设置结束的 x 位置。接下来，我们设置我们的`delta`值，即通过从初始 x 位置中减去结束 x 位置得到的差值。现在我们进行比较；如果`delta`大于阈值，那么触发一个名为`SwipeLeft`的自定义事件。我们的下一个比较有点更加混乱，但基本上我们检查`delta`值是否小于负阈值。这是为了检测向右方向的滑动。

我们的`Swipe`类现在已经完成。我们已经创建了监听我们触摸事件的必要功能，然后模拟了一个手势，我们可以将其连接起来。但实际上我们还没有将它连接到我们的画廊，这是整个过程中的最后一步。因为现在你已经达到了这一点，所以应该感到自豪，因为现在将会发生容易的事情！

## 把所有东西放在一起

好的，到目前为止我们有一个画廊和使用触摸事件检测滑动手势的能力。但现在，没有什么真正连接在一起，实际上我们还没有初始化我们的`Gallery`类，所以现在什么都不应该工作。但这就是最后一部分的内容；我们将会初始化我们的`Gallery`类，添加`Swipe`功能，然后对我们的滑动事件做出反应。

### JavaScript

我们要做的第一件事是打开我们的`App.Touch.js`文件，你还记得这个文件与我们的触摸页面的功能相关，因此这个文件将包含我们所有的初始化。当我们打开这个文件时，转到`init`方法，或者如果还没有创建，那么创建并初始化一个`Gallery`的实例：

```html
Touch.prototype.init = function() {
  var that = this;

  // Initializing Gallery
  this.gallery = new App.Gallery();

  return this;
};
```

现在我们已经初始化了我们的`Gallery`类，画廊应该立即初始化。但请记住，我们还没有修改我们的标记以包含这个文件。所以即使在这一点上，你也看不到你劳动的成果。但让我们确保我们继续设置工作。在下一步中，我们想要初始化我们的`Swipe`类，并确保它将自己设置为`gallery`元素：

```html
Touch.prototype.init = function() {
  // Previous code

  // Initializing Swipe
  this.swipe = new App.Swipe({
    'el': document.querySelector('.gallery')
  });

  return this;
};
```

现在，即使在这一点上，我们的画廊也不会响应滑动事件。这是因为我们的滑动功能只检测触摸并分派我们之前设置的自定义事件，所以我们需要做的是在画廊上监听这些事件，然后告诉它播放下一个或上一个幻灯片：

```html
Touch.prototype.init = function() {
  // Previous code

  // Listen to the swipe and then trigger the appropriate click
  this.swipe.$el.
    on('SwipeLeft', function(){
      that.gallery.$el.find('a[href="#previous"]').trigger('click');
    }).
    on('SwipeRight', function(){
      that.gallery.$el.find('a[href="#next"]').trigger('click');
    });

  return this;
};
```

在前面的代码中，我们监听由我们的滑动实例分派的`SwipeLeft`和`SwipeRight`事件。当任一事件被分派时，根据事件，我们模拟点击上一个或下一个按钮。通过这种方式，我们能够让用户看起来在整个画廊中滑动，同时消除任何复杂性。

当你完成编写你的`init`方法时，它应该是这样的：

```html
Touch.prototype.init = function() {
  var that = this;

  // Initializing Gallery
  this.gallery = new App.Gallery();

  // Initializing Swipe
  this.swipe = new App.Swipe({
    'el': document.querySelector('.gallery')
  });

  // Listen to the swipe and then trigger the appropriate click
  this.swipe.$el.
    on('SwipeLeft', function(){
      that.gallery.$el.find('a[href="#previous"]').trigger('click');
    }).
    on('SwipeRight', function(){
      that.gallery.$el.find('a[href="#next"]').trigger('click');
    });

  return this;
};
```

### 标记

需要处理的最后一项是页面上的标记 - 包括的脚本。为了简化事情并最终使您的应用程序正确运行，以下是您需要在页面上包含的内容：

```html
    <script src="img/zepto.min.js"></script>
    <script src="img/helper.js"></script>
    <!-- BEGIN: Our Framework -->
    <script src="img/App.js"></script>
    <script src="img/App.Nav.js"></script>
    <script src="img/App.Gallery.js"></script>
    <script src="img/App.Swipe.js"></script>
    <script src="img/App.Touch.js"></script>
    <!-- END: Our Framework -->
    <script src="img/main.js"></script>
    <script> touch = new App.Touch(); </script>
```

与其他页面相比，这里的不同之处在于我们只包括我们需要的项目，包括`App.Nav.js`、`App.Gallery.js`、`App.Swipe.js`和`App.Touch.js`。与其他页面相比，我们正在包括整个框架，但对于这个页面或任何以后的页面，我们实际上不需要这样做。需要注意的一点是，我们还创建了一个全局的触摸对象，它被设置为我们`App.Touch`类的一个实例。这样我们可以在调试器中轻松地引用它，但这应该被替换为`App.touch`，这样它就不会污染全局命名空间。

我们到达了终点！在这一点上，你应该有一个完全功能的画廊，可以进行滑动交互。现在给自己一个鼓励吧；这是一个漫长的旅程，但我希望你能欣赏到我们已经创建了可重用的、模块化的代码，它是完全自包含的。除此之外，我们的画廊是完全响应式的，可以适应用户的设备，让他们能够一致地享受体验。

# 总结

在本章中，我们重新设计了我们的主导航，讨论了触摸和手势事件的基本原理，然后使用一个响应式的照片画廊实现了这两种类型的事件，这将适应用户的设备。我们还讨论了如何附加这些事件，并根据幻灯片放映的要求适当地处理它们。从现在开始，你应该对如何使用触摸事件在 iPhone 上创建独特体验有很好的理解，以及在其他移动设备上也是如此。接下来，让我们来看看在 iPhone 上处理 HTML5 表单时会有一些特殊的交互。


# 第五章：了解 HTML5 表单

在本章中，我们将使用最新的 HTML5 技术来查看表单，包括新的输入类型和表单属性。我们将简要回顾一些我们将在示例表单中使用的新输入类型。然后，我们将讨论规范中的一些新属性，同时专门针对移动设备查看`autocapitalize`属性。在深入研究我们的示例表单之前，我们考虑 iOS 设备上的表单布局以及与这些表单交互时出现的限制。最后，我们创建一些示例表单，开发一些简单的验证，然后专门为 iOS 和支持 WebKit 的浏览器样式化我们的表单。

一旦我们审查了所有这些功能，并且已经浏览了我们的示例表单，我们应该对 HTML5 表单以及它们与为 iOS 开发 Web 应用程序有何关联有了扎实的理解。

以下是本章将涵盖的主题：

+   新的 HTML5 输入类型

+   新的 HTML5 表单特定属性

+   iPhone 的表单布局

+   表单验证

+   iOS 的表单样式

因此，让我们首先来看一下新的标准 HTML5 输入类型。

# HTML5 输入类型

HTML5 引入了几种新的输入类型，加快了应用程序的开发。总共有 13 种新的输入类型在 HTML5 规范中引入，包括日期时间、本地日期时间、日期、月份、时间、周、数字、范围、电子邮件、网址、搜索、电话和颜色。不幸的是，这些新输入中只有 10 种在 iOS 上受支持，但不用担心，因为类型会自动默认为文本。这对我们帮助不大，但它确实允许我们为我们需要但不受支持的类型创建 polyfill。无论如何，以下是 iOS 上支持的所有输入类型的详细说明：

| 输入类型 描述 |
| --- |
| --- --- |
| 按钮 代表没有额外语义的按钮。 |
| 复选框 代表可以切换的状态或选项。 |
| 日期 代表将元素的值设置为表示日期的字符串的控件。 |
| 日期时间 代表将元素的值设置为表示全局日期和时间（带有时区信息）的字符串的控件。 |
| 本地日期时间 代表将元素的值设置为表示本地日期和时间（不带时区信息）的字符串的控件。 |
| 电子邮件 代表编辑电子邮件地址列表的控件。 |
| 文件 代表文件项目列表，每个项目包括文件名、文件类型和文件主体（文件的内容）。 |
| 隐藏 代表用户不打算检查或操作的值。 |
| 图像 代表 UA 从中启用用户交互地选择一对坐标并提交表单的图像，或者用户可以从中提交表单的按钮。 |
| 月份 代表一个控件，用于将元素的值设置为表示月份的字符串。 |
| 数字 代表一个精确的控件，用于将元素的值设置为表示数字的字符串。 |
| 密码 代表用于输入密码的单行纯文本编辑控件。 |
| 单选按钮 代表从项目列表中选择一个项目的选择（单选按钮）。 |
| 范围 代表一个不精确的控件，用于将元素的值设置为表示数字的字符串。 |
| 重置 代表重置表单的按钮。 |
| 搜索 代表用于输入一个或多个搜索词的单行纯文本编辑控件。 |
| 提交 代表提交表单的按钮。 |
| 电话 代表用于输入电话号码的单行纯文本编辑控件。 |
| 文本 代表输入元素值的单行纯文本编辑控件。 |
| 时间 代表将元素的值设置为表示时间（不带时区信息）的字符串的控件。 |
| `url` | 代表一个控件，用于编辑元素值中给出的绝对 URL。 |
| `week` | 代表一个控件，用于将元素值设置为表示一周的字符串。 |

这些详细信息可在以下网址找到：

+   [`www.w3.org/TR/html-markup/input.html`](http://www.w3.org/TR/html-markup/input.html)

+   [`developer.apple.com/library/safari/#documentation/AppleApplications/Reference/SafariHTMLRef/Articles/InputTypes.html#//apple_ref/doc/uid/TP40008055-SW1`](http://developer.apple.com/library/safari/#documentation/AppleApplications/Reference/SafariHTMLRef/Articles/InputTypes.html)

尽管我们可以在这里尝试许多输入，但我们只会专注于新的`email`、`number`、`datetime`和`range`类型。本书中的示例表单还将包含常规类型，包括`text`、`password`和`submit`。

现在我们对支持的内容有了很好的了解，并且有了适合我们需求的类型的信息参考，让我们继续审查我们也可以利用的属性。

# HTML5 表单属性

在 HTML5 中有许多属性可供我们使用，但为了简化这部分，我们将专注于我们可以在输入和表单上使用的新属性。以下属性在最新的 HTML5 规范中定义，除了`autocapitalize`外，在 iOS 上也得到支持：

| 输入属性 | 描述 |
| --- | --- |
| `autocapitalize` | 指定文本元素的自动大写行为。 |
| `autocomplete` | 指定元素是否表示用户输入的输入控件（以便用户代理可以稍后预填充表单）。 |
| `min` | 元素值的预期下限。 |
| `max` | 元素值的预期上限。 |
| `multiple` | 指定元素允许多个值。 |
| `placeholder` | 一个短提示（一个词或短语），旨在帮助用户输入控件的数据。 |
| `required` | 指定元素是表单提交的必需部分。 |

您可以在以下网址找到这些属性的详细信息：

+   [`www.w3.org/TR/html-markup/global-attributes.html#global-attributes`](http://www.w3.org/TR/html-markup/global-attributes.html#global-attributes)

+   [`developer.apple.com/library/safari/#documentation/AppleApplications/Reference/SafariHTMLRef/Articles/Attributes.html#//apple_ref/doc/uid/TP40008058-SW2`](https://developer.apple.com/library/safari/#documentation/AppleApplications/Reference/SafariHTMLRef/Articles/Attributes.html)

+   [`www.w3.org/TR/html-markup/form.html#form.attrs.autocomplete`](http://www.w3.org/TR/html-markup/form.html#form.attrs.autocomplete)

### 提示

并非所有表单属性都列在上表中；只列出了 HTML5 规范中定义的最新支持的属性。这是为了让我们对最新和最好有一个很好的了解。然而，如果您想获得更广泛的支持，我鼓励您查看上述详细信息的来源，并对规范中每个属性进行彻底的解释。

我们现在对 iOS 支持的最新属性有了基本的了解。我们现在可以简要地回顾一些设计考虑，然后直接进入一些示例 HTML5 表单，看看最新的输入类型和属性如何一起工作，以简化我们的开发过程。

# iPhone 的表单布局

在这一部分，我们简要介绍了在为 iOS 创建表单时的一些设计考虑。您可能对表单的设计有或没有完全控制；然而，为了更容易理解可能出现的限制，以下表格有助于展示我们在处理表单时所拥有的有限屏幕空间。希望这将帮助您解释这些限制，以便进行调整。让我们来看看以下表格：

| UI 控件 | 像素尺寸 |
| --- | --- |
| 状态栏 | 高度 20 英寸 |
| URL 文本字段 | 高度 60 英寸 |
| 表单助手 | 高度 44 英寸 |
| 键盘 | 竖屏高度 216 英寸，横屏高度 162 英寸 |
| 按钮栏 | 竖屏高度 44 英寸，横屏高度 32 英寸 |

有关这些控件的详细信息可以在[`developer.apple.com/library/safari/#documentation/AppleApplications/Reference/SafariWebContent/DesigningForms/DesigningForms.html`](https://developer.apple.com/library/safari/#documentation/AppleApplications/Reference/SafariWebContent/DesigningForms/DesigningForms.html)找到。

根据这些值，当这些控件出现时，我们需要调整我们的表单以适应特定的尺寸。例如，如果所有这些控件都出现，除了按钮栏，而我们有 480 像素的可用高度，那么我们的屏幕房地产最终将达到惊人的高度 140 像素。

正如你所看到的，为 iOS 创建可用的表单是一个挑战，但并非不可能。有一些有趣的技术可以用来适应我们应用程序中的表单。但最好的技术是简单。确保你不要一次要求用户提供大量信息；所以不要要求姓名、电子邮件、密码和密码确认以及出生日期，而只要求用户名、密码和电子邮件地址。保持简单在我们的应用程序中有很大帮助，并有助于改善用户体验。

我们现在对为 iOS 设计表单时出现的限制有了相当的了解，但现在让我们跳入功能性，看看我们如何创建一些简单的表单。

# 示例 HTML5 表单

现在我们将仔细研究一些代码，包括标记、脚本和样式。其中一些你可能已经知道，大部分重点将放在新的 HTML5 输入和属性上。我们将看看它们如何被实现到表单中，它们对 UI 控件的影响，以及如何将这项新技术应用到我们的脚本中。但首先，让我们做一些设置工作，以确保我们的页面保持一致。

## 设置工作

我们需要做的第一件事是打开我们的表单页面的`index.html`文件。一旦打开了这个文件，你会看到我们最初在本书开始时创建的旧模板。随着我们的应用程序的发展，我们必须更新这个模板以反映这些变化，所以让我们做以下任务：

+   在我们的主要样式之后包含表单样式（`forms.css`）

+   更新导航以反映我们的新菜单

+   包括我们的导航脚本（`App.Nav.js`）和我们的表单脚本（`App.Forms.js`）

### 包括我们的表单样式

目前，我们的页面没有任何样式，但我们应该包括我们的页面特定样式表。当我们这样做时，我们的头部应该是这样的：

```html
    <!DOCTYPE html>
    <html class="no-js">
    <head>
        [PREVIOUS META TAGS]

        <link rel="stylesheet" href="../css/normalize.css">
        <link rel="stylesheet" href="../css/main.css">
        <link rel="stylesheet" href="../css/forms.css">
        <script src="img/modernizr-2.6.1.min.js"></script>
    </head>
```

### 更新导航

与上一章一样，我们需要更新我们的导航以反映新的选择菜单。这有助于为我们的应用程序节省屏幕房地产。当我们更新我们的导航时，我们的标记将更新为以下代码：

```html
<nav>
    <select>
        <option value="../index.html">Application Architecture</option>
        <option value="../video/index.html">HTML5 Video</option>
        <option value="../audio/index.html">HTML5 Audio</option>
        <option value="../touch/index.html">Touch and Gesture Events</option>
        <option value="../forms/index.html" selected>HTML5 Forms</option>
        <option value="../location/index.html">Location Aware Applications</option>
        <option value="../singlepage/index.html">Single Page Applications</option>
    </select>
</nav>
```

### 包括我们的导航和表单脚本

现在我们的导航已经就位，让我们包含导航脚本，同时让我们包含我们的表单的页面特定脚本：

```html
<script src="img/zepto.min.js"></script>
<script src="img/helper.js"></script>
<!-- BEGIN: Our Framework -->
<script src="img/App.js"></script>
<script src="img/App.Nav.js"></script>
<script src="img/App.Forms.js"></script>
<!-- END: Our Framework -->
<script src="img/main.js"></script>
```

正如你所看到的，我们只包含了这个页面所需的必要脚本。

## 表单

我们将在页面上开发三种不同的表单，包括登录、注册和个人资料表单。它们非常基本，大部分将演示表单的实现。在每段代码之后，我们将审查新的输入并提供一些关于它们如何影响我们的标记和用户界面的背景信息。在这部分，不要担心整体结构；也就是说，不要担心表单的包含`div`或带有标题的部分。结构不会被讨论，大部分是作为指导线给你的。所以，让我们从我们的登录表单开始。

### 登录表单

以下是我们**登录**表单的结构。仔细审查这一点，主要关注“表单”元素以及它如何利用“自动大写”属性，然后看看我们如何在用户名和密码字段上实现了必填属性：

```html
<!-- BEGIN: LOGIN CONTAINER -->
<form autocorrect="off" autocapitalize="off">
    <div class="error-messaging"></div>
    <label for="login-username">Username</label>
    <input name="username" id="login-username" type="text" placeholder="johndoe" required>
    <label for="login-password">Password</label>
    <input name="password" id="login-password" type="password" required>
    <input type="submit" value="Submit">
</form>
<!-- END: LOGIN CONTAINER -->
```

当我们看最终产品时，由于我们还没有为我们的表单设置样式，它应该看起来有点像这样：

![登录表格](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_05_01.jpg)

我们的登录表格

如你所见，我们在“表单”元素上将“自动大写”设置为关闭。这基本上告诉移动 Safari 不要对其中的任何输入进行大写。我们可以很容易地在每个单独的输入上设置这个属性为“关闭”，但为了简化这个演示，我们将其保留在“表单”元素上。

这里还有一件很酷的事情是，我们在用户名和密码上都设置了“必填”。这很棒，因为除非填写了这些字段，否则不会提交表单。在过去，我们需要设置一个“必填”的类，然后用 JavaScript 进行检查；现在有了 HTML5，我们就不需要了。

### 提示

我知道你们中的一些人可能会感到震惊，但在 iOS 中，你不会收到任何关于字段是否必填的通知。根据开发者文档，它不受支持。那么为什么在这里提到它呢？因为如果我们真的想要支持多个移动设备，包含这个属性仍然是一个好主意，这样我们的应用程序就会对设备友好，如果苹果选择在未来支持它，我们的应用程序就是未来的。再次强调，这需要你和可能是你的团队来权衡，但拥有这个属性符合 HTML 5 规范——只是在 iOS 上不受支持而已。

我们还可以看到“占位符”属性被用来为我们的文本输入应用一些默认文本。请记住，“占位符”就是一个占位符。它并不设置我们输入的值，所以值仍然是空的。

### 注册表格

现在我们转向我们的注册表格。在这个表格中，我们将收集用户的姓名、用户名、电子邮件、密码和确认密码。再次强调，不要关注结构。集中精力关注“自动更正”属性在“表单”元素上的实现，然后关注“电子邮件”输入类型的使用。

```html
<!-- BEGIN: REGISTER CONTAINER -->
<form autocorrect="off" autocapitalize="off">
    <div class="error-messaging"></div>
    <div class="field">
        <label for="register-name">Name</label>
        <input name="name" id="register-name" type="text" placeholder="John Doe">
    </div>
    <div class="field">                    
        <label for="register-username">Username</label>
        <input class="required" name="username" id="register-username" type="text" placeholder="johndoe">
    </div>
    <div class="field">
        <label for="profile-email">Email</label>
        <input class="required" type="email" id="profile-email" autocorrect="off">
    </div>
    <div class="field">
        <label for="register-password">Password</label>
        <input class="required" named="password" id="register-password" type="password">
    </div>
    <div class="field">
        <label for="register-password-confirm">Confirm Password</label>
        <input class="required" named="password" id="register-password-confirm" type="password">
    </div>
    <input type="submit" value="Register">
</form>
<!-- BEGIN: REGISTER CONTAINER -->
```

当我们完成了这一部分和一些初步的样式后，我们的表单会看起来像这样：

![注册表格](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_05_02.jpg)

我们的注册表格

在这个表格中，我们已经关闭了所有表单字段的“自动更正”。再次强调，我们可以逐个元素地进行设置，但为了简化操作，我们选择将其添加到“表单”元素中。

最后要考虑的一点是使用输入类型“电子邮件”。当我们开始使用一些定制的输入类型时，我们的用户界面会相应调整。例如，当我们点击“电子邮件”输入类型时，我们会看到控件会改变以包括`@`符号：

![注册表格](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_05_03.jpg)

电子邮件输入类型

现在，让我们更仔细地看看其他输入类型是如何影响我们的用户界面的。

### 个人资料表格

以下表单是登录和注册表单的一种组合，带有一些额外的字段。然而，有一些区别，所以让我们专注于改变的部分。在这个例子中，我们会看到我们已经将“自动大写”更改为“句子”，并且只在我们想要应用的字段上将“自动更正”设置为“关闭”。除此之外，我们开始使用“日期时间”、“数字”和“范围”输入类型。我们做出的最后一个改变是使用类而不是属性来应用“必填”字段——这将在我们脚本的实现中进一步解释。现在，先审查标记，然后继续阅读解释。

```html
<!-- BEGIN: PROFILE UPDATES -->
<form autocapitalize="sentences">
    <div class="error-messaging"></div>
    <h2>Basic Information</h2>
    <div class="field">
        <label for="profile-name">Name</label>
        <input name="name" id="profile-name" type="text" placeholder="John Doe">
    </div>
    <div class="field">
        <label for="profile-username">Username</label>
        <input name="username" id="profile-username" type="text" placeholder="johndoe" autocorrect="off">
    </div>            
    <div class="field">
        <label for="profile-dob">Date of Birth</label>
        <input type="datetime" id="profile-dob">
    </div>            
    <div class="field">
        <label for="profile-email">Email</label>
        <input type="email" id="profile-email" autocorrect="off">
    </div>
    <h2>Personal Information</h2>
    <div class="field">
        <label for="profile-age">Age</label>
        <input type="number" id="profile-age">
    </div>
    <div class="field">
        <label for="profile-city">City</label>
        <input type="text" id="profile-city" placeholder="Boston">
    </div>
    <div class="field">
        <label for="profile-state">State</label>
        <select name="state" id="profile-state">
            <!-- OPTIONS GO HERE -->
        </select>
    </div>
    <div class="field">
        <label for="profile-zip">ZipCode</label>
        <input type="number" min="0" id="profile-zip">
    </div>
    <h2>Professional Information</h2>
    <div class="field">
        <label for="profile-skills-markup">HTML5</label>
        <input type="range" min="0" max="5" id="profile-skills-markup">
    </div>
    <div class="field">
        <label for="profile-skills-styles">CSS3</label>
        <input type="range" min="0" max="5" id="profile-skills-styles">
    </div>
    <div class="field">
        <label for="profile-skills-scripts">JavaScript</label>
        <input type="range" min="0" max="5" id="profile-skills-scripts">
    </div>
    <h2>Bio Information</h2>
    <label for="profile-bio">About Yourself</label>
    <textarea id="profile-bio" name="about"></textarea>
    <div class="field">
        <label for="register-password">Password</label>
        <input class="required" named="password" id="register-password" type="password">
    </div>
    <p>Provide your password to confirm.</p>
    <input type="submit" value="Update Profile">
</form>
```

我们的最终产品在样式化后会是这样的：

![个人资料表格](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_05_04.jpg)

我们的个人资料表格

在这个例子中，我们在`form`元素上将`autocapitalize`设置为`sentences`。这有助于我们，因为现在我们已经明确定义了我们希望大写的内容，即只有句子。这在苹果的文档中有描述，可以在那里进一步探索。至于`autocorrect`，我们在各个项目上设置它，因为我们可能希望在`textarea`上进行校正。同样，我们可以选择在`form`元素上将`autocorrect`设置为`off`，然后在`textarea`中将其设置为`on`，但这是一个选择的问题，完全取决于您作为开发人员。现在让我们来回顾一下几种输入类型。

#### 日期时间类型

在这个例子中，我们使用`datetime`来处理**出生日期**字段。这很棒，因为我们的 UI 完全符合我们的期望，以提供准确的信息：

![日期时间类型](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_05_05.jpg)

日期时间输入类型

#### 数字类型

`number`输入类型也可以操作我们的 UI，以便我们在控件中有一组默认的数字选择：

![数字类型](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_05_06.jpg)

我们的数字输入类型

#### 范围类型

`range`输入类型是我们表单中非常有用的控件。同样，这种类型提供了一个自定义的 UI，允许我们使用系统默认值，而不是 JavaScript，来提供我们所需的数值类型：

![范围类型](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_05_07.jpg)

范围输入类型

现在我们已经完成了对 HTML5 中一些新的输入字段和属性以及它们如何影响我们的 iOS Web 应用程序 UI 的审查。接下来是使用 JavaScript 来验证我们的表单。同样，这将是非常基础的，并且将介绍我们如何设置一个可重用的表单组件，不会直接与这些新的输入和属性联系起来。这是因为这些自定义输入和属性是规范的一部分，旨在加快开发速度，因此您对使用脚本进行验证的需求应该是有限的。无论如何，让我们继续前进，快速看一下我们的脚本。

# 表单验证

在这一部分，我们回顾了为这个页面编写的 JavaScript。没有什么真正新颖或突破性的东西；它明确旨在演示如何使用我们在本书中开发的框架来创建自包含的代码，以验证多个表单并使您更容易扩展。所以让我们开始通过回顾基本模板。

## 基本模板

以下是我们一直在使用的基本模板。使用标准的命名空间技术，扩展`App`命名空间的`Form`类将包含我们所有的功能。

```html
var App = window.App || {};

App.Form = (function(window, document, $){
    'use strict';

    var _defaults = {
            'element': 'form',
            'name': 'Form'
        };

    function Form(options) {
        // Customizes the options by merging them with whatever is passed in
        this.options = $.extend({}, _defaults, options);

        this.init();
    }

    //----------------------------------------------------
    //  Private Methods
    //----------------------------------------------------

    //----------------------------------------------------

    //----------------------------------------------------
    //  Event Handlers
    //----------------------------------------------------

    //----------------------------------------------------

    //----------------------------------------------------
    //  Public Methods
    //----------------------------------------------------
    Form.prototype.getDefaults = function() {
        return _defaults;
    };

    Form.prototype.toString = function() {
        return '[ ' + (this.options.name || 'Form') + ' ]';
    };

    Form.prototype.init = function() {
        // Initialization Code

        return this;
    };

    return Form;

}(window, document, Zepto));
```

请记住，代码是包含在立即调用的函数表达式或 IIFE/闭包中的自包含的。当我们初始化`App.Form`时，`Form`构造函数将被调用，我们的公共方法`init`将初始化我们在其中编写的任何代码。所以让我们从那里开始，附加适当的事件。

## 初始化我们的表单

我们需要初始化我们的表单，但我们不需要为每个表单创建一个新对象。我们可以通过事件驱动来处理验证，然后使用我们为每个输入写的属性来处理验证。但让我们来看看我们的事件设置。

### 附加事件

首先，让我们执行事件附加：

```html
this.$element.
  on('submit', 'form', handleFormSubmission);

this.$cache.loginFormContainer.
  on('click', 'a[href="#forgot-password"]', handleForgotPasswordClick).
  on('click', 'a[href="#register"]', handleRegisterClick);

this.$cache.registerFormContainer.
  on('click', 'a[href="#login"]', handleLoginClick);
```

在上面的代码中，我们有一些事情要做。首先，我们要查找页面上任何表单的提交。然后，当我们提交表单时，我们将调用`handleFormSubmission`方法，我们将在一会儿编写。以下的事件监听器基本上是登录和注册按钮的显示/隐藏。

这里没有什么新的或突破性的东西，基本上我们只是做一些设置工作，如果需要的话随时可以回来。关键在于，我们没有为每个表单创建一个新的对象实例，而是将我们的代码概括为只监听每个表单上的`submit`事件。现在让我们创建或设置我们的处理程序，然后编写它们的功能。

### 事件处理程序

现在，让我们来看一下事件处理程序。

```html
function handleFormSubmission(e) {
  e.preventDefault();

  // Code goes here
}

function handleForgotPasswordClick(e) {
  e.preventDefault();

  // Code goes here
}

function handleRegisterClick(e) {
  e.preventDefault();

  // Code goes here
}

function handleLoginClick(e) {
  e.preventDefault();

  // Code goes here
}
```

在这里我们并没有做任何新的事情，我们所做的唯一步骤是为我们的代码设置桩，以便我们知道每个功能的位置。从这里开始，我们看一下每个表单提交的验证代码。我们不会看每个表单的显示/隐藏功能，但是你可以查看本书附带的源代码，以了解它是如何工作的。

## 验证我们的输入

我们将看一下`handleFormSubmission`方法，并逐步了解我们如何验证我们的字段。如果你在任何步骤感到困惑，不要担心。我们都曾经历过这种情况，我自己有时也会在表单验证和如何在项目中处理它方面遇到困难。

首先，让我们开始缓存我们将要使用的变量：

```html
function handleFormSubmission(e) {
  var $target, errors, $required, fields, $errorText, i, required_fields_length;
}
```

这些变量描述了它们自己，这是一个标准的做法，因为我们想要理解发生了什么，因此给我们的变量附上有意义的名称是必不可少的。

现在，我们需要阻止表单的默认行为；这意味着我们暂时不想提交表单。为了做到这一点，让我们做以下操作：

```html
function handleFormSubmission(e) {
  var $target, errors, $required, fields, $errorText, i, required_fields_length;
  e.preventDefault();
}
```

我们添加了`e.preventDefault`，它告诉事件阻止浏览器中的默认行为。接下来，我们想要定义目标，清空任何先前的错误消息，创建一个空的错误对象，然后找到所有必填元素。可以使用以下代码完成：

```html
function handleFormSubmission(e) {
  // Previous code
  $target = $(e.target);
  $target.find('.error-messaging').empty();
  errors = { 'required': [], 'invalid': [] };
  $required = $target.find(':required');
}
```

### 注意

请注意，我们的`errors`对象包含两个数组：一个`required`数组和一个`invalid`数组。这个`errors`数组将跟踪出了什么问题；例如，如果一个字段是`required`并且值是`empty`，那么我们将在`error`对象内填充`required`数组，但如果一个输入已经填写但不合法，那么我们将在`errors`对象内填充`invalid`对象。

现在，记得当我们添加了`required`类但没有添加`required`属性到我们的个人资料表单时吗？前面的代码就无法捕捉到这一点，所以我们会遇到问题。为了防止这种情况发生，我们可以这样做：

```html
function handleFormSubmission(e) {
  // Previous code
  if ($required.length === 0) {
    $required = $target.find('.required')
  }
}
```

这段代码有助于解决我们在`required`类上的问题，但确实存在一个逻辑缺陷。你能找到这个缺陷吗？我会留给你作为一个谜题来解决。这个过程的下一步是找到所有的`form`元素，然后找到`required`字段并检查它们是否已经填写：

```html
function handleFormSubmission(e) {
  //Previous code
  fields = $target[0].elements;

  i = 0, required_fields_length = $required.length;
  for (i; i < required_fields_length; i++) {
  if ($required[i].value === '') {
      errors.required.push($($required[i]).prev('label').text() + ' is required.');
    }
  }
}
```

在这一点上，我们基本上在`error`对象内填充我们的`invalid`数组。如果字段为空，我们收集与该字段关联的标签的值，并附加一个定制的消息，将呈现给用户。

### 注意

不幸的是，特定的验证不会被覆盖，比如电子邮件、数字和其他限制。然而，这里有足够的空间让你探索并添加到这段代码中，希望这足以让你理解验证、要求以及如何在代码中处理这些用例。

最后一步是检查错误，如果存在错误，将这些错误呈现给用户，以便他们相应地进行更正：

```html
function handleFormSubmission(e) {
  //Previous code
  if (errors.required.length === 0 && errors.invalid.length === 0) {
    console.log('Form Requirements and Validations Passed');
    return;
  } else {
    $errorText = $('<ul />');

    if (errors.required.length !== 0) {
      $errorText.append('<li>' + errors.required.join('</li><li>') + '</li>');
    }

    if (errors.invalid.length !== 0) {
      $errorText.append('<li>' + errors.invalid.join('</li><li>') + '</li>');
    }

    $target.find('.error-messaging').append($errorText);
  }
}
```

我们的检查非常简单，我们基本上检查`error`对象内的`invalid`和`required`数组是否为空。如果是，我们希望继续提交——在这种情况下将是一个 AJAX 调用。否则，我们希望创建一个包含错误的无序列表，然后将它们附加到表单上，以便用户在没有页面刷新的情况下了解出了什么问题。

希望这一部分帮助你理解验证表单的方法。有了 HTML5 规范的最新支持，浏览器已经处理了大部分工作。这加快了开发速度，减少了定制组件的开发，并帮助我们专注于交付。现在作为一个额外的功能，我们继续进行表单的样式设计。

# iOS 的表单样式

在本节中，我们将研究如何为我们的表单进行样式设置。如果我们目前在 iOS 设备上甚至桌面浏览器上测试我们的表单，它看起来并不漂亮。事实上，你可能会对它的丑陋感到有点不满。因此，让我们对其进行样式设置，让每个人都满意。我们将从帮助实现良好外观的基本样式开始。然后，我们将考虑如何使用 CSS3 功能自定义我们的组件。

## 基本样式

样式化表单非常容易。我们可以简单地使用元素本身，但有一个“陷阱”。您可能注意到我们在一个选择器中指定了`[type="datetime"]`。这是因为`datetime`输入类型在 iOS 上显示为选择菜单类型的 UI，因此典型的输入选择器不适用。否则，在基本样式中并没有太多真正突出的地方，它基本上给了我们在之前讨论过的表单中使用的输入类型中看到的样式。

```html
/*!
  Forms Styling
*/

label {
    color: #FFF;
    font-family: 'Helvetica', 'Arial', sans-serif;
    font-size: 12px;
    display: block;
    margin: 10px 0 5px 0;
}

input, select, input[type="datetime"], textarea {

    font-size: 13px;

    display: block;
    margin: 0;
    padding: 5px 8px;
}

input[type="submit"] {
    margin: 10px 0;
}

.form-container {
   display: none;
   margin: 15px 0;
}

.form-container.active {
  display: block;
}

form h2 {
    margin: 10px 0 5px 0;
}

.error-messaging ul {
  list-style: square outside;
  margin: 5px 0 0 0;
  padding: 0 0 0 12px;
}

.error-messaging li {
    color: #A12E33;
    font-family: 'Helvetica', 'Arial', sans-serif;
    font-size: 12px;  
}
```

## 自定义样式

这就是许多魔术发生的地方。在本节中，我们使用自定义的 CSS3 样式来自定义我们的组件。以下样式将自定义我们的输入、选择，并给我们一个更加风格化的表单，与我们当前的样式相匹配。在审查样式时，您可能需要记住的一些事情是使用 CSS3 的`gradient`属性作为`background`和`border-radius`的使用。

```html
/*!
  Forms Styling
*/

label {
    color: #FFF;
    font-family: 'Helvetica', 'Arial', sans-serif;
    font-size: 12px;
    display: block;
    margin: 10px 0 5px 0;
}

input, select, input[type="date-time"], textarea {

    background: rgb(69,72,77);
    background: -moz-linear-gradient(top, rgba(69,72,77,1) 0%, rgba(0,0,0,1) 100%);
    background: -webkit-gradient(linear, left top, left bottom, color-stop(0%,rgba(69,72,77,1)), color-stop(100%,rgba(0,0,0,1)));
    background: -webkit-linear-gradient(top, rgba(69,72,77,1) 0%,rgba(0,0,0,1) 100%);
    background: -o-linear-gradient(top, rgba(69,72,77,1) 0%,rgba(0,0,0,1) 100%);
    background: -ms-linear-gradient(top, rgba(69,72,77,1) 0%,rgba(0,0,0,1) 100%);
    background: linear-gradient(to bottom, rgba(69,72,77,1) 0%,rgba(0,0,0,1) 100%);

    font-size: 13px;
    color: #e5e5e5;

    border: 1px solid #000918;

    -moz-border-radius: 3px;
    -webkit-border-radius: 3px;
    -ms-border-radius: 3px;
    -o-border-radius: 3px;
    border-radius: 3px;

    display: block;
    margin: 0;
    padding: 5px 8px;

    -moz-box-shadow: 1px 1px 1px #333;
    -webkit-box-shadow: 1px 1px 1px #333;
    -ms-box-shadow: 1px 1px 1px #333;
    -o-box-shadow: 1px 1px 1px #333;
    box-shadow: 1px 1px 1px #333;
}

input[type="text"], 
input[type="number"], 
input[type="email"], 
input[type="datetime"],
input[type="password"],
textarea {
  background: -webkit-gradient(linear, left top, left bottom, color-stop(0, #42422F), color-stop(0.09, #444));
}

input[type="submit"] {
    margin: 10px 0;
}

.form-container {
   display: none;
   margin: 15px 0;
}

.form-container.active {
  display: block;
}

form h2 {
    margin: 10px 0 5px 0;
}

.error-messaging ul {
  list-style: square outside;
  margin: 5px 0 0 0;
  padding: 0 0 0 12px;
}

.error-messaging li {
    color: #A12E33;
    font-family: 'Helvetica', 'Arial', sans-serif;
    font-size: 12px;
}
```

当我们应用前面的样式时，我们得到以下 UI：

![自定义样式](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_05_08.jpg)

范围输入类型

正如您所看到的，我们给我们的表单赋予了全新的外观和感觉，并且很容易地对选择组件进行了样式设置，这在桌面浏览器上并不容易做到。在这些样式之上，我建议您查看`-webkit-appearance`属性，它基本上允许您进一步自定义您的表单，并在组件的样式方面提供更多的控制。然而，此时您应该已经有了一个坚实的基础，可以为 iOS 构建 HTML5 表单。

# 摘要

在本章中，我们回顾了最新的 HTML5 输入类型和属性，特别是针对我们的示例应用程序。然后，我们讨论了 iOS 上表单的布局及其限制。最后，我们开发了一些表单，并附加了一个非常基本的验证脚本，利用了这些最新的输入和属性。作为一个额外的奖励，我们还讨论了如何为 WebKit 浏览器（包括 iOS 上的移动 Safari）定制我们的表单样式。

现在，我们应该对 iPhone 和 iPad 上的表单有了坚实的掌握，以及如何利用最新的 HTML5 技术为我们带来好处。本章帮助演示了表单的使用以及我们需要考虑的因素，以便创建用户友好的表单。除此之外，我们现在将进入下一章的位置感知，并将使用在这里学到的一些概念来扩展体验。
