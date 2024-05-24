# PHP Ajax 秘籍（五）

> 原文：[`zh.annas-archive.org/md5/5ed725dded7917e2907901dccf658d88`](https://zh.annas-archive.org/md5/5ed725dded7917e2907901dccf658d88)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：iPhone 和 Ajax

在本章中，我们将涵盖：

+   构建网站的触摸版本（使用 jQTouch）

+   在 iPhone Ajax 中利用 HTML5 功能

+   使用 PhoneGap 构建本机应用

+   加速 PhoneGap 项目

+   构建一个货币转换混合应用

iPhone 于 2007 年由苹果公司推出。它以独特的设计、触摸屏和清新的用户界面重新定义了智能手机领域。除了电话功能和支持外，它还弥合了其他智能手机中普遍存在的互联网体验差距。它配备了 Safari 网络浏览器、电子邮件客户端和 iPod，为完整的网络体验。

以下截图显示了 iPhone 4 的主屏幕，其中包含默认内置应用程序：

![iPhone 和 Ajax](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_09_01.jpg)

像 PC 一样，iPhone 有一些称为“应用程序”的有用实用程序。所有应用程序都可以从主屏幕访问。我们有两种方法来编写应用程序：

+   本机应用

+   Web 应用程序

界面与顶部的菜单栏一致，并且在必要时也在底部。

# 构建网站的触摸版本（使用 jQTouch）

触摸站点或触摸版本实际上是指 Web 应用程序。**Web 应用程序**是设计为在 iPhone 上最佳查看的网页，并且是用 HTML 和 JavaScript 编程的。HTML 和 JavaScript 有一些扩展，称为 Safari HTML 和 Safari JavaScript，用于获取设备相关的效果或支持。与普通网页不同，Web 应用程序将遵循 iPhone 的一致用户界面和触摸友好的布局，比如菜单栏、滑动选择选项等。有时，它们也被称为“网络剪辑”。以下图片显示了在 iPhone 上查看的 Facebook 的触摸版本`touch.facebook.com`。

![构建网站的触摸版本（使用 jQTouch）](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_09_02.jpg)

要快速创建 Web 应用程序 UI/样式，有一些可用的框架和工具包，比如 IUI、jQTouch、jQuery Mobile、Sencha Touch 等。jQTouch 和 jQuery Mobile 是基于 jQuery 的库。我们将看到如何使用 jQTouch 构建 Web 应用程序/触摸版本。

## 准备就绪

我们将需要 Safari 网络浏览器来测试 Web 应用程序。通常，所有 Web 应用程序都可以在任何分级浏览器中粗略查看。我们还需要 jQTouch，可在[`jqtouch.com/`](http://jqtouch.com/)上获得，以及 jQuery 核心。

## 操作步骤...

iPhone 的 Web 应用程序开发可以分为：

+   了解对界面有重要意义的`meta`和`link`标签。

+   使用适当的 HTML、CSS 和 JavaScript 调整界面/导航/元素的使用。这些通常由框架来处理，比如 IUI、jQTouch、jQuery Mobile 等。

了解`meta`和`link`标签

当 Web 应用程序被添加到主屏幕书签时，以下声明可以帮助我们指定要使用的图标：

```php
<link rel="apple-touch-icon" href="http:///custom_icon.png"/>

```

通常，iPhone 会在图像上添加圆角、投影和反射光泽。这是一个样本，使用 Packt 标志创建的 57x57 自定义图标：

![操作步骤...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_09_03.jpg)

1.  当我们已经有一个预先制作的图标时，为了避免双重效果，我们需要将`custom_icon.png`重命名为`apple-touch-icon-precomposed.png`，如下所示：

```php
<link rel="apple-touch-icon" href="/apple-touch-icon-precomposed.png"/>

```

1.  图标的默认大小是 57x57。要为不同的分辨率指定不同的图标，我们可以使用`sizes`属性：

```php
<link rel="apple-touch-icon" sizes="72x72" href="http:///custom_icon72x72.png" />
<link rel="apple-touch-icon" sizes="114x114" href="http:///custom_icon114x114.png" />

```

1.  以下截图显示了本机 Skype 应用的启动或闪屏图像。启动图像将在启动应用程序时显示几秒钟。其尺寸必须为 320x460，可以这样指定：

```php
<link rel="apple-touch-startup-image" href="http:///startup.png" />

```

![操作步骤...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_09_04.jpg)

1.  我们可能还想隐藏 Safari 浏览器的控件，以获得本机应用的外观和感觉。我们将通过以下代码实现这一点，以隐藏地址栏：

```php
<meta name="apple-mobile-web-app-capable" content="yes" />

```

1.  要更改状态栏的颜色，我们可以使用以下命令：

```php
<meta name="apple-mobile-web-app-status-bar-style" content="black" />

```

1.  iPhone 的视口调整为 980 像素宽。因此，如果一个网页/ web 应用程序宽度为 980 像素，它将正确适应 iPhone。如果页面只有一个宽度为 200 像素的表格或图像，在 iPhone 上查看时，图像将偏向左上角。对于这种情况，我们有一个选项可以通过编程方式指定视口宽度，如下所示：

```php
<meta name="viewport" content="width = 200" />

```

1.  前面的代码将修复视口宽度，200 像素的图像将以全宽度显示。当同时针对 iPhone 和 iPad 时，最好使用设备常量`device-width`来指定宽度，如下所示：

```php
<meta name="viewport" content="width=device-width" />

```

1.  要禁用用户缩放并设置视口，请使用：

```php
<meta name="viewport" content="user-scalable=no, width=device-width" />

```

1.  使用适当的 HTML、CSS 和 JavaScript 使用调整界面/导航/元素的使用。

iPhone web 应用程序具有类似的 UI——滑动链接选择选项，在页眉中快速导航等等。最好从框架的基本 HTML 代码开始。这将帮助我们快速在必要的地方插入我们的元素。

从框架的基本 HTML 代码开始还有另一个优点。它给了我们关于链接放置的提示，后退按钮的放置方式等等。

## 它是如何工作的...

让我们来看一下以下的 jQTouch HTML 5 代码，用于折扣计算器：

```php
<!doctype html>
<html>
<head>
<meta charset="UTF-8" />
<title>Discount Calc</title>
<style type="text/css" media="screen">@import "./jqtouch/jqtouch.css";</style>
<style type="text/css" media="screen">@import "./themes/apple/theme.css";</style>
<script src="./jqtouch/jquery-1.5.1.min.js" type="text/javascript" charset="utf-8"></script>
<script src="./jqtouch/jqtouch.js" type="application/x-javascript" charset="utf-8"></script>
<script type="text/javascript" charset="utf-8">
var jQT = new $.jQTouch({
icon: 'icon.png',
addGlossToIcon: false,
startupScreen: 'startup.png',
statusBar: 'black'
});
function getDiscountPercentage(actual_price, discounted_price) {
var discount_percentage = 100 * (actual_price - discounted_price)/ actual_price;
return discount_percentage;
}
$(function(){
$('#calc-input input').blur(function(){
$('#calc-result').html(getDiscountPercentage($('#actual-price').val(), $('#discounted-price').val()) + ' %');
});
});
</script>
</head>
<body>
<div id="jqt">
<div id="home">
<div class="toolbar">
<h1>Discount Calc</h1>
<a href="#info" class="button flip">About</a>
</div>
<div id="calc" class="form">
<form id="calc-input">
<ul class="rounded">
<li><input type="text" id="actual-price" name="actual- price" placeholder="Actual Price"></li>
<li><input type="text" id="discounted-price" name="discounted-price" placeholder="Discounted Price"></li>
</ul>
<h3>Discount Percentage</h3>
<div id="calc-result" class="info">
</div>
</form>
</div>
</div>
<div id="info">
<div class="toolbar">
<h1>About</h1>
<a href="#home" class="cancel">Cancel</a>
</div>
<div class="info">
Demo calculator to find discount percentage.
</div>
</div>
</div>
</body>
</html>

```

如前所述，我们已经从 jQTouch 的基本 HTML 代码创建了代码。这让我们可以快速插入我们的折扣计算器逻辑和计算器表单界面。`$.jQTouch()`调用创建了所有必要的元数据和链接元素。主题是通过 CSS 和图像精灵完成的。

jQTouch 通过类名应用效果，例如以下代码：

```php
<a href="#info" class="button flip">About</a>

```

应用了翻转效果，并给出了按钮外观。

## 还有更多...

我们可以使用在线图标生成工具快速创建应用程序图标。苹果自己的开发者指南是关于这个主题的另一个广泛的资源。

### 在线 iPhone 图标生成器

要创建 iPhone 图标，我们有一个第三方网站[`www.flavorstudios.com/iphone-icon-generator`](http://www.flavorstudios.com/iphone-icon-generator)。它可以帮助我们快速创建图标，以防我们对 PhotoShop 不太熟悉。

苹果提供了一份免费指南，可在[`developer.apple.com/library/safari/documentation/appleapplications/reference/safariwebcontent/Introduction/Introduction.html`](http://developer.apple.com/library/safari/documentation/appleapplications/reference/safariwebcontent/Introduction/Introduction.html)上获得。

# 在 iPhone Ajax 中利用 HTML5 功能

HTML5 是 HTML 标准的最新修订版，被现代 Web 浏览器采用。当苹果在 iPhone 上阻止 Flash 访问并推动 HTML5 作为替代开放解决方案时，HTML5 受到了更多的关注。值得注意的是，2010 年 4 月，苹果公司联合创始人史蒂夫·乔布斯在一封名为“关于 Flash 的想法”的公开信中攻击了 Adobe，并强烈解释了在 iPhone 和 iPad 上支持 HTML5 的原因。这封公开信的摘要如下：

+   Flash 不是“开放”的，就像广告中宣传的那样

+   H.264 视频格式得到了广泛支持，不需要 Flash

+   Flash 容易出现安全和性能问题

+   视频的软件解码会影响电池寿命

+   Flash 属于旧的 PC 时代，不兼容触摸

+   依赖 Adobe 作为第三方开发工具提供商将影响苹果平台的增长

因此，HTML5 在 iPhone 上得到了原生支持，并且在生态系统中使用广泛。W3C 于 2011 年 1 月 18 日推出的 HTML5 标志如下：

![在 iPhone Ajax 中利用 HTML5 功能](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_09_05.jpg)

## 准备工作

我们需要在 Mac 上准备一个 iPhone 模拟器。虽然并非所有选项都可用，但我们也可以使用基于 WebKit 的 Web 浏览器，如 Google Chrome 或 Safari，进行预览。

## 如何做...

除了 canvas 等其他新的 API 之外，HTML5 的以下功能对 Web 应用程序和手持设备特别感兴趣：

1.  `audio`元素：

在 HTML5 中，音频播放是浏览器功能的一部分。在此之前，通常依赖于 Flash 编写的音频播放器来播放.mp3 文件。原生 HTML5 音频的使用示例如下：

```php
<audio>
<source src="test.mp3" type="audio/mpeg" />
</audio>

```

1.  `video`元素

视频元素被认为是 Flash 的“杀手”，并且获得了动力。以下是显示 YouTube 视频的 HTML5 代码：

```php
<video width="640" height="360" src="http://www.youtube.com/demo/protected.mp4" preload controls poster="thumbnail.png">
<p>Fallback content: This browser doesn't support HTML5 video</p>
</video>

```

属性可以解释如下：

+   `poster`代表要显示的图像，以便向用户展示视频的内容，通常是第一个非空白帧图像。

+   `controls`决定播放器是否具有视频控件。

+   `preload`允许视频的一部分在播放选项触发之前下载。这样用户可以在播放选项触发/点击时立即播放视频。这样做的缺点是即使用户不愿意播放视频，视频也会始终被下载。

1.  地理定位 API

**地理定位**是确定用户浏览器的物理位置的能力。在手持设备中，通过 GPS 可以实现地理定位，它可以提供设备的纬度和经度。对于一些 iPhone 应用程序，可能需要用户的物理位置来提供必要的功能。例如，对于一个显示周围优惠的应用程序，如果用户的位置可以自动识别，而不需要用户输入地址，那将非常有帮助。以下代码显示用户的纬度和经度：

```php
if (navigator.geolocation) {
navigator.geolocation.getCurrentPosition(
// success callback
function (position) {
alert('Latitude: ' + position.coords.latitude);
alert('Longitude: ' + position.coords.longitude);
},
// failure callback
function (error) {
switch (error.code) {
case error.TIMEOUT:
alert('Timeout');
break;
case error.POSITION_UNAVAILABLE:
alert('Position unavailable');
break;
case error.PERMISSION_DENIED:
alert('Permission denied');
break;
case error.UNKNOWN_ERROR:
alert('Unknown error');
break;
}
}
);
} else {
alert('Geolocation not supported in this browser');
}

```

在真正的 iPhone web 应用中，纬度和经度信息可以传递到服务器脚本以获取本地化数据。

1.  脱机版本

本地应用与 Web 应用的另一个重要区别是能够立即从 iPhone 加载全部或部分 UI，而无需任何互联网连接，以便用户感受到快速响应。我们在上一个示例中设计的折扣计算器 Web 应用是静态的，我们没有从服务器更新任何内容。因此，如果我们使其脱机工作，我们可能会感受到本地应用的感觉。

HTML5 具有缓存清单功能，可以帮助开发人员缓存必要的文件，以便在没有网络连接时 Web 应用程序仍然可以工作：

+   缓存清单的 MIME 类型是`text/cache-manifest`

+   缓存清单文件可以取任何名称，但必须在`html`元素中指定，如下所示：`<html manifest="/cache.manifest">`

+   这是一个纯文本文件：

+   指定要缓存的文件的隐式语法：

要指定要缓存的文件，我们有隐式和显式的语法。

```php
CACHE MANIFEST
# comment
/relative/path
http://example.com/absolute/path

```

+   使用显式语法与头部`CACHE, NETWORK`和`FALLBACK:`

```php
CACHE MANIFEST
CACHE:
# files that are to be cached
/relative/path/to-be-cached
http://example.com/absolute/path/to-be-cached
NETWORK:
# files that should not be cached
/relative/path/no-cache
http://example.com/absolute/path/no-cache
FALLBACK:
# file mapping of network failure.
# Here, the online file's alternative offline will be loaded.
/relative/path/no-cache /relative/path/to-be-cached

```

1.  Web 存储

HTML5 的另一个巧妙功能是能够在客户端机器上存储数据。与 cookie 不同，项目不会在 HTTP 头中发送到服务器。Web 存储有两个存储区域：

+   `localStorage:` 类似于 cookie，它的范围是整个域，即使浏览器关闭也会持续存在。

+   `sessionStorage:` 它的范围是每个窗口每个页面，仅在窗口关闭时可用。这有助于将数据限制在窗口内，这是使用 cookie 和本地存储无法实现的。

localStorage 和 sessionStorage 具有类似的语法来存储值；例如，在 localStorage 中设置、获取和删除键名为 Packt 的语法如下：

```php
localStorage.setItem('name', 'Packt'); // set name
var name = localStorage.getItem('name'); // get name
localStorage.removeItem('name'); // delete name
localStorage.clear(); // delete all local store (for the domain)

```

当键名没有任何空格时，我们也可以使用这种替代语法：

```php
localStorage.name = 'Packt'; // set name
var name = localStorage.name; // get name
delete localStorage.name; // delete name

```

### 注意

访问会话存储具有类似的语法，但是通过`sessionStorage`对象。

1.  客户端 SQL 数据库：

通过 JavaScript API 访问客户端数据库并使用 SQL 命令是 HTML5 的另一个有用功能。新 API 提供了 openDatabase、transaction 和 executeSql 方法。以下是使用这些方法的示例调用：

```php
var db = openDatabase('dbName', '1.0', 'long dbname', 1048576);
db.transaction(function (tx) {
tx.executeSql('CREATE TABLE IF NOT EXISTS books (id unique, text)');
tx.executeSql('INSERT INTO books (id, text) VALUES (1, "Packt")');
});

```

### 它是如何工作的...

由于 iPhone 原生支持 HTML5，在构建 Web 应用时很容易利用这些功能。在 iPhone 上，音频和视频元素可以原生播放，无需额外的 Flash 播放器要求。

地理定位使得轻松找到用户的位置并为用户提供本地化数据。缓存清单功能使得 Web 应用可以在 iPhone 上进行离线访问。使用`localStorage, sessionStorage`或客户端 SQL 数据库可以在 iPhone 上存储本地数据。这些 HTML5 功能帮助我们构建具有原生应用外观和感觉的 Web 应用。

### 还有更多...

当我们想要不断改进应用时，Web 应用可能是首选，因为原生应用必须经过苹果的批准流程。Gmail 和 Yahoo! Mail 利用 HTML5 功能在 iPhone 上提供更好的应用体验。

#### HTML5 演示

[`html5demos.com/`](http://html5demos.com/)提供了一组快速的 HTML5 演示。这有助于理解浏览器的兼容性和使用示例。

#### Persist JS

Persist JS 是一个抽象库，它通过替代手段帮助客户端浏览器上的数据存储，如果浏览器不原生支持 HTML5 功能。它可以在[`pablotron.org/software/persist-js/`](http://pablotron.org/software/persist-js/)找到。

# 使用 PhoneGap 构建原生应用

尽管我们可以为 Web 应用带来离线访问、启动图像、客户端数据存储和其他巧妙的功能，但 Web 应用仍然无法使用设备硬件功能。加速计、声音、振动和 iPhone 内置的地理定位功能是面向硬件的，它们只在原生应用中可用。原生 iPhone 应用通常是在 Mac 机器上使用 Objective C 构建的，直到 PhoneGap 出现。**PhoneGap**是一种替代开发工具，它允许我们使用 HTML、CSS 和 JavaScript 构建原生 iPhone 应用。它充当 Web 应用和移动设备之间的桥梁；因此，它允许我们快速将我们的 Web 应用转换为其他移动目标。除了 iPhone，它还支持其他智能手机，如 Android 和 BlackBerry。它是一种非常经济高效的解决方案，因为它允许我们重用相同的代码库来实现多种目的——网站构建、Web 应用构建和原生应用构建。另一个积极的方面是它是开源的。在这个步骤中，我们将构建一个折扣计算器的原生版本。

## 准备工作

构建原生应用需要：

+   安装了 Xcode 的 Mac 机器。对于订阅了 iOS 开发者计划的人来说，Xcode 是免费的。它可以在[`developer.apple.com/xcode/`](http://developer.apple.com/xcode/)找到。Xcode 4 包括 Xcode IDE、Instruments、iOS 模拟器以及最新的 Mac OS X 和 iOS SDK。

+   PhoneGap 可以通过[`www.phonegap.com/download/`](http://www.phonegap.com/download/)上的简单安装程序获得。请注意，ZIP 文件包含所有支持平台的文件夹。当我们切换到`iOS`文件夹时，我们可以找到安装程序`PhoneGapInstaller.pkg`。它安装了 PhoneGapLib、PhoneGap 框架和 PhoneGap Xcode 模板。这使我们能够快速从 Xcode 创建 PhoneGap 项目。

+   购买 iOS 开发者计划的付费订阅[`developer.apple.com/programs/ios/`](http://developer.apple.com/programs/ios/)，以便将我们的应用提交到 App Store 并能够在 iPhone 上运行。如果没有 iOS 开发者访问权限，我们只能在模拟器上预览应用。

## 如何做...

使用 PhoneGap 构建原生 iPhone 应用可以分为以下步骤：

1.  构建一个 Web 应用：

正如我们在第一个步骤中看到的，首先我们必须构建一个 Web 应用。

1.  在 Xcode 4 中创建一个 PhoneGap 项目：

在这一步中，我们必须通过在 Xcode 中创建一个 PhoneGap 项目来将我们的 Web 应用与 PhoneGap 连接起来：

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_09_06.jpg)

当 PhoneGapLib 安装后，Xcode 将设置必要的模板。因此，创建一个新的 PhoneGap 项目更简单。

+   启动 Xcode 并从**文件**菜单中选择**新建项目**。

+   在**选择新项目的模板**窗口中，选择**基于 PhoneGap 的应用**，如前面的屏幕截图所示。请注意，只有在安装了`PhoneGapInstaller.pkg`后才会出现这个选项。

+   在屏幕**选择新项目的选项**中，输入以下产品详细信息：

+   产品名称：

+   **公司标识符：**

+   输入这些将自动填充**Bundle Identifier**为`com.packt.DiscCalculator`

+   在下一步中选择项目位置。

+   运行项目以创建一个`www`文件夹。

+   在项目中添加一个对`www`的文件夹引用。

### 注意

最后两个步骤是必要的，因为 Xcode 4 模板中存在错误。

Nitobi 提供免费的网络服务，可以快速创建一个 PhoneGap 项目，网址为[`build.phonegap.com/generate`](http://https://build.phonegap.com/generate)。

这些步骤将创建一个默认的 PhoneGap 示例项目。基本上，示例中的代码需要一些注意：

```php
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no;" />
<!-- iPad/iPhone specific css below, add after your main css >
<link rel="stylesheet" media="only screen and (max-device-width: 1024px)" href="http://ipad.css" type="text/css" />
<link rel="stylesheet" media="only screen and (max-device-width: 480px)" href="http://iphone.css" type="text/css" />
-->
<script type="text/javascript" charset="utf-8" src="phonegap.js"></script>
<script type="text/javascript" charset="utf-8">
function onBodyLoad() {
document.addEventListener("deviceready",onDeviceReady,false);
}
/* When this function is called, PhoneGap has been initialized and is ready to roll */
function onDeviceReady() {
// do your thing!
navigator.notification.alert("PhoneGap is working")
}
</script>
<body onload="onBodyLoad()">
<h1>Hey, it's PhoneGap!</h1>
<p>Don't know how to get started? Check out <em><a href="http://github.com/phonegap/phonegap-start">PhoneGap Start</a></em>
</body>

```

在这里，我们可以清楚地注意到这些 PhoneGap 特定的功能在我们的 web 应用代码中不可用。因此，我们必须将这些逻辑合并到我们的 web 应用代码中。这里更容易的选择是：

+   从`www`文件夹中删除`startup.png`和`icon.png`；启动图像和图标位于`www`文件夹之外，文件名为`Default.png`（320x480）、`Default-Landscape.png`（1004x768）、`Default-Portrait.png`（768x1024）、`icon-72.png`（72x72）和`icon.png`（57x57）。当我们针对其他设备时，需要不同分辨率的文件。

+   使用相关的 PhoneGap 代码修改我们的 web 应用程序的`head`部分。

+   然后，用它替换整个`www`文件夹内容。

1.  添加硬件特定的功能。

到目前为止，我们还没有添加任何硬件特定的功能。PhoneGap API 允许我们通过 JavaScript 中的 navigator.notification 对象访问硬件特定的功能：

+   `navigator.notification.alert(message, alertCallback, [title], [buttonName])`允许我们使用更多功能的本机警报窗口。

+   `navigator.notification.confirm(message, confirmCallback, [title], [buttonLabels])`允许我们使用更多功能的本机确认对话框。

+   `navigator.notification.beep(times)`允许我们发出蜂鸣声。

+   `navigator.notification.vibrate(milliseconds)`允许我们使手机振动。

因此，让我们修改代码，以便具有本机的蜂鸣、振动和警报对话框。对于 Disc Calculator 应用程序，最终的代码将在`www`文件夹中如下所示：

```php
<!doctype html>
<html>
<head>
<meta charset="UTF-8" />
<title>Discount Calc</title>
<style type="text/css" media="screen">@import "./jqtouch/jqtouch.css";</style>
<style type="text/css" media="screen">@import "./themes/apple/theme.css";</style>
<script src="phonegap.js" type="text/javascript" charset="utf-8"></script>
<script src="./jqtouch/jquery-1.5.1.min.js" type="text/javascript" charset="utf-8"></script>
<script src="./jqtouch/jqtouch.js" type="application/x-javascript" charset="utf-8"></script>
<script type="text/javascript" charset="utf-8">
var jQT = new $.jQTouch({
statusBar: 'black'
});
function getDiscountPercentage(actual_price, discounted_price) {
var discount_percentage = 100 * (actual_price - discounted_price)/ actual_price;
return discount_percentage;
}
$(function() {
document.addEventListener('deviceready', function() {
navigator.notification.vibrate(2000); // vibrate 2 seconds
navigator.notification.alert('Ready!', '', 'DiscCalculator');
}, false);
$('#calc-input input').blur(function() {
$('#calc-result').html(getDiscountPercentage($('#actual-price').val(), $('#discounted-price').val()) + ' %');
navigator.notification.beep(1); // 1 time beep
});
});
</script>
</head>
<body>
<div id="jqt">
<div id="home">
<div class="toolbar">
<h1>Discount Calc</h1>
<a href="#info" class="button flip">About</a>
</div>
<div id="calc" class="form">
<form id="calc-input">
<ul class="rounded">
<li><input type="text" id="actual-price" name="actual-price" placeholder="Actual Price"></li>
<li><input type="text" id="discounted-price" name="discounted-price" placeholder="Discounted Price"></li>
</ul>
<h3>Discount Percentage</h3>
<div id="calc-result" class="info">
</div>
</form>
</div>
</div>
<div id="info">
<div class="toolbar">
<h1>About</h1>
<a href="#home" class="cancel">Cancel</a>
</div>
<div class="info">
Demo calculator to find discount percentage.
</div>
</div>
</div>
</body>
</html>

```

1.  在 iPhone 模拟器中预览：

在 Xcode 中使用**构建和运行**选项并选择活动可执行文件，可以轻松在 iPhone 模拟器中预览。以下截图显示了我们在 Xcode 中的**DiscCalculator**项目：

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_09_07.jpg)

如下截图所示，我们可以从概述下拉菜单中选择**活动可执行文件**，以便在 iPhone 模拟器中执行它：

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_09_08.jpg)

最后，我们的应用程序在 iPhone 模拟器中运行如下所示：

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_09_09.jpg)

1.  在 iPhone 中预览：

为了预览或提交我们的应用到 App Store，我们需要创建 Provisioning Profile，这又需要 iOS 开发者计划的付费订阅。Provisioning Profile 是一个集合，将应用程序、开发人员和设备（iPhone）绑定在一起，以便在设备上安装它以进行测试。

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_09_10.jpg)

在 iOS 开发者网页的 Provisioning Portal 中找到 Provisioning Assistant，这个过程很容易：

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_09_11.jpg)

尽管如前面截图所示启动 Provisioning Assistant 将指导您完成每一步，但这里是摘要：

+   在 Keychain Access 应用程序中生成 CSR 并将其上传到供应门户。然后，在 Keychain Access 中安装生成的证书。这里，证书的创建应该是为“开发”。

+   在供应门户中输入**APP ID**（在我们的情况下，`com.packt`）的详细信息

+   在供应门户中添加开发设备的**UDID**（唯一设备标识符）。

+   现在，开发配置文件将准备就绪。下载并将其放入 Xcode 项目中。一旦 iPhone 连接到 Mac 机器，在设备上启动应用程序将会在 iPhone 上加载应用程序。

### 注意

要找到 iPhone 的 UDID，我们可以：

在 iPhone 上使用[`itunes.apple.com/app/udidit/id326123820`](http://itunes.apple.com/app/udidit/id326123820)上的 UDIDit 应用程序。

或者

连接 iPhone 后使用 iTunes。

1.  提交到 App Store：

要在 iPhone 上预览，我们必须创建一个“开发”配置文件（也称为“临时”），并且要提交到 App Store，我们必须创建一个“分发”配置文件。创建配置文件的步骤是相似的，但在证书选项中，我们必须为分发创建它。

下一步是通过[`itunesconnect.apple.com/`](http://https://itunesconnect.apple.com/)的 iTunes Connect 提交应用程序。为此，我们必须在 iTunes Connect 网站上添加新应用程序并输入必要的详细信息。在最后一步，我们必须通过充当上传器的 Application Loader 应用程序上传应用程序文件二进制文件。一旦上传并提交，应用程序将由苹果员工审核。当应用程序符合他们的标准时，它将被批准。

## 它是如何工作的...

PhoneGap 实际上是针对不同平台的 WebView 包装器集合。因此，它在浏览器控件中显示 Web 应用程序，给人一种本地的感觉。这些包装器将本地代码函数暴露给 JavaScript API。因此，PhoneGap 为任何应用程序带来了本地感觉和 HTML/CSS 主题。

创建配置文件决定了临时开发测试的授权设备。通过 iTunes Connect 网站，应用程序可以提交并进行进一步的修订。

## 还有更多...

我们已经了解了 iOS 平台上的 PhoneGap。但是，我们可能需要为其他平台构建应用程序。

### 入门指南/帮助向导

PhoneGap 在[`www.phonegap.com/start`](http://www.phonegap.com/start)上为所有平台提供了一个很好的入门指南。通过选择目标平台，我们可以获得逐步视频教程或屏幕演示。

# 加快 PhoneGap 项目的速度

在上一篇文章中，我们已经看到了如何使用 jQTouch 构建 Web 应用程序，并通过 PhoneGap 将其转换为本地应用程序。在本篇文章中，我们将看到如何减少涉及的步骤，并看到 jQTouch 的另一种替代解决方案。

## 准备就绪

我们需要访问[`build.phonegap.com/`](http://https://build.phonegap.com/)上的 PhoneGap Build。在撰写本文时，此功能处于私人测试阶段，需要从[`jquerymobile.com/`](http://jquerymobile.com/)获取 jQuery Mobile 和 jQuery 核心。

## 如何做...

为了加快开发速度，我们必须减少步骤并改进我们的编程方法：

1.  PhoneGap 构建服务：

开发 PhoneGap 的 Nitobi 公司在下图中展示了一个在线构建服务。这意味着我们不需要在我们的机器上遵循任何构建步骤。

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_09_12.jpg)

+   只需上传 HTML/CSS/JavaScript 源文件，然后在云端构建即可。云构建服务还可以为其他平台构建源文件，如 Android、Palm、Symbion 和 Blackberry。这将是一个节省时间的好方法，也是一个适用于使用 Windows 机器的好选择。

1.  jQuery Mobile：

与 jQTouch 相比，jQuery Mobile 是一个较新的框架。它通过 HTML、CSS 和 JavaScript 提供类似的主题和编程能力。这是移动开发的官方 jQuery 库。

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_09_13.jpg)

**jQTouch**主要针对 WebKit 浏览器，因此仅在 iPhone 上支持良好。但是，如果我们针对更多设备，jQTouch 可能无法顺利工作，因为它不是跨平台和跨设备的。另一方面，jQuery Mobile 支持多个平台和设备。上面的图表显示了 jQuery Mobile 在各个平台上的支持情况。

如图所示，当我们为多个平台和设备构建应用时，这是一个节省时间的工具。

## 它的工作原理...

由于 PhoneGap Build 服务在云端工作，我们不需要满足任何开发环境要求。它可以为多个设备构建应用。

jQuery Mobile 针对多个设备和平台。在处理主题和更容易的 JavaScript API 方面，这与 jQTouch 类似。由于其主要关注点是跨平台和跨设备支持，它将节省我们在其他设备上移植应用的时间。支持图表清楚地显示了该框架在特定设备上提供的支持水平。

## 还有更多...

除了 PhoneGap，还有其他原生应用开发工具可用：

+   **Rhomobile Rhodes**

Rhomobile Rhodes 可在[`rhomobile.com/`](http://rhomobile.com/)找到，是另一个用于原生应用的开发解决方案。与 PhoneGap 不同，Rhodes 构建真正的原生应用。它的语言是 Ruby。类似于 PhoneGap Build 服务，它提供了基于浏览器的构建解决方案 RhoHub [`www.rhohub.com/`](http://www.rhohub.com/)。当我们了解 Ruby 并想构建一个真正的原生应用时，这将是一个很好的解决方案。

+   **Appcelerator Titanium/**

Appcelerator Titanium 可在[`www.appcelerator.com/products/titanium-cross-platform-application-development/`](http://www.appcelerator.com/products/titanium-cross-platform-application-development/)找到，之前通过 Web View/浏览器控制模拟原生应用的感觉。最近，它可以生成真正的原生代码。与 Rhodes 不同，它使用 JavaScript。当我们想要用 Web 技术开发真正的原生应用时，这可能是一个很好的解决方案。

# 构建货币转换混合应用

术语**混合应用**宽泛地指的是通过 WebView 包装器构建的应用，它在其中显示远程数据。原生应用包装器内部的 Web 浏览器组件主要用于显示已以 JSON 格式获取的 UI 和数据，以更新内容。PhoneGap 就是这样的技术。因此，使用 PhoneGap 进行原生应用开发，并能够从远程数据更新 UI 也可以称为混合应用。在本配方中，我们将看到如何构建一个货币转换应用。

## 准备工作

我们需要：

+   安装了 Xcode 的 Mac 机器

+   在 Xcode 中安装的 PhoneGapLib

+   jQTouch 可在[`jqtouch.com/`](http://jqtouch.com/)以及 jQuery 核心一起使用

+   `money.js`，一个 JavaScript 货币转换库，可从[`josscrowcroft.github.com/money.js/`](http://josscrowcroft.github.com/money.js/)获取

+   开源汇率 API 可在[`openexchangerates.org/latest.php`](http://openexchangerates.org/latest.php)找到

## 如何做...

开源汇率 API 提供了超过 120 种以美元为基础货币的转换率。它的货币转换姊妹库 money.js 可以在提供汇率数据时转换到不同的货币；请注意，只需要一个基础货币，通过数学计算就可以在其他货币之间进行转换。例如，如果我们有美元兑澳大利亚元和美元兑印度卢比的汇率，我们可以很容易地使用`money.js`计算印度卢比兑澳大利亚元。因此，当我们有`money.js`并且提供了开源汇率数据时，我们可以进行实时货币转换。

有了 API 和货币转换库，我们可以构建一个应用，如下面的截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_09_14.jpg)

这是 Xcode PhoneGap 项目的 HTML 文件中的代码。我们只创建了 HTML 文件。其余文件都是从 PhoneGap Xcode 模板派生的： 

```php
<!doctype html>
<html>
<head>
<meta charset="UTF-8" />
<title>Currency Conv</title>
<style type="text/css" media="screen">@import "./jqtouch/jqtouch.css";</style>
<style type="text/css" media="screen">@import "./themes/apple/theme.css";</style>
<script src="phonegap.js" type="text/javascript" charset="utf-8"></script>
<script src="./jqtouch/jquery-1.5.1.min.js" type="text/javascript" charset="utf-8"></script>
<script src="./jqtouch/jqtouch.js" type="application/x-javascript" charset="utf-8"></script>
<script src="./money.js" type="application/x-javascript"
charset="utf-8"></script>
<script type="text/javascript" charset="utf-8">
// Load exchange rates data in async manner...
$.ajax( {

url: 'http://openexchangerates.org/latest.php',
dataType: 'json',
async: false,
success: function(data) {
// if money.js is loaded
if (typeof fx !== 'undefined' && fx.rates) {
fx.rates = data.rates;
fx.base = data.base;
} else { // keep data in fxSetup global
var fxSetup = {
rates: data.rates,
base: data.base
}
}
}
});
var jQT = new $.jQTouch( {
statusBar: 'black'
});
$(function() {
// build source currency dropdown
// and initial exchange rates listing...
var _options = [];
var _li = [];
$.each(fx.rates, function(currency_code, exchange_rate) {
var target_currency = fx.convert(amount, {
from: source_currency,
to: currency_code
});
var _selected = (currency_code == fx.base) ? ' selected="selected"': '';
_options.push('<option value="' + currency_code + '"' + _selected + '>' + currency_code + '</option>');
_li.push('<li>' + currency_code + ' <small class="counter">' + exchange_rate + '</small></li>');
});
$('#source-currency').html(_options.join(''));
$('#exchange-rates').html(_li.join(''));
// alert the user when ready
document.addEventListener('deviceready', function() {
navigator.notification.vibrate(2000); // vibrate 2 seconds
navigator.notification.alert('Ready!', '', 'Currency Conv');
}, false);
// when user changes amount or source currency,

// repopulate the exchange rates using fx.convert()...
$('#conv-input').change(function() {
var amount = $('#amount').val();
var source_currency = $('#source-currency').val();
var _li = [];
$.each(fx.rates, function(currency_code, exchange_rate) {
_li.push('<li>' + currency_code + ' <small class="counter">' + target_currency + '</small></li>');
});
$('#exchange-rates').html(_li.join(''));
navigator.notification.beep(1); // 1 time beep
});
});
</script>
</head>
<body>
<div id="jqt">
<div id="home">
<div class="toolbar">
<h1>Currency Conv</h1>
<a href="#info" class="button flip">About</a>
</div>
<div id="conv" class="form">
<form id="conv-input">
<ul class="rounded">
<li><input type="text" id="amount" name="amount"
placeholder="Amount" value="1"></li>
<li><select id="source-currency" name="source-currency">
</select></li>
</ul>
<h3>Exchange Rates</h3>
<div class="form">
<ul id="exchange-rates" class="rounded">
</ul>
</div>
</form>
</div>
</div>
<div id="info">
<div class="toolbar">
<h1>About</h1>
<a href="#home" class="cancel">Cancel</a>
</div>
<div class="info">
App for currency conversion.
</div>
</div>
</div>
</body>
</html>

```

要在 iPhone 模拟器中编译或预览应用，请参阅本章中的*使用 PhoneGap 构建原生应用*配方。

## 它的工作原理...

我们使用了`money.js`库和开源汇率 API 进行转换过程。在应用程序加载期间，它以同步方式以 JSON 格式获取汇率数据。我们在`$.ajax()`方法中将`async`标志设置为`false`，以便函数调用将是串行的。来自 API 的汇率数据如下：

```php
"timestamp": 1319050338,
"base": "USD",
"rates": {
"AED": 3.67000019,
"ALL": 103.18125723,
...

```

数据通过`fx.rates`传递给`money.js`库，当加载时，否则设置为全局`fxSetup`变量，以便库在加载后使用。

`fx.rates`对象在其索引中具有货币代码；它们通过`$.each()`方法进行迭代，以填充源货币下拉菜单和初始汇率列表，值为`1 美元`。请注意，为了获得良好的性能，我们通过首先填充 HTML 内容并通过单个`html()`调用注入来减少对 DOM 的访问。

根据要求，当金额或源货币更改时，整个汇率列表将被重新绘制。这是通过挂接`change`事件并使用`fx.convert()`方法实现的。`money.js`支持包括类似 jQuery 的链式支持在内的不同语法：

```php
fx(1).from('USD').to('INR');

```

我们使用了以下语法，它比链式语法更容易迭代，开销更小：

```php
fx.convert(1,{
from: 'USD',
to: 'INR'
});

```

请注意，基于 PhoneGap 的应用程序早些时候被苹果拒绝，理由是它们只是网络剪辑（不完全本地化）。

建议将在 HTML 中完成的模板/视图逻辑始终本地可用，数据以 JSON 格式从服务器接收。这样，即使没有数据，应用程序也不会失去其外观/感觉。换句话说，不鼓励从服务器拉取 HTML 内容，这样的 HTML 内容可能会导致间隙，留下破碎的外观。当 App Store 审核团队审核应用程序时，如果应用程序的设计/感觉通过远程 HTML 内容更改，应用程序可能会被拒绝。应用审核是提交的重要流程，建议检查以下内容：

+   App Store Review Guidelines and Mac App Store Review Guidelines: [`developer.apple.com/appstore/guidelines.html`](http://developer.apple.com/appstore/guidelines.html)

+   App Store Review Guidelines: [`developer.apple.com/appstore/resources/approval/guidelines.html`](http://https://developer.apple.com/appstore/resources/approval/guidelines.html)

## 还有更多...

应用通常会以 JSON 格式从远程服务器获取数据，因此最好使用客户端模板解决方案。

### Mustache

Mustache 是一个流行的无逻辑模板解决方案，可以在[`mustache.github.com/`](http://mustache.github.com/)找到。它在许多编程语言中都有，包括 JavaScript。以下是一些示例用法：

```php
var view = {
name: "Alice",
tax: function() {
return 40000*30/100;
}
}
var template = "{{title}} should pay {{tax}}";
var html = Mustache.to_html(template, view);

```

上述代码将产生输出：**Alice 应支付 12000**。

### drink, jQuery 微模板

这个 jQuery 微模板库可以在[`plugins.jquery.com/project/micro_template`](http://plugins.jquery.com/project/micro_template)找到。它基于 jQuery 作者 John Resig 的 JavaScript 微模板文章[`ejohn.org/blog/javascript-micro-templating/`](http://ejohn.org/blog/javascript-micro-templating/)，讲述了如何开发一个轻量级脚本。该插件改进了模板选择，变量可以是带有模板标记的纯 HTML；数据被推送到模板中。由于其代码大小较小，这是一个适合移动平台的理想模板库。以下是一些示例用法：

```php
<ol id="tpl-users">

      <: for(var i=0; i < users.length; ++i)
{:>
<li><:=users[i].name:>, Age: <:=users[i].age:></li>
<:}
:>
</ol>
<script type="text/javascript">
var users_data={
"users":[
{"name":"Alice", "age":1},
{"name":"Bob", "age":3},
{"name":"Charles", "age":1}

]
};
$('#tpl-users').drink(users_data);
</script>

```
