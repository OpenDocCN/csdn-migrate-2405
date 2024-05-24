# 安卓 Flash 开发秘籍（三）

> 原文：[`zh.annas-archive.org/md5/3A6CCF6F6AAB969F5B96A3C7E7AEF15A`](https://zh.annas-archive.org/md5/3A6CCF6F6AAB969F5B96A3C7E7AEF15A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：本地交互：StageWebView 和 URI 处理程序

本章将涵盖以下食谱：

+   在默认的 Android 浏览器中打开网站

+   在应用程序内渲染网站

+   管理 StageWebView 历史记录

+   使用 StageWebView 和 ActionScript 加载广告

+   在 Flex 移动项目中使用 StageWebView 加载广告

+   从应用程序拨打电话

+   从应用程序发送短信

+   从应用程序调用 Google 地图

+   使用应用程序 URI 调用 Android 市场

+   从应用程序发送电子邮件

# 引言

传统上，Flash 平台开发者无法将 HTML 网站渲染为应用程序的一部分；随着 AIR for Android 中 StageWebView 的引入，这一切都改变了。本章包括关于这种机制与普通显示列表对象的不同之处，以及如何有效地使用它的小贴士。我们还将探讨 URI 处理功能，它允许我们接入 Android 设备上的本地应用程序，如网页浏览器、电子邮件客户端、地图和电话。

# 在默认的 Android 浏览器中打开网站

类似于桌面 Flash 和 AIR 应用程序，默认的系统 Web 浏览器可以通过 `flash.net` 包中的类在用户交互的基础上调用。在 Android 上，由于所有应用程序都占用一个完整的窗口，因此我们必须特别注意这可能会在用户与我们的应用程序交互时造成干扰。例如，当用户接到电话或短信必须退出应用程序时。

## 如何操作...

应用程序调用 `navigateToURL` 并传入一个新的 `URLRequest` 将打开默认的 Web 浏览器。在这个例子中，我们将在检测到 `TOUCH_TAP` 事件时打开一个网站：

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.TouchEvent;
    import flash.text.TextField;
    import flash.text.TextFormat;
    import flash.net.navigateToURL;
    import flash.net.URLRequest;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;

    ```

1.  我们现在将声明一个 `Sprite` 作为我们的交互元素，以及一个 `TextField` 和 `TextFormat` 对作为按钮标签：

    ```kt
    private var fauxButton:Sprite;
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  现在，我们将继续设置我们的 `TextField`，应用一个 `TextFormat` 对象，并使用图形 API 构造一个具有简单背景填充的 `Sprite`。我们按钮构建的最后一步是将 `TextField` 添加到 `Sprite` 中，然后将 `Sprite` 添加到 `DisplayList` 中。在这里，我们创建一个方法来执行所有这些操作，并进行一些风格上的增强：

    ```kt
    protected function setupTextButton():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 42;
    traceFormat.align = "center";
    traceFormat.color = 0x333333;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.autoSize = "left";
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.text = "Invoke Browser";
    traceField.x = 30;
    traceField.y = 25;
    fauxButton = new Sprite();
    fauxButton.addChild(traceField);
    fauxButton.graphics.beginFill(0xFFFFFF, 1);
    fauxButton.graphics.drawRect(0, 0, traceField.width+60, traceField.height+50);
    fauxButton.graphics.endFill();
    fauxButton.x = (stage.stageWidth/2) - (fauxButton.width/2);
    fauxButton.y = 60;
    addChild(fauxButton);
    }

    ```

1.  如果我们现在在设备上运行应用程序，交互式 `Sprite` 应如下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_07_01a.jpg)

1.  我们现将 `Multitouch.inputMode` 设置为通过 `MultitouchInputMode.TOUCH_POINT` 常量响应原始触摸事件。在 `Sprite` 按钮上注册一个类型为 `TouchEvent.TOUCH_TAP` 的事件监听器。这将检测用户发起的任何触摸点击事件，并调用名为 `onTouchTap` 的方法，该方法包含我们的其余逻辑：

    ```kt
    protected function registerListeners():void {
    Multitouch.inputMode = MultitouchInputMode.TOUCH_POINT;
    fauxButton.addEventListener(TouchEvent.TOUCH_TAP, onTouchTap);
    }

    ```

1.  一旦检测到轻触，我们的`onTouchTap`方法将被触发，调用`navigateToURL`并传入一个包含我们想要从应用程序中打开的 HTTP 或 HTTPS 地址的`URLRequest`：

    ```kt
    protected function onTouchTap(e:TouchEvent):void {
    navigateToURL(newURLRequest("http://memoryspiral.com/"));
    }

    ```

1.  当我们在设备上运行应用程序时，只需轻触按钮就会调用原生的网络浏览器应用程序并加载我们的`URL 请求:`![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_07_02.jpg)

## 工作原理...

当我们的应用程序用户轻触我们创建的交互式`Sprite`时，他们会离开我们的应用程序，进入默认的安卓网络浏览器，因为我们提供的 URL 通过网络加载，显示请求的网页。这是通过`navigateToURL`方法传递一个`URLRequest`实现的，这与我们在桌面应用程序中实现相同功能的方式非常相似。

## 还有更多...

虽然从我们的应用程序中调用 Android 网络浏览器可能非常有用，但能够将网页加载到应用程序中而不必在应用程序之间跳转则更有趣。当然，用户可以使用 Android 返回按钮从浏览器返回到我们的应用程序（如果它仍然打开），但还有方法可以确保更无缝的体验。接下来的几个食谱将描述如何实现这一点。

# 在应用程序中渲染网站

使用 Flash 内容，传统上不可能在应用程序中显示完全渲染的 HTML 网站。Adobe AIR 最初通过允许将网页加载到桌面应用程序中并仅通过桌面`HTMLLoader`类通过内部 AIR 构建的 web kit 渲染引擎来改变这一点。在 Android 上，AIR 允许我们通过使用`StageWebView`来做类似的事情。

## 如何操作...

我们将构建一个新的`StageWebView`实例，在移动 Android 应用程序中显示一个网页：

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.Event;
    import flash.events.TouchEvent;
    import flash.geom.Rectangle;
    import flash.media.StageWebView;
    import flash.net.URLRequest;
    import flash.net.navigateToURL;
    import flash.text.TextField;
    import flash.text.TextFormat;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;

    ```

1.  我们现在将声明一个`Sprite`作为我们的交互元素，以及一个`TextField`和`TextFormat`对作为按钮标签。此外，声明一个`StageWebView`实例以及一个`Rectangle`来定义我们的视口：

    ```kt
    private var fauxButton:Sprite;
    private var swv:StageWebView;
    private var swvRect:Rectangle;
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  现在，我们将继续设置我们的`TextField`，应用一个`TextFormat`对象，并使用图形 API 构建一个具有简单背景填充的`Sprite`。按钮构建的最后一步是将`TextField`添加到我们的`Sprite`中，然后将`Sprite`添加到`DisplayList`中。这里，我们创建一个方法来为我们执行所有这些操作，并进行一些风格上的增强：

    ```kt
    protected function setupTextButton():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 42;
    traceFormat.align = "center";
    traceFormat.color = 0x333333;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.autoSize = "none";
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.text = "Load Website";
    traceField.x = 30;
    traceField.y = 25;
    fauxButton = new Sprite();
    fauxButton.addChild(traceField);
    fauxButton.graphics.beginFill(0xFFFFFF, 1);
    fauxButton.graphics.drawRect(0, 0, traceField.width+60, traceField.height+50);
    fauxButton.graphics.endFill();
    fauxButton.x = (stage.stageWidth/2) - (fauxButton.width/2);
    fauxButton.y = 60;
    addChild(fauxButton);
    }

    ```

1.  创建一个方法来构建我们的`StageWebView`对象，通过定义一个新的`Rectangle`，设定我们希望`StageWebView`视口在应用程序中的位置和大小。在这个例子中，我们根据之前创建的`Sprite`的位置以及应用程序`Stage`的尺寸来确定我们的`Rectangle`的属性。

1.  在构造我们的 `StageWebView` 实例之前，通过调用 `StageWebView.isSupported` 来检查是否支持 `StageWebView` 是一个好习惯。实际上，要创建一个 `StageWebView` 对象，我们只需进行简单的实例化并将应用程序 `stage` 分配给 `StageWebView.stage`。现在，将先前构建的 `Rectangle` 分配给 `StageWebView viewport` 属性：

    ```kt
    protected function setupStageWebView():void {
    swvRect = new Rectangle(0,fauxButton.y+fauxButton. height+40,stage.stageWidth,stage. stageHeight-fauxButton.y+fauxButton.height+40);
    if(StageWebView.isSupported){
    swv = new StageWebView();
    swv.stage = this.stage;
    swv.viewPort = swvRect;
    }
    }

    ```

1.  如果我们现在在设备上运行应用程序，带有伴随 `StageWebView` 的交互式 `Sprite` 应如下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_07_03.jpg)

1.  我们现在将 `Multitouch.inputMode` 分配给通过 `MultitouchInputMode.TOUCH_POINT` 常量响应原始触摸事件。在 `Sprite` 按钮上注册一个类型为 `TouchEvent.TOUCH_TAP` 的事件监听器。这将检测用户发起的任何触摸点击事件，并调用名为 `onTouchTap` 的方法，该方法将实例化页面加载。我们还将为 `StageWebView` 对象注册一个类型为 `Event.COMPLETE` 的事件，以确定页面加载何时完成：

    ```kt
    protected function registerListeners():void {
    Multitouch.inputMode = MultitouchInputMode.TOUCH_POINT;
    fauxButton.addEventListener(TouchEvent.TOUCH_TAP, onTouchTap);
    swv.addEventListener(Event.COMPLETE, locationChanged);
    }

    ```

1.  当检测到触摸点击时，我们的 `onTouchTap` 方法将被触发，调用 `navigateToURL`；它将开始使用 `StageWebView.loadURL()` 加载网页，传入页面地址作为 `String` 参数：

    ```kt
    protected function onTouchTap(e:TouchEvent):void {
    swv.loadURL("http://memoryspiral.com/");
    }

    ```

1.  一旦页面加载完成，我们可以收集有关已加载内容的信息，例如页面 `title`。在这种情况下，我们将页面 `title` 分配给我们的 `TextField` 作为示例：

    ```kt
    protected function locationChanged(e:Event):void {
    traceField.text = e.target.title;
    }

    ```

1.  当网页完全加载后，生成的应用程序将如下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_07_04.jpg)

## 工作原理...

`StageWebView` 类将使用主机操作系统上的默认网页控件来渲染视口中显示的任何 HTML 内容。需要注意的是，`StageWebView` 并不是传统 Flash `DisplayList` 的一部分，不能像将视觉元素添加到 `DisplayList`（通过 `addChild()`）那样以常规方式添加到我们的应用程序中。

由于 `StageWebView` 不属于传统的 `DisplayList`，我们必须使用另一种方式来定义它在 `stage` 上的位置以及它将占用的空间。这是通过将 `Rectangle` 对象分配给 `StageWebView.viewPort` 属性来完成的。`StageWebView` 类还需要一个 `stage` 属性，将其分配给当前应用程序的 `stage`。只要这两个属性正确分配，视口就会出现在我们的应用程序中。

### 注意

由于 `StageWebView` 不是 `DisplayList` 的一部分，一旦我们使用完毕，应该始终对其调用 `dispose()` 方法，以便从应用程序中完全移除。

## 还有更多...

如前一部分所述，当调用`StageWebView`时，AIR for Android 将使用原生的 WebKit 渲染引擎。WebKit 被众多流行的网络浏览器使用，包括 Android 浏览器、Apple Safari 和 Google Chrome。值得注意的是：WebKit 实际上是 Adobe AIR 桌面运行时的一部分。关于 WebKit 的更多信息，请访问[`www.webkit.org/`](http://www.webkit.org/)。

# 管理 StageWebView 历史

在为 Android 开发应用程序时，AIR 允许我们通过使用 StageWebView 类来渲染完整的网站。我们还可以利用`StageWebView`实例的导航历史，并在应用程序中以不同的方式应用它。

## 如何操作...

一旦用户在我们的`StageWebView`实例中加载了一些页面，我们就可以通过导航历史前后导航：

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.Event;
    import flash.events.LocationChangeEvent;
    import flash.events.TouchEvent;
    import flash.geom.Rectangle;
    import flash.media.StageWebView;
    import flash.net.URLRequest;
    import flash.net.navigateToURL;
    import flash.text.TextField;
    import flash.text.TextFormat;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;

    ```

1.  我们现在将声明两个`Sprite`对象作为我们的交互元素，以及一个`TextField`和`TextFormat`对作为地址指示器。此外，声明一个`StageWebView`实例以及一个`Rectangle`来定义我们的视口：

    ```kt
    private var prevButton:Sprite;
    private var nextButton:Sprite;
    private var swv:StageWebView;
    private var swvRect:Rectangle;
    private var addressField:TextField;
    private var addressFormat:TextFormat;

    ```

1.  现在，我们将创建两个方法，用来构建我们的前进和后退历史控制，并将它们添加到`stage`上。为每个方法实例化一个新的`Sprite`，并添加一个唯一的`name`属性，指定交互的预期功能。我们稍后可以通过`touch tap`事件读取它，以确定哪个`Sprite`被点击。使用图形 API 绘制基本背景，并在将每个`Sprite`添加到`DisplayList`之前在`stage`上进行定位：

    ```kt
    protected function setupPrevButton():void {
    prevButton = new Sprite();
    prevButton.name = "prev";
    prevButton.graphics.beginFill(0xFFFFFF, 1);
    prevButton.graphics.drawRect(0, 0, 50, 50);
    prevButton.graphics.endFill();
    prevButton.x = 0;
    prevButton.y = 0;
    addChild(prevButton);
    }
    protected function setupNextButton():void {
    nextButton = new Sprite();
    nextButton.name = "next";
    nextButton.graphics.beginFill(0xFFFFFF, 1);
    nextButton.graphics.drawRect(0, 0, 50, 50);
    nextButton.graphics.endFill();
    nextButton.x = stage.stageWidth - 50;
    nextButton.y = 0;
    addChild(nextButton);
    }

    ```

1.  为了完成我们的地址指示器，我们继续设置我们的`TextField`并应用一个`TextFormat`对象。在这个例子中，我们将`TextField`在`stage`上居中（位于两个交互式`Sprites`之间）以模拟网络浏览器的地址栏。创建一个方法来执行所有这些操作以及一些样式增强，并将默认的**加载中**字符串分配给`TextField`，以让用户知道正在发生的事情。

    ```kt
    protected function setupAddressBar():void {
    addressFormat = new TextFormat();
    addressFormat.bold = true;
    addressFormat.font = "_sans";
    addressFormat.size = 26;
    addressFormat.align = "center";
    addressFormat.color = 0xFFFFFF;
    addressField = new TextField();
    addressField.defaultTextFormat = addressFormat;
    addressField.autoSize = "left";
    addressField.selectable = false;
    addressField.mouseEnabled = false;
    addressField.text = "Loading...";
    addressField.x = 60;
    addressField.y = 8;
    addChild(addressField);
    }

    ```

1.  创建一个方法来构建我们的`StageWebView`对象，通过定义一个新的`Rectangle`，设定我们希望`StageWebView`在应用程序中显示的位置和大小。在这个例子中，我们根据之前创建的`Sprite`和`TextField`对象的位置以及应用程序`Stage`的尺寸来确定我们`Rectangle`的属性。

1.  在构建我们的`StageWebView`实例之前，通过调用`StageWebView.is supported`来检查是否支持`StageWebView`是一个好习惯。实际上，要创建一个`StageWebView`对象，我们只需进行简单的实例化并将应用程序`stage`分配给`StageWebView.stage`。现在，将之前构建的`Rectangle`分配给`StageWebView`的`viewport`属性：

    ```kt
    protected function setupStageWebView():void {
    swvRect = new Rectangle(0,addressField.y+addressField.
    height+40,stage.stageWidth ,stage.stageHeight-addressField. y+addressField.height+40);
    if(StageWebView.isSupported){
    swv = new StageWebView();
    swv.stage = this.stage;
    swv.viewPort = swvRect;
    }
    }

    ```

1.  我们现在将`Multitouch.inputMode`设置为通过`MultitouchInputMode.TOUCH_POINT`常量响应原始触摸事件。在两个`Sprite`按钮上注册一个类型为`TouchEvent.TOUCH_TAP`的事件监听器。这将检测用户发起的任何触摸点击事件，并调用一个名为`onTouchTap`的方法，该方法将根据点击的`Sprite`决定是在导航历史中后退还是前进。我们还会在`StageWebView`对象上注册一个类型为`LocationChangeEvent.LOCATION_CHANGE`的事件，以确定页面加载何时完成。最后，我们可以调用`StageWebView.loadURL`，传入一个网页地址作为唯一参数。这将开始加载我们的默认位置：

    ```kt
    protected function registerListeners():void {
    Multitouch.inputMode = MultitouchInputMode.TOUCH_POINT;
    prevButton.addEventListener(TouchEvent.TOUCH_TAP, onTouchTap);
    nextButton.addEventListener(TouchEvent.TOUCH_TAP, onTouchTap);
    swv.addEventListener(LocationChangeEvent.LOCATION_CHANGE, locationChanged);
    swv.loadURL("http://memoryspiral.com/");
    }

    ```

1.  如果我们现在运行这个应用，我们会看到所有的交互元素都出现在舞台上，并且我们想要的网页会在`StageWebView`实例中渲染出来：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_07_05.jpg)

1.  当检测到`Sprite`交互时，我们通过检查实例化后直接提供的`name`属性来确定被点击的特定`Sprite`。这样，我们就知道是否应该使用`historyBack()`或`historyForward()`方法尝试通过历史记录向前或向后移动。为了检测我们是否真的可以这样做，我们可以首先检查设备上是否启用了后退或前进历史，如下面的代码片段所示：

    ```kt
    protected function onTouchTap(e:TouchEvent):void {
    switch(e.target.name){
    case "prev":
    if(swv.isHistoryBackEnabled){
    swv.historyBack();
    }
    break;
    case "next":
    if(swv.isHistoryForwardEnabled){
    swv.historyForward();
    }
    break;
    }
    }

    ```

1.  当我们`StageWebView`实例正在渲染的当前位置发生变化时，我们会像标准网络浏览器的地址栏一样，用当前的 URL 更新我们的`TextField`：

    ```kt
    protected function locationChanged(e:LocationChangeEvent):void {
    addressField.text = e.location;
    }

    ```

1.  用户现在可以通过点击各种超链接，在`StageWebView`的历史记录中前后导航，如下面的截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_07_06.jpg)

## 工作原理...

`StageWebView`类将使用主机操作系统上的默认网络控件来渲染视口中显示的任何 HTML。需要注意的是，`StageWebView`不是传统 Flash `DisplayList`的一部分，不能像将视觉元素添加到`DisplayList`（通过`addChild()`）那样以常规方式添加到我们的应用程序中。

要管理`StageWebView`的历史记录，我们可以使用`historyBack()`或`historyForward()`方法，在应用内沿着用户的历史记录进行导航。

### 注意

除非用户开始点击超链接并在`StageWebView`实例中实际进行导航，否则这两种方法不会执行任何操作。我们基本上是创建了一个小型的网络浏览器。

# 使用 StageWebView 通过 ActionScript 加载广告

使用 Flash 平台进行移动 Android 开发时，最受追捧的功能之一是在应用中包含来自如 Google AdSense 或 AdMob 等服务的广告。这使得开发者可以免费向用户分发应用程序，但仍然可以从应用内显示的广告中获得收入。

## 如何操作...

`StageWebView` 为移动应用开发开辟了众多可能性，其中之一就是能够在运行中的应用程序中加载基于 HTML 的广告。在以下示例中，我们将看看如何轻松管理这一点：

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.TimerEvent;
    import flash.geom.Rectangle;
    import flash.media.StageWebView;
    import flash.utils.Timer;

    ```

1.  我们现在将声明一个 `StageWebView` 实例以及一个 `Rectangle` 来定义我们的视口。最后，设置一个 `Timer`，作为刷新我们广告的机制。

    ```kt
    private var swv:StageWebView;
    private var swvRect:Rectangle;
    private var adTimer:Timer;

    ```

1.  创建一个方法来构建我们的 `StageWebView` 对象，通过定义一个新的 `Rectangle` 来确定 `StageWebView` 在应用中的位置和大小。在构建 `StageWebView` 实例之前，最好先调用 `StageWebView.isSupported` 来检查是否支持 `StageWebView`。

1.  实际上，要创建一个 `StageWebView` 对象，我们只需进行简单的实例化并将应用程序的 `stage` 赋值给 `StageWebView.stage`。现在，将之前构建的 `Rectangle` 赋值给 `StageWebView` 的 `viewport` 属性，或者使用 `loadURL()` 加载一个网页，传入页面地址作为 `String`：

    ```kt
    protected function setupStageWebView():void {
    swvRect = new Rectangle(0, 0, stage.StageWidth, 70);
    if(StageWebView.isSupported){
    swv = new StageWebView();
    swv.stage = this.stage;
    swv.viewPort = swvRect;
    swv.loadURL("http://memoryspiral.com/admob.html");
    }
    }

    ```

1.  如果我们还没有这样做，为了使其正确运行，我们必须在服务器上设置一个网页，以便与我们选择的广告服务进行接口交互。在这个例子中，我们使用 AdMob ([`www.admob.com/`](http://www.admob.com/))，因为广告针对的是移动网络和移动设备应用。

1.  这里有一个重要的事情，就是确保通过 CSS 将 `bodymargin` 和 `padding` 设置为 `0`，以避免广告周围出现任何空间。`StageWebView` 本质上只是运行 HTML，因此如果我们不稍作修改，默认的 HTML 渲染引擎（在 Android 中，这是 web Kit）将简单地通过其默认设置解释所有风格元素。

1.  你需要将 `pubid` 属性替换成你自己的，或者注册一个不同的广告服务。使用这个代码片段作为参考，创建你自己的 HTML 文件，并将其存储在服务器上，然后通过你的特定应用程序调用，正如这个例子中所做的那样：

    ```kt
    <html>
    <head>
    <style type="text/css">
    body {
    background-color: #333;
    margin: 0px;
    padding: 0px;
    }
    </style>
    </head>
    <body>
    <script type="text/javascript">
    var admob_vars = {pubid: 'xxxxxxxxxxx',bgcolor: '000000',text: 'FFFFFF',ama: false,test: true};
    </script>
    <script type="text/javascript" src="img/iadmob.js"></script>
    </body>
    </html>

    ```

1.  下一步是设置我们的 `Timer`，以每 10 秒更换一次广告。我们通过实例化一个新的 `Timer` 对象并传递 10000 毫秒（或者你选择的时间量）来实现这一点。现在，注册一个类型为 `TimerEvent.Timer` 的事件监听器，以便每次 `Timer` 达到 10 秒时触发我们构建的方法。要启动 `Timer`，我们调用 `Timer.start()`：

    ```kt
    protected function setupTimer():void {
    adTimer = new Timer(10000);
    adTimer.addEventListener(TimerEvent.TIMER, onTimer);
    adTimer.start();
    }

    ```

1.  剩下的就是创建我们的`onTimer`方法，以便每次`Timer`达到 10 秒时重新加载`StageWebView`实例。这将再次调用网络，下拉 HTML，从而重新调用广告服务脚本。

    ```kt
    protected function onTimer(e:TimerEvent):void {
    swv.reload();
    }

    ```

1.  每次我们的`Timer`触发时，页面都会刷新，揭示我们应用程序中的新广告：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_07_07.jpg)

## 工作原理...

`StageWebView`类将使用主机操作系统上的默认 Web 控件来渲染视口中显示的任何 HTML。需要注意的是，`StageWebView`不是传统 Flash `DisplayList`的一部分，不能像将视觉元素添加到`DisplayList`（通过`addChild()`）那样以常规方式添加到我们的应用程序中。

为了在应用程序中实际渲染广告，我们可以首先使用`loadURL()`加载一个网页，传入页面地址作为`String`。该地址应指向与我们所选择的广告服务接口的 HTML 文档，我们之前已经注册过。通常，这些服务会提供一个 JavaScript 代码块，让你放入你的 HTML 中，它会在页面加载时调用广告。要刷新我们的视口并加载新的广告，我们可以简单地调用`StageWebView.reload()`。在我们的示例中，我们使用`Timer`每 10 秒执行此操作。

## 更多内容...

尽管我们决定在本例中使用 AdMob，但开发者通常可以包括他们喜欢的任何广告系统。在以下屏幕截图中，我以完全相同的方式从 Google AdSense 获取广告。但您会注意到，使用正常版本的 AdSense（不使用移动内容单元）时，广告不会以智能方式适应屏幕。AdMob 专为移动设备设计，因此在这些情况下效果更好。将来，除了这里提到的两个广告提供商之外，应该还有许多新的机会。我们还必须记住，这些都是第三方服务，可能会随时更改。

![更多内容...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_07_08.jpg)

# 在 Flex 移动项目中使用 StageWebView 加载广告

由于`StageWebView`实例不是`DisplayList`的一部分，在`ViewNavigatorApplication`中使用它可能会出现感知上的问题。主要问题是`StageWebView`总是位于所有其他对象的顶层，并且无法与特定视图中的其他项目一起过渡。在本教程中，我们将研究这个问题，并展示一些应对`StageWebView`对象不规则行为的技术。

## 准备工作...

在本例中，我们将使用 Google AdSense 的**移动内容 | 广告单元**。您需要访问[`www.google.com/adsense/`](http://https://www.google.com/adsense/)注册 AdSense 账户，并配置一个**移动内容广告单元**：

![准备工作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_07_09.jpg)

如果你已经有了 AdMob 账户（或其他服务），你可以选择使用它，或者甚至为本演示创建一个简单的广告。

## 如何操作...

我们将创建一个新的`ViewNavigatorApplication`，其中包含两个不同的视图，演示`StageWebView`如何存在于这个结构之外，如何从视图中移除`StageWebView`，并提供对额外广告服务系统的引用。

在这个例子中，将涉及多个文件；我们将通过不同的部分来组装它们，以便更清晰。

### 创建 HTML 文件以展示我们的广告

如果我们还没有这样做，为了使其正确工作，我们必须在服务器上设置一个网页以与 Google AdSense 进行接口。你可能希望将以下示例中的`client`属性替换为你自己的。使用这段代码作为参考，在服务器上创建你自己的 HTML 文件，并通过你的特定应用程序调用：

```kt
<html>
<head>
<style type="text/css">
body {
background-color: #333;
margin: 0px;
padding: 0px;
}
</style>
</head>
<body>
<script type="text/javascript"><!--
// XHTML should not attempt to parse these strings, declare them CDATA.
/* <![
CDATA[ */
window.googleAfmcRequest = {
client: 'your-id-goes-here',
format: '320x50_mb',
output: 'html',
slotname: '5725525764',
};
/* ]]> */
//--></script>
<script type="text/javascript" src="img/show_afmc_ads.js"></script>
</body>
</html>

```

### 为我们的 ViewNavigatorApplication 创建 MXML 文件

1.  首先，我们创建主应用程序文件，其根节点为`ViewNavigatorApplication`，以便利用它提供的基于视图的布局。如有需要，我们可以设置`applicationDPI`，并使用`firstView`属性引用初始`View`。我们将在本例稍后定义这个`View`。在继续之前，让我们注册一个名为`init()`的方法，以便在应用程序完成后执行：

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <s:ViewNavigatorApplication 
     applicationDPI="160"
    firstView="views.FlexAdsHomeView" applicationComplete="init()">
    </s:ViewNavigatorApplication>

    ```

1.  创建一个脚本块以保存我们应用程序的所有 ActionScript 代码。进行此操作的代码将在另一个步骤中定义，以便更清晰。

    ```kt
    <fx:Script>
    <![
    CDATA[
    ]]>
    </fx:Script>

    ```

1.  现在，我们将在`ActionBar`中添加一些功能，具体来说是在`navigationContent`节点中添加两个`Button`控件。这两个`Button`控件将调用`ViewNavigator.pushView()`方法。这个方法接受一个`View`引用作为参数，当调用时，会将该`View`置于我们的视图栈顶部：

    ```kt
    <s:navigationContent>
    <s:Button label="V1" click="navigator.pushView(views.FlexAdsHomeView)"/>
    <s:Button label="V2" click="navigator.pushView(views.FlexAdsOtherView);"/>
    </s:navigationContent>

    ```

1.  现在，我们将为本例组装两个视图。在每个`View`中放置一个`Button`控件以及一个`click`事件处理程序，该处理程序将调用主应用程序文件中的方法以切换广告的显示和隐藏：

    FlexAdsHomeView.mxml

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <s:View 

    title="Primary View" >
    <s:Button y="120" label="Toggle Ads" horizontalCenter="0" click="this.parentApplication.toggleAds()"/>
    </s:View>

    ```

    FlexAdsOtherView.mxml

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <s:View 

    title="Secondary View">
    <s:Button y="120" label="Toggle Ads" horizontalCenter="0" click="this.parentApplication.toggleAds()"/>
    </s:View>

    ```

#### 生成 ActionScript 代码以连接所有内容

这段代码将存在于我们之前定义的主应用程序文件的`script`块中：

1.  首先，将以下类导入到项目中：

    ```kt
    import flash.events.TimerEvent;
    import flash.geom.Rectangle;
    import flash.media.StageWebView;
    import flash.utils.Timer;

    ```

1.  我们现在将声明一个`StageWebView`实例以及一个`Rectangle`以定义我们的视口。最后，设置一个`Timer`，它将作为刷新我们广告的机制：

    ```kt
    private var swv:StageWebView;
    private var swvRect:Rectangle;
    private var adTimer:Timer;

    ```

1.  设置前面提到的初始化函数，它将简单地调用我们将要构建的方法来设置`StageWebView`实例和我们的广告刷新`Timer`：

    ```kt
    protected function init():void {
    setupStageWebView();
    setupTimer();
    }

    ```

1.  创建一个方法来构建我们的`StageWebView`对象，通过定义一个新的`Rectangle`，设置我们希望`StageWebView`在应用程序中显示的位置和大小。在构建`StageWebView`实例之前，最好通过调用`StageWebView.isSupported`来检查是否支持`StageWebView`。

1.  实际上要创建一个`StageWebView`对象，我们只需简单地实例化并将其分配给应用程序的`stage`到`StageWebView.stage`。现在，将之前构建的`Rectangle`赋值给`StageWebView`的`viewport`属性，然后使用`loadURL()`加载一个网页，传入页面地址作为`String`：

    ```kt
    protected function setupStageWebView():void {
    swvRect = new Rectangle(0, 68, stage.stageWidth, 76);
    if(StageWebView.isSupported){
    swv = new StageWebView();
    swv.stage = this.stage;
    swv.viewPort = swvRect;
    swv.loadURL("http://memoryspiral.com/adsense.html");
    }
    }

    ```

1.  要从各个视图中切换广告的显示与隐藏，我们只需检查`StageWebView.viewPort`是否为`null`，根据这个结果，要么将其设置为一个`Rectangle`对象，要么赋值为`null`。如果`viewPort`为`null`，广告将不再对用户可见：

    ```kt
    public function toggleAds():void {
    if(swv.viewPort != null){
    swv.viewPort = null;
    }else{
    swv.viewPort = swvRect;
    }
    }

    ```

1.  下一步是设置我们的`Timer`，以每 8 秒更换一次广告。我们通过实例化一个新的`Timer`对象，传入 8000 毫秒（或您选择的时间量）来实现这一点。现在，注册一个类型为`TimerEvent.Timer`的事件监听器，以便每次`Timer`达到 8 秒时触发我们构建的方法。要启动`Timer`，我们调用`Timer.start()`：

    ```kt
    protected function setupTimer():void {
    adTimer = new Timer(8000);
    adTimer.addEventListener(TimerEvent.TIMER, onTimer);
    adTimer.start();
    }

    ```

1.  剩下的就是创建我们的`onTimer`方法，以便每次`Timer`达到 10 秒时重新加载`StageWebView`实例。这将再次调用网络，拉取 HTML，从而重新调用广告服务脚本：

    ```kt
    protected function onTimer(e:TimerEvent):void {
    swv.reload();
    }

    ```

1.  当运行应用程序时，广告将立即在`StageWebView`实例中显示，并且我们的初始`View`将呈现给用户。此时，用户可以与`ActionBar`交互，并在每个`View`之间切换。即使`View`内容随着应用程序`ViewNavigator`的切换而变化，`StageWebView`实例仍将保持原位。在任何时候，用户都可以通过任一`View`中的`Button`实例切换广告的显示与隐藏：![生成将所有内容联系在一起的 ActionScript 代码](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_07_10.jpg)

### 工作原理...

在`ViewNavigatorApplication`中使用`StageWebView`一开始可能会觉得有些麻烦，如果我们记住这个特定对象的限制，并以一种经过深思熟虑的方式管理`StageWebView`，那么创建一个可行的实现并不那么困难。

### 还有更多内容...

如果我们想完全从应用程序中移除一个`StageWebView`对象，我们可以调用`StageWebView.dispose()`，这将移除`StageWebView`对象，使其能被垃圾收集器处理。即使我们以这种方式移除`StageWebView`实例，如果需要，我们仍然可以创建一个新的实例。

# 从应用程序中拨打电话

由于 Android 操作系统具有众多出色的功能和强大的实力，很容易让人忘记这些设备首先是电话。在本教程中，我们将展示如何从应用内部调用本地 Android 电话工具，并传递一个要拨打的电话号码。

## 如何操作...

应用程序调用`navigateToURL`并传入带有正确`tel:` URI 的新`URLRequest`，将打开默认的电话应用，并加载指定的电话号码，准备拨号。在这个例子中，我们将在检测到`TOUCH_TAP`事件时执行此操作：

1.  首先，将以下类导入到您的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.TouchEvent;
    import flash.text.TextField;
    import flash.text.TextFormat;
    import flash.net.navigateToURL;
    import flash.net.URLRequest;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;

    ```

1.  我们现在将声明一个`Sprite`作为我们的交互元素，以及一个`TextField`和`TextFormat`对，作为按钮标签：

    ```kt
    private var fauxButton:Sprite;
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  现在，我们继续设置我们的`TextField`，应用一个`TextFormat`对象，并使用图形 API 构建一个具有简单背景填充的`Sprite`。我们按钮构建的最后一步是将`TextField`添加到我们的`Sprite`中，然后将`Sprite`添加到`DisplayList`中。这里，我们创建一个方法来为我们执行所有这些操作，并进行一些风格上的增强：

    ```kt
    protected function setupTextButton():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 42;
    traceFormat.align = "center";
    traceFormat.color = 0x333333;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.autoSize = "left";
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.text = "Invoke Phone";
    traceField.x = 30;
    traceField.y = 25;
    fauxButton = new Sprite();
    fauxButton.addChild(traceField);
    fauxButton.graphics.beginFill(0xFFFFFF, 1);
    fauxButton.graphics.drawRect(0, 0, traceField.width+60, traceField.height+50);
    fauxButton.graphics.endFill();
    fauxButton.x = (stage.stageWidth/2) - (fauxButton.width/2);
    fauxButton.y = 60;
    addChild(fauxButton);
    }

    ```

1.  如果我们现在在设备上运行应用，交互式`Sprite`应该会如以下截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_07_01.jpg)

1.  我们现在将`Multitouch.inputMode`设置为通过`MultitouchInputMode.TOUCH_POINT`常量响应原始触摸事件。在`Sprite`按钮上注册一个类型为`TouchEvent.TOUCH_TAP`的事件监听器。这将检测用户发起的任何触摸点击事件，并调用一个名为`onTouchTap`的方法，其中包含我们剩余的逻辑：

    ```kt
    protected function registerListeners():void {
    Multitouch.inputMode = MultitouchInputMode.TOUCH_POINT;
    fauxButton.addEventListener(TouchEvent.TOUCH_TAP, onTouchTap);
    }

    ```

1.  当检测到一次触摸点击时，我们的`onTouchTap`方法将被触发，调用`navigateToURL`并传入一个包含`tel:` URI 前缀以及我们应用中想要拨打的电话号码的`URLRequest`：

    ```kt
    protected function onTouchTap(e:TouchEvent):void {
    navigateToURL(new URLRequest("tel:15555554385"));
    }

    ```

1.  当我们在设备上运行应用时，只需在按钮上简单触摸点击，就会调用本地电话应用，并显示我们指定的电话号码：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_07_12.jpg)

## 工作原理...

当我们的应用用户触摸点击我们创建的交互式`Sprite`时，他们会从我们的应用中跳转出来，进入默认的 Android 电话工具。这次调用还会提供一个电话号码，这是通过`navigateToURL`方法传递带有`tel:` URI 前缀的`URLRequest`来指定此通话的。

# 从应用中发送短信

在 Android 上使用 Flash，我们有能力通过`flash.net`包中的类根据用户交互调用原生的 Android 短信工具。不幸的是，我们无法为短信提供任何内容。在 Android 上，由于所有应用程序都占用一个完整的窗口，因此我们必须特别留意这可能会在用户与我们的应用程序交互时造成任何干扰。

## 如何操作...

应用程序调用`navigateToURL`并传入带有正确`sms:` URI 前缀的新`URLRequest`将打开默认的短信工具，并加载指定的电话号码，准备好发短信。在这个例子中，我们将在检测到`TOUCH_TAP`事件时执行此操作：

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.TouchEvent;
    import flash.text.TextField;
    import flash.text.TextFormat;
    import flash.net.navigateToURL;
    import flash.net.URLRequest;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;

    ```

1.  我们现在将声明一个`Sprite`作为我们的交互元素，以及一个`TextField`和`TextFormat`对作为按钮标签：

    ```kt
    private var fauxButton:Sprite;
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  现在，我们将继续设置我们的`TextField`，应用一个`TextFormat`对象，并使用图形 API 构建一个带有简单背景填充的`Sprite`。我们按钮构建的最后一步是将`TextField`添加到我们的`Sprite`中，然后将`Sprite`添加到`DisplayList`中。在这里，我们创建了一个方法来执行所有这些操作，并进行一些风格上的增强：

    ```kt
    protected function setupTextButton():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 42;
    traceFormat.align = "center";
    traceFormat.color = 0x333333;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.autoSize = "left";
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.text = "Invoke SMS";
    traceField.x = 30;
    traceField.y = 25;
    fauxButton = new Sprite();
    fauxButton.addChild(traceField);
    fauxButton.graphics.beginFill(0xFFFFFF, 1);
    fauxButton.graphics.drawRect(0, 0, traceField.width+60, traceField.height+50);
    fauxButton.graphics.endFill();
    fauxButton.x = (stage.stageWidth/2) - (fauxButton.width/2);
    fauxButton.y = 60;
    addChild(fauxButton);
    }

    ```

1.  如果我们现在在设备上运行应用程序，交互式`Sprite`应该如下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_07_13.jpg)

1.  我们现在将`Multitouch.inputMode`设置为通过常量`MultitouchInputMode.TOUCH_POINT`响应原始触摸事件。在`Sprite`按钮上注册一个类型为`TouchEvent.TOUCH_TAP`的事件监听器。这将检测用户发起的任何触摸点击事件，并调用名为`onTouchTap`的方法，其中包含我们的其余逻辑：

    ```kt
    protected function registerListeners():void {
    Multitouch.inputMode = MultitouchInputMode.TOUCH_POINT;
    fauxButton.addEventListener(TouchEvent.TOUCH_TAP, onTouchTap);
    }

    ```

1.  一旦检测到触摸点击，我们的`onTouchTap`方法将被触发，调用`navigateToURL`，并传入一个包含`tel:` URI 前缀以及我们想要从应用程序中拨打的电话号码的`URLRequest`：

    ```kt
    protected function onTouchTap(e:TouchEvent):void {
    navigateToURL(new URLRequest("sms:15555554385"));
    }

    ```

1.  在此阶段，我们将失去应用程序焦点，并显示 Android 短信工具，预先填充了我们想要的电话号码，并准备好撰写短信：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_07_14.jpg)

1.  最后，当我们点击**发送**，我们的短信将通过使用的电话号码发送给指定的收件人。在这个例子中，当然这不是一个真实的电话号码：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_07_15.jpg)

## 工作原理...

当我们的应用程序用户触摸点击我们创建的交互式`Sprite`时，他们会从我们的应用程序中退出，进入默认的 Android 短信工具。这次调用还提供了一个电话号码，这是通过`navigateToURL`方法传递带有`sms:` URI 前缀的`URLRequest`分配给这条短信的。这样，我们就可以轻松地让应用程序用户访问电话号码发短信，而无需他们输入数字序列。

# 从应用程序中调用谷歌地图

由于大多数安卓设备都是移动设备，开发者和用户都期望能够使用某种类型的地图。安卓操作系统由谷歌管理，该公司在网页上拥有悠久的优秀地图技术历史。这对于开发者来说非常棒，因为我们可以在安卓上的非常酷的地图应用程序上搭便车，并从我们的应用程序中传入各种坐标。

## 如何操作...

让应用程序检测设备的地理坐标，调用`navigateToURL`，并传入一个格式正确的 URL 的`URLRequest`以访问安卓地图应用程序：

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.TouchEvent;
    import flash.events.GeolocationEvent;
    import flash.text.TextField;
    import flash.text.TextFormat;
    import flash.net.navigateToURL;
    import flash.net.URLRequest;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;
    import flash.sensors.Geolocation;

    ```

1.  我们现在将声明一个`Sprite`作为我们的交互元素，以及一个`TextField`和`TextFormat`对作为按钮标签。我们将使用`Geolocation` API，因此为此目的声明一个对象，以及用于保存纬度和经度数据值的`Number`变量：

    ```kt
    private var fauxButton:Sprite;
    private var traceField:TextField;
    private var traceFormat:TextFormat;
    private var geo:Geolocation;
    private var longitude:Number;
    private var latitude:Number;

    ```

1.  现在，我们继续设置我们的`TextField`，应用一个`TextFormat`对象，并使用图形 API 构建一个带有简单背景填充的`Sprite`。构建按钮的最后一步是将`TextField`添加到我们的`Sprite`中，然后将`Sprite`添加到`DisplayList`中。在这里，我们创建一个方法来执行所有这些操作，并进行一些风格上的增强：

    ```kt
    protected function setupTextButton():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 42;
    traceFormat.align = "center";
    traceFormat.color = 0x333333;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.autoSize = "left";
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.text = "Invoke Maps";
    traceField.x = 30;
    traceField.y = 25;
    fauxButton = new Sprite();
    fauxButton.addChild(traceField);
    fauxButton.graphics.beginFill(0xFFFFFF, 1);
    fauxButton.graphics.drawRect(0, 0, traceField.width+60, traceField.height+50);
    applicationGoogle maps, invokingfauxButton.graphics.endFill();
    fauxButton.x = (stage.stageWidth/2) - (fauxButton.width/2);
    fauxButton.y = 60;
    addChild(fauxButton);
    }

    ```

1.  如果我们现在在设备上运行应用程序，交互式`Sprite`应该会如以下截图所示显示：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_07_16.jpg)

1.  我们现在将`Multitouch.inputMode`设置为通过`MultitouchInputMode.TOUCH_POINT`常量响应原始触摸事件。在`Sprite`按钮上注册一个类型为`TouchEvent.TOUCH_TAP`的事件监听器。这将检测用户发起的任何触摸点击事件，并调用一个名为`onTouchTap`的方法，其中包含我们剩余的逻辑：

    ```kt
    protected function registerListeners():void {
    Multitouch.inputMode = MultitouchInputMode.TOUCH_POINT;
    fauxButton.addEventListener(TouchEvent.TOUCH_TAP, onTouchTap);
    }

    ```

1.  在检测到触摸点击事件时，我们将设置一个`Geolocation`对象，并为它分配一个事件监听器，专门监听`GeolocationEvent.UPDATE`事件。我们将不再需要监听`TouchEvent.TOUCH_TAP`事件，因此可以移除它以允许垃圾回收：

    ```kt
    protected function onTouchTap(e:TouchEvent):void {
    fauxButton.removeEventListener(TouchEvent.TOUCH_TAP, onTouchTap);
    geo = newGeolocation();
    geo.addEventListener(GeolocationEvent.UPDATE, onGeoEvent);
    }

    ```

1.  一旦收集到`Geolocation`数据并将其报告回我们的应用程序，`onGeoEvent`方法将会触发，为我们提供需要传入到原生安卓地图应用程序的`longitude`和`latitude`数据。

1.  为了完成我们的流程，我们将调用`navigateToURL`，并传入一个包含`http://maps.google.com/` URL 的`URLRequest`，后面跟着一个查询字符串，其中包含来自我们的`Geolocation`更新事件数据的`latitude`和`longitude`值。既然我们现在有了所需的所有数据，可以移除`GeolocationEvent.UPDATE`事件监听器：

    ```kt
    protected function onGeoEvent(e:GeolocationEvent):void {
    geo.removeEventListener(GeolocationEvent.UPDATE, onGeoEvent);
    longitude = e.longitude;
    latitude = e.latitude;
    navigateToURL(new URLRequest("http://maps.google.com/?q="+ String(latitude)+", "+String(longitude)));
    }

    ```

1.  由于此示例中使用的 URI 前缀仅为 `http://`，因此一个模型对话框将出现在我们的应用程序上方，询问我们是否希望使用 **浏览器** 或 **地图** 应用程序打开 `URLRequest`。我们将选择 **地图**。勾选 **默认使用此操作** 复选框将防止将来出现此对话框：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_07_17.jpg)

1.  最后，**地图** 应用程序将出现，并根据我们应用程序能够检测到的纬度和经度 Geolocation 坐标向用户展示视图：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_07_18.jpg)

## 工作原理...

当我们应用程序的用户触摸点击我们创建的交互式 `Sprite` 时，我们会配置一个 `Geolocation` 对象来监听位置数据。一旦获取到这些数据，我们就可以通过 `navigateToURL` 方法传递带有 `http://` URI 前缀的 `URLRequest` 来召唤 `maps.google.com`。我们还添加了一个由收集的 `Geolocation` 纬度和经度数据形成的查询字符串，告诉 **地图** 应用程序在我们的地图上导航的确切坐标。

## 还有更多...

一种替代从设备传感器检测 `Geolocation` 数据的方法是在应用程序中存储各种坐标，然后向用户提供多个选择。这对于一个专门的餐厅应用程序很有用，例如，允许用户轻松在地图上查看位置。

# 使用应用程序 URI 调用 Android Market

Android Market 是 Android 平台独有的，有一个专门的应用程序，允许用户轻松搜索、查找并安装设备上的应用程序。Android 允许开发者通过传递特定的搜索词来利用 Market 应用程序。

## 如何操作...

我们将构建一个小应用程序来调用 `navigateToURL` 函数，并通过带有 `market:` URI 前缀的 `URLRequest` 对象传递一个预定义的搜索词。这将打开 Android Market 应用程序，并让它为我们执行搜索。在这个例子中，一旦检测到 `TOUCH_TAP` 事件，我们将打开一个新的请求：

1.  首先，将以下类导入到您的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.TouchEvent;
    import flash.text.TextField;
    import flash.text.TextFormat;
    import flash.net.navigateToURL;
    import flash.net.URLRequest;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;

    ```

1.  我们现在将声明一个 `Sprite` 作为我们的交互元素，以及一个 `TextField` 和 `TextFormat` 对，作为按钮标签：

    ```kt
    private var fauxButton:Sprite;
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  现在，我们继续设置我们的 `TextField`，应用一个 `TextFormat` 对象，并使用图形 API 构造一个具有简单背景填充的 `Sprite`。按钮构建的最后一步是将 `TextField` 添加到我们的 `Sprite` 中，然后将 `Sprite` 添加到 `DisplayList` 中。这里，我们创建了一个方法来执行所有这些操作，并进行一些样式增强：

    ```kt
    protected function setupTextButton():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 42;
    traceFormat.align = "center";
    traceFormat.color = 0x333333;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.autoSize = "left";
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.text = "Invoke Market";
    traceField.x = 30;
    traceField.y = 25;
    fauxButton = new Sprite();
    fauxButton.addChild(traceField);
    fauxButton.graphics.beginFill(0xFFFFFF, 1);
    fauxButton.graphics.drawRect(0, 0, traceField.width+60, traceField.height+50);
    fauxButton.graphics.endFill();
    fauxButton.x = (stage.stageWidth/2) - (fauxButton.width/2);
    fauxButton.y = 60;
    addChild(fauxButton);
    }

    ```

1.  如果我们现在在设备上运行应用程序，交互式 `Sprite` 应该如以下屏幕截图所示出现：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_07_19.jpg)

1.  现在，我们将`Multitouch.inputMode`设置为通过`MultitouchInputMode.TOUCH_POINT`常量响应原始触摸事件。在`Sprite`按钮上注册一个类型为`TouchEvent.TOUCH_TAP`的事件监听器。这将检测用户发起的任何触摸点击事件，并调用名为`onTouchTap`的方法，该方法包含我们的其余逻辑。

    ```kt
    protected function registerListeners():void {
    Multitouch.inputMode = MultitouchInputMode.TOUCH_POINT;
    fauxButton.addEventListener(TouchEvent.TOUCH_TAP, onTouchTap);
    }

    ```

1.  一旦检测到触摸点击，我们的`onTouchTap`方法将被触发，调用`navigateToURL`并传入带有`market:` URI 前缀的`URLRequest`，其中包含我们希望应用程序针对市场库存执行的搜索词：

    ```kt
    protected function onTouchTap(e:TouchEvent):void {
    navigateToURL(new URLRequest("market://search?q=Fractured Vision Media, LLC"));
    }

    ```

1.  当我们在设备上运行应用程序时，只需点击按钮，就会调用安卓市场应用程序，并针对我们传递的搜索词进行搜索：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_07_20.jpg)

## 工作原理...

当我们的应用程序用户触摸点击我们所创建的交互式`Sprite`时，他们会从我们的应用程序中被带到安卓市场应用程序中，在那里会立即针对我们请求中指定的搜索词进行搜索。安卓市场应用程序会向用户展示当前库存中找到的所有应用程序。例如，传入我们应用程序的确切标题，将允许用户在应用程序内手动检查更新。传入我们的公司或开发者名称，则会显示我们提供给用户浏览的所有应用程序。

如果需要更具体的信息，还可以执行其他搜索查询。

要搜索特定的应用程序，我们可以使用以下格式：

```kt
navigateToURL(new URLRequest("market://search?q=pname:air.com.fracturedvisionmedia.SketchNSave"));v

```

要搜索特定的发布者，我们使用以下格式（注意我们在查询字符串中使用反斜杠"\"字符来转义引号）：

```kt
navigateToURL(new URLRequest("market://search?q=pub:\"Fractured Vision Media, LLC\""));

```

# 从应用程序发送电子邮件

类似于桌面 Flash 和 AIR 应用程序，基于用户交互，可以通过`flash.net`包中的类调用默认的系统电子邮件客户端。在 Android 上，由于所有应用程序都占用整个窗口，我们必须特别留意这可能会在用户与我们的应用程序交互时造成干扰。

## 如何操作...

当应用程序调用`navigateToURL`并通过带有`mailto:` URI 前缀的新`URLRequest`传递电子邮件地址时，将打开默认的电子邮件工具。在这个例子中，一旦检测到`TOUCH_TAP`事件，我们就会打开一封新的电子邮件：

1.  首先，将以下类导入到您的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.TouchEvent;
    import flash.text.TextField;
    import flash.text.TextFormat;
    import flash.net.navigateToURL;
    import flash.net.URLRequest;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;

    ```

1.  我们现在将声明一个`Sprite`作为我们的交互元素，以及一个`TextField`和`TextFormat`对，作为按钮标签：

    ```kt
    private var fauxButton:Sprite;
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  现在，我们将继续设置我们的`TextField`，应用一个`TextFormat`对象，并使用图形 API 构建一个具有简单背景填充的`Sprite`。我们按钮构建的最后一步是将`TextField`添加到我们的`Sprite`中，然后将`Sprite`添加到`DisplayList`。在这里，我们创建了一个方法来执行所有这些操作，并进行一些风格上的增强：

    ```kt
    protected function setupTextButton():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 42;
    traceFormat.align = "center";
    traceFormat.color = 0x333333;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.autoSize = "left";
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.text = "Invoke Email";
    traceField.x = 30;
    applicatione-mail, sending fromtraceField.y = 25;
    fauxButton = new Sprite();
    fauxButton.addChild(traceField);
    fauxButton.graphics.beginFill(0xFFFFFF, 1);
    fauxButton.graphics.drawRect(0, 0, traceField.width+60, traceField.height+50);
    fauxButton.graphics.endFill();
    fauxButton.x = (stage.stageWidth/2) - (fauxButton.width/2);
    fauxButton.y = 60;
    addChild(fauxButton);
    }

    ```

1.  如果我们现在在设备上运行应用程序，交互式`Sprite`应该如下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_07_21.jpg)

1.  我们现在将`Multitouch.inputMode`分配给通过`MultitouchInputMode.TOUCH_POINT`常量响应原始触摸事件。在`Sprite`按钮上注册一个类型为`TouchEvent.TOUCH_TAP`的事件监听器。这将检测用户发起的任何触摸点击事件，并调用一个名为`onTouchTap`的方法，其中包含我们的其余逻辑：

    ```kt
    protected function registerListeners():void {
    Multitouch.inputMode = MultitouchInputMode.TOUCH_POINT;
    fauxButton.addEventListener(TouchEvent.TOUCH_TAP, onTouchTap);
    }

    ```

1.  一旦检测到触摸点击，我们的`onTouchTap`方法将被触发，调用`navigateToURL`并传递带有`mailto:` URI 前缀的`URLRequest`，其中包含我们想要从应用程序中打开的电子邮件地址，如果需要，还可以包含一个主题参数：

    ```kt
    protected function onTouchTap(e:TouchEvent):void {
    navigateToURL(new URLRequest("mailto:info@fracturedvisionmedia. com?subject=Email%20From%20Adobe%20AIR%20on%20Android!"));
    }

    ```

1.  当我们在设备上运行应用程序时，只需简单地在按钮上触摸点击，就会调用本地电子邮件客户端，并用我们从应用程序传递的值填充它。![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_07_22.jpg)

## 它是如何工作的...

当我们的应用程序用户触摸点击我们所创建的交互式`Sprite`时，他们会从我们的应用程序中被带出到默认的安卓电子邮件客户端。这是通过使用带有`mailto:` URI 前缀的`URLRequest`传递所需的电子邮件地址，并通过`navigateToURL`方法附加一系列参数来实现的，这与我们在桌面或网络应用程序中实现相同功能的方式非常相似。

## 还有更多...

当然，我们完全可以在内部处理电子邮件的应用程序中编写代码，就像在网页应用程序上一样。只要我们能够访问具有电子邮件功能的服务器，这对于某些应用程序来说可能是首选。


# 第八章：丰富的访问：文件系统和本地数据库

本章将涵盖以下内容：

+   从设备存储中打开本地文件

+   将文件保存到设备存储

+   通过本地共享对象跨会话保存数据

+   使用 Flex 自动保存应用程序状态

+   创建本地 SQLite 数据库

+   提供默认的应用程序数据库

+   使用 FlexORM 自动化数据库任务

# 引言

许多文件系统属性在桌面和移动设备之间是共享的，但在处理应用程序状态保存以应对会话中断，或者简单地在会话之间保存数据时，Android 设备上有特定的使用场景。本章将介绍加载和保存单个文件、创建和管理本地数据库、处理本地共享对象以及使用移动 Flex 框架保存导航状态的技巧。

# 从设备存储中打开本地文件

通常，我们可能需要从应用程序存储或 Android 设备上的其他位置读取某些文件。在以下示例中，我们将对简单的文本文件执行此操作，但这也可用于读取各种文件，从图像数据到编码的`MP3`音频字节。

## 如何操作...

在应用程序中使用`flash.filesystem`包中的各种类来打开本地文件数据：

1.  首先，我们需要导入以下类：

    ```kt
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.Event;
    import flash.filesystem.File;
    import flash.filesystem.FileMode;
    import flash.filesystem.FileStream;
    import flash.text.TextField;
    import flash.text.TextFormat;

    ```

1.  我们现在开始定义一组在整个应用程序中使用的常量和变量。初始化一个`String`常量以保留文件路径，该路径将在示例中使用。我们还需要一个`File`和一个相应的`FileStream`以在应用程序中打开文本文件，以及一个`TextField`和`TextFormat`对作为我们的最终输出显示：

    ```kt
    private const PATH:String = "android.txt";
    private var file:File;
    private var stream:FileStream;
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  现在，我们将继续设置我们的`TextField`，应用`TextFormat`，并将其添加到`DisplayList`中。这里，我们创建一个方法来执行所有这些操作：

    ```kt
    protected function setupTextField():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 24;
    traceFormat.align = "center";
    traceFormat.color = 0xCCCCCC;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.selectable = false;
    traceField.multiline = true;
    traceField.wordWrap = true;
    traceField.mouseEnabled = false;
    traceField.x = 20;
    traceField.y = 20;
    traceField.width = stage.stageWidth-40;
    traceField.height = stage.stageHeight-40;
    addChild(traceField);
    }

    ```

1.  实际上，为了在应用程序中打开文件，我们首先会实例化我们的`File`对象，并通过`File.applicationDirectory`将其分配给当前应用程序目录。然后，我们可以通过传递常量并使用`File.resolvePath()`方法指定该位置中的文件。

1.  此过程的第二部分涉及实例化一个`FileStream`，这将使我们能够执行余下的流程。在`FileStream`上注册一个类型为`Event.COMPLETE`的事件监听器。最后，调用`FileStream.openAsync()`，传入先前定义的`File`作为第一个参数，然后是`FileMode`。我们只是要读取这个文件的字节，因此使用`FileMode.READ`：

    ```kt
    protected function beginFileOpen():void {
    file = new File();
    file = File.applicationDirectory;
    file = file.resolvePath(path);
    stream = new FileStream();
    stream.addEventListener(Event.COMPLETE, fileOpened);
    stream.openAsync(file, FileMode.READ);
    }

    ```

1.  一旦`FileStream`完成了工作，我们的`fileOpened`方法将被触发，允许我们以纯文本（由`File.systemCharset`指定）读取`File`字节并将其分配给我们的`TextField`。每当我们完成与`FileStream`对象的操作时，我们必须调用它的`close()`方法：

    ```kt
    protected function fileOpened(e:Event):void {
    traceField.text = stream.readMultiByte(stream.bytesAvailable, File.systemCharset);
    stream.close();
    }

    ```

1.  当我们在设备上编译并运行应用程序时，它应该如下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_08_01.jpg)

## 工作原理...

我们可以通过创建一个`File`引用，并通过`FileStream`打开该引用，在应用程序中打开一个文件。这个过程完成后，我们可以通过直接赋值或处理加载的字节来处理文件本身的内容。在这个例子中，我们读取文本文件的内容并将其输出到应用程序中的基本`TextField`。`FileStream`类有许多不同的方法和属性，可以更有效地用于不同类型的文件和处理过程。例如，我们在这里使用`FileStream.openAsync()`方法实际打开`FileStream`。我们同样也可以使用`FileStream.open()`方法，但使用`openAsync()`将允许我们使用事件监听器，以便我们可以自信地处理加载的数据。重要的是要阅读这些文档，并选择最适合您特定情况的操作。

我们可以使用`flash.filesystem.File`类的静态属性，快速访问各种存储位置。以下是这些属性的列表：

+   `File.applicationStorageDirectory:` 独特的应用程序存储目录[读写]

+   `File.applicationDirectory:` 应用程序安装目录[只读]

+   `File.desktopDirectory:` 映射到 SD 卡根目录[读写]

+   `File.documentsDirectory:` 映射到 SD 卡根目录[读写]

+   `File.userDirectory:` 映射到 SD 卡根目录[读写]

要全面了解`File`类，请参考 Adobe LiveDocs：

[`help.adobe.com/en_US/FlashPlatform/reference/actionscript/3/flash/filesystem/File.html`](http://help.adobe.com/en_US/FlashPlatform/reference/actionscript/3/flash/filesystem/File.html)

## 还有更多...

在这个例子中，我们打开了一个文本文件，但任何文件都可以以类似的方式打开和处理。然而，如果你没有良好的背景知识来了解这些文件是如何工作的，读取复杂文件类型的字节可能会非常困难，对于较大的文件，由于你可能对加载的字节执行了大量处理，在移动设备上这个过程可能会很慢。

# 将文件保存到设备存储

有多种方法可以将应用程序中的数据保存到本地设备存储中。音频、图像和文本数据都可以由用户创建，并保存到应用程序定义的位置，或者允许用户选择在 Android 设备中的特定位置保存文件。在这个例子中，我们将通过生成一个简单的文本文件来演示这一点。

## 如何操作...

我们将允许用户在我们的应用程序内选择基本文本文件的位置和名称，并将其保存到他们的 Android 设备上：

1.  首先，我们需要导入以下类：

    ```kt
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.Event;
    import flash.events.TouchEvent;
    import flash.filesystem.File;
    import flash.text.TextField;
    import flash.text.TextFormat;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;

    ```

1.  在这个应用程序中，我们需要声明多个对象。一个`String`常量将用于定义我们的文件名。接下来，我们声明一个`File`对象，最终用于将我们的文本文件保存到磁盘。一个`TextField`和`TextFormat`组合将把文本信息传递到设备显示上。最后，声明一个`Sprite`作为我们的交互元素，以及一个额外的`TextField`和`TextFormat`组合作为按钮标签：

    ```kt
    private const FILE_NAME:String = "airandroid.txt";
    private var file:File;
    private var traceField:TextField;
    private var traceFormat:TextFormat;
    private var fauxButton:Sprite;
    private var buttonField:TextField;
    private var buttonFormat:TextFormat;

    ```

1.  现在，我们将继续设置`TextField`，应用`TextFormat`，并将其添加到`DisplayList`中。这里，我们创建一个方法来为我们执行所有这些操作。确保将`TextField.type`设置为`input`，以允许用户输入！

    ```kt
    protected function setupTextField():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 44;
    traceFormat.align = "center";
    traceFormat.color = 0x000000;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.type = "input";
    traceField.border = true;
    traceField.multiline = true;
    traceField.wordWrap = true;
    traceField.background = true;
    traceField.border = true;
    traceField.x = 20;
    traceField.y = 20;
    traceField.width = stage.stageWidth-40;
    traceField.height = 250;
    addChild(traceField);
    }

    ```

1.  现在，我们将继续设置我们的`TextField`，应用一个`TextFormat`对象，并使用图形 API 构建一个带有简单背景填充的`Sprite`。我们按钮构建的最后一步是将`TextField`添加到我们的`Sprite`中，然后将`Sprite`添加到`DisplayList`中。这里，我们创建一个方法来为我们执行所有这些操作，并进行一些风格上的增强：

    ```kt
    protected function setupTextButton():void {
    buttonFormat = new TextFormat();
    buttonFormat.bold = true;
    buttonFormat.font = "_sans";
    buttonFormat.size = 42;
    buttonFormat.align = "center";
    buttonFormat.color = 0x333333;
    buttonField = new TextField();
    buttonField.defaultTextFormat = buttonFormat;
    buttonField.autoSize = "left";
    buttonField.selectable = false;
    buttonField.mouseEnabled = false;
    buttonField.text = "Save as File";
    buttonField.x = 30;
    buttonField.y = 25;
    fauxButton = new Sprite();
    fauxButton.addChild(buttonField);
    fauxButton.graphics.beginFill(0xFFFFFF, 1);
    fauxButton.graphics.drawRect(0, 0, buttonField.width+60, buttonField.height+50);
    fauxButton.graphics.endFill();
    fauxButton.x = (stage.stageWidth/2) (fauxButton.width/2);
    fauxButton.y = traceField.y+traceField.height+40;
    addChild(fauxButton);
    }

    ```

1.  如果我们运行应用程序，我们可以看到所有内容在显示上的布局情况。在这一点上，我们也可以自由编辑`TextField`，它作为我们文本文件的输入：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_08_02.jpg)

1.  我们现在将`Multitouch.inputMode`分配给通过`MultitouchInputMode.TOUCH_POINT`常量响应原始触摸事件。在`Sprite`按钮上注册一个类型为`TouchEvent.TOUCH_TAP`的事件监听器。这将检测用户发起的任何触摸轻触事件，并调用一个名为`onTouchTap`的方法，其中包含我们的其余逻辑：

    ```kt
    protected function registerListeners():void {
    Multitouch.inputMode = MultitouchInputMode.TOUCH_POINT;
    fauxButton.addEventListener(TouchEvent.TOUCH_TAP, onTouchTap);
    }

    ```

1.  当用户与应用程序交互并在按钮上轻触以将任何文本输入保存为文件时，将触发以下方法。在这个函数中，我们首先创建一个新的`File`对象，并在调用`File.save()`之前注册一个类型为`Event.COMPLETE`的事件监听器。`File.Save()`方法需要两个参数：要创建的文件内容以及文件名称：

    ```kt
    protected function onTouchTap(e:TouchEvent):void {
    file = new File();
    file.addEventListener(Event.COMPLETE, fileSaved);
    file.save(traceField.text, FILE_NAME);
    }

    ```

1.  一旦用户输入一些文本并点击按钮将其保存为文件，Android 将产生一个覆盖层，请求确认执行保存操作。此时，用户可以重命名文件或选择其他位置保存。默认情况下，文件保存在设备 SD 卡的根目录中。如果我们想避免保存对话框，可以采用`flash.filesystem.FileStream`类来实现：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_08_03.jpg)

1.  保存成功完成后，我们可以移除事件监听器，清除输入的`TextField`并将按钮标签`TextField`更改为让用户知道一切已正确保存：

    ```kt
    protected function fileSaved(e:Event):void {
    fauxButton.removeEventListener(TouchEvent.TOUCH_TAP, onTouchTap);
    file.removeEventListener(Event.COMPLETE, fileSaved);
    traceField.text = "";
    buttonField.text = "File Saved!";
    }

    ```

1.  下图展示了用户在成功保存后将会看到的内容：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_08_04.jpg)

1.  用户现在可以使用文件浏览器或其他应用程序在默认的 Android 文本查看器中打开文本文件，如下面的截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_08_05.jpg)

## 它是如何工作的...

将纯文本文件写入设备存储相当直接。这个过程涉及创建一个`File`对象，然后调用该对象的`save()`方法。使用此方法，我们传递要保存的文件内容以及所需的文件名。请注意，虽然在这种情况下我们传递的是简单文本，但我们也可以保存音频文件或图像形式的字节。如果我们需要对整个过程进行更多控制，我们还可以使用`FileStream`对象来设置各种编码，并以更多方式写入字节。使用`FileStream`还可以让我们将新信息追加到先前创建的文件中，并且避免了本例中出现的保存对话框。

## 还有更多...

您需要为任何写入本地文件的应用程序提供访问本地文件系统的权限，通过 Android 的清单文件进行设置。关于这方面的更多信息，请参见第九章，*清单保证：安全与 Android 权限。*

# 通过本地共享对象跨会话保存数据

共享对象在基于浏览器的 Flash 应用程序中已经使用了多年。它们有时被称为“Flash Cookies”或“超级 Cookies”，并提供与基于浏览器的普通 Cookies 类似的许多功能，但更适合 Flash 环境。通常，使用 Web 上的 Flash 应用程序保存此类数据需要明确的权限；然而，使用 AIR 使我们摆脱了这些限制中的许多。

## 如何操作...

创建一个本地`SharedObject`以在会话之间保存特定的应用程序数据。我们将使用一个交互式`Sprite`来直观地说明这一点：

1.  首先，我们需要导入以下类：

    ```kt
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.Event;
    import flash.events.TouchEvent;
    import flash.geom.Point;
    import flash.net.SharedObject;
    import flash.net.SharedObjectFlushStatus;
    import flash.text.TextField;
    import flash.text.TextFormat;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;

    ```

1.  然后，我们需要声明一些在此应用程序中使用的对象。声明一个 `SharedObject`，用于保存会话数据。`Point` 对象将用于将坐标写入 `SharedObject`。`Sprite` 将作为用户交互元素和此示例的视觉参考。最后，声明一个 `TextField` 和 `TextFormat` 对，用于在设备显示屏上传递文本消息。

    ```kt
    private var airSO:SharedObject;
    private var ballPoint:Point;
    private var ball:Sprite;
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  现在，我们将继续设置我们的 `TextField`，应用 `TextFormat`，并将其添加到 `DisplayList` 中。在这里，我们创建一个方法来执行所有这些操作：

    ```kt
    protected function setupTextField():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 24;
    traceFormat.align = "center";
    traceFormat.color = 0xCCCCCC;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.selectable = false;
    traceField.multiline = true;
    traceField.wordWrap = true;
    traceField.mouseEnabled = false;
    traceField.x = 20;
    traceField.y = 20;
    traceField.width = stage.stageWidth-40;
    traceField.height = stage.stageHeight-40;
    addChild(traceField);
    }

    ```

1.  我们需要设置一个交互式对象，让用户根据触摸移动它，这个对象的坐标最终将在应用程序会话之间保留。让我们使用图形 API 创建一个基本的圆形 `Sprite`。

    ```kt
    protected function setupBall():void {
    ball = new Sprite();
    ball.graphics.beginFill(0xFFFFFF);
    ball.graphics.drawCircle(0, 0, 60);
    ball.graphics.endFill();
    ball.x = stage.stageWidth/2;
    ball.y = 260;
    addChild(ball);
    }

    ```

1.  在深入这个示例之前，我们必须对我们声明的 `SharedObject` 执行一些操作。首先，在我们的 `SharedObject` 实例上调用 `SharedObject.getLocal("airandroid")`。如果存在名为 `airandroid` 的 `SharedObject`，这将读取它；如果 `SharedObject` 尚不存在，这个调用将为我们创建它。

1.  现在，我们可以检查 `SharedObjectdata` 属性中是否存在 `ballPoint` 对象。如果是这样，这意味着我们之前已经完成了一个会话，可以将 `ballPoint x` 和 `y` 属性赋给我们的 `ballSprite`。

    ```kt
    protected function setupSharedObject():void {
    airSO = SharedObject.getLocal("airandroid");
    if(airSO.data.ballPoint != undefined){
    ball.x = airSO.data.ballPoint.x;
    ball.y = airSO.data.ballPoint.y;
    traceField.text = "Existing Shared Object!";
    }else{
    traceField.text = "No Shared Object Found!";
    }
    }

    ```

1.  当我们第一次运行应用程序时，我们会被告知没有检测到共享对象，并且球被放置在默认位置：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_08_06.jpg)

1.  我们现在将 `Multitouch.inputMode` 设置为通过 `MultitouchInputMode.TOUCH_POINT` 常量响应原始触摸事件。在圆形 `Sprite` 上注册两个类型为 `TouchEvent.TOUCH_MOVE` 和 `TouchEvent.TOUCH_END` 的事件监听器。这将检测用户发起的任何触摸事件，并调用特定方法来处理每一个。

    ```kt
    protected function registerListeners():void {
    Multitouch.inputMode = MultitouchInputMode.TOUCH_POINT;
    ball.addEventListener(TouchEvent.TOUCH_MOVE, onTouchMove);
    ball.addEventListener(TouchEvent.TOUCH_END, onTouchEnd);
    }

    ```

1.  当在我们的 `Sprite` 上检测到 `TouchEvent.TOUCH_MOVE` 事件时，`onTouchMove` 方法将被触发，使我们能够改变 `Sprite` 的 `x` 和 `y` 坐标，从而允许用户在 `Stage` 上拖动它。

    ```kt
    protected function onTouchMove(e:TouchEvent):void {
    ball.x = e.stageX;
    ball.y = e.stageY;
    }

    ```

1.  当我们的应用程序在 `Sprite` 对象上检测到 `TouchEvent.TOUCH_END` 事件时，我们将利用这个机会将 `Sprite x` 和 `y` 坐标包装在一个 `Point` 对象中，并将其赋值给我们的 `SharedObject`。为了执行这个操作，我们首先将 `Sprite` 坐标赋给我们的 `Point` 对象，然后将其赋给我们的 `SharedObjectdata` 属性。

1.  为了将 `SharedObject` 写入本地文件系统，我们必须调用 `SharedObject.flush()`。我们可以将 `flush()` 命令的返回值赋给一个 `String`，以便监控和响应其状态。在这个示例中，我们仅使用 switch/case 语句检查 `SharedObjectFlushStatus` 并在我们的 `TextField` 中写入一条消息，让用户知道正在发生的情况。

    ```kt
    protected function onTouchEnd(e:Event):void {
    ballPoint = new Point(ball.x, ball.y);
    airSO.data.ballPoint = ballPoint;
    var flushStatus:String;
    flushStatus = airSO.flush();
    if(flushStatus != null) {
    switch(flushStatus) {
    case SharedObjectFlushStatus.FLUSHED:
    traceField.text = "Ball location x:" + ball.x + "/y:" + ball.y + " saved!";
    break;
    default:
    traceField.text = "There was a problem :(";
    break;
    }
    }
    }

    ```

1.  用户现在可以通过触摸并移动球体来与球体互动。当用户停止与球体互动时，这些坐标会被保存到我们的本地共享对象中：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_08_07.jpg)

    ### 注意

    如果用户存在，并且在将来的某个时间再次打开应用程序，本地共享对象将被读取，并根据这些保留的数据重新定位球体。为了在设备上真正测试这一点，开发者需要使用 Android **设置**菜单下的应用程序管理功能来结束应用程序，或者使用第三方“任务杀手”以确保应用程序完全停止。

    ![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_08_08.jpg)

## 工作原理...

Flash 中的`SharedObject`与网络浏览器中使用的 cookie 实现非常相似。它最初在基于浏览器的 Flash 中实现，以便当开发人员希望跨用户会话保留小块数据时，能够提供类似的体验。幸运的是，这在 AIR 中同样有效，并可以作为我们 Android 应用程序中的简单存储使用。

要读取`SharedObject`，只需调用它的`getLocal()`方法，传入我们希望检索的`SharedObject`的名称。要保存`SharedObject`，我们为其分配新数据并调用`flush()`方法，该方法将把新信息保存到磁盘。

## 还有更多...

在这个实例中我们使用了一个本地`SharedObject`，但也可以根据需要将此类数据保存到本地或远程数据库、文本或 XML 文件，甚至使用远程`SharedObject`。

# 使用 Flex 自动存储应用程序状态

尽管很多时候我们需要在会话被其他设备功能（如来电）中断时存储特定的应用程序参数，但移动 Flex 框架确实提供了一定程度的会话保留，这可以自动为我们处理。

## 如何操作...

通过启用`persistNavigatorState`，指示 Flex 自动为我们保留应用程序状态：

1.  我们首先会创建一个新的移动 Flex 项目，其中包含两个视图，我们将其简称为`first`和`second`。初始的`ViewNavigatorApplication`文件将如下所示：

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <s:ViewNavigatorApplication 
     firstView="views.first">
    </s:ViewNavigatorApplication>

    ```

1.  在我们的`first`视图中添加一个按钮，这将使我们能够从那里推送`second`视图：

    ```kt
    <s:Button label="Engage Second State" click="navigator.pushView(views.second);"/>

    ```

1.  在我们的`second`视图中添加一个按钮，允许我们返回到`first`视图。现在我们可以来回导航，构建我们的`ViewNavigator`历史记录：

    ```kt
    <s:Button label="Engage First State" click="navigator.pushView(views.first)"/>

    ```

1.  为了让 Flex 在会话被中断的情况下既保存我们的`ViewNavigator`历史记录，又保留我们在该历史记录中的当前位置，我们将修改`ViewNavigatorApplication`以包含一个名为`persistNavigatorState`的属性，并将其设置为`true`。我们还将声明一个`creationComplete`事件，它将调用一个名为`init()`的函数。我们将使用它来设置一些额外的功能：

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <s:ViewNavigatorApplication 
     firstView="views.first"
    persistNavigatorState="true" creationComplete="init()">
    </s:ViewNavigatorApplication>

    ```

1.  在 MXML 中创建一个`Script`标签，并导入`FlexEvent`类：

    ```kt
    <fx:Script>
     <![CDATA[
     import mx.events.FlexEvent;
     ]]>
     </fx:Script>

    ```

1.  现在，我们必须声明我们的`init()`方法，该方法将在`creationComplete`时被调用。在这个方法中，我们将在应用程序上注册一个类型为`FlexEvent.NAVIGATOR_STATE_SAVING`的事件监听器：

    ```kt
    public function init():void {
    this.addEventListener(FlexEvent.NAVIGATOR_STATE_SAVING, stateSaving);
    }

    ```

1.  每当应用程序在退出时通过 Flex 持久化管理器开始保存应用程序状态时，我们的`stateSaving`方法将被触发，允许我们执行额外的操作，甚至可以在`FlexEvent`上调用`preventDefault()`，以便在退出之前让我们的逻辑接管。在开发和测试中，我们可以轻松在这个方法中设置断点，以便检查应用程序状态。

    ```kt
    protected function stateSaving(e:FlexEvent):void {
    // Interception Code
    }

    ```

1.  当我们编译并运行我们的应用程序时，它将显示在下个截图中所示的样子。从我们的第一个视图翻到第二个视图，并来回多次，将填充应用程序`ViewNavigator`的历史记录：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_08_09.jpg)

1.  如果应用程序会话被电话或其他事件中断，导航历史和当前视图将被保留。当再次运行应用程序时，用户将能够从中断发生的地方继续操作：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_08_10.jpg)

## 它的工作原理...

当使用移动 Flex 框架时，我们可以在应用程序中启用`persistNavigatorState`选项。这将自动保存我们的`ViewNavigator`历史记录，并记住在应用程序会话中断时我们正在交互的视图。它通过将会话信息保存到设备上的本地共享对象来实现这一点。保存的数据包括有关应用程序版本号、完整的导航堆栈和当前导航视图的信息。

此外，当应用程序开始退出时，我们可以拦截`FlexEvent.NAVIGATOR_STATE_SAVING`事件，并执行我们自己的期望操作，例如将关键应用程序数据保存到文件系统、本地共享对象，甚至是 SQLite 数据库。

# 创建本地 SQLite 数据库

Adobe AIR 从一开始就支持嵌入式 SQLite 数据库。这是我们在 Android 应用程序中存储结构化信息的最佳方式之一。SQLite 是一个软件库，它实现了一个自包含、无服务器、零配置、事务性的 SQL 数据库引擎。它创建的数据库文件就是单独的`.db`文件，可以通过网络传输、复制和删除，就像其他任何文件类型一样。

## 如何操作...

我们将创建一个带有本地 SQLite 数据库的移动应用程序，该程序可以使用 SQL 查询语言，允许用户添加新记录并基于这些条目运行简单查询：

1.  首先，导入这个示例所需的以下类：

    ```kt
    import flash.data.SQLConnection;
    import flash.data.SQLStatement;
    import flash.data.SQLResult;
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.Event;
    import flash.events.TouchEvent;
    import flash.filesystem.File;
    import flash.text.TextField;
    import flash.text.TextFormat;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;

    ```

1.  我们需要声明一些在此应用程序中使用的对象。一个`SQLConnection`将允许我们与本地 SQLite 数据库进行交互。第一个`TextField`和`TextFormat`对将作为用户输入的输入字段。另一个`TextField`和`TextFormat`对将把文本信息传递到设备显示屏上。最后，声明一个`Sprite`作为我们的交互元素，以及一个最后的`TextField`和`TextFormat`对作为按钮标签：

    ```kt
    private var sqlConnection:SQLConnection;
    private var itemField:TextField;
    private var itemFormat:TextFormat;
    private var fauxButton:Sprite;
    private var buttonField:TextField;
    private var buttonFormat:TextFormat;
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  现在，我们继续设置我们的`TextField`，应用一个`TextFormat`，并将其添加到`DisplayList`中。这里，我们创建一个方法来执行所有这些操作。确保将`TextField.type`设置为`input`，以允许用户输入！

    ```kt
    protected function setupTextField():void {
    itemFormat = new TextFormat();
    itemFormat.bold = true;
    itemFormat.font = "_sans";
    itemFormat.size = 44;
    itemFormat.align = "center";
    itemFormat.color = 0x000000;
    itemField = new TextField();
    itemField.defaultTextFormat = itemFormat;
    itemField.type = "input";
    itemField.border = true;
    itemField.multiline = true;
    itemField.wordWrap = true;
    itemField.background = true;
    itemField.border = true;
    itemField.x = 20;
    itemField.y = 20;
    itemField.width = stage.stageWidth-40;
    itemField.height = 60;
    addChild(itemField);
    }

    ```

1.  对于我们的交互式`Sprite`，我们将设置一个`TextField`，应用一个`TextFormat`对象，并使用图形 API 构建一个具有简单背景填充的`Sprite`。构建按钮的最后一步是将`TextField`添加到我们的`Sprite`中，然后将`Sprite`添加到`DisplayList`中。这里，我们创建一个方法来执行所有这些操作，并进行一些样式增强：

    ```kt
    protected function setupTextButton():void {
    buttonFormat = new TextFormat();
    buttonFormat.bold = true;
    buttonFormat.font = "_sans";
    buttonFormat.size = 42;
    buttonFormat.align = "center";
    buttonFormat.color = 0x333333;
    buttonField = new TextField();
    buttonField.defaultTextFormat = buttonFormat;
    buttonField.autoSize = "left";
    buttonField.selectable = false;
    buttonField.mouseEnabled = false;
    buttonField.text = "Insert to DB";
    buttonField.x = 30;
    buttonField.y = 25;
    fauxButton = new Sprite();
    fauxButton.addChild(buttonField);
    fauxButton.graphics.beginFill(0xFFFFFF, 1);
    fauxButton.graphics.drawRect(0, 0, buttonField.width+60, buttonField.height+50);
    fauxButton.graphics.endFill();
    fauxButton.x = (stage.stageWidth/2) - (fauxButton.width/2);
    fauxButton.y = itemField.y+itemField.height+40;
    addChild(fauxButton);
    }

    ```

1.  我们最后的视觉元素包括另一个`TextField`和`TextFormat`对，用于在设备上显示数据库记录：

    ```kt
    protected function setupTraceField():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 24;
    traceFormat.align = "left";
    traceFormat.color = 0xCCCCCC;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.selectable = false;
    traceField.multiline = true;
    traceField.wordWrap = true;
    traceField.mouseEnabled = false;
    traceField.x = 20;
    traceField.y = fauxButton.y+fauxButton.height+40;
    traceField.width = stage.stageWidth-40;
    traceField.height =stage.stageHeight - traceField.y;
    addChild(traceField);
    }

    ```

1.  我们现在将`Multitouch.inputMode`分配为通过`MultitouchInputMode.TOUCH_POINT`常量响应原始触摸事件。在`Sprite`按钮上注册一个类型为`TouchEvent.TOUCH_TAP`的事件监听器。这将检测用户发起的任何触摸点击事件，并调用一个名为`onTouchTap`的方法来执行额外操作。

    ```kt
    protected function registerListeners():void {
    Multitouch.inputMode = MultitouchInputMode.TOUCH_POINT;
    fauxButton.addEventListener(TouchEvent.TOUCH_TAP, insertDBItem);
    }

    ```

1.  要创建应用程序数据库，我们首先需要初始化我们的`SQLConnection`对象，并将一个`File.db`引用传递给`SQLConnection.open()`方法以建立连接。如果数据库文件不存在，它将被自动创建。为了编写与数据库交互的 SQL 语法，我们必须初始化一个`SQLStatement`对象，并将我们建立的`SQLConnection`分配给`SQLStatement.sqlConnection`属性。此时，我们可以传入一个包含 SQL 语句的`String`到`SQLStatement.text`属性中，并调用`SQLConnection.execute()`实际执行语句。这个语法将在我们的数据库中创建一个包含两列`name`和`time`的表。如果表已经存在，该语句将被忽略：

    ```kt
    protected function createDB():void {
    sqlConnection = new SQLConnection();
    sqlConnection.open(File.applicationStorageDirectory. resolvePath("airandroid.db"));
    var sqlStatement:SQLStatement = new SQLStatement();
    sqlStatement.sqlConnection = sqlConnection;
    sqlStatement.text = "CREATE TABLE IF NOT EXISTS items (name TEXT, time TEXT)";
    sqlStatement.execute();
    getDBItems();
    }

    ```

1.  为了从数据库中检索现有记录，我们将再次初始化一个`SQLStatement`，并将已建立的`SQLConnection`分配给`SQLStatement.sqlConnection`属性。然后，我们会传入一个包含 SQL 语句的`String`到`SQLStatement.text`属性中，并调用`SQLConnection.execute()`从数据库中检索所有记录。

1.  要将返回的数据写入`TextField`，我们只需初始化一个新的`Array`来包含通过将`SQLStatement.getResult()`的`data`属性（它本身是一个`Array`）赋值给`Array`返回的记录。现在创建一个`for`循环来解析结果，将每条记录分配的各种属性输出到我们的`TextField`中。这将在 Android 设备上直观地展示查询结果：

    ```kt
    protected function getDBItems():void {
    traceField.text = "";
    var sqlStatement:SQLStatement = new SQLStatement();
    sqlStatement.sqlConnection = sqlConnection;
    sqlStatement.text = "SELECT * FROM items";
    sqlStatement.execute();
    var sqlArray:Array = new Array();
    var sqlResult:SQLResult = sqlStatement.getResult();
    if(sqlResult.data != null){
    sqlArray = sqlResult.data;
    }
    var itemCount:int = sqlArray.length;
    for(var i:int=0; i<itemCount; i++){
    traceField.appendText("NAME: " + sqlArray[i].name + "\n");
    traceField.appendText("DATE: " + sqlArray[i].time + "\n");
    traceField.appendText("\n");
    }
    }

    ```

1.  我们需要编写的最后一个方法是允许用户向数据库中插入记录。这大部分与我们之前两个方法中建立和执行`SQLStatement`对象的方式非常相似。然而，插入操作可能更加复杂和结构化，因此我们使用内置的`SQLStatement.parametersArray`来为我们的记录赋值。对于`name`值，我们从用户提供的输入`TextField`读取。为了生成一个时间戳来填充`time`的值，我们实例化一个新的`Date`对象并调用`toUTCString()`。执行这个完整形成的语句后，我们再次调用`getDBItems()`以返回新的数据库结果，让用户立即看到记录已被正确插入：

    ```kt
    protected function insertDBItem(e:TouchEvent):void {
    var date:Date = new Date();
    var sqlStatement:SQLStatement = new SQLStatement();
    sqlStatement.sqlConnection = sqlConnection;
    sqlStatement.text = "INSERT into items values(:name, :time)";
    sqlStatement.parameters[":name"] = itemField.text;
    sqlStatement.parameters[":time"] = date.toUTCString();
    sqlStatement.execute();
    getDBItems();
    itemField.text = "";
    }

    ```

1.  在我们的 Android 设备上运行应用程序，允许我们使用原生的虚拟键盘输入一个名字，并通过触摸点击**插入到数据库**按钮，这将在我们的数据库中创建一个由输入文本和当前时间戳组成的新条目。![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_08_11.jpg)

1.  每当我们向应用程序中输入一个新名字时，新条目就会被插入，并且会进行查询，将所有条目以及它们被插入时的时间戳输出到`TextField`中：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_08_12.jpg)

## 工作原理...

SQLite 是一个本地自包含的数据库，可以在 AIR for Android 应用程序中用于执行各种任务，从简单到复杂。为了使用这个功能，我们必须建立一个到设备上本地`.db`文件的`SQLConnection`。一旦建立这个连接，我们可以使用一组`SQLStatements`来执行表创建和管理任务，通过标准的 SQL 语法进行选择、插入和删除查询。在这个例子中，用户可以在应用程序存储目录下的数据库文件中插入记录并执行一般的选择查询。

在这个演示中，我们使用`flash.data.SQLStatement`来执行`INSERT`和`SELECT`操作。要进一步探索这一点以及相关类，我们请您参考 Adobe LiveDocs：

[`help.adobe.com/en_US/FlashPlatform/reference/actionscript/3/flash/data/SQLStatement.html`](http://help.adobe.com/en_US/FlashPlatform/reference/actionscript/3/flash/data/SQLStatement.html)

# 提供默认的应用程序数据库

允许用户直接或间接地向应用程序数据库中添加或删除项目，在多种场景下都非常有用。或许，我们希望用户从一个标准数据集开始操作，或者为用户提供一些默认设置以供日后操作？这些场景要求应用程序能够提供默认的数据库。在本教程中，我们将展示如何通过文件系统智能地处理这个问题。

## 准备工作...

在本教程中，我们将在应用程序目录中捆绑一个已经建立的 SQLite 数据库文件。如果您还没有可用的 SQLite 数据库文件，您可以使用本章中的其他教程来生成一个，或者使用任何一种可免费获得的机制来创建这些便携式的小型数据库文件。

## 如何操作...

我们将把一个默认的 SQLite 数据库与我们的应用程序打包在一起，检查是否存在用户定义的数据库，并在需要时向用户提供我们的默认数据库：

1.  首先，导入本示例所需以下类：

    ```kt
    import flash.data.SQLConnection;
    import flash.data.SQLStatement;
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.filesystem.File;
    import flash.text.TextField;
    import flash.text.TextFormat;

    ```

1.  在这个应用程序中，我们将需要声明几个对象。一个`SQLConnection`将允许我们与本地 SQLite 数据库交互，而`TextField`和`TextFormat`组合将把文本信息传递到设备显示屏上：

    ```kt
    private var sqlConnection:SQLConnection;
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  现在，我们将设置我们的`TextField`，应用一个`TextFormat`，并将其添加到`DisplayList`中，同时进行一些风格上的增强。在这里，我们创建一个方法来执行所有这些操作：

    ```kt
    protected function setupTraceField():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 24;
    traceFormat.align = "left";
    traceFormat.color = 0xCCCCCC;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.selectable = false;
    traceField.multiline = true;
    traceField.wordWrap = true;
    traceField.mouseEnabled = false;
    traceField.x = 20;
    traceField.y = 20;
    traceField.width = stage.stageWidth-40;
    traceField.height = stage.stageHeight-40;
    addChild(traceField);
    }

    ```

1.  这个方法将在`TextField`建立后立即触发，因为我们将把复制过程中每一步完成的消息输出到这个视觉元素中。

1.  首先要确定应用程序数据库是否存在，这将决定我们是否需要复制默认数据库。为此，我们将实例化一个新的`File`对象，并引用应用程序安装目录中的名为`products.db`的文件。如果此文件不存在，我们必须创建另一个`File`对象，引用我们要复制文件到的文件名和位置。

1.  建立连接后，在源`File`上使用`File.copyTo()`方法，并传入目标`File`。如果一切顺利，现在应该在应用程序存储目录中有一个默认数据库的精确副本：

    ```kt
    protected function checkDefaultDB():void {
    traceField.appendText("Checking if DB exists...\n\n");
    var dbFile:File = File.applicationStorageDirectory;
    dbFile = dbFile.resolvePath("products.db");
    if(dbFile.exists){
    traceField.appendText("Application DB Okay!\n\n");
    }else{
    traceField.appendText("Application DB Missing!\n\n");
    traceField.appendText("Copying Default DB...\n\n");
    var sourceFile:File = File.applicationDirectory;
    sourceFile = sourceFile.resolvePath("default.db");
    var destination:File = File.applicationStorageDirectory;
    destination = destination.resolvePath("products.db");
    sourceFile.copyTo(destination, true);
    traceField.appendText("Database Copy Completed!\n\n");
    }
    connectDB();
    }

    ```

1.  要打开应用程序数据库，我们首先必须初始化我们的`SQLConnection`对象，并将`File.db`引用传递给`SQLConnection.open()`方法以建立连接。现在我们有了与新建复制的数据库的连接，我们调用`getDBItems()`方法来检索记录以供显示：

    ```kt
    protected function connectDB():void {
    sqlConnection = new SQLConnection();
    sqlConnection.open(File.applicationStorageDirectory. resolvePath("products.db"));
    getDBItems();
    }

    ```

1.  要从复制的数据库中检索所有记录，我们将初始化一个`SQLStatement`，并将建立的`SQLConnection`分配给`SQLStatement.sqlConnection`属性。然后，我们将 SQL 语句的`String`传递给`SQLStatement.text`属性，并调用`SQLConnection.execute()`从数据库中检索所有记录。

1.  要将返回的数据输出到`TextField`，我们只需初始化一个新的`Array`来包含返回的记录，通过将`SQLStatement.getResult()`的`data`属性（它本身是一个`Array`）分配给`Array`。现在创建一个`for`循环来解析结果，将每条记录分配的各种属性输出到我们的`TextField`。这将在 Android 设备上直观地显示查询结果。

    ```kt
    protected function getDBItems():void {
    traceField.appendText("Gathering items from application DB...\ n\n");
    var sqlStatement:SQLStatement = new SQLStatement();
    sqlStatement.sqlConnection = sqlConnection;
    sqlStatement.text = "SELECT * FROM Products";
    sqlStatement.execute();
    var sqlArray:Array = sqlStatement.getResult().data;
    var itemCount:int = sqlArray.length;
    traceField.appendText("Database Contains:\n");
    for(var i:int=0; i<itemCount; i++){
    traceField.appendText("PRODUCT: " + sqlArray[i].ProductName + "\n");
    }
    }

    ```

1.  应用程序首次运行时，在应用程序存储目录中找不到数据库。然后将默认数据库复制到预期位置，然后检索记录并显示给用户查看：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_08_13.jpg)

1.  如果用户后续运行此应用程序，数据库现在在预期位置，应用程序只需执行查询并显示记录，无需从一处位置复制文件到另一位置：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_08_14.jpg)

## 工作原理...

在此食谱中，我们使用`File`和`SQLConnection/SQLStatement`对象的组合来确定数据库是否存在，然后进行简单的查询和记录显示，或者使用`File.copyTo()`将文件从应用程序安装目录复制到应用程序存储目录的更复杂操作。此方法将复制作为初始参数传入的文件引用到指定位置。还有许多其他类似的文件操作方法。以下列出了一些这些方法：

+   `File.copyTo()：`将文件或目录复制到新位置

+   `File.moveTo()：`将文件或目录移动到新位置

+   `File.deleteFile()XE`"default application database:File.deleteFile()方法"：删除指定的文件

+   `File.createDirectory()：`创建目录以及所需的所有父目录

+   `File.deleteDirectory()：`删除指定的目录

要全面了解`File`类，请参考 Adobe LiveDocs：

[`help.adobe.com/en_US/FlashPlatform/reference/actionscript/3/flash/filesystem/File.html`](http://help.adobe.com/en_US/FlashPlatform/reference/actionscript/3/flash/filesystem/File.html)

数据库文件，仅仅是一个常规文件，可以通过 ActionScript 像其他任何文件一样轻松操作。但是，在这种情况下，了解应用程序是否有权限写入哪些目录是很重要的。例如，`File.applicationDirectory`是只读的。我们不能将文件写入此目录。

如果你需要一个工具来创建或管理 SQLite 数据库文件，你可能会对像 SQLite Database browser 这样的软件项目感兴趣，可以免费从[`sqlitebrowser.sourceforge.net/`](http://sqlitebrowser.sourceforge.net/)下载。

# 使用 FlexORM 自动化数据库任务

尽管我们确实可以通过支持的 SQLite 语法完全控制应用程序数据库，但有一些代码库可以使事情变得更容易。这样一个库叫做**FlexORM**，顾名思义，它只能在 Flex 项目中使用，因此纯 ActionScript 是不行的。

FlexORM 是一个对象关系映射框架，它避免了开发者在项目中编写任何数据库代码或 SQL。对象是持久的，任何数据库转换都由框架本身在幕后处理。

## 准备工作...

在准备这个应用程序示例时，你还需要采取一些额外的步骤来准备，因为涉及到获取 FlexORM 库并在项目中设置它的一些设置：

1.  首先，我们必须打开一个网络浏览器并前往[FlexORM 的项目页面](http://flexorm.riaforge.org/)。

1.  通过屏幕底部的`ZIP`包或通过 SVN 仓库下载文件。

1.  文件一旦在你的系统上，我们将想要导航到**trunk | flexorm | src**目录，并获取**src**下的所有内容。这是我们为了使用 FlexORM 而必须导入到 Flash Builder 中的包。

1.  创建一个新的移动 Flex 项目，并将文件从 Flex 项目**src**文件夹下的**src**拖拽过来。我们现在可以在我们的应用程序中使用**FlexORM**。

1.  你的项目将与下面截图显示的项目非常相似：![准备工作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_08_15.jpg)

## 如何操作...

使用**FlexORM**框架，我们将定义一个持久对象结构，并通过一个简单的 Flex 移动项目管理对象条目的创建和删除：

1.  我们首先要在一个名为`vo` [值对象] 的包中创建一个名为`Product`的类。这将作为我们可绑定对象的声明，并且反映了我们将要从数据库中插入和读取的内容。使用特定于**FlexORM**的元数据，我们声明一个名为`Products`的表，其中有一个名为`id`的 ID 列和一个名为`ProductName`的附加列。这些对象作为我们实际表结构的接口，允许我们通过熟悉的面向对象范例来管理 SQL 命令：

    ```kt
    package vo {
    [Bindable]
    [Table(name="Products")]
    public class Product {
    [Id]public var id:int;
    [Column]public var ProductName:String;
    }
    }

    ```

1.  下一步将编写一个`ViewNavigatorApplication` MXML 文件作为我们的主应用程序文件。我们可以包含一个指向特定`View`的`firstView`属性，以及一个`applicationComplete`属性，它将调用一个初始化函数：

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <s:ViewNavigatorApplication xmlns:fx= "http://ns.adobe.com/mxml/2009"
     firstView="views.FlexORMHomeView" applicationComplete="init()">
    </s:ViewNavigatorApplication>

    ```

1.  现在我们将声明一个`Script`块并执行一系列导入，这对于我们应用程序的这部分是必要的。我们从**FlexORM**只需要`EntityManager`。这是用于读取和写入我们数据库的内容。我们还必须导入与**FlexORM**一起使用的`vo`对象类以及用于保存产生的任何记录的`ArrayCollection`：

    ```kt
    <fx:Script>
    <![
    CDATA[
    import nz.co.codec.flexorm.EntityManager;
    import vo.Product;
    import mx.collections.ArrayCollection;
    ]]>
    </fx:Script>

    ```

1.  在这里，我们将实例化`EntityManager`和`ArrayCollection`以供应用程序使用。调用`EntityManager.getInstance()`将允许我们开始使用**FlexORM**：

    ```kt
    protected var entityManager:EntityManager = EntityManager.getInstance();
    [Bindable] public var productArrayCollection:ArrayCollection;

    ```

1.  我们必须定义在`ViewNavigatorApplication`标签中提到的初始化方法。在此方法内，使用`File`类引用要在应用程序存储目录中创建的数据库文件。创建一个新的`SQLConnection`，并用它打开先前定义的`File`引用。现在，可以将`SQLConnection`绑定到`EntityManager`的`sqlConnection`属性上，使我们能够使用**FlexORM**与数据库交互：

    ```kt
    protected function init():void {
    var databaseFile:File =
    File.applicationStorageDirectory.resolvePath("products.db");
    var connection:SQLConnection = new SQLConnection();
    connection.open(databaseFile);
    entityManager.sqlConnection = connection;
    loadProducts();
    }

    ```

1.  我们可以在任何时候调用此方法从数据库刷新我们的集合。只需在`EntityManager`上调用`findAll()`，并传入我们想要检索的类名，就可以从绑定到该类的表中返回所有记录：

    ```kt
    protected function loadProducts():void {
    productArrayCollection = entityManager.findAll(Product);
    productArrayCollection.refresh();
    }

    ```

1.  我们需要设置方法以插入和删除应用程序数据库中的记录。为了保存记录，我们会根据希望保存到的表创建一个基于类的对象。现在，我们将根据要为此插入写入值的字段为此类分配属性。在传入此对象的同时调用`EntityManager.save()`，将指示**FlexORM**在数据库中插入新记录：

    ```kt
    public function saveProduct(e:String):void {
    var ProductEntry:Product = new Product();
    ProductEntry.ProductName = e;
    entityManager.save(ProductEntry);
    loadProducts();
    }

    ```

1.  从数据库中删除记录同样简单。在传入集合中的对象时调用`EntityManager.remove()`，该对象与要从数据库中删除的特定记录相对应，这将确保**FlexORM**为我们删除真正的记录：

    ```kt
    public function deleteProduct(index:int):void {
    entityManager.remove(productArrayCollection.getItemAt(index));
    loadProducts();
    }

    ```

1.  现在构建我们的应用程序视图。创建一个新的`View` MXML 文件，并为其分配适合您特定项目视图的属性。在这种情况下，我们将其分配给带有一些宽大填充的`VerticalLayout`：

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <s:View 
     title="Product Catalog">
    <s:layout>
    <s:VerticalLayout gap="20" paddingBottom="20" paddingLeft="20" paddingRight="20" paddingTop="20"/>
    </s:layout>
    </s:View>

    ```

1.  我们应用程序中用户可以与之交互的控件将包括一个用于输入的`TextInput`，一个用于提交的`Button`，以及一个用于显示我们所有数据库记录的`List`。我们将在按钮点击时调用一个名为`addProduct()`的函数，以及另一个名为`removeProduct()`的函数，该函数与我们的列表更改事件相关联。最后的修改是将我们的`ListdataProvider`绑定到主 MXML 文件中定义的`productArrayCollection`。

    ### 注意

    在此示例中，我们使用`parentApplication`作为方便。根据应用程序的结构，您可能不想这样做，因为它会在应用程序及其各个模块之间创建通常不希望的关系。

    ```kt
    <s:TextInput id="entry" width="100%"/>
    <s:Button click="addProduct(event)" width="100%" label="Insert New Product"/>
    <s:List id="productList" change="removeProduct(event)" dataProvider="{this.parentApplication.productArrayCollection}" labelField="ProductName" width="100%" height="100%"></s:List>

    ```

1.  创建一个`Script`块并导入我们的`List`变更事件正常触发所需的`IndexChangeEvent`类：

    ```kt
    <fx:Script>
    <![
    CDATA[
    import spark.events.IndexChangeEvent;
    ]]>
    </fx:Script>

    ```

1.  现在要做的只剩下创建一些本地函数，以便将信息传递给我们的主 MXML 文件，并执行本地清理任务。首先，我们为`Button`点击事件创建方法，该方法将数据传递给之前创建的`saveProduct()`方法。我们将输入的文本传递过去，然后清空`TextInput`以允许定义更多的记录：

    ```kt
    protected function addProduct(e:MouseEvent):void {
    this.parentApplication.saveProduct(entry.text);
    entry.text = "";
    }

    ```

1.  最后，编写一个函数来处理基于从`List`生成的变更事件删除记录。在`List`上检测到的任何索引变化都会将索引数据传递给之前创建的`deleteProduct()`方法。然后我们将`ListselectedIndex`设置为`-1`，表示没有选择任何项目：

    ```kt
    protected function removeProduct(e:IndexChangeEvent):void {
    this.parentApplication.deleteProduct(e.newIndex);
    productList.selectedIndex = -1;
    }

    ```

1.  当用户在设备上运行我们的应用程序时，他们能够通过原生的 Android 虚拟键盘输入数据。点击**插入新产品**按钮将把他们的信息添加到数据库中：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_08_16.jpg)

1.  用户将能够向数据库添加多条记录，并且它们会立即出现在`List`控件中。点击`List`中的某个项目将触发一个变更事件，从而相应地从应用程序数据库中删除对应的记录：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_08_17.jpg)

## 它的工作原理...

FlexORM 需要一些初始设置，以便在开发应用程序时以对我们有利的方式运行该框架，但一旦一切就绪，对于不那么复杂的数据库，它可以节省大量的时间。而 SQL 在语法或使用上与 ActionScript 完全不同。FlexORM 提供了一个接口，通过这个接口我们可以以面向对象的方式管理数据库记录，使用的语言与我们的应用程序其余部分使用的 ActionScript 相同！

## 还有更多...

FlexORM 对于简单的交易非常适用，但它并不完全支持 SQLite 提供的所有功能。例如，我们不能使用 FlexORM 创建和管理加密的数据库。对于这类特定活动，最好手写查询语句。
