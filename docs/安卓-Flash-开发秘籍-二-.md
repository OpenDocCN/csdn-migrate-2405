# 安卓 Flash 开发秘籍（二）

> 原文：[`zh.annas-archive.org/md5/3A6CCF6F6AAB969F5B96A3C7E7AEF15A`](https://zh.annas-archive.org/md5/3A6CCF6F6AAB969F5B96A3C7E7AEF15A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：视觉和音频输入：相机和麦克风访问

本章将涵盖以下内容：

+   检测相机和麦克风支持

+   使用传统相机 API 保存捕捉到的图像

+   使用移动设备 CameraUI API 保存捕捉到的照片

+   使用移动设备 CameraUI API 保存捕捉到的视频

+   使用设备麦克风监控音频样本数据

+   记录麦克风音频样本数据

# 引言

相机和麦克风是大多数移动设备和 Android 设备上的标准配件。本章将涵盖从访问相机和拍照，录制视频数据，以及从设备麦克风捕获原始音频并将其编码为 WAV 或 MP3 以便在其他平台和系统上使用的一切内容。

本章中的所有示例都表示为纯 ActionScript 3 类，并且不依赖于外部库或 Flex 框架。因此，我们可以使用我们希望的任何 IDE 中的这些示例。

# 检测相机和麦克风支持

几乎所有的 Android 设备都配备了用于捕捉静态图像和视频的相机硬件。现在许多设备都拥有前后置摄像头。了解默认设备相机是否可通过我们的应用程序使用非常重要。我们绝不能假设某些硬件的可用性，无论它们在设备中多么普遍。

同样，当捕捉视频或音频数据时，我们也需要确保能够访问设备麦克风。

## 如何操作...

我们将确定我们的 Android 设备上可用的音频和视频 API：

1.  首先，将以下类导入到您的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.Stage;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.media.Camera;
    import flash.media.CameraUI;
    import flash.media.Microphone;
    import flash.text.TextField;
    import flash.text.TextFormat;

    ```

1.  声明一个`TextField`和`TextFormat`对象对，以允许在设备上可见输出：

    ```kt
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  我们现在将设置我们的`TextField`，应用`TextFormat`，并将`TextField`添加到`DisplayList`中。这里，我们创建一个方法来执行所有这些操作：

    ```kt
    protected function setupTextField():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 44;
    traceFormat.align = "center";
    traceFormat.color = 0x333333;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    addChild(traceField);
    }

    ```

1.  现在，我们必须检查这些对象的`isSupported`属性。我们在这里创建一个方法来对所有三个进行检查，并将结果写入`TextField：`

    ```kt
    protected function checkCamera():void {
    traceField.appendText("Camera: " + Camera.isSupported + "\n");
    traceField.appendText("CameraUI: " + CameraUI.isSupported + "\n");
    traceField.appendText("Microphone: " + Microphone.isSupported + "\n");
    }

    ```

1.  我们现在知道特定设备的视频和音频输入功能，并可以相应地做出反应：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_04_01.jpg)

## 工作原理...

这三个类都拥有一个属性`isSupported`，我们可以随时调用它来验证在特定 Android 设备上的支持情况。传统的`Camera`和针对移动设备的`CameraUI`都指的是同一硬件相机，但它们是处理闪光灯与相机本身交互的完全不同的类，因为`CameraUI`依赖于设备默认相机应用程序完成所有捕捉工作，而`Camera`仅在 Flash 环境中工作。

### 注意

以这种方式也支持传统的`Microphone`对象。

## 还有更多...

需要注意的是，尽管许多 Android 设备配备了不止一个摄像头，但只有主摄像头（和麦克风）会对我们的应用程序可见。随着 Android 的发展，可能会增加对多个摄像头和其他传感器的支持。

# 使用传统的摄像头 API 保存捕捉到的图像

当通过 Flash 播放器为网页编写应用程序，或者为桌面应用使用 AIR 时，我们可以通过 ActionScript 访问`Camera`类。这使得我们可以访问连接到我们使用的任何机器上的不同摄像头。在 Android 上，我们仍然可以使用`Camera`类来访问设备上的默认摄像头，并获取它提供的视频流用于各种事情。在本例中，我们将简单地从`Camera`的输入中抓取一个静态图像，并将其保存到 Android 的`CameraRoll`中。

## 如何操作...

我们将构建一个`Video`对象来绑定`Camera`的流，并使用`BitmapData`方法捕获并保存我们渲染的图像，使用移动设备的`CameraRoll` API：

1.  至少，我们需要将以下类导入到我们的项目中：

    ```kt
    import flash.display.BitmapData;
    import flash.display.Sprite;
    import flash.display.Stage;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.TouchEvent;
    import flash.media.Camera;
    import flash.media.CameraRoll;
    import flash.media.Video;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;

    ```

1.  现在我们必须声明进行摄像头访问和文件引用所需的实例对象：

    ```kt
    private var video:Video;
    private var camera:Camera;
    private var capture:BitmapData;
    private var cameraRoll:CameraRoll;
    private var videoHolder:Sprite;

    ```

1.  初始化一个`Video`对象，传入所需的宽度和高度，并将其添加到`DisplayList`：

    ```kt
    protected function setupVideo():void {
    videoHolder = new Sprite();
    videoHolder.x = stage.stageWidth/2;
    videoHolder.y = stage.stageHeight/2;
    video = new Video(360, 480);
    videoHolder.addChild(video);
    video.x = -180;
    video.y = -240;
    videoHolder.rotation = 90;
    addChild(videoHolder);
    }

    ```

1.  初始化一个`Camera`对象，并使用`setMode`方法来指定宽度、高度和每秒帧数，然后再将`Camera`附加到`DisplayList`上的`Video`：

    ```kt
    protected function setupCamera():void {
    camera = Camera.getCamera();
    camera.setMode(480, 360, 24);
    video.attachCamera(camera);
    }

    ```

1.  我们现在将在`Stage`上注册一个类型为`TOUCH_TAP`的`TouchEvent`监听器。这将使用户可以通过点击设备屏幕来捕获摄像头显示的快照：

    ```kt
    protected function registerListeners():void {
    Multitouch.inputMode = MultitouchInputMode.TOUCH_POINT;
    stage.addEventListener(TouchEvent.TOUCH_TAP, saveImage);
    }

    ```

1.  要从摄像头输入中捕获图像，我们将初始化我们的`BitmapData`对象，使其与`Video`对象的宽度和高度相匹配，并使用`draw`方法将`Video`的像素转换为`BitmapData`。

1.  要将我们获取的图像保存到设备上，我们必须初始化一个`CameraRoll`对象，并调用`addBitmapData()`，传入我们使用`Video`对象像素创建的`BitmapData`对象。我们还将确定此设备是否支持`addBitmapData()`方法，通过验证`CameraRoll.supportsAddBitmapData`是否等于`true`：

    ```kt
    protected function saveImage(e:TouchEvent):void {
    capture = new BitmapData(360, 480);
    capture.draw(video);
    cameraRoll = new CameraRoll();
    if(CameraRoll.supportsAddBitmapData){
    cameraRoll.addBitmapData(capture);
    }
    }

    ```

    ![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_04_02.jpg)

1.  如果我们现在检查我们的 Android 图库，我们会找到保存的图像：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_04_03.jpg)

## 工作原理...

这大部分操作与在桌面上的正常 Flash 平台开发完全相同。将一个`Camera`附加到一个`Video`上，将`Video`添加到`DisplayList`，然后根据你的特定应用程序进行需要的操作。在本例中，我们只是简单地捕获显示的`BitmapData`作为图像。

然而，`CameraRoll`类是特定于移动应用开发的，因为它总是指的是设备相机存储所产生照片的目录。如果你想要将这些图片保存在不同的目录中，我们可以使用`File`或`FileReference`对象来实现，但这需要用户进行更多操作。

注意，在使用`Camera`类时，相机的硬件方向是横屏的。我们可以通过将应用限制为横屏模式，或者像我们在示例类中所做的那样通过旋转和额外的操作来处理这个问题。在这种情况下，我们使用了`videoHolder.rotation`对图像应用了 90 度旋转，以在读取`BitmapData`时考虑这个偏移。具体应用如何处理，可能不需要这样做。

## 还有更多...

传统 Camera 对象的其他用例包括将视频流发送到 Flash Media Server 进行直播，增强现实应用，或者实时点对点聊天。

## 另请参阅...

为了访问相机和存储，我们需要添加一些 Android 权限，分别是`CAMERA`和`WRITE_EXTERNAL_STORAGE`。关于如何进行，请参考第十一章，*最终考虑：应用程序编译和分发*。

# 使用移动端 CameraUI API 保存捕获的照片

使用新的`CameraUI` API（在移动 AIR SDK 中可用），我们可以执行与正常`Camera` API 不同的捕获过程。`Mobile CameraUI`类将利用默认的 Android 相机应用程序以及我们的自定义应用程序来捕获一张照片。

## 如何操作...

我们将设置一个`CameraUI`对象来调用原生的 Android 相机来捕获一张照片：

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.Event;
    import flash.events.MediaEvent;
    import flash.events.TouchEvent;
    import flash.media.CameraUI;
    import flash.media.MediaType;
    import flash.media.MediaPromise;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;
    import flash.text.TextField;
    import flash.text.TextFormat;

    ```

1.  声明一个`TextField`和`TextFormat`对象对，以便在设备上显示输出。这个示例还需要声明一个`CameraUI`对象：

    ```kt
    private var camera:CameraUI;
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  我们现在将设置我们的`TextField`，应用`TextFormat`，并将`TextField`添加到`DisplayList`中。这里，我们创建一个方法来执行所有这些操作：

    ```kt
    protected function setupTextField():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 22;
    traceFormat.align = "center";
    traceFormat.color = 0xFFFFFF;
    traceField = newTextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    addChild(traceField);
    }

    ```

1.  实例化一个新的`CameraUI`实例，它将用于启动设备相机应用程序，并将文件信息返回给我们。如果某个特定设备不支持`CameraUI`对象，则会向我们的`TextField`输出一条消息表示这一点：

    ```kt
    protected function setupCamera():void {
    if(CameraUI.isSupported) {
    camera = new CameraUI();
    registerListeners();
    }else{
    traceField.appendText("CameraUI is not supported...");
    }
    }

    ```

1.  在`CameraUI`对象上添加一个事件监听器，这样我们就可以知道捕获何时完成。我们还将为`Stage`注册一个触摸事件来启动捕获：

    ```kt
    protected function registerListeners():void {
    Multitouch.inputMode = MultitouchInputMode.TOUCH_POINT;
    camera.addEventListener(MediaEvent.COMPLETE, photoReady);
    stage.addEventListener(TouchEvent.TOUCH_TAP, launchCamera);
    }

    ```

1.  要在 Android 设备上使用默认的相机应用，我们需要调用`launch`方法，并传入`MediaType.IMAGE`常量以指定我们希望拍摄一张照片：

    ```kt
    protected function launchCamera(e:TouchEvent):void {
    camera.launch(MediaType.IMAGE);
    }

    ```

1.  现在，默认的安卓相机将初始化，允许用户拍摄照片。用户点击**确定**后，焦点将返回到我们的应用程序。![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_04_04.jpg)

1.  最后，一旦我们完成捕获过程，将触发一个类型为`MediaEvent.COMPLETE`的事件，调用我们的`photoReady`方法。从中我们可以确定有关我们捕获的照片的某些细节。

    ```kt
    protected function photoReady(e:MediaEvent):void {
    var promise:MediaPromise = e.data;
    traceField.appendText("mediaType: " + promise.mediaType + "\n");
    traceField.appendText("relativePath: " + promise.relativePath + "\n");
    traceField.appendText("creationDate: " + promise.file.creationDate + "\n");
    traceField.appendText("extension: " + promise.file.extension + "\n");
    traceField.appendText("name: " + promise.file.name + "\n");
    traceField.appendText("size: " + promise.file.size + "\n");
    traceField.appendText("type: " + promise.file.type + "\n");
    traceField.appendText("nativePath: " + promise.file.nativePath + "\n");
    traceField.appendText("url: " + promise.file.url + "\n");
    }

    ```

1.  输出将类似于这样：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_04_05.jpg)

## 工作原理...

调用`CameraUI.launch`方法将请求安卓设备打开默认的相机应用程序，并允许用户拍照。在完成捕获过程并确认捕获的照片后，焦点将返回到我们的应用程序，同时返回包含在`MediaEvent.COMPLETE`事件对象中的一组关于新文件的数据。

在这一点上，我们的应用程序可以对返回的数据执行各种操作，甚至可以在应用程序中打开文件，假设文件类型可以被运行时加载和显示。

## 还有更多内容...

如果设备没有挂载存储卡，则默认的相机应用程序将不会加载。还需要注意的是，如果在捕获过程中设备内存不足，安卓可能会在过程完成前终止我们的应用程序。

## 另请参阅...

我们将在第五章讨论通过 AIR for Android 应用程序显示图像：*富媒体展示：处理图像、视频和音频。*

# 使用移动 CameraUI API 保存捕获的视频

使用新的`CameraUI` API（在移动 AIR SDK 中可用），我们可以执行与正常`Camera` API 不同的捕获过程。移动`CameraUI`类将利用默认的安卓相机应用程序，以及我们的自定义应用程序来捕获视频。

## 如何操作...

我们将设置一个`CameraUI`对象来调用原生的安卓相机以捕获视频：

1.  首先，将以下类导入到您的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.Event;
    import flash.events.MediaEvent;
    import flash.events.TouchEvent;
    import flash.media.CameraUI;
    import flash.media.MediaPromise;
    import flash.media.MediaType;
    import flash.text.TextField;
    import flash.text.TextFormat;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;

    ```

1.  声明一个`TextField`和`TextFormat`对象对，以允许在设备上可见输出。对于此示例，还必须声明一个`CameraUI`对象：

    ```kt
    private var camera:CameraUI;
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  我们现在将设置我们的`TextField`，应用一个`TextFormat`，并将`TextField`添加到`DisplayList`中。在这里，我们创建一个方法来执行所有这些操作：

    ```kt
    protected function setupTextField():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 22;
    traceFormat.align = "center";
    traceFormat.color = 0xFFFFFF;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    addChild(traceField);
    }

    ```

1.  实例化一个新的`CameraUI`实例，它将用于启动设备相机应用程序并将文件信息返回给我们。如果特定设备不支持`CameraUI`对象，则会在我们的`TextField`中输出一条消息指示这一点。

    ```kt
    protected function setupCamera():void {
    if(CameraUI.isSupported) {
    camera = new CameraUI();
    registerListeners();
    }else{
    traceField.appendText("CameraUI is not supported...");
    }
    }

    ```

1.  向`CameraUI`对象添加一个事件监听器，以便我们知道捕获何时完成。我们还将向`Stage`注册一个触摸事件来启动捕获：

    ```kt
    protected function registerListeners():void {
    Multitouch.inputMode = MultitouchInputMode.TOUCH_POINT;
    camera.addEventListener(MediaEvent.COMPLETE, videoReady);
    stage.addEventListener(TouchEvent.TOUCH_TAP, launchCamera);
    }

    ```

1.  为了在安卓设备上使用默认相机应用程序，我们需要调用`launch`方法，并传入`MediaType.VIDEO`常量以指定我们希望捕获视频文件：

    ```kt
    protected function launchCamera(e:TouchEvent):void {
    camera.launch(MediaType.VIDEO);
    }

    ```

1.  现在，默认的安卓相机将初始化，允许用户拍摄一些视频。当用户点击**确定**后，焦点将返回到我们的应用程序：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_04_06.jpg)

1.  最后，一旦我们完成捕获过程，将触发一个类型为`MediaEvent.COMPLETE`的事件，调用我们的`videoReady`方法。从中我们可以了解有关捕获的视频文件的某些详细信息：

    ```kt
    protected function videoReady(e:MediaEvent):void {
    var promise:MediaPromise = e.data;
    traceField.appendText("mediaType: " + promise.mediaType + "\n");
    traceField.appendText("relativePath: " + promise.relativePath + "\n");
    traceField.appendText("creationDate: " + promise.file.creationDate + "\n");
    traceField.appendText("extension: " + promise.file.extension + "\n");
    traceField.appendText("name: " + promise.file.name + "\n");
    traceField.appendText("size: " + promise.file.size + "\n");
    traceField.appendText("type: " + promise.file.type + "\n");
    traceField.appendText("nativePath: " + promise.file.nativePath + "\n");
    traceField.appendText("url: " + promise.file.url + "\n");
    }

    ```

1.  输出将类似于这样：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_04_07.jpg)

## 工作原理...

调用`CameraUI.launch`方法将请求安卓设备打开默认的相机应用程序，并允许用户捕获一些视频。在完成捕获过程并确认捕获的视频文件后，焦点将连同包含在`MediaEvent.COMPLETE`事件对象中的一组新文件数据一起返回到我们的应用程序。

在这一点上，我们的应用程序可以对返回的数据执行各种操作，甚至可以在应用程序中打开文件，假设文件类型可以被运行时加载和显示。这对于视频来说非常重要，因为某些设备将使用各种编解码器来编码捕获的视频，并非所有这些编解码器都与 Flash 平台兼容。

## 还有更多...

如果设备没有挂载存储卡，则默认相机应用程序将无法加载。还需要注意的是，如果在捕获过程中设备内存不足，安卓可能会在过程完成前终止我们的应用程序。

此外，除了`MediaEvent.COMPLETE`，我们还可以在类似过程中使用许多其他事件。例如，注册一个类型为`Event.CANCEL`的事件监听器，以响应用户取消视频保存。

## 另请参阅...

我们将在第五章中讨论通过 AIR for Android 应用程序播放视频文件。

# 使用设备麦克风监控音频样本数据

通过监控从安卓设备麦克风通过 ActionScript `Microphone` API 返回的样本数据，我们可以收集有关正在捕获的声音的许多信息，并在我们的应用程序内执行响应。这种输入可以用于实用程序、学习模块，甚至游戏。

## 如何操作...

我们将设置一个事件监听器，以响应通过`Microphone` API 报告的样本数据：

1.  首先，将以下类导入到您的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.Stage;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.SampleDataEvent;
    import flash.media.Microphone;
    import flash.text.TextField;
    import flash.text.TextFormat;

    ```

1.  声明一个`TextField`和`TextFormat`对象对，以允许在设备上可见输出。本示例还需要声明一个`Microphone`对象：

    ```kt
    private var mic:Microphone;
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  我们现在将设置`TextField`，应用`TextFormat`，并将`TextField`添加到`DisplayList`中。这里，我们创建一个方法来执行所有这些操作：

    ```kt
    protected function setupTextField():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 44;
    traceFormat.align = "center";
    traceFormat.color = 0x333333;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    addChild(traceField);
    }

    ```

1.  现在，我们必须实例化我们的`Microphone`对象，并根据我们的需求和偏好调整`codec, rate, silenceLevel`等来设置它。这里我们使用`setSilenceLevel()`来确定应用程序应视为“声音”的最小输入水平，并将`rate`属性设置为**44**，表示我们将以 44kHz 的速率捕获音频数据。将`setLoopBack()`属性设置为 false 将防止捕获的音频通过设备扬声器播放：

    ```kt
    protected function setupMic():void {
    mic = Microphone.getMicrophone();
    mic.setSilenceLevel(0);
    mic.rate = 44;
    mic.setLoopBack(false);
    }

    ```

1.  一旦我们实例化了`Microphone`对象，我们就可以注册各种事件监听器。在这个例子中，我们将监控来自设备麦克风的音频采样数据，因此我们需要为`SampleDataEvent.SAMPLE_DATA`常量注册我们的监听器：

    ```kt
    protected function registerListeners():void {
    mic.addEventListener(SampleDataEvent.SAMPLE_DATA, onMicData);
    }

    ```

1.  由于`Microphone` API 从 Android 设备输入生成采样数据，我们现在可以通过多种方式对此做出响应，因为我们能够访问有关`Microphone`对象本身的信息，更重要的是，我们可以访问采样字节，从而执行许多高级操作：

    ```kt
    public function onMicData(e:SampleDataEvent):void {
    traceField.text = "";
    traceField.appendText("activityLevel: " + e.target.activityLevel + "\n");
    traceField.appendText("codec: " + e.target.codec + "\n");
    traceField.appendText("gain: " + e.target.gain + "\n");
    traceField.appendText("bytesAvailable: " + e.data.bytesAvailable + "\n");
    traceField.appendText("length: " + e.data.length + "\n");
    traceField.appendText("position: " + e.data.position + "\n");
    }

    ```

1.  输出将类似于这样。前三个值来自`Microphone`本身，后三个来自`Microphone`采样数据：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_04_08.jpg)

## 它是如何工作的...

当我们实例化一个`Microphone`对象并注册一个`SampleDataEvent.SAMPLE_DATA`事件监听器时，我们可以轻松监控 Android 设备麦克风的各项属性以及正在收集的相关采样数据。然后我们可以以多种方式对这些数据做出响应。一个例子是依据`Microphone.activityLevel`属性在`Stage`上移动对象。另一个例子是将采样数据写入`ByteArray`以便稍后分析。

### 所有这些属性意味着什么？

+   `activityLevel:` 这是一个表示接收到的声音量的测量值

+   `codec:` 这表示正在使用的编解码器：Nellymoser 或 Speex

+   `gain:` 这是麦克风为声音信号提供的增强量

+   `bytesAvailable:` 这揭示了从当前位置到采样数据`byteArray`末尾的字节数量

+   `length:` 让我们知道采样数据`byteArray`的总长度

+   `position:` 这是我们的采样数据`byteArray`中的当前位置，以字节为单位

## 另请参阅...

为了访问麦克风，我们需要添加一些 Android 权限以`RECORD_AUDIO`。有关如何进行此操作的信息，请参考第十一章。

# 记录麦克风音频采样数据

对于开发者来说，使用从 Android 麦克风收集的音频采样数据最基础的事情之一，就是捕获数据并在应用程序中以某种方式使用它。本教程将演示如何保存和回放捕获的麦克风音频采样数据。

## 如何操作...

我们将使用一个事件监听器来响应通过`Microphone` API 报告的样本数据，通过将捕获的音频数据写入`ByteArray`，然后通过`Sound`对象在内部播放：

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.Stage;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.SampleDataEvent;
    import flash.events.TouchEvent;
    import flash.media.Microphone;
    import flash.media.Sound;
    import flash.media.SoundChannel;
    import flash.utils.ByteArray;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;
    import flash.text.TextField;
    import flash.text.TextFormat;

    ```

1.  声明一个`TextField`和`TextFormat`对象对，以便在设备上输出可见内容。这个例子还需要声明一个`Microphone`对象。为了存储和播放样本数据，我们还需要声明一个`ByteArray`，以及一个`Sound`和`SoundChannel`对：

    ```kt
    private var mic:Microphone;
    private var micRec:ByteArray;
    private var output:Sound;
    private var outputChannel:SoundChannel;
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  我们现在将设置`TextField`，应用`TextFormat`，并将`TextField`添加到`DisplayList`中。这里，我们创建一个方法来执行所有这些操作：

    ```kt
    protected function setupTextField():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 44;
    traceFormat.align = "center";
    traceFormat.color = 0x333333;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    addChild(traceField);
    }

    ```

1.  然后，实例化一个`Microphone`对象，并根据我们的需求和偏好调整`codec`、`rate`、`silenceLevel`等来设置它。这里我们使用`setSilenceLevel()`来确定应用程序应考虑的最小输入级别作为“声音”，并将`rate`属性设置为**44**，表示我们将以 44kHz 的速率捕获音频数据。将`setLoopBack()`属性设置为 false 将防止捕获的音频通过设备扬声器播放。我们还将实例化一个`ByteArray`来保存所有拦截到的音频样本：

    ```kt
    protected function setupMic():void {
    mic = Microphone.getMicrophone();
    mic.setSilenceLevel(0);
    mic.rate = 44;
    mic.setLoopBack(false);
    micRec = new ByteArray();
    }

    ```

1.  一旦我们实例化了`Microphone`和`ByteArray`对象，我们就可以注册一个事件监听器来启用触摸交互。一个简单的轻触就足够了：

    ```kt
    protected function registerListeners():void {
    Multitouch.inputMode = MultitouchInputMode.TOUCH_POINT;
    stage.addEventListener(TouchEvent.TOUCH_TAP, startRecording);
    traceField.text = "Tap to Record";
    }

    ```

1.  一旦用户启动录音，我们将监控来自设备麦克风的音频样本数据，因此需要为`SampleDataEvent.SAMPLE_DATA`常量注册我们的监听器：

    ```kt
    protected function startRecording(e:TouchEvent):void {
    stage.removeEventListener(TouchEvent.TOUCH_TAP, startRecording);
    stage.addEventListener(TouchEvent.TOUCH_TAP, stopRecording);
    mic.addEventListener(SampleDataEvent.SAMPLE_DATA, onMicData);
    traceField.text = "Recording Audio \nTap to Stop";
    }

    ```

1.  由于`Microphone` API 从 Android 设备输入生成样本数据，我们可以访问音频样本数据字节，我们可以将其写入`ByteArray`以供以后使用：

    ```kt
    protected function onMicData(e:SampleDataEvent):void {
    micRec.writeBytes(e.data);
    }

    ```

1.  要停止录音，我们需要从`Microphone`对象中移除`SampleDataEvent.SAMPLE_DATA`事件监听器：

    ```kt
    protected function stopRecording(e:TouchEvent):void {
    mic.removeEventListener(SampleDataEvent.SAMPLE_DATA, onMicData);
    stage.removeEventListener(TouchEvent.TOUCH_TAP, stopRecording);
    stage.addEventListener(TouchEvent.TOUCH_TAP, playBackAudio);
    traceField.text = "Tap to Playback";
    }

    ```

1.  为了准备播放，我们将实例化一个新的`Sound`对象，并在其上注册一个`SampleDataEvent.SAMPLE_DATA`事件，就像我们之前对`Microphone`对象所做的那样。我们还将实例化一个`SoundChannel`对象，并调用我们`Sound`对象的`play()`方法来播放捕获的`Microphone`音频：

    ```kt
    protected function playBackAudio(e:TouchEvent):void {
    stage.removeEventListener(TouchEvent.TOUCH_TAP, playBackAudio);
    micRec.position = 0;
    output = new Sound();
    output.addEventListener(SampleDataEvent.SAMPLE_DATA, onSampleDataRequest);
    outputChannel = output.play();
    traceField.text = "Playing Audio";
    }

    ```

1.  当我们对`Sound`对象调用`play()`方法时，它将从名为`onSampleDataRequest`的方法中开始收集生成的样本数据。我们现在需要创建这个方法，并让它遍历我们之前写入`ByteArray`对象的字节，这实际上是我们的捕获过程的反操作。

1.  为了在应用程序中提供适当的播放，我们必须提供 2048 到 8192 个样本数据。建议尽可能使用更多的样本，但这还取决于采样频率。

    ### 注意

    请注意，我们在同一个循环中两次调用`writeFloat()`，因为我们需要将数据表示为立体声对，每个通道一个。

1.  在本例中使用 `writeBytes()` 时，我们实际上是通过 `SampleDataEvent` 和 `Sound` 对象将声音数据输出，从而使应用程序能够产生声音：

    ```kt
    protected function onSampleDataRequest(e:SampleDataEvent):void {
    var out:ByteArray = new ByteArray();
    for(var i:int = 0; i < 8192 && micRec.bytesAvailable; i++ ) {
    var micsamp:Number = micRec.readFloat();
    // left channel
    out.writeFloat(micsamp);
    // right channel
    out.writeFloat(micsamp);
    }
    e.data.writeBytes(out);
    }

    ```

1.  输出到我们的 `TextField` 的内容将根据当前应用程序状态的变化而变化：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_04_09.jpg)

## 工作原理...

当我们实例化一个 `Microphone` 对象并注册一个 `SampleDataEvent.SAMPLE_DATA` 事件监听器时，我们可以轻松监控相关样本数据的收集，并将这些数据写入 `ByteArray` 以便稍后播放。随着新样本的到来，更多的数据被添加到 `ByteArray` 中，随着时间的推移构建声音数据。

通过向 `Sound` 对象注册 `SampleDataEvent.SAMPLE_DATA` 事件监听器，我们指示它在我们调用 `play()` 时主动寻找由特定方法生成的音频数据。在我们的示例中，我们遍历构建的 `ByteArray`并通过此方法将音频数据输出，通过 `Sound` 对象和相关联的 `SoundChannel` 实际播放录制的音频。

## 另请参阅...

ActionScript 中字节的使用是一个复杂的主题。要了解更多关于这个话题的信息，我们推荐 Thibault Imbert 的书 *"你能用字节做什么？"*，该书可在[`www.bytearray.org/?p=711`](http://www.bytearray.org/?p=711)免费获取。

想要阅读关于音频文件播放的配方，请查看第五章。有关将捕获的音频数据保存到 Android 设备的信息，请参考第八章： *丰富访问：文件系统和本地数据库*。


# 第五章：富媒体展示：处理图像、视频和音频

本章节将涵盖以下食谱：

+   从设备 cameraRoll 加载照片

+   将 Pixel Bender 着色器效果应用于加载的图像

+   从本地文件系统或通过 HTTP 播放视频文件

+   通过 RTMP 播放远程视频文件

+   从本地文件系统或通过 HTTP 播放音频文件

+   生成音频频谱可视化器

+   为您的应用程序生成音频音调

# 引言

本章节将包含多种展示图像数据和播放视频及音频流的食谱。这些食谱中包括的例子演示了从设备相机库加载图像的能力，对加载的图像应用 Pixel Bender 着色器，通过不同协议播放音频和视频，以及从声音生成视觉数据和原始声音数据。

Flash 平台作为全球领先的视频分发平台而闻名。在以下几页中，我们将看到这种体验和影响力绝不仅限于桌面和基于浏览器的计算。随着 AIR 2.6 和 Flash Player 10.2 中提供的 StageVideo 等新功能，Flash 正在成为在保持设备电池寿命的同时提供更佳用户体验的更强大的视频交付平台。

# 从设备 cameraRoll 加载照片

安卓操作系统有一个中央存储库，用于存储用户可能安装的各种相机应用程序捕获的照片。AIR for Android 中提供了 API，允许 Flash 开发者专门针对这个存储库进行操作，并在应用程序中显示。

## 如何操作...

我们必须使用移动`CameraRoll` API 直接浏览到设备相机胶卷，并选择一张照片以显示：

1.  首先，将以下类导入到您的项目中：

    ```kt
    import flash.display.Loader;
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.Event;
    import flash.events.MediaEvent;
    import flash.events.TouchEvent;
    import flash.filesystem.File;
    import flash.media.CameraRoll;
    import flash.media.MediaPromise;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;

    ```

1.  声明一个`CameraRoll`对象和一个`Loader`，用于在选定照片后显示照片：

    ```kt
    private var loader:Loader;
    private var cameraRoll:CameraRoll;

    ```

1.  我们将创建我们的`Loader`对象，将其添加到`Stage`中，并注册一个事件监听器，以便在照片加载后适当缩放：

    ```kt
    protected function setupLoader():void {
    loader = new Loader();
    loader.contentLoaderInfo.addEventListener(Event.COMPLETE, sizePhoto);
    stage.addChild(loader);
    }

    ```

1.  对于`CameraRoll`本身，我们需要做的就是实例化它，然后添加一个事件监听器，以便在用户选择要显示的照片时触发。我们应该始终检查设备是否支持`CameraRoll.browseForImage()`，通过检查`supportsBrowseForImage`属性：

    ```kt
    protected function setupCameraRoll():void {
    if(CameraRoll.supportsBrowseForImage){
    cameraRoll = new CameraRoll();
    cameraRoll.addEventListener(MediaEvent.SELECT, imageSelected);
    registerListeners();
    }else{
    trace("CameraRoll does not support browse for image!");
    }
    }

    ```

1.  我们现在将在`Stage`上注册一个类型为`TOUCH_TAP`的`TouchEvent`监听器。这将使用户能够通过轻敲设备屏幕来调用浏览对话框，从`CameraRoll`中选择照片。

    ### 注意

    我们将`Multitouch.inputMode`设置为`MultitouchInputMode.TOUCH_POINT`常量，以便我们的应用程序接受触摸事件。

    ```kt
    protected function registerListeners():void {
    Multitouch.inputMode = MultitouchInputMode.TOUCH_POINT;
    stage.addEventListener(TouchEvent.TOUCH_TAP, loadFromCameraRoll);
    }

    ```

1.  一旦从用户交互中调用了以下方法，我们就可以对我们之前设置的`CameraRoll`对象调用`browseForImage()`方法。这将打开 Android 设备上的默认图库应用，允许用户从他们的收藏中选择一张照片。如果设备上有不止一个图库应用，用户将首先通过一个原生的 Android 对话框选择在这个事件中使用哪一个。我们的应用将失去焦点，这由操作系统处理，一旦做出选择，就会返回到我们的应用。

    ```kt
    protected function loadFromCameraRoll(e:TouchEvent):void {
    cameraRoll.browseForImage();
    }

    ```

1.  在这里，我们可以看到 Android 上的默认图库应用。用户可以在做出选择之前花尽可能多的时间浏览各种收藏和照片。![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_05_01.jpg)

1.  当用户在原生的 Android 图库应用中进行了有效的选择后，焦点将返回到我们的应用，并返回一个包含`MediaPromise`对象的事件。`Loader`类有一个特定的方法`loadFilePromise()`，专门用于这类操作。现在我们将`MediaPromise`通过这个方法传递。

    ```kt
    protected function imageSelected(e:MediaEvent):void {
    var promise:MediaPromise = e.data;
    loader.loadFilePromise(promise);
    }

    ```

1.  一旦我们使用`loadFilePromise()`将`MediaPromise`对象传递给`Loader`，它将被加载到`Stage`上。在这里，我们将执行一个额外的操作，调整`Loader`的大小以适应我们的`Stage`的约束条件。

    ```kt
    protected function sizePhoto(e:Event):void {
    loader.width = stage.stageWidth;
    loader.scaleY = loader.scaleX;
    }

    ```

1.  加载到`Stage`上的结果图像将如下所示：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_05_02.jpg)

# 工作原理…

ActionScript 的`CameraRoll` API 专门针对 Android 设备上的照片存储位置。每当用户进行一些交互，调用我们应用中的`CameraRoll.browseForImage()`方法时，默认的 Android 图库应用将启动，允许用户从他们的收藏中选择一个图像文件。

一旦用户在图库应用中选择了照片，他们将被返回到我们的 AIR for Android 应用，并带有一个`MediaPromise`对象，通过这个对象我们可以确定文件的一些信息，甚至可以直接将照片加载到我们的应用中。

# 还有更多…

在这个例子中，我们探讨了如何从`CameraRoll`将图像加载到`Stage`上的`Loader`中。当然，一旦照片被加载，我们可以对它进行很多操作。关于这方面的例子，请看下一个食谱：*对已加载的图像应用 Pixel Bender 着色器效果*。

# 对已加载的图像应用 Pixel Bender 着色器效果

一旦我们将视觉对象加载到我们的应用程序中，由于这一切都是基于 Flash 的，我们可以进行各种强大的视觉操作。在这个例子中，我们将从本地文件系统加载一个预先选择的照片，然后对其应用各种 Pixel Bender 着色器，极大地改变它的外观。

## 准备工作…

本食谱使用了 Pixel Bender 着色器。你可以在 Adobe Exchange 下载`.pbj`文件，或者创建自己的文件。

如果你决定编写自己的 Pixel Bender 内核，可以从[`www.adobe.com/devnet/pixelbender.html`](http://www.adobe.com/devnet/pixelbender.html)免费下载 Pixel Bender 工具包，并使用它编译各种着色器，以便在 Flash 和 AIR 项目中使用。

该工具包允许你使用 Pixel Bender 内核语言（以前称为 Hydra）编写内核，并提供图像预览和分离属性操作的机制，这些可以暴露给 ActionScript。

![准备就绪…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_05_03.jpg)

要了解关于编写 Pixel Bender 着色器的良好资源，请查看位于[`www.adobe.com/devnet/pixelbender.html`](http://www.adobe.com/devnet/pixelbender.html)的文档。

在这个示例中，我们还引用了 Android 图像库中存在的照片，我们之前使用默认相机应用程序捕获的。你可以做同样的事情，或者将图像文件与应用程序一起打包以便后续引用。

## 如何操作…

我们现在将从本地设备存储中加载一个预定的图像，并对其应用多个 Pixel Bender 着色器：

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.Loader;
    import flash.display.Shader;
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.Event;
    import flash.events.TouchEvent;
    import flash.filters.ShaderFilter;
    import flash.net.URLLoader;
    import flash.net.URLLoaderDataFormat;
    import flash.net.URLRequest;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;

    ```

1.  对于这个示例，我们首先需要声明许多不同的对象。我们将声明一个`String`常量来保存图像的路径和一个`Loader`，用于显示照片。`URLRequest`和`URLLoader`对象对将用于加载我们的`.pbj`文件。`Array`将用于保存我们将要加载的每个`.pbj`的名称。使用`int`来跟踪我们当前从`Array`集合中加载的着色器。最后，声明一个`Shader`和`ShaderFilter`对，以将加载的`.pbj`应用到我们的`Loader`上。

    ```kt
    private const photoURL:String = " {local file path or http address}";
    private var loader:Loader;
    private var urlRequest:URLRequest;
    private var urlLoader:URLLoader;
    private var pbjArray:Array;
    private var currentFilter:int;
    private var shader:Shader;
    private var shaderFilter:ShaderFilter;

    ```

1.  下一步是初始化我们的`Array`，并用我们将要加载到应用程序中的 Pixel Bender 着色器文件引用来填充它。这些文件可以通过 Adobe Exchange、网络上的其他位置获取，或者使用 Pixel Bender 工具包编写：

    ```kt
    protected function setupArray():void {
    pbjArray = new Array();
    pbjArray[0] = "dot.pbj";
    pbjArray[1] = "LineSlide.pbj";
    pbjArray[2] = "outline.pbj";
    }

    ```

1.  然后，我们创建`Loader`对象，将其添加到`Stage`中，并注册一个事件监听器，以便在照片加载后适当缩放：

    ```kt
    protected function setupLoader():void {
    loader = new Loader();
    loader.contentLoaderInfo.addEventListener(Event.COMPLETE, sizePhoto);
    stage.addChild(loader);
    }

    ```

1.  我们现在将为`Loader`注册一个类型为`TOUCH_TAP`的`TouchEvent`监听器。这将允许用户点击加载的图像以循环浏览各种 Pixel Bender 着色器。我们还设置`currentFilter int`为`0`，这将表示我们的`Array`中的第一个位置：

    ```kt
    protected function registerListeners():void {
    Multitouch.inputMode = MultitouchInputMode.TOUCH_POINT;
    loader.addEventListener(TouchEvent.TOUCH_TAP, loadShader);
    currentFilter = 0;
    }

    ```

1.  要将照片加载到`Loader`实例中以便在我们的应用程序中显示，我们将调用`load()`方法，并传入先前声明的`photoURL String`常量以及新的`URLRequest`：

    ```kt
    protected function loadPhotograph():void {
    loader.load(new URLRequest(photoURL));
    }

    ```

1.  文件加载后，我们将执行一个操作，调整`Loader`的大小以适应我们的`Stage`的约束：

    ```kt
    protected function sizePhoto(e:Event):void {
    loader.width = stage.stageWidth;
    loader.scaleY = loader.scaleX;
    }

    ```

1.  加载到`Stage`上的原始图像，在没有应用任何着色器的情况下，将如下所示：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_05_04.jpg)

1.  每当用户在`Loader`实例上执行触摸点击时，此方法将会执行。基本上，我们正在使用之前设置的着色器位置`Array`中的值来设置`URLRequest`，从已记录到`currentFilter`对象的当前索引中提取值。

1.  在我们调用`URLLoader.load()`方法之前，我们必须显式地将`dataFormat`属性设置为`URLLoaderDataFormat.BINARY`常量。这确保了当我们的文件加载时，它被视为二进制文件而不是文本。

1.  注册了一个`Event.COMPLETE`监听器，一旦着色器加载完毕，就会调用`applyFilter`方法。

1.  最后，我们可以递增我们的`currentFilter`值，或者将其设置回`0`，具体取决于我们在`Array`的长度上的位置：

    ```kt
    protected function loadShader(e:TouchEvent):void {
    urlRequest = new URLRequest(pbjArray[currentFilter]);
    urlLoader = new URLLoader();
    urlLoader.dataFormat = URLLoaderDataFormat.BINARY;
    urlLoader.addEventListener(Event.COMPLETE, applyFilter);
    urlLoader.load(urlRequest);
    if(currentFilter < pbjArray.length-1){
    currentFilter++;
    }else{
    currentFilter = 0;
    }
    }

    ```

1.  为了实际将加载的`.pbj`应用到我们的`Loader`上，我们首先将二进制数据分配给一个新的`Shader`对象。然后，这个对象通过`ShaderFilter`的构造函数传递，最后作为一个`Array`应用到我们的`Loader`的`filters`属性上。

    ```kt
    protected function applyFilter(e:Event):void {
    shader = new Shader(e.target.data);
    shaderFilter = new ShaderFilter(shader);
    loader.filters = [shaderFilter];
    }

    ```

1.  当用户点击图像时，我们会遍历可用的 Pixel Bender 着色器，并依次应用到加载的照片上。结果图像循环如下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_05_05.jpg)

## 工作原理...

使用 Pixel Bender 着色器是在应用程序中进行强大视觉处理的一种简单直接的方式。在此配方中，我们将图像加载到`Loader`对象中，构建一个`.pbj`文件引用的`Array`，通过`URLLoader`传递。当用户与加载的图像交互时，我们将加载一个`.pbj`文件，并根据接收到的数据构建一个`Shader`。最后，我们可以基于此对象构建一个`ShaderFilter`，并通过`Loader.filters`属性将其传递给图像。

## 还有更多内容...

在此示例中，我们将探讨如何将图像加载到`Stage`上的`Loader`中，并在用户交互时应用 Pixel Bender 着色器。当然，你可以将这些着色器应用到任何你喜欢的`DisplayObject`上，包括视频！

要找到一个各种 Pixel Bender 文件用于此类示例的好地方，可以访问 Adobe Exchange。访问 Exchange 网站：[`www.adobe.com/exchange`](http://www.adobe.com/exchange)。

# 从本地文件系统或通过 HTTP 播放视频文件

在 Android 设备上，我们拥有完整的 Flash 播放器（和 Adobe AIR），因此视频文件的播放与在桌面上一样简单。主要考虑的是视频是否针对移动设备播放进行了优化。

## 准备工作...

此配方涉及播放与应用程序一起打包的视频文件。我们可以同样轻松地引用 HTTP 地址，甚至是 Android 设备上的本地存储，只要它是可以通过 Flash Platform 运行时播放的文件格式和编解码器。你需要提前准备这个文件。

## 如何操作...

我们将创建一个`Video`对象，将其添加到`Stage`中，并通过基本的`NetConnection`和`NetStream`对来流式传输文件：

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.NetStatusEvent;
    import flash.media.Video;
    import flash.net.NetConnection;
    import flash.net.NetStream;
    import flash.text.TextField;
    import flash.text.TextFormat;

    ```

1.  对于这个配方，我们首先需要声明许多不同的对象。在这种情况下，我们将一个视频文件与应用程序本身打包在一起；我们将声明一个引用这个文件的`String`常量。

1.  下一个对象集合与实际的视频流有关。声明一个`Video`对象以显示通过我们的本地`NetConnection`传入的`NetStream`数据。我们还将声明一个`Object`，以绑定特定的、必要的函数来进行视频播放。

1.  最后，我们将声明一个`TextField`和`TextFormat`对，以将文本消息传递到设备显示屏上：

    ```kt
    private const videoPath:String = "assets/test.m4v";
    private var video:Video;
    private var streamClient:Object;
    private var connection:NetConnection;
    private var stream:NetStream;
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  现在，我们将设置我们的`TextField`，应用一个`TextFormat`，并将其添加到`DisplayList`中。这里，我们创建一个方法来为我们执行所有这些操作：

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
    traceField.mouseEnabled = false;
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    addChild(traceField);
    }

    ```

1.  接下来，设置我们的视频连接；我们将创建一个名为`streamClient`的新对象，我们将使用它将一些辅助函数绑定到我们的流对象上。必须创建一个`Video`对象并将其添加到`DisplayList`中，以便用户实际查看视频流。最后，我们创建一个`NetConnection`，将`streamClient`分配给它的`client`属性，注册一个事件监听器以监控连接状态，然后调用`connect()`方法，传入`null`作为连接参数，因为在这个例子中我们没有使用任何类型的媒体服务器。

1.  我们可能并不总是希望将`Video.smoothing`属性设置为 true；在这种情况下，由于我们不确定视频的确切大小，我们将启用它以平滑通过缩放可能发生的任何潜在图像失真：

    ```kt
    protected function setupVideoConnection():void {
    streamClient = new Object();
    streamClient.onTextData = onTextData;
    streamClient.onMetaData = onMetaData;
    streamClient.onCuePoint = onCuePoint;
    video = new Video();
    video.smoothing = true;
    addChild(video);
    connection = new NetConnection();
    connection.client = streamClient;
    connection.addEventListener(NetStatusEvent.NET_STATUS, onNetStatus);
    connection.connect(null);
    }

    ```

1.  一旦我们确定`NetConnection`已成功连接，以下方法将从我们的`onNetStatus`函数中调用。在这个方法中，创建一个新的`NetStream`对象，通过我们的`NetConnection`流式传输视频。我们还将`streamClient`分配给`client`属性，并注册一个事件监听器以监控流状态。要通过我们的`Video`对象显示流，请使用`attachStream()`方法，并传入我们的`NetStream`对象。现在，只需调用`play()`方法，传入我们的`videoPath`常量，并指向视频文件位置：

    ```kt
    protected function connectStream():void {
    stream = new NetStream(connection);
    stream.addEventListener(NetStatusEvent.NET_STATUS, onNetStatus);
    stream.client = streamClient;
    video.attachNetStream(stream);
    stream.play(videoPath);
    }

    ```

1.  在以下代码片段中定义的`onNetStatus`方法，可以与我们的`NetStream`和`NetConnection`对象一起使用，以便根据返回的不同状态消息做出决策。在这个例子中，我们要么在`NetConnection`成功连接后触发`connectStream`方法，要么在确定`NetStream`播放成功后执行一些缩放和布局。

1.  要查看所有支持的 `NetStatusEvent` 信息代码的完整列表，请访问：[`help.adobe.com/en_US/FlashPlatform/reference/actionscript/3/flash/events/NetStatusEvent.html#info`](http://help.adobe.com/en_US/FlashPlatform/reference/actionscript/3/flash/events/NetStatusEvent.html#info)。

    ```kt
    protected function onNetStatus(e:NetStatusEvent):void {
    traceField.appendText(e.info.code + "\n");
    switch (e.info.code) {
    case "NetConnection.Connect.Success":
    connectStream();
    break;
    case "NetStream.Buffer.Full":
    video.width = stage.stageWidth;
    video.scaleY = video.scaleX;
    traceField.y = video.height;
    break;
    }
    }

    ```

1.  接下来的三个步骤包括绑定到 `NetConnection` 或 `NetStream` 的 `client` 属性的方法。这些方法必须是客户端对象的一部分，否则可能会抛出错误，因为它们是预期的方法。`onTextData` 方法在流式文件中遇到文本时触发：

    ```kt
    public function onTextData(info:Object):void {
    traceField.appendText("Text!\n");
    }

    ```

1.  `onMetaData` 方法在流元数据加载到应用程序中时触发。这为我们提供了许多有用的信息，如流宽度、高度和持续时间：

    ```kt
    public function onMetaData(info:Object):void {
    traceField.appendText("Duration: " + info.duration + "\n");
    traceField.appendText("Width: " + info.width + "\n");
    traceField.appendText("Height: " + info.height + "\n");
    traceField.appendText("Codec: " + info.videocodecid + "\n");
    traceField.appendText("FPS: " + info.videoframerate + "\n");
    }

    ```

1.  `onCuePoint` 方法在流式文件中遇到嵌入的提示点时触发：

    ```kt
    public function onCuePoint(info:Object):void {
    traceField.appendText("Cuepoint!\n");
    }

    ```

1.  结果应用程序的界面将类似于以下屏幕渲染：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_05_06.jpg)

## 工作原理…

整个工作流程与为桌面开发时的流程几乎完全相同。在 Flash 中播放视频时，我们首先必须为 `NetStream` 建立一个 `NetConnection`。一旦 `NetConnection` 连接，我们创建 `NetStream` 并将它们绑定在一起。将 `Video` 对象添加到 `Stage` 将使流可以在我们的设备上观看，只要我们将 `NetStream` 绑定到它上面。此时，我们可以通过简单地调用 `play()` 方法，在 `NetStream` 上播放我们希望的任何文件。

在处理 `NetConnection` 和 `NetStream` 时，我们总是需要创建一些辅助函数。这些函数包括注册事件监听器以检测特定状态事件，以及定义一个自定义的 `client` 属性以及关联的方法，这些方法将符合已建立的工作流程的预期。

## 还有更多…

在这个例子中，我们播放的是与应用程序打包在一起的视频文件。从设备图库播放视频文件也同样简单（假设用于压缩视频的编解码器由 Flash 和 AIR 支持），或者通过无线网络连接从可用位置渐进式地流式传输视频。

通过 Flash Player 或 AIR 播放的视频文件必须是 Flash Platform 运行时支持的类型。

有效的视频文件类型包括：

+   FLV

+   MP4

+   M4V

+   F4V

+   3GPP

Flash Platform 运行时支持 H.264 标准的每个级别和配置文件，并保持对 FLV 的完全支持。然而，针对 Android 推荐的分辨率如下：

+   **4:3 视频：** 640 × 480, 512 × 384, 480 × 360

+   **16:9 视频：** 640 × 360, 512 x 288, 480 × 272

当打包这样一个应用程序时，需要确保包含作为应用程序包一部分分发的文件，可以通过使用 GUI（如果您的 IDE 支持）或者在命令行编译过程中作为额外的文件包含它们。

# 通过 RTMP 播放远程视频流

除了可以通过本地文件系统或远程 HTTP 网络地址播放视频之外，我们还可以使用 Flash 媒体服务器和 RTMP 协议将视频文件流式传输到 Android 设备上。如果可以使用这样的流媒体服务器，那么在将视频部署到移动 Android 设备时可以充分利用它。

## 准备就绪…

本食谱涉及播放一个已经部署在 Flash 媒体服务器上的视频文件。如果你没有生产服务器的访问权限，实际上可以免费设置一个开发者版本的 FMS。想要了解更多关于通过**实时消息传递协议**（**RTMP**）流式传输视频的信息，你可以查看以下资源：[`www.adobe.com/products/flashmediaserver/`](http://www.adobe.com/products/flashmediaserver/)

## 如何操作…

我们将创建一个`Video`对象，将其添加到`Stage`中，并通过`NetConnection`和`NetStream`对通过 RTMP 流式传输文件：

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.NetStatusEvent;
    import flash.media.Video;
    import flash.net.NetConnection;
    import flash.net.NetStream;
    import flash.text.TextField;
    import flash.text.TextFormat;

    ```

1.  对于这个食谱，我们首先需要声明许多不同的对象。在这种情况下，我们使用 Flash 媒体服务器通过 RTMP 进行流式传输；我们将声明一个指向 FMS 应用程序路径的`String`常量。

1.  下一个对象集合与实际的视频流有关。声明一个`Video`对象以显示通过我们的本地`NetConnection`传入的`NetStream`数据。我们还将声明一个`Object`，以绑定特定必要的功能，用于视频播放。

1.  最后，我们将声明一个`TextField`和`TextFormat`对，将文本消息传递到设备显示屏上：

    ```kt
    private const fmsPath:String = "rtmp://fms/vod";
    private var video:Video;
    private var streamClient:Object;
    private var connection:NetConnection;
    private var stream:NetStream;
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  我们现在将设置我们的`TextField`，应用`TextFormat`，并将其添加到`DisplayList`中。在这里，我们创建一个方法来执行所有这些操作：

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
    traceField.mouseEnabled = false;
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    addChild(traceField);
    }

    ```

1.  现在设置我们的视频连接；我们将创建一个名为`streamClient`的新对象，我们将用它将一些辅助函数绑定到我们的流对象上。必须创建一个`Video`对象并将其添加到`DisplayList`中，以便用户实际查看视频流。

1.  最后，我们创建一个`NetConnection`，将其`client`属性分配给`streamClient`，注册一个事件监听器来监控连接状态，然后调用`connect()`方法，传入预定义的`fmsPath`常量作为连接参数。这是因为我们必须在继续之前连接到 Flash 媒体服务器上的这个应用程序实例。

    ```kt
    protected function setupVideoConnection():void {
    streamClient = new Object();
    streamClient.onBWDone = onTextData;
    streamClient.onTextData = onTextData;
    streamClient.onMetaData = onMetaData;
    streamClient.onCuePoint = onCuePoint;
    video = new Video();
    video.smoothing = true;
    addChild(video);
    connection = new NetConnection();
    connection.client = streamClient;
    connection.addEventListener(NetStatusEvent.NET_STATUS, onNetStatus);
    connection.connect(fmsPath);
    }

    ```

1.  一旦我们确定`NetConnection`成功连接，以下方法将从我们的`onNetStatus`函数中调用。在此方法中，创建一个新的`NetStream`对象，通过我们的`NetConnection`流式传输视频。我们还将`streamClient`分配给`client`属性，并注册事件监听器以监控流状态。

1.  要通过我们的`Video`对象显示流，请使用`attachStream()`方法，并传入我们的`NetStream`对象。

1.  现在，只需调用`play()`方法，传入一个标识特定流或文件的`String`，通过 RTMP 播放。你会注意到，由于我们使用基于 H.264 的文件格式，因此必须以`mp4:`为流名称前缀。如果是直播或通过 FLV 流式传输，则不需要前缀。

    ```kt
    protected function connectStream():void {
    stream = new NetStream(connection);
    stream.addEventListener(NetStatusEvent.NET_STATUS, onNetStatus);
    stream.client = streamClient;
    video.attachNetStream(stream);
    stream.play("mp4:test.m4v");
    }

    ```

1.  `onNetStatus`方法，如以下代码片段中定义的，可以与我们的`NetStream`和`NetConnection`对象一起使用，以便根据返回的不同状态消息做出决策。在这个例子中，我们要么在`NetConnection`成功连接后触发`connectStream`方法，要么在确定`NetStream`正在成功播放后执行一些缩放和布局操作：

    ```kt
    protected function onNetStatus(e:NetStatusEvent):void {
    traceField.appendText(e.info.code + "\n");
    switch (e.info.code) {
    case "NetConnection.Connect.Success":
    connectStream();
    break;
    case "NetStream.Buffer.Full":
    video.width = stage.stageWidth;
    video.scaleY = video.scaleX;
    traceField.y = video.height;
    break;
    }
    }

    ```

1.  下三个步骤包括绑定到`NetConnection`或`NetStream`的客户端属性的方法。这些方法必须作为客户端对象的一部分存在，否则可能会抛出错误，因为它们是预期的方法。`onBWDone`方法特别适用于通过 RTMP 传输的文件。它会在流媒体服务器完成对客户端可用带宽的估算后触发。

    ```kt
    public function onBWDone():void {
    traceField.appendText("BW Done!\n");
    }

    ```

1.  `onTextData`方法在流文件中遇到文本时触发。

    ```kt
    public function onTextData(info:Object):void {
    traceField.appendText("Text!\n");
    }

    ```

1.  `onMetaData`方法在流元数据加载到应用程序时触发。这为我们提供了许多有用的信息，如流宽度、高度和持续时间：

    ```kt
    public function onMetaData(info:Object):void {
    traceField.appendText("Duration: " + info.duration + "\n");
    traceField.appendText("Width: " + info.width + "\n");
    traceField.appendText("Height: " + info.height + "\n");
    traceField.appendText("Codec: " + info.videocodecid + "\n");
    traceField.appendText("FPS: " + info.videoframerate + "\n");
    }

    ```

1.  `onCuePoint`方法在流文件中遇到嵌入的提示点时触发：

    ```kt
    public function onCuePoint(info:Object):void {
    traceField.appendText("Cuepoint!\n");
    }

    ```

1.  生成的应用程序将类似于以下屏幕渲染：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_05_07.jpg)

## 它的工作原理…

在回放 RTMP 流时，我们首先必须为`NetStream`建立一个`NetConnection`以便传输。`NetConnection`将尝试连接到在 Flash 媒体服务器地址上定义的特定应用程序。一旦`NetConnection`连接，我们创建`NetStream`并将它们绑定在一起。将`Video`对象添加到`Stage`将使流可以在我们的设备上观看，只要我们将`NetStream`附加到它上面。此时，我们可以通过简单地调用`play()`方法，在`NetStream`上播放我们希望的任何文件。

在处理`NetConnection`和`NetStream`时，总是需要创建许多辅助函数。这些函数包括注册事件监听器以检测特定状态事件，以及定义一个自定义`client`属性和关联的方法，这些方法将由已建立的工作流程预期。

## 还有更多内容...

在此示例中，我们通过 Flash Media Server 在互联网上通过 RTMP 位置流式传输视频文件。你可以使用相同的技术通过 RTMP 流式传输音频文件，或者编写一个使用设备摄像头视频聊天应用程序。虽然这里我们演示了如何从零开始生成一个`Video`对象，但请记住，还有各种组件解决方案可供选择，例如随 Flash Professional 提供的`FLVPlayBack`控件以及 Flex 框架中的`VideoDisplay`和`VideoPlayer`组件。这项技术有着无限的可能性！

# 从本地文件系统或通过 HTTP 播放音频文件

通过 Android 设备上的 Flash Platform 运行时播放音频文件相当直接。我们可以指向与应用程序捆绑的文件，正如本配方所示，设备存储上的文件，或者远程网络连接上的文件。无论文件位于何处，播放都是通过相同的方式完成的。

## 如何操作...

我们必须将音频文件加载到`Sound`对象中，然后才能操作播放、音量、声道平衡等属性。在此配方中，我们将允许用户通过旋转一个基本的旋钮来控制音量：

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.TransformGestureEvent;
    import flash.media.Sound;
    import flash.media.SoundChannel;
    import flash.media.SoundTransform;
    import flash.net.URLRequest;
    import flash.text.TextField;
    import flash.text.TextFormat;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;

    ```

1.  对于这个配方，我们前端必须声明许多不同的对象。我们将从声音对象组开始，包括`Sound`、`SoundChannel`和`SoundTransform`。这些对象将允许我们完全控制此配方的音频。我们还将创建一个`Sprite`，作为用户交互点。最后，我们将声明一个`TextField`和`TextFormat`对，将文本消息传递到设备显示屏上：

    ```kt
    private var sound:Sound;
    private var channel:SoundChannel;
    private var sTransform:SoundTransform;
    private var dial:Sprite;
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  我们现在将设置我们的`TextField`，应用一个`TextFormat`，并将其添加到`DisplayList`中。这里，我们创建一个方法来执行所有这些操作：

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
    traceField.mouseEnabled = false;
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    addChild(traceField);
    }

    ```

1.  为了创建音量旋钮，我们将初始化一个新的`Sprite`对象，并使用`graphics` API 在其内部绘制一个旋钮的表示。然后，我们将这个`Sprite`添加到`Stage`中：

    ```kt
    protected function setupDial():void {
    dial = new Sprite();
    dial.graphics.beginFill(0xFFFFFF, 1);
    dial.x = stage.stageWidth/2;
    dial.y = stage.stageHeight/2;
    dial.graphics.drawCircle(0,0,150);
    dial.graphics.endFill();
    dial.graphics.lineStyle(5,0x440000);
    dial.graphics.moveTo(0, -150);
    dial.graphics.lineTo(0, 0);
    addChild(dial);
    }

    ```

1.  现在，我们将开始设置与音频相关的对象。初始化我们的`Sound`对象，并通过`URLRequest`将一个`MP3`文件加载到其中。

1.  接下来，我们将通过创建一个`SoundTransform`并将`0.5`作为`volume`值（在 ActionScript 中注册的范围是`0 - 1`）传递给音量，将声音的初始音量设置为 50%。

1.  为了播放`Sound`，我们将创建一个`SoundChannel`对象，将我们的`SoundTransform`分配给它的`soundTransform`属性，并通过`Sound.Play()`方法最终设置`SoundChannel`：

    ```kt
    protected function setupSound():void {
    sound = new Sound();
    sound.load(new URLRequest("assets/test.mp3"));
    sTransform = new SoundTransform(0.5, 0);
    channel = new SoundChannel();
    channel.soundTransform = sTransform;
    channel = sound.play();
    traceField.text = "Volume: " + sTransform.volume;
    }

    ```

1.  通过将`Multitouch.inputMode`设置为`MultitouchInputMode.GESTURE`常量，为多点触控 API 设置特定的输入模式以支持触摸输入。我们还将为`Sprite`注册一个`TransformGestureEvent.GESTURE_ROTATE`事件的监听器，以截获用户交互：

    ```kt
    protected function registerListeners():void {
    Multitouch.inputMode = MultitouchInputMode.GESTURE; dial.addEventListener(TransformGestureEvent. GESTURE_ROTATE, onRotate);
    }

    ```

1.  当用户旋转`Sprite`时，我们希望相应地调整播放音量。为了实现这一点，我们将根据手势事件收到的数据调整`Sprite`的旋转。然后我们可以将`Sprite`的旋转转换为一个有效的`音量数字`，并修改`SoundTransform`以反映这一点，这将提高或降低我们的音频音量：

    ```kt
    protected function onRotate(e:TransformGestureEvent):void {
    dial.rotation += e.rotation;
    sTransform.volume = (dial.rotation+180)/360;
    channel.soundTransform = sTransform;
    traceField.text = "Volume: " + sTransform.volume;
    }

    ```

1.  生成的应用程序将类似于以下屏幕渲染：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_05_08.jpg)

## 它是如何工作的…

我们通过`URLRequest`将音频文件加载到 ActionScript 中的`Sound`对象中，以便我们的应用程序可以使用它。通过调用`Sound`上的`play()`方法可以实现简单的播放，但我们通过将声音播放分配给`SoundChannel`对象可以保留更多的控制权，因为我们可以通过构建和分配`SoundTransform`对象来控制诸如立体声声像和音量等方面。在这个食谱中，我们修改了`SoundTransform`的音量，然后将其分配给正在播放我们`Sound`的`SoundChannel.soundTransform`属性，从而改变声音。

## 还有更多…

在这个例子中，我们播放的是与应用程序打包在一起的文件。从设备文件系统播放音频文件（假设 Flash 和 AIR 支持用于压缩音频的编解码器）或者通过 HTTP 从网络连接可访问的位置渐进式流式传输文件也同样简单。

通过 Flash Player 或 AIR 播放的音频文件必须是 Flash Platform 运行时支持的类型。

有效的音频格式包括：

+   FLV

+   MP3

+   AAC+

+   HE-AAC

+   AAC v1

+   AAC v2

当打包这样的应用程序时，需要确保包含作为应用程序包一部分分发的文件，如果你的 IDE 支持，可以通过 GUI 包含它们，或者在命令行编译过程中作为额外的文件包含。

# 生成音频频谱可视化器

在播放音频时能够生成某种视觉反馈对用户非常有用，因为他们将能够看到即使设备音量被静音或调低，播放仍在进行。从音频生成视觉在某些游戏中或在监控音频输入水平时也很有用。

## 如何操作…

我们将一个`MP3`文件加载到一个`Sound`对象中。通过使用`SoundMixer.computeSpectrum()`方法，我们可以访问实际正在播放的字节，并使用`Sprite graphics` API 用这些数据构建可视化：

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.TimerEvent;
    import flash.media.Sound;
    import flash.media.SoundChannel;
    import flash.media.SoundMixer;
    import flash.net.URLRequest;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;
    import flash.utils.ByteArray;
    import flash.utils.Timer;

    ```

1.  对于这个配方，我们首先需要声明许多不同的对象。我们将从`Sound`和`SoundChannel`声音对象对开始。这些对象将使我们能够完全控制这个配方的音频。我们还将创建一个`Sprite`对象，它将作为绘制音频频谱数据的画布。最后，我们将声明一个`Timer`，以便每隔几毫秒刷新声音频谱可视化：

    ```kt
    private var sound:Sound;
    private var channel:SoundChannel;
    private var spectrum:Sprite;
    private var timer:Timer;

    ```

1.  为了构建我们将绘制可视化元素的画布，我们必须初始化一个`Sprite`，在`graphics` API 上定义特定的线条样式，并将其添加到`Stage`上：

    ```kt
    protected function setupSpectrum():void {
    spectrum = new Sprite();
    addChild(spectrum);
    }

    ```

1.  我们将使用`Timer`来确定我们将在容器`Sprite`中刷新可视化的频率。在这种情况下，我们将它设置为每 100 毫秒触发一次`TIMER`事件，也就是每秒 10 次。

    ```kt
    protected function registerTimer():void {
    timer = new Timer(100);
    timer.addEventListener(TimerEvent.TIMER, onTimer);
    }

    ```

1.  现在我们将开始设置我们的音频相关对象。初始化我们的`Sound`并通过`URLRequest`加载一个`MP3`文件。为了播放`Sound`，我们将创建一个`SoundChannel`对象，将我们的`SoundTransform`分配给它的`soundTransForm`属性，并最终通过`Sound.Play()`方法设置`SoundChannel`。现在我们的`Sound`已经加载并准备就绪，我们可以开始运行我们的`Timer`。

    ```kt
    protected function setupSound():void {
    sound = new Sound();
    sound.load(new URLRequest("assets/test.mp3"));
    channel = new SoundChannel();
    channel = sound.play();
    timer.start();
    }

    ```

1.  最后，构建一个类似于以下的方法，该方法将从全局 Flash `SoundMixer`中提取字节数据，并使用`graphics` API 基于这些数据绘制可视化。我们首先初始化此方法中将要使用的几个变量，并运行`SoundMixer`类中的`computeSpectrum()`。这将用创建我们的视觉效果所需的所有声音样本数据填充我们的`ByteArray`。

1.  在遍历数据时，我们可以使用`graphics` API 在我们的`Sprite`容器中绘制线条、圆形或任何我们想要的内容。在这个例子中，我们绘制一系列线条以创建频谱可视化。由于这被设置为每 100 毫秒更新一次，因此它成为播放声音的持续变化的视觉指示器。

    ```kt
    protected function onTimer(e:TimerEvent):void {
    var a:Number = 0;
    var n:Number = 0;
    var i:int = 0;
    var ba:ByteArray = new ByteArray();
    SoundMixer.computeSpectrum(ba);
    spectrum.graphics.clear();
    spectrum.graphics.lineStyle(4, 0xFFFFFF, 0.8, false);
    spectrum.graphics.moveTo(0, (n/2)+150);
    for(i=0; i<=256; i++) {
    a = ba.readFloat();
    n = a*300;
    spectrum.graphics.lineTo(i*(stage.stageWidth/256), (n/2)+150);
    }
    spectrum.graphics.endFill();
    }

    ```

1.  结果应用程序将类似于以下屏幕渲染：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_05_09.jpg)

## 它的工作原理…

`SoundMixer`类提供了对`computeSpectrum()`方法的访问，该方法能够捕获通过 Flash Player 或 AIR 播放的任何声音的快照，并将其写入一个`ByteArray`对象。共有 512 个`Number`值写入`ByteArray`；前 256 个代表左声道，剩下的 256 个代表右声道。根据您需要的可视化类型，可能不需要全部 512 个值，正如本例所示。

为了生成确定使用图形 API 绘制线条位置的价值，我们使用`ByteArray.readFloat()`，它从字节数据流中读取一个 32 位的浮点值，并将其转换为一个`Number`。由于这个值表示该特定样本的具体声音数据，我们可以使用它通过图形 API 绘制一系列线条，形成我们的可见频谱。

## 还有更多…

你可以通过简单的搜索在网上找到大量的方法和公式。这种生成性可视化的可能性确实是无限的，但在决定将任何可视化引擎推进多远时，我们必须考虑到这些设备上低于正常的硬件规格。

# 为你的应用程序生成音频音调

在应用程序中打包大量的声音文件是一种包含音频的方法。另一种方法是运行时生成声音数据。在这个配方中，我们将生成一些简单的正弦音调，这些音调根据检测到的触摸压力而变化。

## 如何操作…

我们将探讨如何根据用户的触摸压力生成音频样本字节数据，并将其输入到`Sound`对象中以产生各种音调：

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.SampleDataEvent;
    import flash.events.TouchEvent;
    import flash.media.Sound;
    import flash.media.SoundChannel;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;
    import flash.utils.ByteArray;
    import flash.text.TextField;
    import flash.text.TextFormat;

    ```

1.  对于这个配方，我们首先必须声明多个不同的对象。我们将从由`Sound`和`SoundChannel`组成的声波对象对开始。这些对象将允许我们对这个配方的音频进行完全控制。我们还将创建一个`Number`，用来通过用户触摸获取压力信息。最后，我们将声明一个`TextField`和`TextFormat`对，用于在设备显示屏上传递文本消息：

    ```kt
    private var sound:Sound;
    private var channel:SoundChannel;
    private var touchPressure:Number;
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  我们现在将设置我们的`TextField`，应用一个`TextFormat`，并将其添加到`DisplayList`中。这里，我们创建一个方法来执行所有这些操作：

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
    traceField.mouseEnabled = false;
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    addChild(traceField);
    }

    ```

1.  现在我们将开始设置与音频相关的对象。初始化一个`Sound`和`SoundChannel`对象对。这些将在后面用来回放我们生成的音频数据：

    ```kt
    protected function setupSound():void {
    sound = new Sound();
    channel = new SoundChannel();
    }

    ```

1.  将多点触控 APIs 的特定输入模式设置为通过将`Multitouch.inputMode`设置为`MultitouchInputMode.TOUCH_POINT`常量来支持触摸输入。我们还将为`SampleDataEvent.SAMPLE_DATA`事件注册一个监听器，一旦我们通过先前建立的`SoundChannel`让`Sound`对象`play()`，这些请求就会开始。

    ```kt
    protected function registerListeners():void {
    Multitouch.inputMode = MultitouchInputMode.TOUCH_POINT;
    stage.addEventListener(TouchEvent.TOUCH_BEGIN, onTouch);
    sound.addEventListener(SampleDataEvent.SAMPLE_DATA, onSampleDataRequest);
    channel = sound.play();
    }

    ```

1.  每当检测到触摸事件时，我们将会通过以下方法来监控它。基本上，我们修改`touchPressure Number`，这将用于计算我们的正弦波生成：

    ```kt
    protected function onTouch(e:TouchEvent):void {
    touchPressure = e.pressure;
    traceField.text = "Pressure: " + touchPressure;
    }

    ```

1.  我们最后的方法将在当前播放的`Sound`对象请求新的样本数据以回放时执行。我们将使用`ByteArray.writeFloat()`方法将生成的音频数据发送回我们的`Sound`对象，在每个样本请求时进行回放：

    ```kt
    protected function onSampleDataRequest(e:SampleDataEvent):void {
    var out:ByteArray = new ByteArray();
    for( var i:int = 0 ; i < 8192; i++ ) { out.writeFloat(Math.sin((Number(i+e.position)/ Math.PI/2))*touchPressure);
    out.writeFloat(Math.sin((Number(i+e.position)/ Math.PI/2))*touchPressure);
    }
    e.data.writeBytes(out);
    }

    ```

1.  结果应用程序将根据通过触摸施加的压力量产生可变音调，并且应该类似于以下屏幕渲染：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_05_10.jpg)

## 它是如何工作的…

当注册了`SampleDataEvent`事件监听器的 ActionScript `Sound`对象在播放启动时，它将作为一个插座。我们必须通过一个函数提供样本数据，这个函数生成数据，并将样本传递给等待的`Sound`对象。样本的数量可以在 2048 到 8192 之间变化，在这种情况下，我们尽可能提供多的样本数据。Adobe 提供的生成正弦波的通用公式是：`Math.sin((Number(loopIndex+SampleDataEvent.position)/Math.PI/2))`乘以 0.25。由于我们是根据记录的触摸点压力修改公式，所以我们用这个记录的值来代替乘数。这改变了应用程序产生的音频输出。

## 还有更多内容...

对于更可控的生成声音库，存在 ActionScript 库，可以免费使用，或者根据库的不同可能需要付费。我建议查看一下[Sonoport](http://www.sonoport.com/)。


# 第六章：结构适应性：处理设备布局和缩放

本章将涵盖以下内容：

+   检测可用的屏幕边界和分辨率

+   检测屏幕方向变化

+   在运行时跨设备缩放视觉元素

+   在 Flash Professional CS5.5 中基于舞台大小调整视觉元素

+   在 Flash Professional CS5.5 中使用项目面板

+   将 Flex 应用程序锁定为横屏或竖屏模式

+   定义一个空的 Flex 移动应用程序

+   定义一个基于视图的 Flex 移动应用程序

+   定义一个具有多个部分的 Flex 移动标签应用程序

+   在 Flex 移动应用程序中使用启动画面

+   在 Flex 移动项目中配置 ActionBar 以与 ViewNavigator 一起使用

+   在 Flex 移动项目中为单一视图隐藏 ActionBar 控件

+   在 Flex 移动项目中所有视图中隐藏 ActionBar 控件

# 简介

由于运行 Android 系统的硬件设备种类繁多，开发在不同分辨率下都能正确显示和运行的应用程序可能是一项挑战。幸运的是，Flash 平台非常适合这项工作。无论是使用 Flex SDK 中的默认布局机制，还是编写自己的布局和缩放逻辑，都有许多需要考虑的事项。

在本章中，我们将探讨在使用 Flex 框架进行移动应用程序开发时处理布局机制的问题，并探索纯 ActionScript 项目的各种注意事项。

# 检测可用的屏幕边界和分辨率

当为桌面或笔记本电脑制作应用程序时，我们不必过多考虑我们实际可用的屏幕空间，或者 **每英寸像素(PPI)** 分辨率。我们可以假设至少有一个 1024x768 的屏幕供我们使用，并且我们可以确定这是一个 72 PPI 的显示。对于移动设备来说，这一切都不同了。

对于移动设备显示屏，我们的应用程序基本上可以是全屏或几乎全屏；也就是说，除了通知栏。这些设备屏幕的大小可以从仅仅几像素到几百像素不等。然后，我们还必须考虑不同的宽高比以及屏幕肯定能显示 250 PPI 或更高的事实。我们必须有一套新的检查机制，以便根据设备进行应用程序布局的修改。

## 如何操作…

在运行时，我们可以监控许多设备功能，并通过调整屏幕上的各种视觉元素做出反应：

1.  首先，将以下类导入到您的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.system.Capabilities;
    import flash.text.TextField;
    import flash.text.TextFormat;

    ```

1.  我们现在将声明一个`TextField`和`TextFormat`组合，以将文本消息传递到设备显示屏上：

    ```kt
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  现在，我们将继续设置我们的 `TextField`，应用一个 `TextFormat`，并将其添加到 `DisplayList` 中。在这里，我们创建一个方法来为我们执行所有这些操作：

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
    traceField.mouseEnabled = false;
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    addChild(traceField);
    }

    ```

1.  最后一步是创建一个方法来收集我们进行任何进一步布局修改或 UI 组件所需的所有数据。在这个例子中，我们读取`Stage.stageHeight`和`Stage.stageWidth`以获取可用区域。我们可以将其与`Capabilities.screenResolutionX`和`Capabilities.screenResolutionY`进行比较，以获取实际的显示分辨率。

1.  其他重要信息包括`Capabilities.touchscreenType`以确定触摸屏是预期使用手指还是触笔，`Capabilities.pixelAspectRatio`以获取像素宽高比（尽管这通常是 1:1），以及最重要的是我们使用`Capabilities.screenDPI`来发现显示器的 PPI 测量值：

    ```kt
    protected function readBounds():void {
    traceField.appendText("Stage Width: " + stage.stageWidth + "\n");
    traceField.appendText("Stage Height: " + stage.stageHeight + "\n");
    traceField.appendText("Pixel AR: " + Capabilities.pixelAspectRatio + "\n");
    traceField.appendText("Screen DPI: " + Capabilities.screenDPI + "\n");
    traceField.appendText("Touch Screen Type: " + Capabilities.touchscreenType + "\n");
    traceField.appendText("Screen Res X: " + Capabilities.screenResolutionX + "\n");
    traceField.appendText("Screen Res Y: " + Capabilities.screenResolutionY);
    }

    ```

1.  结果应用程序将显示如下截图所示：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_06_01.jpg)

## 工作原理…

通过`flash.display.Stage`和`flash.system.Capabilities`类，我们可以了解很多关于应用程序正在运行的特定设备显示屏的信息，并让应用程序以某种方式对此作出反应。在这个例子中，我们将收集到的信息输出到一个`TextField`中，但这些数据也可以用来根据`Stage`分辨率调整视觉元素的位置、大小或布局。

# 检测屏幕方向变化

由于大多数 Android 设备至少有两种屏幕方向，即纵向和横向，因此在为这些设备开发时，了解当前的屏幕方向以正确显示应用程序用户界面元素是非常有用的。

## 如何操作…

我们将在我们的`Stage`上注册一个事件监听器，以监听`StageOrientationEvent`的变化：

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageOrientation;
    import flash.display.StageScaleMode;
    import flash.events.StageOrientationEvent;
    import flash.text.TextField;
    import flash.text.TextFormat;

    ```

1.  我们现在将声明一个`TextField`和`TextFormat`对，以将文本信息传递到设备显示屏上：

    ```kt
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  现在，我们将继续设置我们的`TextField`，应用一个`TextFormat`，并将其添加到`DisplayList`中。这里，我们创建了一个方法来执行所有这些操作：

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
    traceField.mouseEnabled = false;
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    addChild(traceField);
    }

    ```

1.  下一步将注册一个事件监听器，以检测屏幕方向的变化。我们通过在`Stage`上监听`StageOrientationEvent.ORIENTATION_CHANGE`事件来实现这一点：

    ```kt
    protected function registerListeners():void {
    stage.addEventListener(StageOrientationEvent.ORIENTATION_CHANGE, onOrientationChange);
    }

    ```

1.  当检测到`StageOrientationEvent.ORIENTATION_CHANGE`事件时，它将调用一个名为`onOrientationChange`的方法。我们将创建这个方法，并使用它将表示新方向的文本常量写入`TextField`。我们还将在此处调用一个方法来调整我们的布局：

    ```kt
    protected function onOrientationChange(e:StageOrientationEvent):void {
    traceField.appendText(e.afterOrientation+"\n");
    reformLayout();
    }

    ```

1.  最后，我们将使用`reformLayout`方法调整屏幕上的任何视觉组件以匹配我们新的`Stage`尺寸。这里，我们简单调整了我们的`TextField`对象的大小：

    ```kt
    protected function reformLayout():void {
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    }

    ```

1.  结果应用程序将显示如下截图所示：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_06_01_2.jpg)

## 工作原理…

基本上，这是一个简单的事件监听器，与具有各种可能方向设置的设备相关联。我们在`Stage`上注册类型为`StageOrientationEvent.ORIENTATION_CHANGE`的事件监听器，并接收两个重要数据返回：`StageOrientationEvent.beforeOrientation`和`StageOrientationEvent.afterOrientation`。这些事件结果中包含的值将报告设备方向常量。

有四个可能被报告的常量：

1.  `StageOrientation.DEFAULT`

1.  `StageOrientation.ROTATED_LEFT`

1.  `StageOrientation.ROTATED_RIGHT`

1.  `StageOrientation.UPSIDE_DOWN`

再次强调，这些只是可能性。有些设备不支持这四个常量中的所有，因此我们必须谨慎，不能想当然。

## 还有更多内容…

实际上，有多种方法可以检测屏幕方向变化。一种是通过`Timer`监控`Stage.orientation`并相应地做出反应。另一种涉及测试`Accelerometer`值以检测方向变化。然而，使用`StageOrientationEvent`是最直接的方法，它为我们提供了事件触发前后的方向信息，这非常有用。

## 另请参阅…

若想了解如何通过`Accelerometer` API 完成类似任务，请参阅第三章，*空间移动：加速度计和地理定位传感器。*

# 在运行时跨设备缩放视觉元素

安卓设备间广泛的每英寸像素（PPI）测量和整体屏幕分辨率差异，使得在创建视觉元素时，特别是在制作交互式元素时，难以进行大小和布局决策。一般认为，一个半英寸的物理测量正方形是便于用户用指尖触摸的理想大小。在本教程中，我们将演示如何确保在设备间保持相同的物理规格。

## 如何操作…

我们将在屏幕上创建一些视觉元素，这些元素的大小基于检测到的设备显示 PPI 进行物理测量：

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.Shape;
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.display.StageOrientation;
    import flash.events.StageOrientationEvent;
    import flash.system.Capabilities;

    ```

1.  下一步将是声明将在我们的应用程序中使用的一些对象。我们将创建三个`Shape`对象，用于演示这种特定的布局和大小调整技术。同时，我们还设置两个`Number`对象，用于在确定应用程序中的大小和位置时保存特定的测量值：

    ```kt
    private var boxTopLeft:Shape;
    private var boxTopRight:Shape;
    private var boxBottom:Shape;
    private var halfInch:Number;
    private var fullInch:Number;

    ```

1.  现在，我们必须将我们的视觉元素绘制到`Stage`上。如前所述，我们的目标是物理分辨率为半英寸作为最小测量值。因此，我们首先进行计算，以确定半英寸和一英寸在像素中的表示。

1.  我们将在左上角创建一个方块，在右上角创建另一个方块；每个方块都是半英寸见方，并根据可用的`Stagewidth`和`height`进行定位。在屏幕最底部将放置一个更大的方块，其宽度将延伸至`Stage`的整个宽度：

    ```kt
    protected function setupBoxes():void {
    halfInch = Capabilities.screenDPI * 0.5;
    fullInch = Capabilities.screenDPI * 1;
    boxTopLeft = new Shape();
    boxTopLeft.graphics.beginFill(0xFFFFFF, 1);
    boxTopLeft.x = 0;
    boxTopLeft.y = 0;
    boxTopLeft.graphics.drawRect(0, 0, halfInch, halfInch);
    boxTopLeft.graphics.endFill();
    addChild(boxTopLeft);
    boxTopRight = new Shape();
    boxTopRight.graphics.beginFill(0xFFFFFF, 1);
    boxTopRight.x = stage.stageWidth - halfInch;
    boxTopRight.y = 0;
    boxTopRight.graphics.drawRect(0, 0, halfInch, halfInch);
    boxTopRight.graphics.endFill();
    addChild(boxTopRight);
    boxBottom = new Shape();
    boxBottom.graphics.beginFill(0xFFFFFF, 1);
    boxBottom.x = 0;
    boxBottom.y = stage.stageHeight - fullInch;
    boxBottom.graphics.drawRect(0, 0, stage.stageWidth, fullInch);
    boxBottom.graphics.endFill();
    addChild(boxBottom);
    }

    ```

1.  在`Stage`上注册一个类型为`StageOrientationEvent.ORIENTATION_CHANGE`的事件监听器。这将检测设备方向变化并通知我们，以便我们可以适当地调整和重新定位视觉元素：

    ```kt
    protected function registerListeners():void { stage.addEventListener(StageOrientationEvent.ORIENTATION_CHANGE, onOrientationChange);
    }

    ```

1.  以下方法将在我们的应用程序检测到每次方向变化时触发。在这种情况下，我们并不太关心当前的实际方向是什么，但会重新定位（必要时重新调整大小）`Stage`上的任何视觉元素，以正确地重新排列屏幕。我们再次使用我们的数值测量来执行这些操作：

    ```kt
    protected function onOrientationChange(e:StageOrientationEvent):void {
    boxTopLeft.x = 0;
    boxTopLeft.y = 0;
    boxTopRight.x = stage.stageWidth - halfInch;
    boxTopRight.y = 0;
    boxBottom.x = 0;
    boxBottom.y = stage.stageHeight - fullInch;
    boxBottom.width = stage.stageWidth;
    }

    ```

1.  结果应用程序的显示将类似于我们在以下屏幕截图中所看到的：![如何实现…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_06_03.jpg)

## 工作原理…

视觉组件大小调整的一个好方法是，将报告的`Capabilities.screenDPI`乘以您想要达到的任何物理尺寸。例如，如果我们想要确保某些触摸元素在设备上的宽度正好是半英寸，可以使用以下公式：

```kt
private var halfInch:Number = Capabilities.screenDPI * 0.5;

```

在此示例中，我们设置了一些变量，这些变量表示物理半英寸和全英寸的计算，然后在创建我们的元素进行布局和大小调整时应用这些变量。如果检测到设备方向发生变化，我们将根据新的`Stage`尺寸调整我们的布局，并适当地调整视觉元素的大小。由于两个顶部的`Shapes`是半英寸的方块，我们只需调整它们的`x`和`y`坐标，但底部的形状还需要在每次方向变化时调整其`width`以填满屏幕宽度。

# 在 Flash Professional CS5.5 中根据舞台大小调整视觉元素的缩放

Flash Professional CS5.5 引入了一项功能，使针对各种设备分辨率的目标定位变得更加容易，即当`Stage`大小调整时，Flash 能够重新调整和定位视觉元素。这使得我们可以轻松地修改针对特定分辨率和设备的 FLA 文件。

## 如何实现…

我们将展示如何使用**随舞台缩放内容**以针对不同的屏幕分辨率：

1.  在这里，我们看到一个针对 Nexus S 设备的**480x800**布局的演示应用程序。在**属性**面板中，点击**大小**控制旁边的扳手图标：![如何实现…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_06_04.jpg)

1.  我们希望调整显示分辨率以匹配 Droid2，因此我们将**文档设置**更改为反映**480x854**的显示分辨率以匹配此设备。此外，我们可以选择**随舞台缩放内容**，这将按比例缩放我们的视觉元素：![如何实现…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_06_05.jpg)

1.  点击**确定**按钮后，我们可以看到`舞台`已调整大小，我们的视觉元素现在位于`舞台`中心。由于我们只调整了应用程序的**高度**，视觉元素的布局会根据可以在**编辑 | 首选项 | 常规 | 缩放内容**中调整的设置重新定位。如果不清除这个复选框，元素会在缩放舞台并选择缩放内容时居中，如下所示。

1.  为了进一步演示，我们将调整`舞台`大小以匹配假想的 Android 平板设备的分辨率。在**属性**面板中，再次点击**大小**控制旁边的扳手图标：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_06_06.jpg)

1.  我们假想的平板分辨率为**800x1000**，因此我们将再次调整宽度和高度设置，选择**随舞台缩放内容**，然后点击标记为**确定**的按钮：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_06_07.jpg)

1.  新的缩放功能现在更加明显，我们可以通过参考最初标记我们初始分辨率的指南，查看应用程序资源被缩放的情况。在这个阶段，我们可以对应用程序布局进行进一步的调整，以确保在目标设备上显示的效果完全符合我们的预期：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_06_08.jpg)

如果我们想要以视觉方式针对多个设备，可以使用此技术为每个设备构建一个 FLA 文件，并共享代码库。尽管许多设备可以使用完全相同的`.fla`生成的应用程序，但这取决于目标设备的分辨率以及我们想要对每个设备进行多少调整。

## 工作原理…

使用 Flash Professional CS5.5 及其以上版本，我们现在在调整`舞台`尺寸时，可以增加缩放`舞台`上内容的功能。这对于移动 Android 开发来说非常棒，因为设备间存在如此多的显示分辨率差异。缩放内容的能力使得 FLA 文档的布局调整变得迅速，当编译成`.APK`文件时，可以针对特定设备。

## 还有更多…

需要注意的是，我们视觉元素的缩放将始终以保持其原始宽高比的方式进行。如果新的宽高比与原始宽高比不同，将需要进一步调整以使布局适合我们针对的任何设备。

# 使用 Flash Professional CS5.5 中的项目面板

在 Flash Professional 中设计应用程序布局传统上一直很麻烦，因为它需要手动组织各种 FLA 文件，并通过代码和资产管理之间的某种机制来同步它们之间的更改。Flash Professional CS5.5 试图通过新的项目结构减轻这种负担，包括在项目文档之间共享作者时间的 Flash 库资产的能力。

## 如何操作…

我们将配置一个 Flash 项目，这将允许我们针对多个屏幕分辨率使用相同的共享资产池，跨设备针对的 FLAs：

1.  通过在欢迎屏幕上选择**创建新项目 | Flash 项目**打开**项目面板**，或者通过应用程序菜单中的**文件 | 新建** | **Flash 项目**创建一个新的 Flash Professional 项目：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_06_09.jpg)

1.  将会出现**创建新项目**的面板，允许我们配置一个新的**Flash 项目**。我们将提供一个**项目名称**，定义一个用于存放项目文件的**根文件夹**，并选择一个**播放器**。在针对 Android 的 AIR 的情况下，我们一定要选择**AIR 2.6**或您希望针对的最新版本的 AIR：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_06_10.jpg)

1.  Flash 项目结构允许我们在一个项目中定义多个不同的 FLA 文档，这些文档针对各种分辨率和布局。这里，例如，我们创建了针对 Droid、EVO 和 Nexus One 移动 Android 设备的具体文档。除了这些文档，我们还有一个`AuthortimeSharedAssets.fla`文件，这是 Flash Professional 自动为我们生成的。这将包含我们其他文档之间共享的任何资产。![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_06_11.jpg)

1.  现在，当我们设计和开发应用程序资产时，我们可以将每个资产标记为作者时间共享资产，这可以在所有文档之间链接，使得在这个特定项目中的资产管理比其他情况下更有组织。要将**库**资产标记为共享，只需点击它旁边的复选框：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_06_12(2).jpg)

1.  在项目中将特定资产标记为在文档之间共享确实使其可共享，我们还必须确保在相关的文档中包含**库**资产，以便在特定设备文档中在作者时间内访问它。

1.  例如，如果我们有两个`.fla`文件，希望共享一个名为"RedBall"的 MovieClip 符号，我们首先在一个`.fla`中定义"RedBall"，并将其在库中标记为共享。这样会将符号放入我们的`AuthortimeSharedAssets.fla`文件中，但在我们实际将其引入第二个`.fla`的**库**之前，其他任何`.fla`都无法使用它。此时，在任何`.fla`中进行的任何修改都会因为项目中的共享资产链接而在这两个文件之间共享。

## 它的工作原理…

`AuthortimeSharedAssets.fla` 文件包含了所有跨多个 FLA 文件共享的 Flash **库** 资源。这使得我们可以在一个文件中修改共享资源，并且这些更改会影响到所有使用它的项目文档。通过多个针对不同目标分辨率布局的 FLA 文件，设计师在构建应用程序用户界面时具有极大的灵活性。所有这些界面元素通过这种新的项目结构链接起来，保持了工作的有序性和整洁性。

## 还有更多内容…

新的 Flash 项目面板及其相关项目结构不仅允许通过多个 FLA 文件进行作者时间资源共享和多设备定位，而且文件结构现在完全兼容 Flash Builder。这使得开发人员可以在 Flash Professional 中启动 Flash 项目，并通过在 Flash Builder 中导入项目文件夹继续编辑。

# 将 Flex 应用程序冻结为横向或纵向模式

有时我们希望将应用程序布局限制为特定的宽高比，横向或纵向。在使用 Flex 框架构建 Android 项目时，实现这一点非常简单。

## 如何操作…

我们可以通过修改 AIR 应用程序描述符文件来为我们的应用程序冻结特定的宽高比：

1.  默认情况下，当我们定义一个新的 Flex 移动项目时，会创建一个应用程序描述符 `XML` 文件。这个文件包括一个专门用于应用程序 `initialWindow` 配置的节点。它将类似于以下代码：

    ```kt
    <initialWindow>
    <autoOrients>true</autoOrients>
    <fullScreen>false</fullScreen>
    <visible>true</visible>
    <softKeyboardBehavior>none</softKeyboardBehavior>
    </initialWindow>

    ```

1.  我们希望以两种方式修改这个节点的内容。首先，将 `autoOrients` 标签设置为 `false`。这将防止应用程序在设备旋转时重新定位：

    ```kt
    <initialWindow>
    <autoOrients>false</autoOrients>
    <fullScreen>false</fullScreen>
    <visible>true</visible>
    <softKeyboardBehavior>none</softKeyboardBehavior>
    </initialWindow>

    ```

1.  现在，我们将添加一个 `aspectRatio` 标签，并为其赋予两个值之一，`landscape` 或 `portrait`：

    ```kt
    <initialWindow>
    <autoOrients>false</autoOrients>
    <aspectRatio>landscape</aspectRatio>
    <fullScreen>false</fullScreen>
    <visible>true</visible>
    <softKeyboardBehavior>none</softKeyboardBehavior>
    </initialWindow>

    ```

1.  当我们在设备上测试这个应用程序时，即使将其竖直持握，在纵向模式下，我们的应用程序仍然锁定为横向：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_06_13(2).jpg)

## 工作原理…

应用程序描述符文件非常强大，因为它可以定义我们应用程序的许多元素，而无需编辑任何 MXML 或 ActionScript。在这个例子中，我们正在修改项目 `initialWindow` 节点内的标签；将 `autoOrients` 设置为 false 并添加一个 `aspectRation` 标签，将我们应用程序的宽高比设置为 `landscape` 或 `portrait`。进行这些编辑将确保无论用户如何旋转设备，我们的应用程序都在固定的宽高比下运行。

## 还有更多内容…

Flash Professional CS5.5 的用户会发现，他们可以通过 **AIR for Android 设置** 对话框轻松调整这些属性。可以从 **属性** 面板或从 **文件 | AIR for Android 设置** 访问：

![还有更多内容…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_06_14(2).jpg)

## 另请参阅…

我们将在第九章中更深入地探讨应用程序描述符文件，*清单保证：安全性和安卓权限*。

# 定义一个空白 Flex 移动应用程序

在 Flash Builder 中创建一个**Flex 移动项目**时，它会附带许多默认视图和布局控件，包括 `ActionBar` 控件和 `ViewNavigator` 容器。这些控件对于许多类型的项目非常有用，但并非所有项目都会从这些额外结构中受益。有时从空白项目开始并逐步构建会更好。

## 如何操作…

定义一个空白 Flex 移动应用程序有两种方法。

在 Flash Builder 中创建一个**新的 Flex 移动项目**时：

1.  定义你的**项目位置**并点击**下一步**。

1.  现在，只需在**应用程序模板**区域选择**空白**，然后继续你的项目设置：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_06_15(2).jpg)

第二种方法是修改现有的**Flex 移动项目**以移除某些移动相关结构：

1.  你的移动项目最初将包含以下 MXML：

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <s:ViewNavigatorApplication xmlns:fx= "http://ns.adobe.com/mxml/2009"

    firstView="views.MainHomeView">
    </s:ViewNavigatorApplication>

    ```

1.  我们现在将以多种方式修改这部分内容。首先，将你的 `ViewNavigatorApplication` 标签更改为 `Application` 标签：

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <s:Application 

    firstView="views.MainHomeView">
    </s:Application>

    ```

1.  移除代码中所有的 `View` 引用：

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <s:Application 
    >
    </s:Application>

    ```

这两种方法都将创建一个空白 Flex 移动应用程序：

![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_06_16(2).jpg)

## 工作原理…

决定 Flex 移动项目中是否存在 `ActionBar` 和其他移动相关结构的是应用程序是否为 `spark.components.ViewNavigatorApplication` 或 `spark.components.TabbedViewNavigatorApplication` 类型。当你的 Flex 移动项目使用更传统的 `spark.components.Application` 时，`ActionBar, TabBar` 和 `ViewStack` 将不再存在于项目中或无法使用。

有关上述结构的更多信息，请查看接下来的几个食谱，其中描述了在启用了 `ViewNavigator` 的项目中工作的方法。

## 还有更多…

在一段时间后对 Flex 移动项目进行修改不是一个好主意，因为那时你可能会深深依赖于 `ViewStack`。

# 定义一个基于 Flex 移动视图的应用程序

基于视图的 Flex 移动应用程序为我们提供了许多非常有用的控件和容器，这些控件和容器专门针对移动应用程序开发的布局和结构。包括屏幕顶部的 `ActionBar` 和 `ViewNavigator` 控件。

## 如何操作…

创建基于 Flex 移动视图的应用程序有两种方法。

在 Flash Builder 中创建一个**新的 Flex 移动项目**时：

1.  定义你的**项目位置**并点击**下一步**。

1.  现在，只需在**应用程序模板**区域选择**基于视图的应用程序**，然后继续你的项目设置：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_06_17(2).jpg)

第二种方法是修改现有的 Flex 项目，以添加某些与移动相关的结构：

1.  你的 Flex 项目最初将包含以下 MXML：

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <s:Application 
    >
    </s:Application>

    ```

1.  我们现在将以几种方式修改这一点。首先，将你的`Application`标签更改为`ViewNavigatorApplication`标签：

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <s:ViewNavigatorApplication 
    >
    </s:ViewNavigatorApplication>

    ```

1.  在当前项目源文件夹内创建一个名为`MainHomeView.mxml`的`View` MXML 文件，作为示例。在这种情况下，我们是在项目结构中的`views`包内创建它。重要的是要认识到每个`ViewNavigatorApplication`都包含任意数量的单个视图。一个`View`是一种可以通过`ViewNavigator`管理以展示或关闭移动 Flex 应用程序内各种“屏幕”的 Flex 容器类型：

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <s:View 
     title="HomeView">
    </s:View>

    ```

1.  现在，我们必须将我们刚刚创建的文件指向`ViewNavigatorApplication`的`firstView`属性：

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <s:ViewNavigatorApplication 

    firstView="views.MainHomeView">
    </s:ViewNavigatorApplication>

    ```

这两种方法都可以定义一个基于 Flex 移动视图的应用程序。

![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_06_18(2).jpg)

## 它是如何工作的…

决定`ActionBar`是否存在于 Flex 移动项目中的是应用程序是否为`spark.components.ViewNavigatorApplication`（或`spark.components.TabbedViewNavigatorApplication`）类型。通过将我们的应用程序定义为`ViewNavigatorApplication`，我们可以访问所有这些移动特定的结构和控件，包括强大的`ViewNavigator`，通过它我们可以管理所有的应用程序视图。

一个`View`定义了应用程序内的一个特定“屏幕”，用户在使用应用程序时可能会切换到许多不同的视图。我们可以通过`ViewNavigator`管理所有这些视图，当应用程序在使用时，它会自动为我们保存视图历史。因此，当用户与 Android 后退按钮互动时，可以重新访问之前的视图。

# 定义一个具有多个部分的 Flex 移动标签应用程序

使用 Flex 框架设置一个移动 Android 项目可以像我们想要的那么简单或复杂。超越`ViewNavigatorApplication`的一步是`TabbedViewNavigatorApplication`，它包括拥有多个内容部分的能力，每个部分都有自己的`ViewNavigator`和`View`集合。定义一个`TabbedViewNavigatorApplication`将允许我们访问`TabBar`。

## 如何操作…

配置 Flex 移动标签应用程序有两条路径。

在 Flash Builder 中创建一个**新的 Flex 移动项目**时：

1.  定义你的**项目位置**并点击**下一步 >**

1.  现在，只需在**应用程序模板**区域选择**标签式应用程序**，然后继续你的项目设置：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_06_19(2).jpg)

第二种方法是修改现有的 Flex 项目，以添加某些与移动相关的结构：

1.  你的 Flex 项目最初将包含以下 MXML：

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <s:Application 
    >
    </s:Application>

    ```

1.  我们现在将以几种方式修改这一点。首先，将你的`Application`标签更改为`TabbedViewNavigatorApplication`标签：

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <s:TabbedViewNavigatorApplication 
    >
    </s:TabbedViewNavigatorApplication>

    ```

1.  在当前项目源文件夹内创建一组`View` MXML 文件。在本例中，我们将在项目结构中的`views`包内创建它们：

    TabOne.mxml：

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <s:View 
     title="Tab One">
    <s:layout>
    <s:VerticalLayout paddingBottom="20" paddingLeft="20" paddingRight="20" paddingTop="20"/>
    </s:layout>
    <s:Label text="Tab View: #1" />
    </s:View>

    ```

    TabTwo.mxml：

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <s:View 
     title="Tab Two">
    <s:layout>
    <s:VerticalLayout paddingBottom="20" paddingLeft="20" paddingRight="20" paddingTop="20"/>
    </s:layout>

    ```

    ```kt
    <s:Label text="Tab View: #2" />
    </s:View>

    ```

    TabThree.mxml：

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <s:View 
     title="Tab Three">
    <s:layout>
    <s:VerticalLayout paddingBottom="20" paddingLeft="20" paddingRight="20" paddingTop="20"/>
    </s:layout>
    <s:Label text="Tab View: #3" />
    </s:View>

    ```

1.  现在，我们必须通过将一系列`ViewNavigator`声明嵌套在我们的`TabbedViewNavigatorApplication`结构中，来指向我们刚刚创建的文件。每个都将指向我们刚刚创建的独特`View` MXML 文件之一：

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <s:TabbedViewNavigatorApplication 
    >
    <s:ViewNavigator label="Tab One" width="100%" height="100%" firstView="views.TabOne"/>
    <s:ViewNavigator label="Tab Two" width="100%" height="100%" firstView="views.TabTwo"/>
    <s:ViewNavigator label="Tab Three" width="100%" height="100%" firstView="views.TabThree"/>
    </s:TabbedViewNavigatorApplication>

    ```

这些方法中的任何一种都将定义一个 Flex 移动标签应用程序：

![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_06_20(2).jpg)

## 它是如何工作的…

在 Flex 移动项目中是否包含`TabBar`是由应用程序是否为`spark.components.TabbedViewNavigatorApplication`类型来定义的。当在 Flex 移动项目中使用更传统的`spark.components.Application`时，`TabBar`和`ViewStack`在项目中不再存在或可用。

## 还有更多…

需要注意的是，当使用`TabbedViewNavigator`时，每个标签都有自己专用的`ViewNavigator`，每个都有自己的视图堆栈。除非从其他来源（如共享数据池）获取，否则`ViewNavigotor`实例之间没有机制共享数据，这需要由开发人员定义。

# 在 Flex 移动应用程序中使用启动画面

安卓版的 Adobe AIR 是一个优秀的运行时环境，用于构建和分发安卓应用程序，但与原生开发相比，它有一些权衡。根据应用程序的大小，它可能需要几秒钟的时间为用户加载所有内容。移动 Flex 框架允许我们定义一个启动画面，让用户在启动应用程序时知道应用程序正在加载，并为整个体验增添一点额外的装饰。

## 如何操作…

我们将配置应用程序，在应用程序加载过程中显示启动画面：

1.  在定义 Flex 移动项目时，我们需要确保`ViewNavigatorApplication`或`TabbedViewNavigatorApplication`（取决于你的项目）是当前选定的 MXML 标签，并进入**设计**视图。

1.  接下来，我们将修改**属性**面板中**通用**区域内的几个设置。在这里，浏览到一个图像文件以嵌入**启动画面**，并将**启动画面缩放模式**设置为**无，信箱，拉伸**或**缩放**：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_06_21(2).jpg)

1.  进入**源代码视图**，MXML 文档将如下所示：

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <s:ViewNavigatorApplication 

    applicationDPI="240" firstView="views.SplashScreenHomeView"
    splashScreenImage="@Embed('assets/splash.png')"
    splashScreenScaleMode="stretch"
    title="Splash!">
    </s:ViewNavigatorApplication>

    ```

1.  当然，你可以从这里修改我们刚刚配置的任何设置，指向另一个文件进行嵌入或更改缩放模式。我们将在主应用程序标签中添加一个名为`splashScreenMinimumDisplayTime`的属性，并将其值设置为希望启动画面图像显示的最短持续时间（毫秒）：

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <s:ViewNavigatorApplication 

    applicationDPI="240" firstView="views.SplashScreenHomeView"
    splashScreenImage="@Embed('AndroidSplash.png')"
    splashScreenScaleMode="stretch"
    splashScreenMinimumDisplayTime="2000"
    title="Splash!">
    </s:ViewNavigatorApplication>

    ```

1.  当用户在他们的设备上运行应用程序时，他们会看到一个精美的启动画面，标识应用程序并告知它们正在加载：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_06_22(2).jpg)

## 工作原理…

在主应用程序文件上设置`splashScreenImage`属性，可以在用户加载应用程序时向其显示一个嵌入的自定义图像。添加`splashScreenMinimumDisplayTime`属性允许我们定义启动画面显示的最短时间（以毫秒为单位）。如果应用程序加载时间超过这个定义的时间，启动画面将根据需要继续显示。启动画面还可以通过设置`splashScreenScaleMode`属性接受特定的缩放模式行为：

+   将`splashScreenScaleMode`设置为`none`会以原始分辨率呈现我们定义的图像，不做任何修改。这可能无法接受，因为设备屏幕分辨率差异很大。

+   将`splashScreenScaleMode`设置为`letterbox`将把启动图像缩放到由设备显示分辨率定义的框架中，但在图像未覆盖的区域会显示空白填充。

+   将`splashScreenScaleMode`设置为`stretch`将拉伸定义的图像以适应由设备显示分辨率定义的框架，填充整个显示区域。由于图像可能不成比例地缩放，这种设置可能会导致一些失真。

+   将`splashScreenScaleMode`设置为`zoom`将把启动图像缩放到由设备显示分辨率定义的框架中，不允许任何填充。它将通过裁剪图像的某些部分来填充整个显示区域。这可能是不希望的，因为用户可能无法看到图像的某些部分。

例如：一个 480x800 像素的图像在 320x480 的设备显示屏上呈现时如下所示：

![工作原理…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_06_23(2).jpg)

# 在 Flex 移动项目中配置 ActionBar，以便与 ViewNavigator 一起使用。

Flex 移动`ViewNavigatorApplication`和`TabbedViewNavigatorApplication`包含一个名为`ActionBar`的特殊控件，其中包含三个可编辑的子容器。我们可以通过修改项目文档中的 MXML 来定义这些子容器的内容。

## 如何操作…

修改文档 MXML 来自定义我们的`ActionBar`内容。在这个例子中，我们将定义一些交互式图像控件，并在应用程序`ViewStack`中提供一个丰富的标题图像。

1.  当我们第一次配置新的 Flex 移动项目时，主 MXML 文档将如下所示：

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <s:ViewNavigatorApplication

    firstView="views.CustomActionBarHomeView">
    </s:ViewNavigatorApplication>

    ```

1.  `ActionBar`包含三个独立区域，我们可以在其中定义额外的控件，它们分别是`navigationContent`、`titleContent`和`actionContent`容器。![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_06_24(2).jpg)

1.  我们首先在我们的主应用程序 MXML 中定义一个`navigationContent`节点。在其中定义一个 Spark `Image`控件，嵌入一个导航图片，这将作为用户返回到我们应用程序“主页”屏幕的方式：

    ```kt
    <s:navigationContent>
    <s:Image source="@Embed('images/home.png')"/>
    </s:navigationContent>

    ```

1.  现在，定义`titleContent`容器，并在其中创建一个`Image`控件，嵌入作为我们应用程序标题的图片：

    ```kt
    <s:titleContent>
    <s:Image source="@Embed('images/title.png')"/>
    </s:titleContent>

    ```

1.  最后，定义一个`actionContent`节点，并在其中嵌入另一个图片，就像我们对`navigationContent`容器所做的那样。这将作为一个关闭按钮：

    ```kt
    <s:actionContent>
    <s:Image source="@Embed('images/close.png')"/>
    </s:actionContent>

    ```

1.  然后，我们将在 MXML 中设置一个`script`块，以包含我们将要编写的任何函数：

    ```kt
    <fx:Script>
    <![CDATA[
    ]]>
    </fx:Script>

    ```

1.  在我们的脚本块中定义一个方法，当用户按下`navigationContent`子级的`Image`时，通过调用`ViewNavigator.popToFirstView()`方法将用户返回到我们的初始`View`。

    ```kt
    private function goHome(e:MouseEvent):void {
    navigator.popToFirstView();
    }

    ```

1.  定义一个第二种方法，当用户按下`actionContent`子级的`Image`时退出应用程序：

    ```kt
    private function closeApp(e:MouseEvent):void {
    NativeApplication.nativeApplication.exit();
    }

    ```

1.  现在，我们将通过为每个交互式`ActionBarImage`控件分配点击事件来完成此示例，使用我们之前创建的方法注册它们：

    ```kt
    <s:navigationContent>
    <s:Image click="goHome(event)" source="@Embed('images/home.png')"/>
    </s:navigationContent>
    <s:actionContent>
    <s:Image click="closeApp(event)" source="@Embed('images/close.png')"/>
    </s:actionContent>

    ```

1.  我们还将以这种方式定义两个`View` mxml 文件，以便这些`ActionBar`控件对于此示例清晰起作用。初始`View`将包括一个按钮，以便使用`ViewNavigator.push()`方法导航到次要`View`。调用此方法时，我们只需传入对特定应用程序应允许用户交互的视图的引用。我们可以选择性地传入第二个参数，其中包含要传递给`View`的数据。

1.  从次要`View`，用户可以通过点击`ActionBar`上的退出`Image`退出应用程序，按 Android 返回按钮，或者点击`ActionBar`上的主页`Image`来调用`ViewNavigator.popToFirstView()`方法，返回到初始的应用程序状态：

    自定义 ActionBar 的 HomeView.mxml：

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <s:View 
     title="Home View">
    <s:layout>
    <s:VerticalLayout paddingBottom="20" paddingLeft="20" paddingRight="20" paddingTop="20"/>
    </s:layout>
    <fx:Script>
    <![CDATA[
    protected function switchView():void {
    this.navigator.pushView(views.CustomActionBarSecondaryView);
    }
    ]]>
    </fx:Script>
    <s:Label text="Home View: Hit the EXIT icon to exit." />
    <s:Button label="Go to Secondary View" click="switchView()"/>
    </s:View>
    CustomActionBarSecondaryView.mxml
    <?xml version="1.0" encoding="utf-8"?>
    <s:View 
     title="Secondary View">
    <s:layout>
    <s:VerticalLayout paddingBottom="20" paddingLeft="20" paddingRight="20" paddingTop="20"/>
    </s:layout>
    <s:Label text="Secondary View: Hit the HOME icon to pop to the first view or the EXIT icon to exit." />
    </s:View>

    ```

1.  当我们在设备上运行应用程序时，**ActionBar**将如下显示：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_06_25.jpg)

## 工作原理…

`Flex`移动端的`ActionBar`是一个优秀的结构元素，可以广泛应用于各种 Android 移动应用程序中。三个容器区域：`navigationContent`、`titleContent`和`actionContent`与其他 Flex 容器的行为类似。`ActionBar`中的内容及其功能实际上取决于应用程序开发人员，以及这对目标用户是否有意义。我们必须确保考虑可用的空间量以及这如何在不同设备间变化。

在处理`ViewNavigator`时，移动开发人员应该熟悉许多重要方法。我们在这里将简要提及它们。

`popToFirstView()`方法会移除`ViewNavigator`中除最底层视图外的所有视图，实质上是让应用程序返回到“主页”视图。`popView()`方法将当前视图从导航堆栈中弹出，向用户展示上一个视图。

`pushView()`方法将一个新的视图推送到`ViewNavigator`导航堆栈的顶部，使其成为当前视图。为此，必须将有效的`View`对象引用作为此方法的参数传入。

## 还有更多内容…

我们还可以通过在前一节中概述的`ViewNavigator`方法的最后一个参数中传递一个过渡引用来管理视图过渡。例如，如果我们想用翻转的立方体替换正常的滑动过渡，可以通过以下步骤实现：

1.  导入以下类：

    ```kt
    import spark.transitions.FlipViewTransition;
    import spark.transitions.FlipViewTransitionMode;
    import spark.transitions.ViewTransitionDirection;

    ```

1.  调用创建我们过渡的方法，并将其作为`ViewNavigator.popView()`的参数传递。创建过渡时，我们可以定义诸如持续时间、移动方向以及`ActionBar`控件是否与视图内容一起动画等事项：

    ```kt
    protected function removeViews():void {
    var androidTransition:FlipViewTransition = new FlipViewTransition();
    androidTransition.duration = 500;
    androidTransition.direction = ViewTransitionDirection.UP;
    androidTransition.transitionControlsWithContent = false;
    androidTransition.mode = FlipViewTransitionMode.CUBE;
    this.navigator.popView(androidTransition);
    }

    ```

在开发移动 Flex 项目时，我们可以探索许多不同的过渡类型。这仅是使用其中一种类型的方法示例。

# 在 Flex 移动项目的单个视图中隐藏 ActionBar 控件

您可能想使用`ViewNavigatorApplication`容器的`ViewNavigator`结构和功能，但只是想在特定应用程序视图中隐藏`ActionBar`。

## 如何操作…

将 View 的`actionBarVisible`属性设置为`true`。以下示例显示如何根据按钮点击为特定`View`打开和关闭`ActionBar`：

1.  定义一个新的基于 Flex 移动视图的应用程序：

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <s:ViewNavigatorApplication 

    firstView="views.MainHomeView">
    </s:ViewNavigatorApplication>

    ```

1.  在一个`views`包中创建一个名为`MainHomeView.mxml`的新 MXML 文件，这将定义此应用程序的主要视图：

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <s:View 
     title="HomeView">
    </s:View>

    ```

1.  在我们刚才创建的 MXML 文件中定义一个`Button`组件，这构成了我们的`ViewNavigatorApplicationfirstView:`：

    ```kt
    <s:Button x="10" y="10" label="Toggle"/>

    ```

1.  然后，我们将在 MXML 中设置一个`script`块，以包含我们将要编写的任何函数：

    ```kt
    <fx:Script>
    <![CDATA[
    ]]>
    </fx:Script>

    ```

1.  现在，创建一个名为`toggleActionBar`的函数，并在其中创建一个`if`语句，检查我们`View`的`actionBarVisible`属性是`true`还是`false`。根据当前的`Boolean`值，我们将切换到相反的值：

    ```kt
    protected function toggleActionBar():void {
    if(actionBarVisible){
    actionBarVisible = false;
    }else{
    actionBarVisible = true;
    }
    }

    ```

1.  最后，我们只需在`Button`组件上创建一个点击事件处理程序，以调用刚才创建的函数：

    ```kt
    <s:Button x="10" y="10" label="Toggle" click="toggleActionBar()"/>

    ```

1.  现在，这个`Button`可以在切换时打开和关闭`ActionBar`：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_06_26.jpg)

## 工作原理…

应用程序中的每个`View`都有一个`actionBarVisible`属性。设置`actionBarVisible = false`; 将隐藏特定`View`上的`ActionBar`控件。这实际上非常灵活，因为我们可以根据当前所在的`View`按需打开或关闭`ActionBar`控件。

## 还有更多内容…

我们从`View`中移除`ActionBar`控件的方法与从`TabbedViewNavigatorApplication`项目中移除`TabBar`的方法类似，通过设置以下内容：

```kt
tabbedNavigator.tabBar.visible = false;
tabbedNavigator.tabBar.includeInLayout

```
