# 安卓 Flash 开发秘籍（四）

> 原文：[`zh.annas-archive.org/md5/3A6CCF6F6AAB969F5B96A3C7E7AEF15A`](https://zh.annas-archive.org/md5/3A6CCF6F6AAB969F5B96A3C7E7AEF15A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：清单保障：安全与 Android 权限

本章节将涵盖以下内容：

+   使用 Android Manifest 文件设置应用程序权限

+   防止设备屏幕变暗

+   建立 Android 自定义 URI 方案

+   预期 Android 兼容性筛选

+   指导应用程序安装到设备 SD 卡

+   加密本地 SQLite 数据库

# 引言

Android 有一个非常特定的权限和安全系统，基于清单文件声明，允许或限制应用程序访问各种设备功能。本章将详细介绍如何为你的 Flash 平台应用程序正确识别所需权限，以便利用 Android 市场筛选，应用本地应用程序数据库加密，以及其他有用的技巧！

# 使用 Android Manifest 文件设置应用程序权限

当用户选择在 Android 上安装应用程序时，他们总会收到关于应用程序将在其系统中拥有哪些权限的警告。从互联网访问到完整的地理位置、相机或外部存储权限；用户会明确知道应用程序在他们的系统上会拥有哪些权利。如果看起来应用程序请求的权限比实际需要的多，用户通常会拒绝安装并寻找其他可以完成所需任务的应用程序。只请求应用程序真正需要的权限非常重要，否则用户可能会对你和你提供的应用程序产生怀疑。

## 如何操作...

我们可以通过三种方式修改`Android Manifest`文件，为使用 Adobe AIR 编译应用程序时设置应用权限。

### 使用 Flash Professional：

在 AIR for Android 项目中，打开**属性**面板，点击**播放器**选择旁边的扳手图标：

![使用 Flash Professional：](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_09_01.jpg)

将会出现**Android 的 AIR 设置**对话框窗口。你将看到一个权限列表，可以选择为你的应用程序启用或禁用。只选中你的应用程序需要的权限，完成后点击**确定**。

![使用 Flash Professional：](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_09_02.jpg)

### 使用 Flash Builder：

1.  在 Flash Builder 中首次设置你的 AIR for Android 项目时，在**项目位置**区域定义所需的一切，然后点击**下一步**。

1.  你现在处于**新建 Flex 移动项目**对话框的**移动设置**区域。点击**权限**标签，确保已选择**Google Android**作为平台。你将看到一个权限列表，可以选择为你的应用程序启用或禁用。只选中你的应用程序需要的权限，然后继续你的项目设置：![使用 Flash Builder：](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_09_03.jpg)

1.  在开始开发应用程序后，若要修改这些权限，只需打开 AIR 描述文件，按照下面几节的详细说明进行编辑。

### 使用简单的文本编辑器：

1.  在你的项目中找到 AIR 描述文件。它通常被命名为类似`{MyProject}-app.xml`的名称，位于项目根目录。

1.  浏览文件，寻找名为`<android>`的节点，在这个节点内会有一个名为`<manifestAdditions>`的节点，它包含一个名为`<manifest>`的子节点。本文档的这一部分包含了我们为 Android 应用程序设置权限所需的一切。

1.  我们需要做的就是注释掉或移除那些应用程序不需要的特定权限。例如，这个应用程序需要互联网、外部存储和相机访问权限。其他所有权限节点都使用标准的 XML 注释语法`<!-- {在此处注释} -->`进行注释。

    ```kt
    <uses-permission name="android.permission.INTERNET"/>
    <uses-permission name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    <!--<uses-permission name="android.permission.READ_PHONE_STATE"/>-->
    <!--<uses-permission name="android.permission.ACCESS_FINE_LOCATION"/>-->
    <!--<uses-permission name="android.permission.DISABLE_KEYGUARD"/>-->
    <!--<uses-permission name="android.permission.WAKE_LOCK"/>-->
    <uses-permission name="android.permission.CAMERA"/>
    <!--<uses-permission name="android.permission.RECORD_AUDIO"/>-->
    <!--<uses-permission name="android.permission.ACCESS_NETWORK_STATE"/>-->
    <!--<uses-permission name="android.permission.ACCESS_WIFI_STATE"/>-->

    ```

### 工作原理如下...

在 AIR 描述文件中定义的权限将被用于创建一个 Android 清单文件，该文件将被打包进编译项目时产生的`.apk`文件中。这些权限限制并启用了应用程序，一旦安装在用户设备上，也会在安装前告知用户应用程序将获得哪些活动和资源的访问权限。为应用程序提供仅完成预期任务所需的权限非常重要。

以下是 Android 清单文档可能包含的权限列表：

+   `ACCESS_COARSE_LOCATION:` 允许`Geoloctaion`类访问 WIFI 和三角定位的基站位置数据。

+   `ACCESS_FINE_LOCATION:` 允许`Geolocation`类使用设备的 GPS 传感器。

+   `ACCESS_NETWORK_STATE:` 允许应用程序通过`NetworkInfo`类访问网络状态。

+   `ACCESS_WIFI_STATE:` 允许应用程序通过`NetworkInfo`类访问 WIFI 状态。

+   `CAMERA:` 允许应用程序访问设备摄像头。

+   `INTERNET:` 允许应用程序访问互联网并执行数据传输请求。

+   `READ_PHONE_STATE:` 允许应用程序在电话通话过程中静音音频。

+   `RECORD_AUDIO:` 允许应用程序访问麦克风以录制或监控音频数据。

+   `WAKE_LOCK:` 允许应用程序使用`SystemIdleMode`类防止设备进入休眠状态。（必须与`DISABLE_KEYGUARD`一起使用）

+   `DISABLE_KEYGUARD:` 允许应用程序使用`SystemIdleMode`类防止设备进入休眠状态。（必须与`WAKE_LOCK`一起使用）

+   `WRITE_EXTERNAL_STORAGE:` 允许应用程序写入外部存储。这部分存储通常是指设备的 SD 卡。

# 防止设备屏幕变暗

安卓操作系统会在经过一定时间后，降低亮度并最终关闭设备屏幕。这样做是为了节省电池寿命，因为显示屏幕是设备上的主要耗电项。对于大多数应用程序，如果用户正在与界面互动，那么这种互动将阻止屏幕变暗。然而，如果你的应用程序在长时间内不涉及用户互动，但用户正在观看或阅读屏幕上的内容，那么阻止屏幕变暗是合理的。

## 如何操作...

AIR 描述文件中有两个设置可以更改，以确保屏幕不会变暗。我们还将修改应用程序的属性来完成这个配方：

1.  在你的项目中找到 AIR 描述文件。它通常像`{MyProject}-app.xml`这样命名，位于项目根目录。

1.  浏览文件，寻找名为`<android>`的节点，在这个节点内会有一个名为`<manifestAdditions>`的节点，它包含一个名为`<manifest>`的子节点。本文档的这一部分包含了我们为 Android 应用程序设置权限所需的一切。

1.  我们需要确保以下两个节点存在于描述文件的这一部分中。请注意，启用这两个权限是允许应用程序通过`SystemIdleMode`类控制系统的必要条件。如有必要，请取消注释它们。

    ```kt
    <uses-permission android:name="android.permission.WAKE_LOCK" />
    <uses-permission android:name="android.permission.DISABLE_KEYGUARD" />

    ```

1.  在我们的应用程序中，我们将导入以下类：

    ```kt
    import flash.desktop.NativeApplication;
    import flash.desktop.SystemIdleMode;
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.text.TextField;
    import flash.text.TextFormat;

    ```

1.  声明一个`TextField`和`TextFormat`对，以向用户输出跟踪信息：

    ```kt
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  现在，我们将通过将`SystemIdleMode.KEEP_AWAKE`常量赋值给`NativeApplication.nativeApplication.systemIdleMode`属性，为我们的应用程序设置系统空闲模式：

    ```kt
    protected function setIdleMode():void {
    NativeApplication.nativeApplication.systemIdleMode = SystemIdleMode.KEEP_AWAKE;
    }

    ```

1.  在这一点上，我们继续设置我们的`TextField`，应用`TextFormat`，并将其添加到`DisplayList`中。这里，我们创建一个方法来执行所有这些操作：

    ```kt
    protected function setupTraceField():void {
    device screenpreventing, from dimmingtraceFormat = new TextFormat();
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
    traceField.y = 20
    traceField.width = stage.stageWidth-40;
    traceField.height = stage.stageHeight - traceField.y;
    addChild(traceField);
    }

    ```

1.  在这里，我们简单地将当前分配的系统空闲模式字符串输出到我们的`TextField`中，让用户知道设备不会进入休眠状态：

    ```kt
    protected function checkIdleMode():void {
    traceField.text = "System Idle Mode: " + NativeApplication. nativeApplication.systemIdleMode;
    }

    ```

1.  当应用程序在设备上运行时，**系统空闲模式**将被设置，结果将输出到我们的显示屏幕。用户可以将设备留置不管，只要需要，屏幕就不会变暗或锁定。在以下示例中，这个应用程序在五分钟内没有用户干预的情况下被允许运行：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_09_04.jpg)

## 它是如何工作的...

为了使此功能正确工作，必须完成两件事，这两件事都是绝对必要的。首先，我们必须确保应用程序通过 Android 清单文件具有正确的权限。在 AIR 描述符文件中允许应用程序具有 `WAKE_LOCK` 和 `DISABLE_KEYGUARD` 权限将为我们完成此操作。第二部分涉及将 `NativeApplication.systemIdleMode` 属性设置为 `keepAwake`。最好使用 `SystemIdleMode.KEEP_AWAKE` 常量来完成此操作。确保满足这些条件将使应用程序能够保持设备显示屏亮起，并防止 Android 在设备空闲后锁定设备。

## 另请参阅...

在此食谱中，我们通过基本文本编辑器编辑了 AIR 描述符文件。有关在其他环境中设置这些权限的其他方法，请参阅之前的食谱。

# 建立 Android 自定义 URI 方案

Android 向 AIR 公开了许多有用的 URI 协议，用于标准操作，如映射、短信和电话。为我们应用程序定义自定义 URI 允许它从系统的任何地方调用：通过网页浏览器、电子邮件，甚至本地应用程序。自定义 URI 提供了调用 AIR 应用程序的一种替代方法。

## 如何操作...

我们将创建一个可以从设备网页浏览器使用自定义 URI 打开的应用程序。我们通过修改 AIR 描述符文件来定义 URI 意图设置：

1.  在您的项目中找到 AIR 描述符文件。它通常像 `{MyProject}-app.xml` 这样命名，位于项目根目录。

1.  浏览文件以查找名为 `<android>` 的节点；在此节点内将有一个名为 `<manifestAdditions>` 的节点，其中包含一个名为 `<manifest>` 的子节点。本文档的此部分包含设置我们 Android 应用程序权限所需的一切。

1.  我们现在将突出显示的 `<intent-filter>` 节点添加到我们的描述符文件中。定义我们 URI 的意图部分是 `<data android:scheme="fvm"/>`。这将使我们的应用程序能够使用 `fvm://` URI。请注意，本例中使用了 `"fvm"`；在根据此类示例编写应用程序时，我们可以自由地将此值更改为适合特定应用程序的任何值：

    ```kt
    <application android:enabled="true">
    <activity android:excludeFromRecents="false">
    <intent-filter>
    <action android:name="android.intent.action.MAIN"/>
    <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
    <intent-filter>
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <data android:scheme="fvm"/>
    </intent-filter>
    </activity>
    </application>

    ```

1.  在我们的应用程序中，我们将导入以下类：

    ```kt
    import flash.desktop.NativeApplication;
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.InvokeEvent;
    import flash.text.TextField;
    import flash.text.TextFormat;

    ```

1.  声明一个 `TextField` 和 `TextFormat` 对，以向用户输出消息：

    ```kt
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  在这一点上，我们将继续设置我们的 `TextField`，应用 `TextFormat`，并将其添加到 `DisplayList` 中。在这里，我们创建一个方法来执行所有这些操作：

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
    traceField.y = 40;
    traceField.width = stage.stageWidth-40;
    traceField.height =stage.stageHeight - traceField.y;
    addChild(traceField);
    }

    ```

1.  在 `NativeApplication` 上注册一个类型为 `InvokeEvent.INVOKE` 的事件监听器。这将检测用户使用我们定义的 URI 发起的任何应用程序调用事件：

    ```kt
    protected function registerListeners():void {
    NativeApplication.nativeApplication. addEventListener(InvokeEvent.INVOKE, onInvoke);
    }

    ```

1.  当应用程序从我们的 URI 打开时，将处理以下方法。我们可以从我们的调用事件中收集一定量的信息，比如 `reason` 属性。这个属性将具有 `"login"` 或 `"standard"` 的值。如果应用程序在系统登录时自动启动，该值将显示为 `"login"`。在 URI 调用的情况下，它将显示为 `"standard"`。我们还可以访问 `currentDirectory`。应用程序可能从文件系统内部调用，或者访问通过 URI 传递的任何 `arguments`。请注意，在从网络浏览器进行 URI 调用的这种情况下，`arguments` 属性将只包含所选链接的完整 URL。这是我们可以在启动时向应用程序传递数据的一种方式。

    ```kt
    protected function onInvoke(e:InvokeEvent):void {
    traceField.text = "";
    traceField.text = "Invoke Reason: " + e.reason + "\n"; traceField.appendText("Directory URL: " + e.currentDirectory. url + "\n\n");
    var args:Array = e.arguments;
    if (arguments.length > 0) {
    traceField.appendText("Message: " + args.toString() + "\n");
    }
    }

    ```

1.  对于这个例子，让我们设置一个简单的网页，其中包含一个使用我们定义的 `fvm:// URI:<a href="fvm://arg1=Hello&arg2=AIRAndroid">打开 AIR Android 应用!</a>` 的链接。如果用户已经安装了该应用程序并点击了这个链接，应用程序应该会打开，因为我们的 URI 意图在设备上已经注册了：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_09_05.jpg)

1.  一旦用户点击了使用我们定义的 URI 的链接，AIR 应用程序将会打开并检测到一个 `InvokeEvent`，在设备显示屏上显示以下信息。我们可以看到这里目录 URL 是空的，因为应用程序不是从设备文件系统中调用的：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_09_06.jpg)

## 它的工作原理...

当我们在应用程序描述符文件中定义 URI 意图时，这会被编译到 Android 清单文件中，与应用程序一起安装到设备上。在设备上安装此应用程序会告知操作系统我们定义的 URI 意图。这使得操作系统知道特定的 URI，并指示在遇到该 URI 时打开应用程序。我们可以将 URI 放置在多个不同的位置，包括系统上的本地 Android 应用程序。这使得本地应用程序能够打开 AIR for Android 应用程序。在之前的示例中，我们将 URI 嵌入 HTML 中，并使用 Android 网络浏览器打开我们的应用程序。

## 另请参阅...

想要了解更多关于在 AIR for Android 中使用 URI 协议的信息，请查看 第七章，*本地交互：StageWebView 和 URI 处理器。*

# 预期 Android 兼容性筛选

根据特定应用程序中使用的 API，一些 Android 设备可能无法提供对预期传感器或硬件钩子的访问。如果用户下载了一个无法按预期工作的应用程序，这个用户将会感到沮丧，很可能会给我们一个差评，甚至可能是一条恶评。幸运的是，Android 市场可以代表我们进行一些筛选，以确保只有支持我们应用程序的设备才有下载和安装的选项。

## 如何操作...

修改 Android Manifest 文件，以指定我们的应用程序需要哪些特定特性：

1.  在你的项目中找到 AIR 描述文件。它通常被命名为类似`{MyProject}-app.xml`的名称，因为它位于项目根目录。

1.  浏览文件，查找名为`<android>`的节点；在这个节点内，会有一个名为`<manifestAdditions>`的节点，它包含一个名为`<manifest>`的子节点。文档的这一部分将包含我们需要声明 Android 应用程序兼容性的所有内容。

1.  我们将根据需求添加某些标签。查看以下信息布局，以确定你应该在 manifest 节点中为特定的特性依赖添加什么内容。设置`android:required="false"`可以使一个特性成为可选。

### 当使用 Android 摄像头的特性时：

```kt
<uses-feature android:name="android.hardware.camera" android:required="false"/>
<uses-feature android:name="android.hardware.camera.autofocus" android:required="false"/>
<uses-feature android:name="android.hardware.camera.flash" android:required="false"/>

```

### 当使用 Android 麦克风的特性时：

```kt
<uses-feature android:name="android.hardware.microphone" android:required="false"/>

```

### 当使用 Geolocation 传感器时：

```kt
<uses-feature android:name="android.hardware.location" android:required="false"/>
<uses-feature android:name="android.hardware.location.network" android:required="false"/>
<uses-feature android:name="android.hardware.location.gps" android:required="false"/>

```

### 当使用加速度传感器时：

```kt
<uses-feature android:name="android.hardware.accelerometer" android:required="false"/>

```

## 工作原理...

通过指定摄像头和麦克风的一些必需或可选特性，我们可以确保只有设备满足这些具体要求的用户才会被提供下载和安装我们应用程序的选项。我们通过修改 Android manifest 文件，通过向我们的 AIR 描述文件中添加内容来公开这些规范，如本食谱所示。使用这些修改编译我们的应用程序将确保这些规范与我们的`.APK`一起编码，并在我们的应用程序发布后通过 Android Market 公开。

## 另请参阅...

有关在 AIR for Android 中使用摄像头和麦克风的内容，请查看第四章，*视觉和音频输入：摄像头和麦克风访问*。

# 指示应用程序安装到设备 SD 卡

通过稍微修改我们 AIR 应用程序描述文件中的 Android manifest 指令，我们可以通知设备操作系统，如果可能，我们的应用程序应该安装在 SD 卡上，而不是内部存储。这将有助于将内部设备存储保留给操作系统和相关文件。

## 如何操作...

修改 Android Manifest 文件以确定安装位置选项：

1.  在你的项目中找到 AIR 描述文件。它通常被命名为类似`{MyProject}-app.xml`的名称，并且位于项目根目录。

1.  浏览文件，查找名为`<android>`的节点；在这个节点内，会有一个名为`<manifestAdditions>`的节点，其中包含一个名为`<manifest>`的子节点。

1.  我们将在`<manifest>`节点中添加`installLocation`属性。要设置应用程序由 Android 自行决定安装位置：

    ```kt
    <manifest android:installLocation="auto"/>

    ```

1.  要设置应用程序优先选择设备 SD 卡：

    ```kt
    <manifest android:installLocation="preferExternal"/>

    ```

    ### 注意

    不能保证设置`installLocation="preferExternal"`实际上会将应用程序安装到设备 SD 卡。

用户还可以通过以下步骤，如果允许的话，移动应用程序：

1.  首先，在设备上导航到安装了我们的 AIR 应用程序的**应用程序管理**屏幕。在大多数 Android 设备上，这个屏幕的位置是**设置 | 应用程序 | 管理应用程序**。现在从这个屏幕上选择你创建的 AIR 应用程序。

1.  要将应用程序移动到设备 SD 卡，只需点击标记为**移动到 SD 卡**的按钮：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_09_07.jpg)

## 工作原理...

让用户在一定程度上选择应用程序的安装位置是一个好主意。在 Android 上，只有两个选项：设备存储区域或外部 SD 卡。考虑到大多数设备在外部 SD 卡上的存储空间比内部存储要多，最好是在 AIR 描述符文件中的清单节点上设置`android:installLocation="preferExternal"`，优先选择 SD 卡。尽管不能保证 Android 在安装我们的应用程序时会使用外部 SD 卡，但这至少会让系统知道该位置是首选的。Android 是否能够将应用程序安装到外部存储，主要取决于操作系统版本。一般来说，如果设备能够安装和运行适用于 Android 的 AIR 运行时，它应该具备这个功能。

正如我们之前所见，如果用户愿意，他们总是可以将应用程序从内部存储移动到外部存储，然后再移回来。同样值得注意的是：即使应用程序安装在设备的 SD 卡上，应用程序存储目录、本地共享对象和任何临时文件仍然会被写入内部存储。如果我们打算与我们的应用程序一起保存大量数据，那么我们将使用`File.documents`目录或`File.user`目录将这些数据存储在外部 SD 卡上。

## 参见...

有关本地文件系统的更多信息，请查看第八章，*丰富访问：文件系统和本地数据库*。

# 加密本地 SQLite 数据库

通常，本地 SQLite 数据库不需要任何安全或加密。然而，如果我们的应用程序包含存储在本地应用程序数据库文件中的敏感数据，我们会希望确保入侵者或小偷无法访问这些信息。幸运的是，我们可以加密在 Android 上可用的数据库，以确保即使用户的设备丢失或被盗，他们的私人信息仍然保持安全。

## 准备就绪...

为了正确加密数据库文件，我们需要使用一个加密库。在这个例子中，我们将使用位于[`code.google.com/p/as3crypto/`](http://code.google.com/p/as3crypto/)的 as3crypto 包。下载`.SWC`文件，跟随这个例子操作。

我们需要使`.SWC`在我们的项目中可用。根据所使用的工具不同，操作过程也会有所不同。

### 关于将.SWC 包包含到 Flash Builder 项目的说明

1.  在您的项目中，选择**文件**菜单，然后选择**属性**。

1.  在左侧列中，点击**ActionScript 构建路径**并选择**库路径**标签页。在这个屏幕中找到标记为**添加 SWC**的按钮并点击它。

1.  将会出现一个对话框窗口。选择**浏览到 SWC**选项，找到包含我们加密库的`.SWC`文件，然后点击**确定**。

1.  加密库现在将显示在此屏幕的**构建路径库**部分。确认这是正确的，并退出**属性**窗口。加密库现在可以在我们的移动 Android 项目中使用了：![将.SWC 包包含到 Flash Builder 项目的操作指南](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_09_08.jpg)

### 将.SWC 包包含到 Flash Professional 项目的操作指南

1.  在您的 Flash 项目中，导航到**属性**面板，点击**脚本**选择框旁边的扳手图标：![将.SWC 包包含到 Flash Professional 项目的操作指南](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_09_09.jpg)

1.  这将打开**高级 ActionScript 3.0 设置**对话框窗口。选择**库路径**标签页。在这个屏幕中找到**浏览到 SWC 文件**的图标并点击它。它显示为一个白色和红色的盒子，是此屏幕上唯一不是灰度的图标：![将.SWC 包包含到 Flash Professional 项目的操作指南](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_09_10.jpg)

1.  将会出现一个**文件浏览**对话框窗口。找到包含我们加密库的`.SWC`文件，然后点击**确定**。

1.  加密库现在将显示在此屏幕的**库路径**部分。确认这是正确的，并退出**高级 ActionScript 3.0 设置**窗口。加密库现在可以在我们的移动 Android 项目中使用了：![将.SWC 包包含到 Flash Professional 项目的操作指南](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_09_11.jpg)

## 如何操作...

为了加密应用程序数据库，我们将声明一个密码，并使用外部加密库对其进行加密。这将用于创建和打开我们的数据库连接：

1.  在我们的应用程序中，我们将导入以下类。确保导入`MD5`类或等效类以进行正确的密钥加密：

    ```kt
    import com.hurlant.crypto.hash.MD5;
    import flash.data.SQLConnection;
    import flash.data.SQLMode;
    import flash.data.SQLStatement;
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.SQLEvent;
    import flash.filesystem.File;
    import flash.text.TextField;
    import flash.text.TextFormat;
    import flash.utils.ByteArray;

    ```

1.  我们现在必须声明一些在此应用程序中使用的对象。一个`String`常量将保存我们的纯文本密码以供稍后加密。通常，这会由用户提供，这里为了简单起见而硬编码。我们将需要一个`SQLConnection`来创建或打开我们的数据库文件，以及一组`ByteArray`对象和一个`MD5`对象来执行实际的加密。最后，我们声明一个`TextField`和`TextFormat`对，以向用户输出跟踪消息：

    ```kt
    private const pass:String = "AIR@ndr0idIsKo0l";
    private var sqlConnection:SQLConnection;
    private var encryptionPass:ByteArray;
    private var encryptionKey:ByteArray;
    private var md5:MD5;
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  在这一点上，我们将继续设置我们的`TextField`，应用`TextFormat`，并将其添加到`DisplayList`以进行文本输出。这里，我们创建一个方法来执行所有这些操作：

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
    traceField.y = 40;
    traceField.width = stage.stageWidth-40;
    traceField.height =stage.stageHeight - traceField.y;
    addChild(traceField);
    }

    ```

1.  要执行我们数据库的加密，我们首先会实例化一个`ByteArray`并调用`writeUTFBytes()`方法，传递我们预定义的密码常量。这将把我们的`String`写入字节流。

1.  现在，实例化一个新的`MD5`对象以及另一个`ByteArray`，将`ByteArray`分配给`MD5.hash()`方法的结果，传递包含密码字节的先前的`ByteArray`。

1.  实例化一个`SQLConnection`并注册一个类型为`SQLEvent.OPEN`的事件监听器。这将在数据库成功创建或打开后触发一个事件。

1.  最后，调用`SQLConnection.open()`方法，传递数据库路径作为`File`对象，`SQLMode.CREATE`的打开模式常量，自动压缩`Boolean`，默认页面大小为 1024，以及对于此示例最重要的是，我们的 MD5 加密`ByteArray`：

    ```kt
    protected function encryptDB():void {
    encryptionPass = new ByteArray();
    encryptionPass.writeUTFBytes(pass);
    md5 = new MD5();
    encryptionKey = new ByteArray();
    encryptionKey = md5.hash(encryptionPass);
    sqlConnection = new SQLConnection();
    sqlConnection.addEventListener(SQLEvent.OPEN, dbOpened);
    sqlConnection.open(File.applicationStorageDirectory. resolvePath("encrypted.db"), SQLMode.CREATE, false, 1024, encryptionKey);
    }

    ```

1.  只要数据库成功创建（或打开）并验证加密有效，以下方法就会触发，将有关加密数据库的信息输出到我们的显示界面：

    ```kt
    protected function dbOpened(e:SQLEvent):void {
    traceField.appendText("Encrypted DB Created!\n\n");
    traceField.appendText("Pass: " + pass + "\n\n");
    traceField.appendText("Key: " + encryptionKey.toString());
    }

    ```

1.  当应用程序在我们的 Android 设备上运行时，它将如下所示。由于密钥是一个真正 MD5 加密的`ByteArray`，它在`TextField`中显示为乱码字符，因为它不再是明文`String`：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_09_12.jpg)

## 工作原理...

如果一个应用程序需要在数据库上进行加密，那么在创建我们的数据库时必须应用加密密钥。实现`SQLConnection.open()`或`SQLConnection.openAsync()`方法需要我们传递一个使用`as3Crypto`或类似加密库创建的加密`ByteArray`密钥。如果我们需要修改加密密钥，可以使用`SQLConnection.reencrypt()`来进行修改，以本食谱中演示的方式生成密钥。请注意，有效的加密密钥长度必须为 16 字节。

## 另请参阅...

要了解有关在 AIR for Android 中使用本地数据库的更多信息，请查看第八章，*丰富的访问：文件系统和本地数据库*。


# 第十章：避免问题：调试和资源考虑

本章将涵盖以下内容：

+   使用 Flash Professional 调试应用程序

+   使用 Flash Builder 调试应用程序

+   使用设备 GPU 渲染应用程序元素

+   在设备中断事件发生时自动化应用程序关闭

+   使用设备后退按钮退出应用程序

+   监控应用程序中的内存使用和帧率

# 引言

由于 Android 是一个移动操作系统，因此在性能和用户体验优化方面提出了新的特定挑战。Flash 平台开发者在开发 AIR for Android 和移动 Flash Player 应用程序时必须考虑这一点。本章将提供调试和优化技术以及用户体验调整的概览，以使我们的 AIR for Android 应用程序尽可能良好地运行。

# 使用 Flash Professional 调试应用程序

使用 Flash Professional 调试 AIR for Android 应用程序与调试桌面 AIR 或 Flash 项目非常相似，但有一些值得注意的区别。

## 准备就绪…

请确保您的 AIR for Android 项目在 Flash Professional 中已打开，并且您的播放器是 AIR for Android。这可以通过**属性**面板进行验证：

![准备就绪…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_10_01.jpg)

## 如何操作…

使用移动调试启动器或在通过 USB 连接的设备上进行调试：

1.  在应用程序菜单中，选择**调试**，并将鼠标悬停在标有**调试影片**的选项上。这将导致出现一个调试选项的子菜单：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_10_02.jpg)

1.  当选择在**AIR 调试启动器（移动）**中调试时，Flash Professional 将切换到完整的调试控制台，并在设备调试器中启动应用程序。这对于在涉及多触控、加速度计或其他设备特定输入和传感器时快速调试应用程序非常有用。断点、跟踪语句和其他调试工具将完全与普通桌面项目中的功能一样。![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_10_03.jpg)

1.  一旦我们在调试播放器中完成了初步测试，并准备好通过 USB 在设备上进行调试，我们可以在**调试**菜单中切换到该选项。如果我们从未为此项目配置过 AIR for Android 设置，将出现一个对话框窗口，允许我们进行配置。在随后的调试会话中不应出现此窗口。确保在**Android 部署类型**下选择**调试**选项，并在**发布后**部分选择**安装并启动**选项。

1.  在此阶段，你会注意到有用于确定证书来签署你的应用程序的字段。要了解更多关于代码签名过程的信息，请参考第十一章，*最后的考虑：应用程序编译和分发*。![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_10_04.jpg)

1.  在启动调试会话以在我们的设备上部署后，Flash Professional 将需要几秒钟来编译和部署应用程序。当应用程序开始在设备上加载时，AIR 将会启动一个小对话框，告诉我们它正在尝试连接到我们计算机上的调试器。一旦建立连接，窗口将消失，我们的完整应用程序将启动，使我们能够像平常一样进行测试和调试。![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_10_05.jpg)

## 工作原理...

通过断点和变量检查来调试应用程序与使用任何 Flash 平台技术开发应用程序的课程相同。在使用 AIR for Android 时，我们需要处理外部硬件，并采取一些额外的步骤以确保我们能够在正常环境中进行调试，同时与在真实设备上运行的应用程序进行交互。本食谱展示了在我们当前工作流程中实现这一切所需步骤。

## 另请参阅...

若想了解更多关于使用 Flash Professional 进行项目设置的信息，你可以参考第一章，*准备使用 Android：开发环境和项目设置*。

# 使用 Flash Builder 调试应用程序

在 Flash Builder 中定义调试配置的能力是一个优秀的工作流程改进，我们在设置新的移动项目或准备测试我们工作了一段时间的项目时应该利用这一点。我们可以使用 Flash Builder 的**调试配置**面板为同一个项目设置多个配置。

## 如何操作…

我们将要探索**调试配置**面板，为我们的移动项目配置一组自定义的启动设置：

1.  选择一个移动项目，点击 Flash Builder 工具栏中**调试**按钮旁边的箭头。从菜单中选择**调试配置**选项。调试配置对话框窗口将会打开：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_10_06.jpg)

1.  双击左侧菜单中标记为**MobileApp**的条目，以编辑此选定项目的特定设置。从这个窗口，我们可以选择另一个要配置的项目，为项目指定默认的`Application`文件，设置一个`Target`平台（在我们的情况下是 Google Android），并配置一个`Launch`方法。如果在桌面上调试，我们还可以从各种设备配置文件中选择，甚至可以配置我们自己的。在下一个截图中，我们选择使用摩托罗拉 Droid 上的尺寸和分辨率进行调试：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_10_07.jpg)

1.  如果有必要定义其他设备，我们可以点击**配置**按钮以启动**设备配置**屏幕，该屏幕允许我们导入设备配置文件，甚至添加我们自己的配置文件：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_10_08.jpg)

1.  添加自定义设备配置文件时，我们可以指定显示的宽度和高度以及支持的每英寸像素。Google Android 有一个标准平台 UI，根据制造商对标准显示元素进行的定制程度，在不同设备之间可能有所不同。例如，通知栏除非设备处于全屏模式，否则始终会出现。如果特定设备上的通知栏更高或更短，我们可以在这一步进行相应调整。

    ### 注意

    尽管这里可以模拟分辨率和 PPI，但除非开发机器具有多点触控界面，否则我们仍需要在实际设备上测试任何触摸或手势输入。当然，设备性能也不是模拟的一部分。

    ![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_10_09.jpg)

1.  当选择在实际物理硬件上调试时，我们可以选择通过 USB 或无线网络在设备上进行调试。USB 调试通常更为直接，大多数情况下推荐使用。在以下屏幕截图中，您可以看到我们已经为桌面调试定义了一个配置，以及一个用于通过 USB 连接的设备调试的配置：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_10_10.jpg)

1.  完成后，点击**应用**然后**关闭**。我们现在可以通过 Flash Builder 调试图标或项目上下文菜单访问任何已定义的配置：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_10_11.jpg)

1.  一旦我们选择为项目启动调试会话，那么在桌面调试时，它将在 Flash Builder 移动调试播放器中打开；如果是 USB 设备调试，它将被编译、推送到设备并安装。对于设备调试会话，AIR 将启动一个小对话框，告知我们它正在尝试连接到计算机上的调试器。一旦建立连接，窗口将消失，我们的完整应用程序将启动，使我们能够正常测试和调试。![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_10_12.jpg)

## 工作原理…

如果你选择在桌面上启动，你将能够在 Flash Builder 中进行本地调试。你也可以通过选择一系列配置文件来模拟各种 Android 设备。如果你想创建自己的配置文件，可以点击**配置**按钮。

当选择在设备上启动时，你也可以通过 Flash Builder 在设备上进行调试。这是迄今为止调试移动应用程序的最佳方式，因为它是在真正的 Android 硬件上进行测试的。

## 另请参阅...

有关使用 Flash Builder 进行项目设置的信息，你可以参考第一章，*准备使用 Android：开发环境和项目设置。*

# 使用设备 GPU 渲染应用程序元素

虽然较旧的 Android 设备必须依赖 CPU 来渲染移动 Adobe AIR 项目中的所有内容，但市场上许多较新的设备完全支持图形处理单元（GPU）渲染并提供必要的钩子让我们的应用程序利用这一点。本食谱将展示我们必须采取的必要步骤，以启用应用程序元素的 GPU 加速。

## 如何操作...

我们将修改 AIR 描述符文件中的设置，并使`DisplayObject`实例能够利用这些修改：

1.  在你的项目中找到 AIR 描述符文件。它通常被命名为类似`{MyProject}-app.xml`，并位于项目根目录。

1.  浏览文件，找到名为`<initialWindow>`的节点，位于本文档的开头部分。这个节点包含了许多关于我们应用程序窗口视觉方面的默认设置。

1.  我们现在必须找到名为`<renderMode>`的子节点。如果此节点不存在，我们可以轻松地在这里添加它。`renderMode`的值决定了应用是使用 CPU 还是 GPU 来渲染内容。应用程序`renderMode`有三个可能的值：

    +   **AUTO:** 应用将尝试使用设备 GPU 来渲染视觉显示对象：

        ```kt
        <renderMode>auto</renderMode>

        ```

    +   **GPU:** 应用将被锁定在 GPU 模式下。如果设备不支持 Adobe AIR 中的 GPU 渲染，将会出现问题：

        ```kt
        <renderMode>gpu</renderMode>

        ```

    +   **CPU:** 应用将使用设备 CPU 来渲染所有视觉显示对象。这是最安全的设置，但提供的优势最少：

        ```kt
        <renderMode>cpu</renderMode>

        ```

1.  现在，每当我们想在应用程序中的`DisplayObject`实例利用这一点时，我们必须将`DisplayObject`实例的`cacheAsBitmap`属性设置为`true`，并将`cacheAsBitmapMatrix`属性分配给一个新的 Matrix 对象。这将使这些单个对象通过设备 GPU 进行 2D 内容渲染。当在 2.5D 空间中使用对象时，它们将自动使用 GPU 进行渲染，不需要这些额外的设置。

    ```kt
    displayObject.cacheAsBitmap = true;
    displayObject.cacheAsBitmapMatrix =new Matrix();

    ```

### 它的工作原理...

在 AIR 描述符文件中将应用的`renderMode`设置为`gpu`将强制应用使用 GPU 渲染视觉对象。然而，不在 2.5D 空间中渲染的个别对象需要将`cacheAsBitmap`属性设置为`true`，并将`cacheAsBitmapMatix`属性分配给一个 Matrix 对象。当设置`renderMode`为`auto`时，应用将尝试通过 GPU 渲染这些对象，如果特定设备不支持 GPU 加速，则回退到 CPU 渲染。我们还可以将`renderMode`设置为`cpu`，这样会完全绕过 GPU 渲染，只通过 CPU 渲染所有内容。

当适当使用时，设置应用的`renderMode`可以显著提高应用内部视觉对象的渲染速度。重要的是要意识到许多设备可能无法通过 AIR for Android 获得完整的 GPU 支持，在这种情况下，强制使用 GPU 可能会对应用造成问题，甚至可能导致在某些特定设备上无法使用。在使用 GPU 时也存在一些限制，例如：不支持滤镜、PixelBender 混合以及各种标准的混合模式。

### 还有更多内容...

如果使用 Flash Professional，我们还可以通过 AIR 的**Android 设置**面板设置`渲染`模式。这可以通过**属性**面板访问。点击**播放器选择**旁边的扳手图标来配置这些设置。

![还有更多...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_10_13.jpg)

# 在设备中断事件时自动化应用关闭

当应用在 Android 设备上运行时，用户会话很可能因为电话来电或其他不可预见的事件而中断。当发生此类情况时，我们应该考虑是否应该退出应用并释放系统资源供其他任务使用。

## 如何操作...

我们将监听一个应用发出的停用事件并响应退出应用：

1.  首先，我们需要将以下类导入到我们的应用中：

    ```kt
    import flash.desktop.NativeApplication:
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.Event;

    ```

1.  我们必须在`NativeApplication.nativeApplication`对象上注册一个类型为`Event.DEACTIVATE`的事件监听器。当设备上发生电话来电或其他中断导致应用失去焦点时，将触发此事件：

    ```kt
    protected function registerListeners():void {
    NativeApplication.nativeApplication.addEventListener(Event. DEACTIVATE, appDeactivate);
    }

    ```

1.  在下面的函数中，我们将在`NativeApplication.nativeApplication`对象上调用`exit()`方法，完全关闭应用。这将释放资源供其他设备应用使用：

    ```kt
    protected function appDeactivate(e:Event):void {
    NativeApplication.nativeApplication.exit();
    }

    ```

### 工作原理...

我们希望在使用用户设备上的资源时，成为我们应用程序运行的良好管理者。有效的方法是确保在应用程序处于非活动状态时释放应用程序使用的任何内存。监听停用事件将允许我们知道何时有其他应用程序获得焦点。在这一点上，我们可以完全退出应用程序，释放用户当前正在使用的资源。

### 另请参阅…

在实际退出应用程序之前，我们有机会通过本地共享对象或本地数据库保存会话数据。有关如何执行此操作的信息，请查看第八章，*丰富的访问：文件系统和本地数据库。*

# 使用设备后退按钮退出应用程序

安卓设备通常在设备的一侧有一组四个软键，这些软键始终对用户可见。其中两个键涉及导航——后退和主页键。当用户激活某个事件，例如按下后退按钮时，我们应该考虑是否完全退出应用程序并释放系统资源以供其他任务使用。

### 注意

主页按钮将始终使用户返回到 Android 桌面，从而停用我们的应用程序。要了解如何在发生此类事件时关闭应用程序，请参阅之前的食谱。

## 如何操作...

我们将监听专用安卓后退按钮的按下，并在响应中退出应用程序：

1.  首先，我们需要将以下类导入到我们的应用程序中。

    ```kt
    import flash.desktop.NativeApplication;
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.KeyboardEvent;
    import flash.ui.Keyboard;

    ```

1.  我们必须在`NativeApplication.nativeApplication`对象上注册一个类型为`KeyboardEvent.KEY_DOWN`的事件监听器。当用户激活专用的安卓后退键时，此事件将被触发：

    ```kt
    protected function registerListeners():void {
    NativeApplication.nativeApplication. addEventListener(KeyboardEvent.KEY_DOWN, onBackPressed);
    }

    ```

当用户按下后退键时，我们将调用`NativeApplication.nativeApplication`对象的`exit()`方法，完全关闭应用程序。这将释放资源供其他设备应用程序使用：

```kt
protected function onBackPressed(e:KeyboardEvent):void {
if(e.keyCode == Keyboard.BACK){
NativeApplication.nativeApplication.exit();
}
}

```

## 工作原理...

我们希望在使用用户设备上的资源时，成为我们应用程序运行的良好管理者。有效的方法是确保在应用程序处于非活动状态时释放应用程序使用的任何内存。做到这一点的方法之一是监听键盘事件并拦截后退键的按下。在这一点上，我们可以完全退出应用程序，释放用户当前正在使用的资源。

根据我们应用程序的当前状态，我们可以选择是退出应用程序还是仅返回到某个之前的状态。在基于 Flex 的移动项目中执行此类操作时，我们可能只有在当前视图是我们应用程序中的初始视图`ViewNavigator`时才会退出应用程序。

## 还有更多…

通过使用`KeyboardEvent.preventDefault()`，也可以阻止安卓返回按钮执行任何操作：

```kt
protected function onBackPressed(e:KeyboardEvent):void {
if(e.keyCode == Keyboard.BACK){
KeyboardEvent.preventDefault();
}
}

```

## 另请参阅…

请注意，在实际退出应用程序之前，我们有机会通过本地共享对象或本地数据库保存任何会话数据。有关如何执行此操作的更多信息，请查看第八章，*丰富的访问：文件系统和本地数据库*。

# 监控应用程序中的内存使用和帧率

安卓设备通常与传统桌面或笔记本电脑相比，内存较少且 CPU 性能较弱。在构建安卓应用时，我们必须非常小心，以免创建出过于耗能的应用，导致帧率降至不可接受的水平或应用无响应。为了帮助我们排查和监控这些问题，我们可以跟踪运行中应用的内存消耗和计算出的帧率，以便相应地作出响应。

## 如何操作...

我们可以通过使用`flash.system`包以及`flash.utils.getTimer`类来监控许多系统属性，以计算当前应用程序的帧率：

1.  首先，我们需要将以下类导入到我们的应用程序中：

    ```kt
    import flash.display.Sprite;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.Event;
    import flash.system.Capabilities;
    import flash.system.System;
    import flash.text.TextField;
    import flash.text.TextFormat;
    import flash.utils.getTimer;

    ```

1.  我们需要声明一组`Number`对象来保存持久的计时值，以便计算应用程序的帧率。同时，声明一个`TextField`和`TextFormat`对，以向用户输出此和其他设备消息：

    ```kt
    private var prevTime:Number;
    private var numFrames:Number;
    private var frameRate:Number;
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  在这一点上，我们继续设置我们的`TextField`，应用`TextFormat`，并将其添加到`DisplayList`中。这里，我们创建一个方法来执行所有这些操作：

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
    traceField.y = 40;
    traceField.width = stage.stageWidth-40;
    traceField.height = stage.stageHeight - traceField.y;
    addChild(traceField);
    }

    ```

1.  下一步包括创建处理我们帧率计算的机制。我们将`prevTimeNumber`设置为应用程序初始化后当前经过的毫秒数。我们还将`numFrames`变量设置为`0`。这为我们提供了一组基础数字。最后，我们在应用程序上注册一个`Event.ENTER_FRAME`类型的事件监听器，以定期为我们执行新的帧率计算：

    ```kt
    protected function registerListeners():void {
    prevTime = getTimer();
    numFrames = 0;
    this.addEventListener(Event.ENTER_FRAME, onEnterFrame);
    }

    ```

1.  这个冗长的方法会在每次进入帧时刷新我们`TextField`中的所有内容。首先，我们将输出一些关于 CPU 架构、制造商以及应用程序可用的内存的信息。在这一步中，内存是重要的部分。

1.  为了计算运行帧率，我们首先会递增我们的帧计数器，并再次获取从应用程序初始化开始经过的毫秒数。可以减去上一次读取的值，这样我们就得到了自上次运行此函数以来经过的时间。

1.  如果经过的时间超过 1000，那么已经过去了一秒钟，然后我们可以进行一些计算来确定我们实际每秒的帧数。我们将通过将本次循环中处理的帧数除以持有我们之前时间的变量乘以 1000，来获取每分钟的帧数。将上一个时间变量设置为当前经过的时间，并将我们的帧数重置为`0`，将开始一个新的周期：

    ```kt
    protected function onEnterFrame(e:Event):void {
    traceField.text = "CPU Arch: " + Capabilities.cpuArchitecture + "\n";
    traceField.appendText("Manufacturer: " + Capabilities. manufacturer + "\n");
    traceField.appendText("OS: " + Capabilities.os + "\n\n");
    traceField.appendText("Free Memory: " + System.freeMemory + "\n");
    traceField.appendText("Total Memory: " + System.totalMemory + "\n\n");
    numFrames++;
    var timeNow:Number = getTimer();
    var timePast:Number = timeNow - prevTime;
    if(timePast > 1000){
    var fpm:Number = numFrames/timePast;
    frameRate = Math.floor(fpm * 1000);
    prevTime = timeNow;
    numFrames = 0;
    }
    traceField.appendText("Framerate: " + frameRate);
    }

    ```

1.  当我们在设备上运行应用程序时，我们可以看到 CPU 和操作系统信息，以及内存使用情况和计算出的帧率：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_10_14.jpg)

## 它的工作原理...

关于 CPU 和内存使用，可以通过 Capabilities 和 System 类访问大量信息。我们可以通过从`getTimer()`实用方法获取的数据计算实际 FPS，来获取有关当前帧率的更多信息。将这些信息综合使用，将为我们提供一组合理的数据，以确定应用程序在特定设备上的运行情况。然后，我们可以使用这些数据在应用程序运行时通过修改应用程序属性、改变我们渲染内容的方式，甚至提醒用户可能存在问题。

## 还有更多...

如果帧率变得太慢，我们可能需要考虑降低帧率，甚至降低应用程序的渲染质量以改善性能。这可以通过使用以下代码片段来完成：

```kt
this.stage.frameRate = 10;
this.stage.quality = StageQuality.LOW;

```

## 另请参阅...

我们还可以推荐使用像`Hi-ReS-Stats`这样的包，可以从[`github.com/mrdoob/Hi-ReS-Stats`](http://https://github.com/mrdoob/Hi-ReS-Stats)下载，并在移动 Android 应用程序上使用来监控资源使用情况。使用这个类将在我们的应用程序中生成一个图形覆盖层，以监控应用程序性能。


# 第十一章：最后考虑：应用程序编译和分发

本章节将涵盖以下内容：

+   使用 Flash Professional 生成代码签名证书

+   使用 Flash Builder 生成代码签名证书

+   使用 FDT 生成代码签名证书

+   使用 AIR 开发工具生成代码签名证书

+   准备图标文件以供分发

+   使用 Flash Professional 编译应用程序

+   使用 Flash Builder 编译应用程序

+   使用 FDT 编译应用程序

+   使用 AIR 开发工具编译应用程序

+   将应用程序提交到 Android Market

# 简介

当将移动 Flash 应用程序（`.swf`）部署到 Web 上时，这个过程与桌面版非常相似；将你的 `.swf` 嵌入 HTML 容器中，就完成了。然而，将 AIR 应用程序部署到 Android Market 上则完全不同。在本章中，我们将了解如何准备一个应用程序以分发给 Android Market，生成适当的代码签名证书，以及编译和提交过程的相关细节。

# 使用 Flash Professional 生成代码签名证书

在 Android Market 上分发的应用程序必须使用 25 年有效期的代码签名证书进行数字签名。我们有多种不同的方法来生成 Android 应用程序的代码签名证书。在本食谱中，我们将演示如何使用 Flash Professional 生成此类证书。

## 如何操作...

在 Flash Professional 中，执行以下操作以创建自签名数字证书：

1.  打开一个针对 **AIR for Android** 的项目，打开 **属性** 面板，并点击 **播放器选择** 框旁边的扳手图标。这将打开 **AIR for Android 设置** 对话框：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_11_01.jpg)

1.  在 **AIR for Android 设置** 对话框中，点击 **创建** 按钮以打开 **创建自签名数字证书** 对话窗口：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_11_02.jpg)

1.  当 **创建自签名数字证书** 对话框出现在我们面前时，我们将输入所需的信息并为证书选择名称和位置。正确输入所有信息后，我们将点击 **确定** 以便 Flash Professional 生成证书。确保在 **有效期** 输入框中输入 25 年，以适用于 Android：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_11_03.jpg)

## 工作原理...

通过生成有效的数字代码签名证书，我们可以正确地为提交到 Android Market 的 Android 应用程序签名。Flash Professional 提供了一个简单的方法来生成适当的证书类型并将其应用于我们的分发应用程序。

# 使用 Flash Builder 生成代码签名证书

在 Android Market 上分发的应用程序必须使用 25 年有效期的代码签名证书进行数字签名。我们有多种不同的方法可以为 Android 应用程序生成代码签名证书。在本食谱中，我们将演示如何使用 Flash Builder 生成此类证书。

## 如何操作...

在 Flash Builder 中，执行以下操作以创建自签名数字证书：

1.  在**包资源管理器**中选择移动项目，进入**文件**菜单并选择**属性**。将为此项目显示**属性**对话框。

1.  在**属性**对话框中，根据所选项目的类型，向下滚动至**Flex 构建打包**或**ActionScript 构建打包**项，并选择**Google Android**。选择**数字签名**标签后，点击**创建**按钮以打开**创建自签名数字证书**对话框：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_11_04.jpg)

1.  现在需要做的就是输入所需信息并为证书选择名称和位置。正确输入所有信息后，我们将点击**确定**，让 Flash Builder 生成证书：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_11_05.jpg)

## 工作原理...

通过生成有效的数字代码签名证书，我们可以正确地为提交到 Android Market 的 Android 应用程序签名。Flash Professional 提供了一种简单的方法来生成适当的证书类型，并将其应用于我们分发的应用程序。

# 使用 FDT 生成代码签名证书

在 Android Market 上分发的应用程序必须使用 25 年有效期的代码签名证书进行数字签名。我们有多种不同的方法可以为 Android 应用程序生成代码签名证书。在本食谱中，我们将演示如何使用 PowerFlasher FDT 生成此类证书。

## 如何操作...

在 FDT 中，执行以下操作以创建自签名数字证书：

1.  点击顶部菜单中**运行**图标旁边的小箭头，并从出现的子菜单中选择**运行配置**。这将打开**运行配置**对话框：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_11_07.jpg)

1.  打开**运行配置**对话框窗口，双击**FDT AIR 应用程序发布**菜单项以创建新配置。选择**证书**标签，并输入所需信息，为证书选择名称和位置。正确输入所有信息后，我们将点击**创建证书**，让 FDT 为我们生成证书：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_11_08.jpg)

## 工作原理...

通过生成有效的数字代码签名证书，我们可以正确地为提交到 Android Market 的 Android 应用程序签名。FDT 提供了一种简单的方法来生成适当的证书类型，并将其应用于我们分发的应用程序。

# 使用 AIR 开发者工具生成代码签名证书

Android Market 上发布的应用程序必须使用 25 年代码签名证书进行数字签名。我们有多种方法可以生成 Android 应用程序的代码签名证书。在本食谱中，我们将演示如何使用 ADT 命令行工具生成此类证书。

## 准备中…

要了解如何在特定环境中配置 ADT，请查看第一章，*准备使用 Android：开发环境和项目设置。*

## 如何操作...

使用 ADT 命令行工具，执行以下操作以创建自签名的数字证书：

1.  对于此示例，我们将假设以下情况：

    ```kt
    Publisher Name: "Joseph Labrecque"
    Validity Period: 25 (years)
    Key Type: 1024-RSA
    PFX File: C:\Users\Joseph\Documents\airandroid.p12
    Password: airAndroidPass

    ```

1.  打开命令提示符或终端（取决于操作系统），并输入生成我们证书的命令字符串：

    ```kt
    adt -certificate -cn "Joseph Labrecque" -validityPeriod 25 1024-
    RSA C:\Users\Joseph\Documents\airandroid.p12 airAndroidPass

    ```

1.  ADT 实用程序现在将处理命令并完成证书生成过程。如果我们的命令有问题，ADT 将在这里打印错误信息，让我们知道出现了错误：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_11_09.jpg)

1.  现在，我们可以浏览到命令字符串中指定的位置来找到我们新创建的证书，并使用它来签署我们的 AIR for Android 应用程序：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_11_10.jpg)

## 工作原理...

通过生成有效的数字代码签名证书，我们可以正确签署我们的 Android 应用程序以便提交到 Android Market。使用与 AIR SDK 捆绑的 ADT 工具，我们可以生成适合分发的适当证书类型。

# 准备分发图标文件

当我们为在 Android Market 上发布的应用程序编译应用程序时，我们必须包括一组标准图标图像以及我们的应用程序。这些图标的位置在我们的 AIR 应用程序描述符文件中定义。Android 期望一组三个图标：36x36、48x48 和 72x72。每个图标用于不同的屏幕密度，并且都应该包括为标准的 PNG 文件。

## 如何操作...

根据使用的工具不同，这项任务可以有不同的处理方式。我们将演示如何使用 Flash Professional CS5.5 在应用程序中包含这些图标，以及如何通过直接修改 AIR 应用程序描述符文件来实现。

### 使用 Flash Professional CS5.5

1.  打开一个针对**AIR for Android**的项目，打开**属性**面板，点击**播放器选择**框旁边的扳手图标。这将打开**AIR for Android 设置**对话框：![使用 Flash Professional CS5.5](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_11_11.jpg)

1.  在 **AIR for Android 设置** 对话框中，点击 **图标** 选项卡。要为我们的项目指定特定图标，我们只需在列表中选择每个图标条目，并通过使用文件夹和放大镜图标浏览来定位每个图标要使用的文件：

### 直接修改 AIR 描述符文件

1.  在您的项目中找到 AIR 描述符文件。它通常命名为类似 `{MyProject}-app.xml` 的名称，并位于项目根目录下。

1.  在本文档中浏览名为`<icon>`的节点。此节点包含许多与我们的应用程序窗口视觉方面相关的默认设置。如果它被注释掉了，我们必须在继续之前取消注释。

1.  我们现在必须确保在`<icon>`节点内存在以下三个子节点。确保我们的图标文件路径正确。如果它们不正确，在我们尝试编译此应用程序时编译器会告知我们：

    ```kt
    <image36x36>assets/icon_36.png</image36x36>
    <image48x48>assets/icon_48.png</image48x48>
    <image72x72>assets/icon_72.png</image72x72>

    ```

例如，以下是适用于 Android 应用程序的一组三个图标及其像素测量值：

![直接修改 AIR 描述符文件](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_11_13.jpg)

## 工作原理...

在 Android 应用程序包中包含一组图标对于通过 Android Market 分发应用程序至关重要。它还能在应用程序安装到设备上后为用户提供一个容易识别的视觉提示。花点时间设计一组真正能反映应用程序代表的图标。

## 还有更多...

如果应用程序要发布到 Android Market，我们还需要制作多种其他图像来正确地为我们的应用程序品牌。查看 Android Market 以了解当前需要哪些图像的详细信息，请访问[`market.android.com/`](http://https://market.android.com/)。

# 使用 Flash Professional 编译应用程序

将项目编译为 Android 发布版本 `.apk` 文件是在将应用程序分发到 Android Market 或其他渠道之前的最后一步。根据使用的工具不同，有许多方法可以做到这一点。在本食谱中，我们将使用 Flash Professional 中的工具来编译和打包我们的应用程序。

## 如何操作...

要从 Flash Professional 编译 `.apk`，我们将采取以下步骤：

1.  打开针对 **AIR for Android** 的项目，打开 **属性** 面板并点击 **发布设置** 按钮。这将打开 **发布设置** 对话框：

1.  我们可以在这里检查我们的设置，如果我们确定一切配置正确，甚至可以直接点击**发布**。要验证所有设置是否都已就绪以发布到 Android，请点击我们的**播放器选择**框的小扳手图标，它应该设置为**适用于 Android 的 AIR**。这将提供对**适用于 Android 的 AIR 设置**对话框的访问：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_11_16.jpg)

1.  打开**适用于 Android 的 AIR 设置**对话框后，我们可以验证我们的**特定配置**选项，然后再决定发布。**常规**标签包含许多重要输入，包括生成的`.apk`文件的路径、应用程序名称、版本、ID 和其他必需的配置设置。我们还可以选择包含除了编译的`.swf`和 AIR 描述文件之外的其他文件，例如外部图像资源。**图标**标签允许我们使用基本的 GUI 包含图标文件，而**权限**标签将允许我们设置特定于 Android 的应用程序权限。

    ### 注意

    这些设置都会修改应用程序描述文件，进而生成 Android 清单文档。我们可以将这些设置视为这些文件的图形用户界面。

1.  作为最后一步，点击**部署**标签：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_11_17.jpg)

1.  在**部署**标签中存在一个部署类型设置，以及使用自签名证书为应用程序签名的机会。这非常重要，因为 Android 市场不接受未签名的应用程序或不符合 Android 市场条款设置要求的应用程序。

1.  一定要提供应用名称，用于用户在设备上安装后识别应用程序，以及一个唯一的应用 ID。`App ID`非常重要，因为这是 Android Market 中应用程序的主要标识符。为了使应用程序更新正常工作，它必须是唯一的，建议开发人员特别小心地使用反向域名表示法以保持这种唯一性。

1.  我们需要确保从选择获取 AIR 运行时的选项指示我们正在定位的具体分发市场。对于一般的 Android 市场，我们选择谷歌 Android 市场。此对话框还通过 Android 部署类型设置为我们提供了编译用于不同目的的应用程序版本的选择：

    +   **设备发布：**当我们想通过 Android 市场分发我们的应用程序时，需要选择的选项

    +   **模拟器发布：**生成与 Android SDK 模拟器和 AIR 运行时的模拟器版本兼容的发布版本

    +   **调试：**此选项生成专门用于调试应用程序的发布版本

1.  一旦我们对所有配置设置感到满意，我们可以退出到**发布设置**对话框并点击**发布**，或者直接在此处点击**发布**按钮。只要我们之前已经完成这些配置步骤，我们也可以使用 Flash Professional 中提供的传统发布方法。![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_11_18.jpg)

现在我们有一个完全编译、有效签名的`.apk`文件，准备进行分发。

## 工作原理...

我们通过 Flash Professional GUI 对话框更改的配置设置实际上是在幕后修改 AIR 描述符文件。一旦我们选择发布应用程序，Flash Professional 将使用此文件来编译并将所有内容打包成一个有效的`.apk`文件，以便在 Android Market 上分发。

# 使用 Flash Builder 编译应用程序

将项目编译为 Android 发布版本`.apk`文件是分发应用程序到 Android Market 或其他渠道之前的最后一步。根据使用的工具不同，有许多方法可以做到这一点。在本教程中，我们将使用 Flash Builder 中的工具来编译和打包我们的应用程序。

## 如何操作...

要从 Flash Builder 编译`.apk`，请执行以下步骤：

1.  在移动 ActionScript 或 Flex 项目中，导航到 Flash Builder 菜单，选择**项目**菜单项。这将显示一个包含多个选项的子菜单。从该菜单中，选择**导出发布构建**，打开**导出发布构建**对话框窗口：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_11_19.jpg)

1.  在此窗口中，我们可以选择要执行发布构建的项目以及该项目中的具体应用程序，决定要定位的平台，指定构建的路径和文件名，以及选择要导出哪种类型的应用程序。对于 Android，我们将在每个目标平台上选择**签名包**。只要我们选择了**Google Android**作为目标平台，点击**下一步**后，这将打开**打包**设置对话框：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_11_20.jpg)

1.  现在，我们可以为构建配置一些高级属性。点击**包内容**标签，以验证构建中是否包含所有必需的文件。如果我们想打包其他文件，甚至排除某些资源，我们可以通过使用每个项目旁边的复选框来完成。点击**数字签名**标签以继续：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_11_21.jpg)

1.  最后的任务是选择一个签名证书，以便在 Android Market 上发布我们的应用程序时进行数字签名。选择一个证书并输入关联的密码。点击**完成**将执行构建，并将编译的`.apk`保存到我们之前选择的位置。如果我们愿意，可以通过**包内容**标签包含外部文件，并通过**部署**标签选择部署到任何连接的设备：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_11_22.jpg)

现在我们已经拥有一个完全编译、有效签名的`.apk`文件，准备进行分发。

## 工作原理...

Flash Builder 在导出项目的发布版本时提供了目标平台的概念。如果我们选择 Google Android 作为目标平台，我们会得到一些特定于 Android 的附加选项，我们可以根据特定项目的需求进行修改。额外的对话框元素允许我们将所有内容编译并打包成一个有效的`.apk`，准备在 Android Market 上发布。

# 使用 FDT 时编译应用程序

将项目编译为 Android 发布版本的`.apk`文件是在 Android Market 或其他渠道发布应用程序之前的最后一步。根据使用的工具不同，有许多方法可以做到这一点。在这个食谱中，我们将讨论在使用 Powerflasher FDT 编译和打包应用程序时可用的三种流行方法。

## 如何操作...

在撰写本文时，FDT 不支持直接与 Android 的 AIR 一起工作。然而，FDT 用户可以通过三种主要方法编译他们的项目以进行 Android 分发。

### 使用移动项目模板

FDT 社区制作了许多支持 Android 的 AIR 移动项目模板。这些模板适用于所有 FDT 项目使用的新模板系统，并为工作流程添加不同级别的功能。其中大多数还包括 ANT 脚本，使用 AIR 开发者工具编译`.apk`。

### 使用 ANT

迄今为止，这是编译 Android 项目最灵活的方法，因为它实际上与 IDE 无关，任何人都可以使用。ANT 随 FDT 的标准安装一起打包，网上社区有许多启动脚本可以部署 Android 的 AIR。若要开始使用 FDT 中的 ANT，请查看[`fdt.powerflasher.com/docs/FDT_Ant_Tasks`](http://fdt.powerflasher.com/docs/FDT_Ant_Tasks)。

### 通过 CLI 使用 ADT

最基本的方法是直接使用 FDT 开发一个移动项目，然后通过命令行界面使用 AIR 开发者工具将其打包成`.apk`。下一个食谱将详细介绍如何实现这一过程。

## 工作原理...

无论选择哪种方法，目标都是相同的——编译和打包所有内容到一个有效的 `.apk`，准备在 Android Market 上分发。FDT 的一个优点是它不限制开发者只能用一种特定的方式做事。在为 Android 生成发布版本时，我们有多种选择。

# 使用 AIR 开发者工具编译应用程序

将项目编译为 Android 发布版本 `.apk` 文件是分发应用程序到 Android Market 或其他渠道之前的最后一步。根据使用的工具不同，有许多方法可以做到这一点。在本教程中，我们将使用 **AIR 开发者工具** (**ADT**) 命令行实用程序来编译和打包我们的应用程序。

## 如何操作...

要使用 ADT 命令行工具从移动 AIR 项目编译 `.apk`，我们将执行以下步骤：

1.  在此示例中，我们将假定以下内容：

    +   **证书：** `android.p12`

    +   **期望的 APK：** `mobileAIR.apk`

    +   **AIR 描述符：** `mobileAIR\src\mobileAIR-app.xml`

    +   **SWF 文件：** `mobileAIR\src\mobileAIR.swf`

1.  打开命令提示符或终端（取决于操作系统），输入命令字符串以生成我们的证书。在这种情况下，我们将目标类型设置为 `.apk` 以进行发布构建。我们也可以将其设置为 apk-debug 以进行调试构建，或者设置为 apk-emulator 以在模拟器上安装：

    ```kt
    -package -target apk -storetype pkcs12 -keystore android.p12
    mobileAIR.apkmobileAIR\src\mobileAIR-app.xml mobileAIR\src\
    mobileAIR.swf

    ```

1.  其他文件，如资源或图标，可以在 .swf 条目之后包含，用空白分隔：

    ```kt
    -package -target apk -storetype pkcs12 -keystore android.p12
    mobileAIR.apkmobileAIR\src\mobileAIR-app.xml mobileAIR\src\
    mobileAIR.swf mobileAIR\src\assets\icon_32.pngmobileAIR\src\
    assets\icon_36.pngmobileAIR\src\assets\icon_72.png

    ```

1.  现在 ADT 实用程序将处理该命令并完成 `.apk` 编译过程。如果我们的命令有问题，ADT 将在这里打印错误信息，让我们知道出了问题。通常，如果出现问题，可能是 AIR 描述符文件有问题，或者预期输入文件的路径不正确。![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_11_23.jpg)

1.  现在，我们可以浏览到命令字符串中指定的结果位置，找到我们新创建的 `.apk` 文件，该文件可以直接安装在 Android 设备上，也可以通过 Android Market 进行分发：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_11_24.jpg)

现在我们已经拥有一个完全编译、有效签名的 `.apk` 文件，准备进行分发。

## 工作原理...

假设我们已经正确配置了我们的应用程序，ADT 将为我们编译、签名并打包所有的项目文件到一个 `.apk` 中。ADT 有许多不同的实用程序和配置选项，可以对项目执行许多操作。请查看 [`help.adobe.com/en_US/air/build/`](http://help.adobe.com/en_US/air/build/) 并在菜单中选择 **AIR 开发者工具** (**ADT**) 以获取完整文档。

## 另请参阅…

要了解如何在特定环境中配置 ADT，请查看第一章，*准备使用 Android：开发环境和项目设置*。

# 将应用程序提交到 Android 市场

Google 使注册成为 Android 开发者和在 Android 市场上发布应用程序变得非常容易。这个指南将详细说明在编译完成`.apk`之后进行这些操作的必要步骤。

## 准备就绪...

在开发者能够向 Android 市场提交任何内容之前，必须创建一个开发者账户。这个过程可以在几分钟内完成，既简单又实惠。

要注册成为 Android 开发者：

1.  使用网络浏览器，前往 [`market.android.com/publish/signup`](http://market.android.com/publish/signup)。

1.  使用您的 Google 账户登录（或创建新账户）。

1.  填写注册表单并支付一次性的 25 美元设置费用。

1.  恭喜您成为 Android 开发者！

## 如何操作...

1.  1 将编译并签名的`.apk`文件上传到 Android 市场，以供全球分发。

1.  使用您的 Android 开发者凭据在[`market.android.com/publish/`](http://https://market.android.com/publish/)登录 Android 市场。

1.  点击右下角标有**上传应用程序：**的按钮![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_11_25.jpg)

1.  现在展现给我们的是一个相当长的表单，它允许我们包含有关我们应用程序的各种信息。我们可以对应用程序进行分类，添加描述性和促销文本，更新发行说明，并选择是否向用户收费或允许免费下载。如果我们决定要求付费，我们必须首先通过此页面上提供的链接建立 Google 商家账户。

1.  除了文本条目和其他输入选择外，我们还有机会上传各种图片，这些图片将代表我们的应用程序在 Android 市场中的形象。具体的图片属性在此表单中有详细说明：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_11_26.jpg)

1.  在此页底部有三个按钮。我们可以点击**保存**以保存我们的应用程序资料以供以后编辑。点击**删除**按钮，将允许我们从 Android 市场完全移除一个应用程序。要发布我们的应用程序，我们将点击**发布**按钮。

### 注意

一旦发布应用程序，此按钮将显示为**取消发布**，如果用户已安装应用程序，则**删除**按钮将不再作为选项出现。

![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_11_27.jpg)

应用程序现在已发布到 Android 市场，可供全球数百万用户使用。

## 工作原理...

将应用程序上传并发布到 Android 市场，将允许用户下载并安装应用程序。我们对应用程序描述、版本信息以及相关图像资产拥有完全控制权。我们还能够从开发者区域跟踪评分和评论，并在必要时管理商家账户。发布到 Android 市场是即时的。没有像其他应用程序市场那样的审批和拒绝过程。

## 还有更多...

将应用程序更新到新版本比设置一个全新的应用程序简单得多：

1.  一旦进入安卓市场，点击现有应用程序的名称。这将允许你编辑与其相关的任何图片或文本。

1.  要实际发布应用程序的新版本，我们必须点击`[上传升级]`的链接。这将导致出现一组新的表单控件。![还有更多...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_11_28.jpg)

1.  点击**选择文件**并浏览新的`.apk`文件。现在点击**上传**将文件提交到谷歌服务器。

1.  新文件将被解析以获取版本信息并验证内容是否有效。对版本号、应用图标、请求的权限等所做的任何更改都将在草稿中反映出来。

1.  应用描述文件中定义的版本号必须高于之前提交的版本，以便进行有效的升级。如果需要，我们还可以在此页面对一般应用信息进行额外编辑。点击页面底部的**发布**，新版本将立即在安卓市场可用。
