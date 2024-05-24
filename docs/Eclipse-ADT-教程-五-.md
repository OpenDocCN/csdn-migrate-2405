# Eclipse ADT 教程（五）

> 原文：[`zh.annas-archive.org/md5/D0CC09ADB24DCE3B2F724DF3004C1363`](https://zh.annas-archive.org/md5/D0CC09ADB24DCE3B2F724DF3004C1363)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：社交模式

到目前为止，在这本书中我们已经涵盖了移动应用开发的许多方面。然而，即使设计得最好和最有用的应用也可以通过采用社交媒体和其他网页内容获得巨大的好处。

我们在前面章节中介绍的快餐制作应用是一个很好的例子，这个应用可以通过生成 Facebook 点赞和推文来提升其知名度，而这些以及其他社交媒体都提供了直接将这些功能整合到我们应用中的技术。

除了将现有的社交媒体平台整合到我们的应用中，我们还可以使用 **WebView** 类将任何喜欢的网页内容直接嵌入到活动中。这个视图类的扩展可以用来向应用添加单个网页，甚至构建完整的网页应用。当我们的产品或数据需要定期更新时，WebView 类非常有用，因为这样可以实现，无需重新编码和发布更新。

我们将从查看 WebView 类开始本章，并了解如何引入 JavaScript 以赋予页面功能；然后，我们将探索一些社交媒体 SDK，它们允许我们整合许多功能，如分享、发布和点赞。

在本章中，你将学习如何执行以下操作：

+   在 WebView 中打开网页

+   在浏览器中打开网页

+   启用和使用 JavaScript

+   使用 JavaScriptInterface 将脚本与原生代码绑定

+   为网页应用编写高效的 HTML

+   创建一个 Facebook 应用

+   添加一个 LikeView 按钮

+   创建一个 Facebook 分享界面

+   集成 Twitter

+   发送推文

# 添加网页

使用 WebView 类在活动或片段中包含单个网页几乎和添加其他类型的视图一样简单。以下是三个简单步骤：

1.  在清单中添加以下权限：

    ```kt
    <uses-permission 
        android:name="android.permission.INTERNET" /> 

    ```

1.  `WebView` 本身看起来像这样：

    ```kt
    <WebView  
        android:id="@+id/web_view" 
        android:layout_width="match_parent" 
        android:layout_height="match_parent" /> 

    ```

1.  最后，添加页面的 Java 代码如下：

```kt
WebView webView = (WebView) findViewById(R.id.web_view); 
webView.loadUrl("https://www.packtpub.com/"); 

```

这就是全部内容，尽管你可能想要移除或减少大多数页面默认的 16dp 边距。

![添加网页](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_12_001.jpg)

当处理专门为我们的应用设计的页面时，这个系统非常理想。如果我们想将用户发送到任何其他网页，那么使用链接被认为是更好的做法，这样用户就可以使用他们选择的浏览器打开它。

## 包含一个链接

为此，任何可点击的视图都可以作为链接，然后点击监听器可以像这样响应：

```kt
@Override 
    public void onClick(View v) { 
        Intent intent = new Intent(); 
        intent.setAction(Intent.ACTION_VIEW); 
        intent.addCategory(Intent.CATEGORY_BROWSABLE); 
        intent.setData(Uri.parse("https://www.packtpub.com/")); 
        startActivity(intent); 
    } 

```

我们可以看到，正确使用 WebView 是将专门设计为应用一部分的页面融入进来。尽管用户需要知道他们处于在线状态（可能产生费用），但我们的 WebView 应该看起来和表现得像应用的其他部分一样。在屏幕上可以有多个 WebView，并且可以与其他小部件和视图混合使用。如果我们正在开发一个存储用户详细信息的应用，通常使用网页工具来管理会比使用 Android API 更容易。

WebView 类附带了一系列全面的设置，可以用来控制许多属性，比如缩放功能、图片加载和显示设置。

## 配置 WebSettings 和 JavaScript

尽管我们可以设计网页视图，使其看起来像其他应用程序组件，但它们当然拥有许多与网页相关的属性，并且可以作为网页元素，像在浏览器中一样进行导航。这些和其他设置都由**WebSettings**类优雅地管理。

这个类主要由一系列设置器和获取器组成。整个集合可以这样初始化：

```kt
WebView webView = (WebView) findViewById(R.id.web_view); 
WebSettings webSettings = webView.getSettings(); 

```

我们现在可以使用这个对象来查询网页视图的状态，并将它们配置为我们所希望的样子。例如，默认情况下禁用 JavaScript，但可以轻松更改：

```kt
webSettings.setJavaScriptEnabled(true); 

```

有许多这样的方法，所有这些都在文档中列出：

```kt
developer.android.com/reference/android/webkit/WebSettings.html

```

这些设置并不是我们控制网页视图的唯一方式，它还有一些非常有用的自有方法，其中大部分在这里列出：

+   `getUrl()` - 返回网页视图当前的 URL

+   `getTitle()` - 如果 HTML 中指定了页面标题，则返回页面标题。

+   `getAllAsync(String)` - 简单的搜索功能，突出显示给定字符串的出现

+   `clearHistory()` - 清空当前历史缓存

+   `destroy()` - 关闭并清空网页视图

+   `canGoForward()`和`canGoBack()` - 启用本地历史堆栈

这些方法，连同网页设置，使我们能够使用网页视图做更多的事情，而不仅仅是访问可更改的数据。只要稍加努力，我们就能提供大部分网络浏览器功能。

无论我们是选择将网页视图作为应用程序的无缝部分呈现，还是为用户提供更全面的基于互联网的体验，我们很可能会希望在自己的页面中包含一些 JavaScript。我们之前了解到如何启用 JavaScript，但这仅允许我们运行独立的脚本；更好的是，如果我们能从 JavaScript 调用 Android 方法，这正是`JavaScriptInterface`所做的。

使用这种接口来管理两种语言之间的自然不兼容性，这当然是**适配器设计模式**的经典示例。要了解如何实现这一点，请按照以下步骤操作：

1.  将以下字段添加到用于任务的任何活动中：

    ```kt
        public class WebViewActivity extends Activity { 

            WebView webView; 
            JavaScriptInterface jsAdapter; 

    ```

1.  按如下方式编辑`onCreate()`方法：

    ```kt
        @Override 
        public void onCreate(Bundle savedInstanceState) { 
            super.onCreate(savedInstanceState); 
            setContentView(R.layout.main); 

            webView = (WebView) findViewById(R.id.web_view); 

            WebSettings settings = webView.getSettings(); 
            settings.setJavaScriptEnabled(true); 

            jsAdapter = new JavaScriptInterface(this); 
            webView.addJavascriptInterface(jsAdapter, "jsAdapter");  

            webView.loadUrl("http://someApp.com/somePage.html"); 
        } 

    ```

1.  创建适配器类（这也可能是内部类）。`newActivity()`方法可以是任何我们选择的内容。这里，仅作为示例，它启动了一个新的活动：

    ```kt
        public class JavaScriptInterface { 
            Context context; 

            JavaScriptInterface(Context c) { 
                context = c; 
            } 

            // App targets API 16 and higher 
            @JavascriptInterface 
            public void newActivity() { 
                Intent i = new Intent(WebViewActivity.this, 
                    someActivity.class); 
                startActivity(i); 
            } 
        } 

    ```

1.  剩下的就是编写 JavaScript 来调用我们的原生方法。这里可以使用任何可点击的 HTML 对象。在您的页面上创建以下按钮：

    ```kt
        <input type="button"  
           value="OK"  
           onclick="callandroid()" /> 

    ```

1.  现在，只需在脚本中定义函数，如下所示：

    ```kt
        <script type="text/javascript"> 

            function callandroid() { 
                isAdapter.newActivity(); 
            } 

        </script> 

    ```

这个过程实施起来非常简单，使 WebView 成为一个非常强大的组件，而且能够从网页中调用我们的 Java 方法意味着我们可以将网页功能整合到任何应用中，而无需牺牲移动功能。

尽管在构建网页时你不需要任何帮助，但在最佳实践方面仍有一两点需要注意。

## 为 WebViews 编写 HTML

人们可能会认为移动网页应用的设计遵循与移动网页类似的约定，在许多方面确实如此，但以下列表指出了一两个细微的差别：

+   确保你使用了正确的`DOCTYPE`，在我们的情况下是这样的：

```kt
    <?xml version="1.0" encoding="UTF-8"?> 
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML Basic 1.1//EN" 
        "http://www.w3.org/TR/xhtml-basic/xhtml-basic11.dtd"> 

```

+   创建单独的 CSS 和脚本文件可能会导致连接变慢。请将此代码内联，理想情况下放在 head 中或 body 的最后。遗憾的是，这意味着我们必须避免使用 CSS 和网页框架，而且像材料设计这样的特性必须手动编码。

+   尽可能避免水平滚动。如果应用确实需要这样做，那么请使用标签页，或者更好的是，使用滑动导航抽屉。

如我们所见，WebView 是一个强大的组件，它使得开发复杂的移动/网页混合应用变得非常简单。这个主题非常广泛，实际上可以专门用一整本书来介绍。但现在，仅仅理解这个工具的范围和力量就足够了。

使用内置的网页工具只是我们利用互联网力量的方式之一。能够连接到社交媒体可能是推广产品最有效且成本最低的方法之一。其中最实用且最简单设置的是 Facebook。

# 连接到 Facebook

Facebook 不仅是最大的社交网络之一，而且它的设置非常完善，能够帮助那些希望推广产品的人。这种方式可以通过提供自动登录、可定制的广告以及用户与他人分享他们*喜欢*的产品等多种方式实现。

要将 Facebook 功能整合到我们的 Android 应用中，我们需要**Android 的 Facebook SDK**，为了充分利用它，我们还需要一个 Facebook 应用 ID，这需要我们在 Facebook 上创建一个简单的应用：

![连接到 Facebook](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_12_002.jpg)

## 添加 Facebook SDK

将 Facebook 功能添加到我们的应用中的第一步是下载 Facebook SDK。可以在以下位置找到：

```kt
developers.facebook.com/docs/android

```

SDK 是一套强大的工具，包括视图、类和接口，Android 开发者将会非常熟悉。Facebook SDK 可以被视为我们本地 SDK 的有用扩展。

在 Facebook 开发者页面上可以找到一个方便的快速入门指南，但像往常一样，在这种情况下，按照以下步骤手动操作会更加具有指导意义：

1.  使用最低 API 级别为 15 或更高启动新的 Android Studio 项目。

1.  打开模块化的 `build.gradle` 文件，并做出这里强调的更改：

    ```kt
        repositories { 
            mavenCentral() 
        } 

        dependencies { 

            . . . 

            compile 
                'com.android.support:appcompat-v7:24.2.1' 
            compile 
                'com.facebook.android:facebook-android-sdk:(4,5)' 
            testCompile 'junit:junit:4.12' 
        } 

    ```

1.  在清单文件中添加以下权限：

    ```kt
        <uses-permission 
            android:name="android.permission.INTERNET" /> 

    ```

1.  然后，将以下库导入到您的主活动或应用类中：

    ```kt
        import com.facebook.FacebookSdk; 
        import com.facebook.appevents.AppEventsLogger; 

    ```

1.  最后，从启动活动的 `onCreate()` 方法中初始化 SDK，如下所示：

    ```kt
        FacebookSdk.sdkInitialize(getApplicationContext()); 
        AppEventsLogger.activateApp(this); 

    ```

这并不是我们前进所需的全部，但在我们继续之前，我们需要一个 Facebook App ID，我们只能通过在 Facebook 上创建应用来获得。

## 获取 Facebook App ID

如您所见，Facebook 应用可以非常复杂，它们的功能仅受创建者的想象力和编程能力的限制。它们可以，而且经常是，仅仅是一个简单的页面，当我们的重点是 Android 应用时，我们只需要最简单的 Facebook 应用即可。

目前，使用 Facebook 快速入门流程，可以在以下位置找到：

```kt
https://developers.facebook.com/quickstarts

```

![获取 Facebook App ID](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_12_003.jpg)

一旦您点击 **创建 App ID**，您将被带到开发者仪表盘。App ID 可以在窗口的左上角找到。以下两个步骤演示了如何完成我们之前开始的过程：

1.  打开 `res/values/strings.xml` 文件，并添加以下值：

    ```kt
        <string 
            name="facebook_app_id">APP ID HERE</string> 

    ```

1.  现在，在清单文件的 application 标签中添加以下元数据：

    ```kt
        <meta-data 
            android:name="com.facebook.sdk.ApplicationId" 
            android:value="@string/facebook_app_id" /> 

    ```

这完成了将我们的 Android 应用连接到其 Facebook 对应应用的过程，但我们需要通过向 Facebook 应用提供有关我们的移动应用的信息来完善这个连接。

为此，我们需要回到 Facebook 开发者仪表盘，从您的个人资料（右上角）下拉菜单中选择 **开发者设置**，然后点击 **示例应用** 选项卡。这将要求您输入您的包名、启动活动以及 **哈希密钥**。

如果您正在开发打算发布的应用，或者为所有项目使用同一个哈希密钥，您会知道它，或者能马上拿到它。否则，以下代码会为您找到它：

```kt
PackageInfo packageInfo; 

packageInfo = getPackageManager() 
        .getPackageInfo("your.package.name", 
        PackageManager.GET_SIGNATURES); 

for (Signature signature : packageInfo.signatures) { 

    MessageDigest digest; 
    digest = MessageDigest.getInstance("SHA"); 
    digest.update(signature.toByteArray()); 
    String key = new 
            String(Base64.encode(digest.digest(), 0)); 

    System.out.println("HASH KEY", key); 
} 

```

如果您直接输入这段代码，Studio 会通过快速修复功能提供一系列库供您选择导入。正确的选择如下：

```kt
import android.content.pm.PackageInfo; 
import android.content.pm.PackageManager; 
import android.content.pm.Signature; 
import android.util.Base64; 

import com.facebook.FacebookSdk; 
import com.facebook.appevents.AppEventsLogger; 

import java.security.MessageDigest; 

```

这其中的内容比想象中要多，但现在我们的应用已经连接到了 Facebook，我们可以利用所有的推广机会。其中最重要的之一就是 Facebook 的点赞按钮。

## 添加 LikeView

您可以想象，Facebook SDK 配备了传统的 *点赞* 按钮。这个按钮作为一个视图提供，可以像添加其他任何视图一样添加：

```kt
<com.facebook.share.widget.LikeView 
        android:id="@+id/like_view" 
        android:layout_width="wrap_content" 
        android:layout_height="wrap_content"/> 

```

![添加 LikeView](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_12_004.jpg)

与其他视图和小部件一样，我们可以在 Java 活动内部修改这个视图。我们可以用这个和其他 Facebook 视图做很多事情，Facebook 对此有详尽的文档。例如，LikeView 的文档可以在这里找到：

```kt
developers.facebook.com/docs/reference/android/current/class/LikeView

```

目前，我们可以考虑用户点赞的是什么。这是通过 `setObjectId()` 方法实现的，它接受一个字符串参数，可以是您的应用 ID 或者一个 URL，如下所示：

```kt
LikeView likeView = (LikeView) findViewById(R.id.like_view); 
likeView.setObjectId("Facebook ID or URL"); 

```

应用内点赞视图与网页上的点赞视图之间存在一两个差异。与网页点赞不同，Android 点赞视图不会告知用户还有多少用户点击了赞，在没有安装 Facebook 的设备上，我们的点赞视图将完全无法工作。通过使用 WebView 来包含点赞视图，可以轻松解决 Android LikeView 的这些限制，这样它就会像在网页上一样工作。

LikeView 为我们和用户提供了查看特定项目受欢迎程度的机会，但要真正利用这个社交平台的力量，我们希望用户通过现代口碑营销方式，即通过*分享*我们的产品给他们的朋友来推广我们。

# 内容构建器

拥有大量赞是吸引流量的好方法，但这里有一个规模经济在起作用，它有利于下载量非常大的应用。应用不必做得很大才能成功，特别是如果它们提供个人或本地服务，比如定制三明治。在这些情况下，一个标签显示只有 12 个人*喜欢*某物并不是一个很好的推荐。然而，如果这些人向他们的朋友分享他们的三明治有多棒，那么我们就拥有了一个非常强大的广告工具。

Facebook 成为一个如此成功的平台的主要因素之一是它理解人类对自己的朋友比对无名陌生人更感兴趣和受影响，对于中小型企业来说，这可能是无价的。最简单的方式，我们可以像添加点赞按钮一样添加一个分享按钮，这将打开分享对话框。**ShareButton**的添加就像 LikeView 一样简单，如下所示：

```kt
<com.facebook.share.widget.ShareButton 
    android:id="@+id/share_button" 
    android:layout_width="wrap_content" 
    android:layout_height="wrap_content"/> 

```

我们还需要在清单文件中设置一个内容提供者。以下代码应插入到根节点中：

```kt
<provider 
    android:authorities="com.facebook.app.FacebookContentProvider{ 
        your App ID here 
    }" 
          android:name="com.facebook.FacebookContentProvider" 
          android:exported="true"/> 

```

与点赞视图不同，在分享时我们可以更多地选择要分享的内容类型，我们可以选择分享链接、图片、视频甚至多媒体。

Facebook SDK 为每种内容类型提供了一个类，以及一个构建器，用于将多个项目组合成一个可分享的对象。

在分享照片或图片时，`SharePhotoContent`类使用位图对象，这是一种比我们迄今为止使用的可绘制资源更复杂且可序列化的图像格式。尽管有许多方法可以创建位图，包括从代码动态创建，但将我们的任何可绘制资源转换为位图也相对简单，如下面的代码段所示：

```kt
Context context; 
Bitmap bitmap; 
bitmap = BitmapFactory.decodeResource(context.getResources(), 
        R.drawable.some_drawable); 

```

然后可以通过以下两个简单步骤将其定义为可分享内容：

```kt
// Define photo to be used 
SharePhoto photo = new SharePhoto.Builder() 
        .setBitmap(bitmap) 
        .build(); 

// Add one or more photos to the shareable content 
SharePhotoContent content = new SharePhotoContent.Builder() 
        .addPhoto(photo) 
        .build(); 

```

`ShareVideo`和`ShareVideoContent`类的工作方式几乎相同，并使用文件的 URI 作为其来源。如果你之前没有处理过视频文件和 URI，以下简要步骤将介绍包含它们的最简单方法：

1.  如果你还没有这样做，直接在`res`目录内创建一个名为`raw`的文件夹。

1.  将你的视频放在这个文件夹里。

1.  确保文件名不包含空格或大写字母，并且是接受的格式，如`mp4`、`wmv`或`3gp`。

1.  下面的代码可以用来提取视频的 URI：

    ```kt
            VideoView videoView = (VideoView)context 
                    .findViewById(R.id.videoView) 
            String uri = "android.resource://" 
                    + getPackageName() 
                    + "/" 
                    + R.raw.your_video_file; 

    ```

1.  现在可以使用这个 URI 来定义我们的共享视频内容，如下所示：

    ```kt
            ShareVideo = new ShareVideo.Builder() 
                    .setLocalUrl(url) 
                    .build(); 

            ShareVideoContent content = new ShareVideoContent.Builder() 
                    .setVideo(video) 
                    .build(); 

    ```

这些技术非常适合分享单个项目，甚至是同一类的多个项目，但当然有时候我们希望混合内容，这可以通过更通用的 Facebook SDK `ShareContent` 类实现。以下代码演示了如何做到这一点：

```kt
// Define photo content 
SharePhoto photo = new SharePhoto.Builder() 
    .setBitmap(bitmap) 
    .build(); 

// Define video content 
ShareVideo video = new ShareVideo.Builder() 
    .setLocalUrl(uri) 
    .build(); 

// Combine and build mixed content 
ShareContent content = new ShareMediaContent.Builder() 
    .addMedium(photo) 
    .addMedium(video) 
    .build(); 

ShareDialog dialog = new ShareDialog(...); 
dialog.show(content, Mode.AUTOMATIC); 

```

这些简单的类提供了一种灵活的方式，允许用户与朋友们分享内容。还有一个发送按钮，允许用户将我们的内容私密地分享给个人或群组，尽管这对用户很有用，但这个功能几乎没有商业价值。

测试共享内容时，Facebook 共享调试器提供了一个非常有价值的工具，可以在以下链接找到：

```kt
 `developers.facebook.com/tools/debug/sharing/?q=https%3A%2F%2Fdevelopers.facebook.com%2Fdocs%2Fsharing%2Fandroid` 

```

这特别有用，因为没有其他简单的方法可以看到我们的共享内容实际上是如何被他人查看的。

![内容构建器](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_12_005.jpg)

Facebook 不仅是最受欢迎的社交网络之一，还拥有一个非常周到的 SDK，可能是对开发者最友好的社交网络。当然，这并不是忽略其他社交平台的原因，其中 Twitter 最为重要。

# 整合 Twitter

Twitter 提供了一个与 Facebook 截然不同的社交平台，人们使用它的方式也大不相同。然而，它也是我们武器库中的另一个强大工具，与 Facebook 一样，它提供了无与伦比的推广机会。

Twitter 使用一个强大的框架集成工具，名为**Fabric**，它允许开发者将 Twitter 功能集成到我们的应用程序中。Fabric 可以直接作为插件下载到 Android Studio 中。在下载插件之前，需要先在 Fabric 上注册。这是免费的，可以在 fabric.io 上找到。

注册后，打开 Android Studio，然后从**设置 > 插件**中选择**浏览仓库...**：

![整合 Twitter](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_12_006.jpg)

安装完成后，Fabric 有一个逐步教程系统，不需要进一步指导。然而，如果应用程序只需要发布单个推文，完全可以不使用这个框架，因为这可以通过普通的 SDK 实现。

## 发送推文

Fabric 是一个复杂的工具，多亏了内置的教学功能，它的学习曲线很快，但仍然需要时间来掌握，并且提供了大多数应用程序不需要的许多功能。如果你只想让应用程序发布一条推文，可以不使用 Fabric，像这样：

```kt
String tweet 
        = "https://twitter.com/intent/tweet?text 
        =PUT TEXT HERE &url=" 
        + "https://www.google.com"; 
Uri uri = Uri.parse(tweet); 
startActivity(new Intent(Intent.ACTION_VIEW, uri)); 

```

即使我们对 Twitter 的所有操作仅限于发送推文，这仍然是一个非常实用的社交功能。如果我们选择利用 Fabric，我们可以构建严重依赖 Twitter 的应用程序，发布实时流并进行复杂的流量分析。与 Facebook 一样，考虑使用 WebView 可以实现的功能总是一个好主意，将部分网页应用嵌入我们的移动应用通常是最简单的解决方案。

# 总结

将社交媒体集成到我们的移动应用中是一项强大的工具，它可以使应用程序的成功与否产生巨大差异。在本章中，我们看到了 Facebook 和 Twitter 提供了哪些软件开发工具来促进这一点，当然，其他社交媒体，如 Instagram 和 WhatsApp，也提供了类似的开发工具。

社交媒体是一个不断变化的世界，新的平台和开发工具层出不穷，没有理由相信 Twitter 甚至 Facebook 有一天不会步 MySpace 的后尘。这也是我们尽可能考虑使用 WebView 的另一个原因：在主应用内创建简单的网页应用可以让我们拥有更高的灵活性。

这几乎是我们旅程的终点，在下一章我们将要了解通常开发过程的最后阶段——发布。然而，这也是我们必须考虑潜在收入的时候，尤其是广告和应用程序内购买。


# 第十三章：分发模式

在覆盖了安卓开发的大部分重要方面之后，我们只需要处理部署和发布的过程。简单来说，将应用发布在谷歌应用商店并不是一个复杂的流程，但我们可以应用一些技巧和诀窍来最大化应用的可能覆盖范围，当然，我们应用获利的方式也在不断增加。

在本章中，我们将探讨如何在使用支持库提供的向后兼容性之外增加兼容性，然后继续了解注册和分发过程是如何工作的，接着我们将探索各种让我们的应用程序盈利的方式。

在本章中，你将学习如何进行以下操作：

+   准备应用分发

+   生成数字证书

+   注册成为谷歌开发者

+   准备宣传材料

+   在谷歌应用商店发布应用

+   加入应用内购

+   包含广告

# 扩展平台范围

我们在整个书中一直在使用的支持库在让应用在旧设备上可用方面做得非常出色，但它们并不适用于所有情况，许多新的创新在一些旧机器上根本无法实现。看看下面的设备仪表盘，很明显，我们希望将应用扩展回 API 级别 16：

![扩展平台范围](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/B05685_13_01.jpg)

我们已经看到 AppCompat 库是如何让我们的应用运行在比当前平台更旧的平台上，但我们不得不避免使用某些功能。例如，`view.setElevation()`方法（以及其他材料特性）在 API 级别 21 以下将不起作用，如果调用它会导致机器崩溃。

我们可能会很自然地认为，我们可以简单地为了吸引更广泛的受众而牺牲这些功能，但幸运的是，这并不必要，因为我们可以使用以下条件子句动态检测我们的应用正在运行的平台：

```kt
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) { 
    someView.setElevation(someValue); 
} 

```

这总是取决于个别开发者，但这种轻微的质量下降通常值得潜在用户采用的大幅增加。

然而，前面的例子很简单，添加这种动态向后兼容性通常需要额外的编码工作。一个很好的例子是 camera2 API，它比其前身复杂得多，但只在携带 API 21 及更高版本的设备上可用。在这种情况下，我们可以应用完全相同的原理，但需要设置一个更复杂系统。该子句可能导致调用不同的方法，甚至启动不同的活动。

然而，无论我们选择如何实现这一点，当然可以采用设计模式。这里有几种可能被使用，但最适合的可能是在这里看到的策略模式：

![扩展平台范围](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_13_002.jpg)

这种方法可能经常需要额外的编码工作，但扩大的潜在市场往往使这些额外工作变得非常值得。一旦我们像这样设置了我们应用的范畴，它就可以发布了。

# 发布应用

不言而喻，你应该在各种各样的手机和模拟器上彻底测试你的应用，并可能准备好你的推广材料，查看 Google Play 的政策和协议。在发布之前有很多事情要考虑，比如内容分级和国家分布。从编程的角度来看，在我们继续之前，只需检查三件事情：

+   从项目中删除所有日志记录，例如以下内容：

```kt
    private static final String DEBUG_TAG = "tag"; 
    Log.d(DEBUG_TAG, "some info"); 

```

+   确保你的清单中声明了应用`label`和`icon`。以下是一个示例：

```kt
    android:icon="@mipmap/my_app_icon" 
    android:label="@string/my_app_name" 

```

+   确保在清单中声明了所有必要的权限。以下是一个示例：

```kt
    <uses-permission android:name="android.permission.INTERNET" /> 
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" /> 

```

现在我们只需三个步骤就能在 Google Play 商店上看到我们的应用。我们需要做的就是生成一个已签名的发布 APK，注册成为 Google Play 开发者，最后将应用上传到商店或发布在自己的网站上。还有一两种发布应用的其他方式，我们将在本节末尾了解它们是如何完成的。首先，我们将开始生成一个准备上传到 Google Play 商店的 APK。

## 生成签名的 APK

所有发布的 Android 应用都需要一个数字签名的证书。这用于证明应用程序的真实性。与其他许多数字证书不同，它没有权威机构，你持有签名的私钥，这显然需要被安全保护。为此，我们需要生成一个私钥，然后使用它来生成签名的 APK。GitHub 上有些工具可以方便地完成这个过程，但为了帮助理解，我们将遵循传统的方法。这可以在 Android Studio 中的“生成签名的 APK 向导”中完成。以下步骤将引导你完成：

1.  打开你想要发布的应用。

1.  从**构建 | 生成签名的 APK...**菜单启动生成签名的 APK 向导。

1.  在第一个屏幕上选择**创建新的...**。

1.  在下一个屏幕上，为你的密钥库提供一个路径和名称，以及一个强密码。

1.  对别名做同样的操作。

1.  选择一个有效期超过 27 年的选项，如下所示：![生成签名的 APK](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_13_003.jpg)

1.  至少填写一个证书字段。点击**确定**，你将被带回向导。

1.  选择**release**作为构建变体，然后点击**完成**。

1.  你现在有一个准备发布的已签名 APK。

密钥库（一个`.jks`文件）可以用来存储任意数量的密钥（别名）。对所有应用使用同一个密钥是完全可以的，而且在产生应用更新时也必须使用相同的密钥。谷歌要求证书有效期至少到 2033 年 10 月 22 日，任何超过这个日期的数字都足够。

### 提示

**重要**：至少保留一份密钥的安全备份。如果丢失了，你将无法开发这些应用程序的未来版本。

一旦我们有了数字签名，我们就可以注册成为 Google 的开发者。

## 注册为开发者

与签名 APK 一样，注册为开发者也同样简单。请注意，Google 收取一次性费用 25 美元，以及你的应用程序可能产生的任何收入的 30%。以下说明假设你已经有一个 Google 账户：

1.  查阅以下链接中的**支持的位置**：

    [support.google.com/googleplay/android-developer/table/3541286?hl=en&rd=1](http://support.google.com/googleplay/android-developer/table/3541286?hl=en&rd=1)

1.  前往开发者 Play 控制台：

    ```kt
    play.google.com/apps/publish/
    ```

1.  使用你的 Google 账户登录，并输入以下信息：![注册为开发者](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_13_004.jpg)

1.  阅读并接受**Google Play 开发者分发协议**。

1.  使用 Google Checkout 支付 25 美元，如有必要请创建一个账户，这样你就成为了注册的 Google 开发者。

如果你打算让你的应用程序在全球范围内可用，那么检查支持的位置页面总是值得的，因为它经常变化。剩下要做的就是上传我们的应用程序，我们接下来会做。

## 在 Google Play 商店上发布应用程序

将我们的应用程序上传并发布到 Play 商店是通过**开发者控制台**完成的。正如你将看到的，在这个过程中，我们可以提供大量关于我们应用程序的信息和推广材料。只要你按照本章前面的步骤操作，并且有一个准备好的已签名的`.apk`文件，那么就按照以下说明发布它。或者，你可能只是想看看此时涉及的内容以及推广材料的形式。在这种情况下，确保你有以下四张图片和一个已签名的 APK，并在最后选择**保存草稿**而不是**发布应用**：

1.  至少两张应用程序的截图。这些截图的任何一边不得短于 320 像素或长于 3840 像素。

1.  如果你希望你的应用程序在 Play 商店中对搜索设计用于平板电脑的应用程序的用户可见，那么你应该至少准备一张 7 英寸和一张 10 英寸的截图。

1.  一个 512 x 512 像素的高分辨率图标图像。

1.  一个 1024 x 500 像素的特色图形。

准备好这些图片和一个已签名的`.apk`文件后，我们就可以开始了。决定你希望为应用程序收取多少费用（如果有的话），然后按照以下说明操作：

1.  打开你的开发者控制台。

1.  填写**标题**并点击**上传 APK**按钮。

1.  点击**上传你的第一个 APK 到生产环境**。

1.  定位到你的已签名`app-release.apk`文件。它将在`AndroidStudioProjects\YourApp\app`目录中。

1.  将此内容拖放到建议的空间中。

1.  完成后，你将被带到应用程序页面。

1.  按照前四个部分进行操作：![在 Google Play 商店上发布应用程序](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_13_005.jpg)

1.  完成所有必填字段，直到“发布应用”按钮可以点击。

1.  如果您需要帮助，按钮上方的**为什么我不能发布？**链接将列出未完成的必填字段。

1.  当所有必填字段都填写完毕后，点击页面顶部的**发布应用**（或**保存草稿**）按钮。

1.  恭喜！您现在已成为一名已发布的安卓开发者。

我们现在知道如何将应用发布到 Play 商店。当然，还有许多其他的应用市场，它们都有各自的上传流程。然而，Google Play 提供了最广泛的受众群体，是发布应用的自然选择。

尽管 Play 商店是理想的市场，但仍然值得看看两种其他的分发方法。

## 通过电子邮件和网站进行分发

这两种方法中的第一种就像听起来一样简单。如果您将 APK 作为电子邮件附件发送，并在安卓设备上打开，用户在打开附件时会被邀请安装应用。在较新的设备上，他们可以直接在电子邮件中点击安装按钮。

### 提示

对于这两种方法，用户将必须在设备的 安全设置 中允许安装未知来源。

从您的网站分发应用几乎和通过电子邮件发送一样简单。您需要做的就是在网站上托管 APK 文件，并提供如下所示的下载链接：

```kt
<a href="download_button.jpg" download="your_apk">. 

```

当用户从安卓设备浏览您的网站时，点击您的链接将在他们的设备上安装您的应用。

### 提示

通过电子邮件分发无法防止盗版，因此只有在考虑到这一点时才应使用此方法。其他方法尽可能安全，但如果您想采取额外措施，谷歌提供了一项**许可服务**，可以在 developer.android.com/google/play/licensing 找到。

无论我们是发布付费应用还是免费应用，我们都希望能够触达尽可能多的用户。谷歌提供了几种工具来帮助我们实现这一点，以及我们接下来将看到的盈利方法。

# 推广和盈利应用

很少有应用在没有经过良好推广的情况下就能成功。有无数种推广方法，毫无疑问，您将遥遥领先于如何推广您的产品。为了帮助您触达更广泛的受众，谷歌提供了一些实用的工具来协助推广。

在了解了推广工具之后，我们将探索两种通过应用赚钱的方法：应用内支付和广告。

## 推广应用

谷歌提供了两种非常简单的方法，帮助引导人们从网站和我们的应用中关注 Play 商店上的产品：链接以及**谷歌 Play 徽章**，它为我们的链接提供官方品牌标识。

我们可以添加指向单个应用和我们发布商页面的链接，在发布商页面可以浏览我们所有的应用，并且我们可以在我们的应用和网站中包含这些链接：

+   如果要包含指向 Play 商店中特定应用页面的链接，请使用以下格式中的清单中找到的完整包名：

```kt
        http://play.google.com/store/apps/details?id=com.full.package.name 

```

+   要在 Android 应用中包含这个，请使用这个：

```kt
        market://details?id= com.full.package.name 

```

+   如果你想要一个指向你的发布者页面以及你所有产品的列表的链接，请使用这个：

```kt
        http://play.google.com/store/search?q=pub:my publisher name 

```

+   当从应用中链接时，请像之前一样进行相同的更改：

```kt
        Market://search?q=pub:my publisher name 

```

+   要链接到特定的搜索结果，请使用这个：

```kt
        search?q=my search query&c=apps. 

```

+   如果要使用官方 Google 徽章作为你的链接，请用下面突出显示的 HTML 替换前面元素之一：

```kt
        <a href="https://play.google.com/store/search?q=pub: publisher name"> 
        <img alt="Get it on Google Play" 
               src="img/en_generic_rgb_wo_60.png" /> 
        </a> 

```

徽章有两种尺寸，`60.png`和`45.png`，以及两种样式，Android 应用在 Google Play 上和在 Google Play 上获取。只需更改相关代码以选择最适合你目的的徽章：

![推广应用](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_13_006.jpg)

随着我们的应用发布，并在合适的位置放置了指向我们 Play 商店页面的链接，现在是考虑如何从不可避免的下载中获利的时候了，因此我们来看看如何实现 Android 应用的盈利。

## 应用盈利

有很多方法可以从应用中赚钱，但最流行和有效的两种方法是**应用内购买**和**广告**。应用内购买可能会相当复杂，或许值得用一整章来讲述。这里，我们将看到一个有效的模板，你可以将其作为开发可能的应用内产品的基础。它将包括所有需要的库和包，以及一些非常有用的帮助类。

相比之下，现在我们在应用中包含 Google AdMob 广告对我们来说是一个非常熟悉的过程。实际上，广告只是另一个 View，并且可以像其他任何 Android 小部件一样被识别和引用。本章的最后一个练习，也是整本书的最后一个练习，将构建一个简单的 AdMob 演示。不过，首先让我们看看应用内购买。

## 应用内购买

用户可以从应用内购买大量产品，从升级和可解锁内容到游戏内物品和货币，这当然为我们在书中前面开发的那个三明治制作应用提供了一个支付选项。

无论用户购买什么，Google 结账流程都会确保他们以与其他 Play 商店产品相同的方式支付。从开发者的角度来看，每次购买都会归结为响应一个按钮的点击。我们需要安装 Google Play Billing Library，并向我们的项目中添加一个 AIDL 文件和一些帮助类。以下是方法：

1.  开始一个新的 Android 项目，或者打开一个你想要添加应用内购买功能的已有项目。

1.  打开 SDK 管理器。

1.  在 Extras 下，确保你已经安装了 Google Play Billing Library。

1.  打开清单并应用这个权限：

    ```kt
            <uses-permission 
                android:name="com.android.vending.BILLING" /> 

    ```

1.  在项目窗格中，右键点击 app 并选择**新建 | 文件夹 | AIDL 文件夹**。

1.  从这个 AIDL 文件夹中，创建一个**新建 | 包**，并将其命名为 com.android.vending.billing。

1.  在`sdk\extras\google\play_billing`目录中找到并复制`IinAppBillingService.aidl`文件。

1.  将文件粘贴到`com.android.vending.billing`包中。

1.  在 Java 文件夹中创建一个名为`com.`**你的包名**`.util`的**新包**，然后点击**完成**。

1.  从`play_billing`目录中找到并打开`TrivialDrive\src\com\example\android\trivialdrivesample\util`文件夹。

1.  将九个 Java 文件复制到你刚刚创建的 util 包中。

现在你已经拥有了一个适用于任何想要加入应用内购买功能的应用的模板。或者，你也可以在已经开发好应用内产品的项目中完成上述步骤。无论哪种方式，无疑你都将利用`IabHelper 类`，它极大地简化了编码工作，并为购买过程的每一步提供了监听器。相关文档可以在这里找到：

[`developer.android.com/google/play/billing/index.html`](https://developer.android.com/google/play/billing/index.html)

### 提示

在开始实现应用内购买之前，你需要为你的应用获取一个**许可密钥**。这可以在开发者控制台中的应用详情中找到。

付费应用和应用内产品只是从应用中赚钱的两种方式，很多人选择通过广告来获取收入，这通常是一种更有利可图的途径。**Google AdMob**提供了很大的灵活性以及熟悉的编程接口，我们将在下一节中看到。

## 包含广告

广告赚钱的方式有很多，但 AdMob 提供的方法最为简单。该服务不仅允许你选择想要推广的产品类型，还提供了优秀的分析工具，并能无缝地将收入转入你的 Checkout 账户。

此外，我们将会看到，**AdView**可以通过几乎与我们熟悉的方法一样的编程方式来处理，我们将在最后的练习中开发一个带有演示横幅 AdMob 广告的简单应用。

在开始这个练习之前，你需要先在 google.com/admob 上注册一个 AdMob 账户。

1.  打开你想要测试广告的项目，或者开始一个新的 Android 项目。

1.  确保你已经通过 SDK Manager 安装了 Google Repository。

1.  在`build.gradle`文件中，添加这个依赖项：

    ```kt
        compile 'com.google.android.gms:play-services:7.0.+' 

    ```

1.  重建项目。

1.  在清单文件中设置这两个权限：

    ```kt
        <uses-permission 
            android:name="android.permission.INTERNET" /> 
        <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" /> 

    ```

1.  在应用节点内，添加这个`meta-data`标签：

    ```kt
    <meta-data 
        android:name="com.google.android.gms.version" 
        android:value="@integer/google_play_services_version" /> 

    ```

1.  在清单文件中包含这个第二个 Activity。

    ```kt
    <activity 
        android:name="com.google.android.gms.ads.AdActivity" 
        android:configChanges=
        "keyboard|keyboardHidden|orientation|screenLayout|uiMode|screenSize|smallestScreenSize" 
        android:theme="@android:style/Theme.Translucent" /> 

    ```

1.  在`res/values/strings.xml`文件中添加以下字符串：

    ```kt
    <string name="ad_id">ca-app-pub-3940256099942544/6300978111</string> 

    ```

1.  打开`main_activity.xml`布局文件。

1.  在根布局中添加这个第二个命名空间：

1.  在`TextView`下方添加这个`AdView`：

    ```kt
    <com.google.android.gms.ads.AdView 
        android:id="@+id/ad_view" 
        android:layout_width="match_parent" 
        android:layout_height="wrap_content" 
        android:layout_alignParentBottom="true" 
        android:layout_centerHorizontal="true" 
        ads:adSize="BANNER" 
        ads:adUnitId="@string/ad_id"></com.google.android.gms.ads.AdView> 

    ```

1.  在`MainActivity`的`onCreate()`方法中，插入以下代码行：

    ```kt
    AdView adView = (AdView) findViewById(R.id.ad_view); 
    AdRequest adRequest = new AdRequest.Builder() 
            .addTestDevice(AdRequest.DEVICE_ID_EMULATOR) 
            .build(); 

    adView.loadAd(adRequest); 

    ```

1.  现在在设备上测试应用。![包含广告](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_13_007.jpg)

我们在这里所做的几乎与我们编程任何其他元素的方式相同，有一两个例外。使用`ACCESS_NETWORK_STATE`权限并不是严格必要的；它在这里用于在请求广告之前检查网络连接。

任何显示广告的活动都将需要一个单独的 ID，并在清单中声明。这里提供的 ID 仅用于测试目的，因为不允许使用实时 ID 进行测试。`android.gms.ads`包中只有六个类，它们的全部文档可以在[developer.android.com/reference/com/google/android/gms/ads/package-summary](http://developer.android.com/reference/com/google/android/gms/ads/package-summary)找到。

AdMob 广告有两种形式，我们在这里看到的横幅广告和插屏广告，或全屏广告。我们在这里只处理了横幅广告，但插屏广告的处理方式非常相似。了解了如何实现付费应用、应用内购买和 AdMob，我们现在有能力收获辛勤工作的回报，最大限度地利用我们的应用程序。

# 总结

本章概述了应用程序开发的最后阶段，尽管这些阶段只占工作量的很小一部分，但它们至关重要，当涉及到应用程序的成功时，它们可以起到决定性的作用。

在整本书中，我们大量依赖支持库来增加我们应用程序可以在其上运行的设备数量，但在这里，我们看到了如何通过动态确定平台并相应地运行适当的代码来进一步扩大这一范围。这个过程很好地展示了设计模式如何渗透到编程的所有方面。

一旦我们使用这些工具扩大了我们的影响范围，我们还可以通过谨慎的推广来进一步提高我们应用程序成功的可能性，并希望我们的工作能够得到回报，无论是直接向用户收取应用程序或其功能的费用，还是通过投放广告间接盈利。

在整本书中，我们探讨了设计模式如何在开发的许多方面帮助我们，但真正有用的是设计模式背后的思考方式，而不是任何一个单独的模式。设计模式提供了一种解决问题的方法和一条通往解决方案的清晰路径。这是一种旨在引导我们找到新的创造性解决方案的方法，设计模式不应被视为一成不变的，而应更多地视为一种指导，任何模式都可以根据其目的进行修改和调整。

本书中的模式和示例并非设计为可以直接复制粘贴到其他项目中，而是作为帮助我们发现解决自己原始情况的最优雅解决方案的方法论。如果这本书完成了它的任务，那么你接下来设计的模式将不是这里所概述的，而是你自己全新的原创作品。
