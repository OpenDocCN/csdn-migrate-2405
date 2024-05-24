# jQueryMobile 秘籍（三）

> 原文：[`zh.annas-archive.org/md5/55209463BC487F6190B6A043F64AEE64`](https://zh.annas-archive.org/md5/55209463BC487F6190B6A043F64AEE64)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：配置

本章将涵盖以下内容：

+   配置活动类

+   配置`ajaxEnabled`

+   配置`autoInitializePage`

+   配置默认转换

+   配置`ignoreContentEnabled`

+   配置页面加载和错误消息

+   配置默认命名空间

+   配置`hashListeningEnabled`和`subPageUrlKey`

+   配置`pushStateEnabled`和`linkBindingEnabled`

# 介绍

jQuery Mobile 框架会在文档加载后立即增强标记和元素。您可以通过在文档对象上设置`mobileinit`事件处理程序中的值来调整用于这些增强的默认配置。本章向您展示了如何使用框架中提供的各种配置。

# 配置活动类

jQuery Mobile 框架默认使用 CSS 类`activeBtnClass`来为主题为`b`的活动状态的按钮设置样式。`activeBtnClass`类具有默认字符串值`ui-btn-active`。为了为活动页面（正在查看或正在过渡的页面）设置样式，框架使用 CSS 类`activePageClass`，该类具有默认字符串值`ui-page-active`。本配方向您展示如何配置框架以使用这些默认类的自定义类。

## 准备就绪

从`code/07/active-class`源文件夹中复制此配方的完整代码。您可以使用以下网址启动此代码：`http://localhost:8080/07/active-class/main.html`。

## 如何实现...

1.  在`main.html`中，将以下样式添加到页面的`<head>`标签中，以定义自定义的活动按钮类和活动页面类：

    ```js
    <link rel="stylesheet" 
      href="http://code.jquery.com/mobile
      /1.1.1/jquery.mobile-1.1.1.min.css" />
    <style>
     .ui-custom-btn-active {
        background: #53C584;
        background-image: -webkit-gradient(linear, left top, 
          left bottom, from( #53C584 ), to( #6FD598 ));
        background-image: -webkit-linear-gradient( #53C584 , 
          #6FD598 );
        background-image: -moz-linear-gradient( #53C584 , 
          #6FD598 );
        background-image: -ms-linear-gradient( #53C584 , 
          #6FD598 );
        background-image: -o-linear-gradient( #53C584 , 
          #6FD598 );
        background-image: linear-gradient( #53C584 , 
          #6FD598 );
      }
     .ui-mobile .ui-custom-page-active {
        border: 3px;
        border-style: dotted;
        width: 99%;
        display: block;
        overflow: visible;
      }
    </style>
    ```

1.  在包含 jQuery Mobile 脚本之前添加以下脚本：

    ```js
    $(document).bind("mobileinit", function() { 
     $.mobile.activePageClass = "ui-custom-page-active"; 
     $.mobile.activeBtnClass = "ui-custom-btn-active";
    });
    ```

1.  创建带有链接以打开`#page1`的`#main`页面，如下所示：

    ```js
    <div id="main" data-role="page" data-theme="e">
      <div data-role="header" data-theme="e">
        <h1>Active Classes</h1>
      </div>
      <div data-role="content">
        <a href="#page1" data-role="button">Open Page 1</a>
      </div>
    </div>
    ```

1.  创建`#page1`，并添加一个链接以返回到`#main`页面，如下所示；这是一个多页文档：

    ```js
    <div id="page1" data-role="page" data-theme="e">
      <div data-role="header" data-theme="e">
        <h1>Page 1</h1>
      </div>
      <div data-role="content">
        <a href="#main" data-rel="back" data-role="button">
          Go Back
        </a>
      </div>
    </div>
    ```

## 工作原理...

在`main.html`中，添加一个样式标签并定义类`ui-custom-btn-active`，以在活动按钮上设置不同的渐变背景（绿色阴影）。默认的活动按钮背景是明亮的蓝色阴影。还添加一个`ui-custom-page-active`类，该类为页面设置`3px`厚的虚线边框。接下来，在包含对`jquery.mobile.js`引用之前，添加给定的脚本。在脚本中，为`mobileinit`事件添加一个事件处理程序，该事件在应用程序启动时触发。在这里，将`$.mobile.activePageClass`和`$.mobile.activeBtnClass`属性设置为这两个新类。最后，添加`#main`和`#page1`页面容器。当您启动应用程序时，`#main`页面现在将显示为带有虚线边框，如下面的屏幕截图所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_07_1.jpg)

当您点击**打开页面 1**按钮时，按钮的活动状态在按下时显示绿色阴影，如下面的屏幕截图所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_07_2.jpg)

接下来，页面 `#page1` 打开，它也有虚线边框：

![如何运作...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_07_3.jpg)

单击时，**返回**按钮也会变成绿色：

![如何运作...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_07_4.jpg)

## 还有更多...

你可以使用 `mobileinit` 事件处理程序来自定义和配置 jQuery Mobile 框架的默认设置。你必须在包含 `jquery.mobile.js` 脚本之前添加此自定义脚本，以确保框架使用你的设置进行初始化。

### 使用 jQuery 的 `.extend()` 调用

你也可以使用 `.extend()` jQuery 调用来扩展 `$.mobile` 对象，而不是直接在 `$.mobile` 上设置属性，如下所示：

```js
$.extend( $.mobile, {
  $.mobile.activeBtnClass = "ui-custom-btn-active";
});
```

## 另请参阅

+   第二章, *页面和对话框*, *使用 CSS 创建弹跳页面转换*：此教程提供了供应商前缀的概述

# 配置 ajaxEnabled

在可能的情况下，jQuery Mobile 框架会自动使用 Ajax 处理链接点击和表单提交。这可以使用 `$.mobile.ajaxEnabled` 属性进行配置，默认情况下其布尔值为 `true`。如果禁用了 Ajax 或不支持它，则使用普通的 HTTP 请求并进行完整页面加载。URL 散列监听也被禁用。这个教程向你展示了如何配置 `$.mobile.ajaxEnabled` 属性。

## 准备就绪

从 `code/07/ajax-enabled` 源文件夹中复制此教程的完整代码。你可以使用以下 URL 启动此代码：`http://localhost:8080/07/ajax-enabled/main.html`。

## 怎么做...

1.  在 `main.html` 中，在包含 `jquery.mobile.js` 之前添加以下脚本：

    ```js
    $(document).bind("mobileinit", function() {
     $.mobile.ajaxEnabled = true;
    });
    ```

1.  创建包含链接以打开 `page1.html` 的主页面：

    ```js
    <div id="main" data-role="page" data-theme="e">
      <div data-role="header" data-theme="a">
        <h1>Ajax Enabled</h1>
      </div>
      <div data-role="content">        
        <p>This is the main page</p>
        <a href="page1.html" data-role="button">
          <p>Open Page 1</p>
        </a>
      </div>
    </div>
    ```

1.  最后，创建 `page1.html`，其中包含一个返回到 `main.html` 的链接，如下所示：

    ```js
    <div data-role="page" data-theme="e" data-add-back-
      btn="true">
      <div data-role="header">
        <h1>Page 1</h1>
      </div>
      <div data-role=content>    
        <p>Sub Page Contents</p>
        <a href="main.html" data-role="button">Go back</a>
      </div>
    </div>
    ```

## 如何运作...

在包含对 `jquery.mobile.js` 的引用之前，在代码中添加给定的脚本。在脚本中，添加一个用于在应用程序启动时触发的 `mobileinit` 事件的事件处理程序。在这里，设置配置 `$.mobile.ajaxEnabled=true`。

### 注意

由于 `$.mobile.ajaxEnabled` 默认为 `true`，因此您不必在代码中明确设置它。它包含在此教程中，因为您将在代码中稍后将此值更改为 `false`。

添加 `#main` 页面。按照代码中所示创建 `page1.html`（请注意，`page1.html` 中没有 `<head>` 元素）。显示 `#main` 页面，如下图所示：

![如何运作...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_07_5.jpg)

单击 **打开第一页** 按钮以打开 `page1.html`，如下所示。此页面通过 Ajax 加载，并且框架增强了控件。

![如何运作...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_07_6.jpg)

然后，在 `main.html` 中将 `ajaxEnabled` 属性设置为 `false`，然后重新加载页面。现在，当打开 `page1.html` 时，元素不会被增强，如下图所示：

![如何运作...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_07_7.jpg)

## 还有更多...

当禁用 Ajax 时，将加载整个页面。在`page1.html`中，由于缺少指向 jQuery Mobile 框架库的链接的`<head>`元素，因此页面不会获得任何样式或增强效果。

# 配置 autoInitializePage

当您导航到新页面或将页面加载到 DOM 中时，框架会初始化页面并使其可见。这由`$.mobile.intializePage`属性控制，默认情况下其布尔值为`true`。如果将其设置为`false`，则不会显示页面。您将不得不手动将其设置回`true`以显示页面。本示例向您展示了如何执行相同操作。

## 准备就绪

从`code/07/auto-initialize`源文件夹中复制此示例的全部代码。您可以通过使用 URL 启动此代码：`http://localhost:8080/07/auto-initialize/main.html`。

## 如何操作...

1.  在`main.html`中，在包含`jquery.mobile.js`之前，添加以下脚本：

    ```js
    $(document).bind("mobileinit", function() {
     $.mobile.autoInitializePage = false;
    });
    ```

1.  创建具有以下内容的主页：

    ```js
    <div data-role="content">
      <a href="#" data-role="button">A button</a>
      <script>
     $.mobile.autoInitializePage = true;
      </script>
    </div>
    ```

## 工作原理...

在包含对`jquery.mobile.js`的引用之前，将给定的`autoInitializePage`脚本添加到代码中。在脚本中，添加一个在应用程序启动时触发的`mobileinit`事件处理程序。在这里，将配置`$.mobile.autoInitializePage=false`。最后，添加`#main`页面。页面内容将类似于以下屏幕截图：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_07_8.jpg)

初始化内容并将其设置为`$mobile.autoInitializePage`的值手动设置为`true`，如代码所示。您可以注释此行（在页面内容部分）并重新加载页面，以发现什么也没有显示。

## 还有更多...

您可以使用此功能延迟显示页面，同时在后台执行一些后台工作或从服务器后台获取数据时。在手动处理页面更改时很有用。

# 配置默认过渡效果

默认情况下，jQuery Mobile 框架在使用 Ajax 加载页面时使用**fade**过渡。在使用 Ajax 打开对话框时，默认使用**pop**过渡。本示例向您展示了如何为您的应用设置不同的默认过渡效果。

## 准备就绪

从`code/07/default-transitions`源文件夹中复制此示例的全部代码。您可以使用以下 URL 启动此代码：`http://localhost:8080/07/default-transitions/main.hml`。

## 如何操作...

1.  在`main.html`中，在包含`jquery.mobile.js`之前，添加以下脚本：

    ```js
    $(document).bind("mobileinit", function() {
     $.mobile.defaultDialogTransition = "flow";
     $.mobile.defaultPageTransition = "turn";
    });
    ```

1.  创建`#main`页面如下：

    ```js
    <div id="main" data-role="page" data-theme="e">
      <div data-role="header">
        <h1>Configure Transitions</h1>
      </div>
      <div data-role=content>
        <a href="#page1" data-role="button">Open as Page</a>
        <a href="#page1" data-rel="dialog" data-role="button">Open as Dialog</a>
      </div>
    </div>
    ```

1.  创建`#page1`如下；这是一个多页面文档：

    ```js
    <div id="page1" data-role="page" data-theme="e" data-add-back-btn="true">
      <div data-role="header">
        <h1>Page 1</h1>
      </div>
      <div data-role=content>
        <p>Page 1 Content</p>
      </div>
    </div>
    ```

## 工作原理...

创建`main.html`并在代码中包含给定的脚本，然后再包含对`jquery.mobile.js`的引用。在脚本中，添加一个在应用程序启动时触发的`mobileinit`事件处理程序。在这里，使用`$.mobile.defaultDialogTransition`和`$.mobile.defaultPageTransition`属性设置页面和对话框的默认过渡效果。最后，如所示，添加`#main`和`#page1`页面容器。

在`#main`中，有两个按钮。第一个按钮将`#page1`作为页面打开，第二个按钮将其作为对话框打开。您将看到默认转换已更改。页面现在使用`turn`转换，对话框使用`flow`转换。

## 还有更多...

您还可以将页面和对话框的默认转换都设置为`none`。这将只是加载页面或对话框而不使用任何转换：

```js
$.mobile.defaultDialogTransition = "none";
$.mobile.defaultPageTransition = "none";
```

### 使用自定义转换

你可以配置框架以使用自定义转换作为默认转换。您必须按以下方式设置转换名称：

```js
$.mobile.defaultDialogTransition = "myDialogTransition";
$.mobile.defaultPageTransition = "myPageTransition";
```

### 转换回退

`fade`转换是默认转换，它使用 2D。所有其他转换都使用 3D。不支持 3D 变换的旧浏览器和设备将退回到使用`fade`。您可以将此默认回退转换配置为`none`，或者您可以将其设置为自己的自定义 2D 转换。可以为每个单独的 3D 转换执行此操作，如下所示：

```js
$.mobile.transitionFallbacks.slideout = "none";
$.mobile.transitionFallbacks.flip = "myCustom2DTransition";
```

## 另请参阅

+   第二章, *使用 CSS 创建弹跳页面转换*

+   第二章, *使用 JS 创建滑动'淡出'转换*

# 配置 ignoreContentEnabled

jQuery Mobile 框架会自动增强页面中找到的控件和标记。要跳过增强某些标记部分，您可以使用`$.mobile.ignoreContentEnabled`配置（默认为`false`）。此示例向您展示如何执行相同操作。

## 准备工作

从`code/07/content-enabled`源文件夹中复制此示例的完整代码。您可以使用以下网址启动此代码：`http://localhost:8080/07/content-enabled/main.html`。

## 如何做...

1.  在`main.html`中，在包含`jquery.mobile.js`之前添加以下脚本：

    ```js
    $(document).bind("mobileinit", function() {
     $.mobile.ignoreContentEnabled = true;
    });
    ```

1.  创建带有以下内容的`#main`页面：

    ```js
    <div data-role="content">
     <div data-enhance="false">
        <input type="checkbox" name="chkbox1" id="chkbox1" 
          checked />
        <label for="chkbox1">Checkbox</label>
        <input type="radio" name="radiobtn1" id="radiobtn1" 
          checked />
        <label for="radiobtn1">Radio Button</label>
     </div>
      <div>
        <input type="checkbox" name="chkbox2" id="chkbox2" 
          checked />
        <label for="chkbox2">Enhanced Checkbox</label>
        <input type="radio" name="radiobtn2" id="radiobtn2" 
          checked />
        <label for="radiobtn2">Enhanced Radio Button</label>
      </div>
    </div>
    ```

## 它是如何工作的...

创建`main.html`并在包含对`jquery.mobile.js`的引用之前添加代码中的给定脚本。在脚本中，为在应用程序启动时触发的`mobileinit`事件添加事件处理程序。在这里，将属性`$.mobile.ignoreContentEnabled=true`设置为`true`。在`#main`中，添加两个 div。在每个`div`中添加一个复选框和一个单选按钮。将属性`data-enhance=false`设置为第一个`div`。现在，框架不会增强添加到此`div`中的元素。第二个`div`中的元素会自动增强。页面显示如下截图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_07_9.jpg)

## 还有更多...

当您使用`$.mobile.ignoreContentEnabled=true`配置时，它告诉框架避免增强某些标记部分。通过使用`data-enhance="false"`属性来执行此操作，如此示例所示。现在，当框架遇到每个控件或标记时，它首先检查父元素是否将`data-enhance`属性设置为`false`。如果是，则跳过将样式或任何增强应用于控件。

### 注意

使用 `$.mobile.ignoreContentEnabled` 和 `data-enhance` 可能会在页面增强时导致性能下降。

# 配置页面加载和错误消息

默认情况下，jQuery Mobile 框架在加载新页面时显示一个带有主题 `a` 的旋转动画，不带任何文本。如果出现错误，页面加载超时，将显示错误消息 `Error Loading Page`，带有主题 `e`。本教程向你展示如何更改和自定义页面加载和错误消息。

## 准备工作

从 `code/07/load-message` 文件夹的源文件中复制此教程的全部代码。要尝试此教程，请使用该文件夹中可用的简单 `nodejs` web 服务器，使用以下命令：

```js
node jqmserver.js

```

然后，您可以使用以下 URL 启动代码：`http://localhost:8080/07/load-message/main.hml`。

## 如何做...

1.  在 `main.html` 中，添加以下脚本以在包含 `jquery.mobile.js` 之前使用：

    ```js
    $(document).bind("mobileinit", function() {
     $.mobile.loadingMessage = "Fetching it...";
     $.mobile.loadingMessageTextVisible = true;
     $.mobile.loadingMessageTheme = "b";
     $.mobile.pageLoadErrorMessage = "Oops, it's missing!";
     $.mobile.pageLoadErrorMessageTheme = "b";
    });
    ```

1.  创建以下内容的 `#main` 页面：

    ```js
    <div data-role="content">
     <a href="/delay" data-role="button">Dummy page</a>
    </div>
    ```

## 它是如何工作的...

创建 `main.html`，并在包含对 `jquery.mobile.js` 的引用之前添加给定脚本。在脚本中，为 `mobileinit` 事件添加一个事件处理程序，该事件在应用程序启动时触发。在这里，设置默认的页面加载消息和错误消息如代码所示。

在 `#main` 中，有一个尝试打开 `"/delay"` 页面的链接。这是对 `nodejs` 服务器的 `GET` 操作。服务器处理此请求，并在暂停几秒钟后返回错误代码。在此持续时间内显示带有文本消息的旋转控件，如下截图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_07_10.jpg)

错误响应会导致以下错误消息显示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_07_11.jpg)

# 配置默认命名空间

本教程向你展示如何配置 jQuery Mobile 框架以使用你自定义的命名空间作为 `data-` 属性。

## 准备工作

从 `code/07/namespace` 源文件夹中复制此教程的全部代码。您可以使用以下命令启动此代码：`http://localhost:8080/07/namespace/main.html`。

## 如何做...

1.  在 `main.html` 中，添加以下脚本以在包含 `jquery.mobile.js` 之前使用：

    ```js
    $(document).bind("mobileinit", function() {
     $.mobile.ns = "my-";
    });
    ```

1.  在 `<head>` 标签中添加以下样式：

    ```js
    <link rel="stylesheet" href="http://code.jquery.com/mobile/1.1.1/jquery.mobile-1.1.1.min.css" />
    <style>
     .ui-mobile [data-my-role=page], .ui-mobile [data-my-role=dialog], 
     .ui-page { top: 0; left: 0; width: 100%; min-height: 100%; 
     position: absolute; display: none; border: 0; } 
    </style>
    ```

1.  创建主页面如下所示：

    ```js
    <div id="main" data-my-role="page" data-my-theme="e">
      <div data-my-role="header" data-my-theme="a">
        <h1>Configure Namespace</h1>
      </div>
     <div data-my-role="content"> 
        <p>This is the main page</p>
        <a href="#dialog" data-my-role="button">
          Open Dialog
        </a>
      </div>
    </div>
    ```

1.  创建 `#dialog` 页面如下；这是一个多页面文档：

    ```js
    <div id="dialog" data-my-role="dialog" data-my-theme="e">
      <div data-my-role="header" data-my-theme="a">
        <h1>Dialog</h1>
      </div>
      <div data-my-role="content">
        <p>This is a dialog</p>
     <a href="#" data-my-role="button" data-my-
     rel="back">Go Back</a>
      </div>
    </div>
    ```

## 它是如何工作的...

要使用自定义命名空间，您必须在 `jquery.mobile.css` 文件中覆盖一个特定的选择器，即 `.ui-mobile [data-my-role=page]` 和 `.ui-mobile [data-my-role=dialog]` 选择器。按照代码中所示覆盖此样式。使用 `data-my-role` 意味着命名空间设置为 `my`。

创建 `main.html`，并在包含对 `jquery.mobile.js` 的引用之前添加前述脚本以设置此配置。在脚本中，为 `mobileinit` 事件添加一个事件处理程序，该事件在应用程序启动时触发。在这里，使用 `$.mobile.ns="my-"` 配置设置默认命名空间。添加 `#main` 和 `#dialog` 页面。

以下截图显示了通过 DOM 检查器看到的页面：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_07_12.jpg)

您会注意到代码还使用了`data-my-`属性。您还会观察到框架已添加增强功能，甚至这些增强功能在整个页面上都使用自定义命名空间。

### 注意

对于自定义命名空间，使用尾随连字符，例如`"my-"`。这样增强代码更易读。

# 配置`hashListeningEnabled`和`subPageUrlKey`

当您使用嵌套`listview`时，jQuery Mobile 框架会生成一个子页面，形式为`pagename.html&ui-page=subpageidentifier`。在子页面 URL 键`(&ui-page)`之前的哈希段由框架用于导航。本示例向您展示了如何使用自定义子页面 URL 键。它还向您展示了如何使用`$.mobile.hashListeningEnabled`配置。

## 准备工作

从源文件夹`code/07/sub-page`中复制此示例的完整代码。您可以使用以下 URL 启动此代码：`http://localhost:8080/07/sub-page/main.html`。

## 如何做...

1.  在`main.html`中，在包含`jquery.mobile.js`之前添加以下脚本：

    ```js
    $(document).bind("mobileinit", function() {
     $.mobile.subPageUrlKey = "my-page";
     $.mobile.hashListeningEnabled = false; 
    });
    ```

1.  在其内容中创建带有嵌套列表的`#main`页面如下所示：

    ```js
    <div data-role="content">
     <ul data-role="listview" data-theme="e">
        <li>Main Page Item 1</li>
        <li>Sub Page Items
     <ul data-role="listview">
            <li>Sub Page Item A</li>
            <li>Sub Page Item B</li>
          </ul>
        </li>
      </ul>
    </div>
    ```

## 它是如何工作的...

创建`main.html`，并在包含对`jquery.mobile.js`的引用之前在代码中添加给定的脚本。在脚本中，添加一个在应用程序启动时触发的`mobileinit`事件的事件处理程序。在这里，设置`$.mobile.subPageUrlKey="my-page"`和`$.mobile.hashListeningEnabled=false`配置。最后，在代码中添加`#main`页面与嵌套列表一样。输出将类似于以下截图：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_07_13.jpg)

点击**子页面项**，并在子页面中打开嵌套列表。地址栏显示自定义的子页面 URL 键`my-page`，如下面的截图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_07_14.jpg)

现在，使用浏览器的**返回**按钮返回。地址栏中的 URL 会更新，但页面不会返回到上一个屏幕，如下面的代码所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_07_15.jpg)

这是因为在启动时将`hashListeningEnabled`配置为`false`。这将阻止框架监听和处理位置哈希更改。如果将`hashListeningEnabled`设置为`true`（默认值）并重新加载页面，则页面导航将正常工作，并且主列表将再次显示为嵌套列表。

### 注意

只有在想要自定义管理哈希更改而不是允许框架处理它时，才配置`hashListeningEnabled`。

## 另请参阅

+   第七章，*配置*，*配置`pushStateEnabled`和`link**BindingEnabled`*

# 配置`pushStateEnabled`和`linkBindingEnabled`

当您单击链接时，将进行导航并更新 URL 散列。框架允许您在支持 `history.replaceState` API 的浏览器中将 URL 散列替换为完整路径。此示例向您展示了如何使用 `$.mobile.pushStateEnabled` 配置来实现此目的。它还向您展示了如何使用 `$.mobile.linkBindingEnabled` 配置，该配置允许框架自动绑定文档中锚链接的单击事件。这两者默认值均为 `true`。

## 准备工作

从 `code/07/push-state` 文件夹中复制此示例的完整代码。您可以使用以下 URL 启动此代码：`http://localhost:8080/07/push-state/main.html`。

## 如何操作...

1.  在 `main.html` 中，在包含 `jquery.mobile.js` 前添加以下脚本：

    ```js
    $(document).bind("mobileinit", function() {
     $.mobile.linkBindingEnabled = true;
     $.mobile.pushStateEnabled = false; 
    });
    ```

1.  创建以下内容的 `#main` 页面：

    ```js
    <div data-role="content">
      <a href="page1.html" data-role="button">Go to Page 1</a>
    </div>
    ```

1.  创建 `page1.html` 如下：

    ```js
    <div id="page1" data-role="page" data-theme="e">
      <div data-role="header">
        <h1>Header of Page 1</h1>
      </div>
      <div data-role="content">
        <a href="#" data-role="button" data-rel="back">Go Back</a>
      </div>
    </div>    
    ```

## 它的工作原理...

创建 `main.html`，并在引用 `jquery.mobile.js` 之前在代码中添加给定的脚本。在脚本中，为在应用程序启动时触发的 `mobileinit` 事件添加事件处理程序。在这里，设置 `$.mobile.pushStateEnabled=false` 和 `$.mobile.linkBindingEnabled=true` 配置。最后，根据代码中所示添加 `#main` 页面内容和 `page1.html`。输出将类似于以下屏幕截图：

![它的工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_07_16.jpg)

当您打开 **页面 1** 时，URL 地址栏将完整路径附加到 `main.html`，如下截图所示：

![它的工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_07_17.jpg)

这是因为在启动时将 `pushStateEnabled` 设置为了 `false`。如果您将其设置为 `true`（默认值）并重新加载页面，URL 散列将被替换，并显示为 `http://localhost:8080/07/push-state/page1.html`。

### 注意

当应用程序中未使用 Ajax 或者大量使用外部链接时，将 `pushStateEnabled` 配置设置为 `false`。

## 还有更多...

在本示例中，在启动时将 `linkBindingEnabled` 配置设置为了 `true`（其默认值）。如果您将其设置为 `false` 并重新加载页面，您将注意到单击 **转到页面 1** 按钮时它未获得活动状态。在这种情况下，框架不会自动绑定链接点击。

### 注意

仅在您希望您的自定义代码（或其他库）处理链接点击时，使用 `linkBindingEnabled` 配置。

## 参见也

+   第七章, *配置*, *配置 hashListeningEnabled 和 subPageUrlKey*


# 第八章：事件

在本章中，我们将涵盖：

+   使用方向事件

+   使用滚动事件

+   使用触摸事件

+   使用虚拟鼠标事件

+   使用页面初始化事件

+   使用页面加载和移除事件

+   使用页面切换事件

+   使用页面过渡和动画事件

+   使用布局事件

# 介绍

jQuery Mobile 框架不仅提供了默认的本机事件，还为桌面和移动平台提供了特定的事件。它允许你使用 jQuery 的 `bind()` 或 `live()` 方法绑定到这些事件，并允许你执行自定义操作。本章将向您展示如何使用 jQuery Mobile 框架中提供的事件。

# 使用方向事件

当移动设备的方向（**纵向** 或 **横向**）改变时，jQuery Mobile 框架会触发一个 `orientationchange` 事件。这个示例向您展示如何使用 `orientationchange` 事件。

## 准备工作

从 `code/08/orientation` 源文件夹中复制此示例的完整代码。您可以通过使用 URL `http://localhost:8080/08/orientation/main.html` 启动此代码。

## 如何实现...

执行以下步骤：

1.  创建 `main.html` 如下所示：

    ```js
    <div id="main" data-role="page" data-theme="e">
      <div data-role="header" data-theme="a">
     <h1>Orientation Events</h1>
      </div>    
      <div data-role="content">
        <p>Change orientation</p>
      </div>
    </div>
    ```

1.  在 `<head>` 部分添加处理 `orientationchange` 事件的脚本：

    ```js
    $(window).bind("orientationchange", function(event, data) {
     $("h1").html(data.orientation);
    });
    ```

## 工作原理...

创建 `main.html`，其中包含页面内容，如前面的代码片段所示。添加给定的脚本，并将 `orientationchange` 事件绑定到回调函数。在这里，将设备的当前方向设置为页面的 `h1` 标题。您可以通过回调函数的 `data.orientation` 属性获取设备的方向。

当页面加载时，改变设备的方向；头部文本将根据当前方向显示 **纵向** 或 **横向**。

## 更多信息...

在不支持 orientation 属性的平台（`$.support.orientation` 为 `false`）或者 `$.mobile.orientationChangeEnabled` 全局配置设置为 `false` 时，框架会绑定 resize 事件处理程序来处理设备方向的改变。

### orientationChangeEnabled 全局配置

您可以在应用程序开始时调用的 `mobileinit` 事件处理程序中配置 `$.mobile.orientationChangeEnabled` 配置。这必须在包含 `jquery.mobile.js` 脚本之前完成。

```js
$(document).bind("mobileinit", function() {
  $.mobile.orientationChangeEnabled = false;
});
```

# 使用滚动事件

当您滚动时，jQuery Mobile 框架会触发 scrollstart 事件。当您停止滚动时，会触发 `scrollstop` 事件。这个示例向您展示如何使用这两个事件。

## 准备工作

从 `code/08/scroll` 源文件夹中复制此示例的完整代码。您可以通过使用 URL `http://localhost:8080/08/scroll/main.html` 启动此代码。

## 如何实现...

执行以下步骤：

1.  创建 `main.html`，其中页面内容的 `div` 元素使用一个较大的高度值进行样式设置，以便出现滚动条：

    ```js
    <div id="main" data-role="page" data-theme="e">
      <div data-role="header" data-theme="a" data-
      position="fixed">
     <h1>Scroll Events</h1>
      </div>    
      <div data-role="content">
        <div style="height: 1000px">Scroll now</div>
      </div>
    </div>
    ```

1.  在 `<head>` 部分添加以下脚本来处理 `scroll` 事件：

    ```js
    $(window).bind("scrollstart", function(event) {
      $("h1").html("Scrolling now...");
    });
    $(window).bind("scrollstop", function(event) {
      $("h1").html("Scrolling done!");
    });
    ```

## 工作原理...

在前面的代码中创建`main.html`。在页面内容中添加一个高度为`1000px`的`div`容器。这将使垂直滚动条出现。现在，在页面的`<head>`部分添加给定的脚本。将`scrollstart`事件绑定到一个回调函数，该函数更新页面头部文本。类似地，将`scrollstop`事件绑定到一个回调函数，该函数更新头部文本。现在，保持垂直滚动条手柄，滚动页面。您可以看到页面头部文本显示为`"正在滚动..."`，当您停止或暂停滚动时，文本更新为`"滚动完成!"`。

## 还有更多...

在 iOS 设备上，`scrollstart`事件的工作方式存在问题。在滚动期间不允许 DOM 操作，并且事件被排队，一旦滚动停止就会触发。因此，在处理 iOS 设备上的滚动事件时，请记住这一点。您将不得不在滚动开始之前进行更改，而不是一开始就进行更改。

# 使用触摸事件

jQuery Mobile 框架提供了五个触摸事件。它们是`tap`、`taphold`、`swipe`、`swipeleft`和`swiperight`事件。当您点击屏幕时，将触发`tap`事件。如果点击持续时间较长，则首先触发`taphold`事件，然后在您放开手指后触发`tap`事件。当您在屏幕上滑动时，首先触发`swipe`事件，然后根据您滑动的方向触发`swipeleft`或`swiperight`事件。本配方向您展示了如何使用这些触摸事件。

在这个配方中，显示一个黄色框，显示您最后点击屏幕的位置。每次您点击并保持时，都会创建一个绿色框。您还可以通过将蓝色条拉到屏幕的左侧或右侧来查看滑动操作的工作方式。

## 准备工作

从`code/08/touch`源文件夹复制此配方的完整代码。您可以通过使用 URL `http://localhost:8080/08/touch/main.html` 来启动此代码。

## 如何操作...

应该遵循的步骤是

1.  在`main.html`中，在`<head>`标签中定义以下样式：

    ```js
    <style>
      .box { width:60px; height:60px; position:fixed }
      .yellow { background-color:yellow; z-index:1 }
      .green { background-color:green; z-index:2 }
      .blue { background-color: blue; z-index:3; height:100% }
    </style>
    ```

1.  使用两个带有蓝色条和黄色框样式的`<div>`标签添加页面内容：

    ```js
    <div id="content" data-role="content">
      <div id="movingbox" class="box yellow" style="top:0px; left:0px"></div>
      <div id="edgebar" class="box blue" style="top:0px; left:0px"></div>
    </div>
    ```

1.  在`<head>`部分添加以下脚本，以处理`tap`和`taphold`事件：

    ```js
    var tapholdflag = false;
    $("#main").live("tap", function(event) {
      var stylestr = "left:" + event.clientX + "px; top:" 
        + event.clientY + "px;"
      if (tapholdflag) {
        var str = "<div class=''box green'' style=''" + 
          stylestr + "''></div>";
        $("#content").append(str).trigger("create");
      } else {
        $("#movingbox").attr("style", 
          stylestr).trigger("refresh");
      }
      tapholdflag = false;
    });
    $("#main").live("taphold", function(event) {
      tapholdflag = true;
    });
    ```

1.  最后，处理`swipe`、`swipeleft`和`swiperight`事件：

    ```js
    $("#main").live("swipe", function(event) {
      $.event.special.swipe.scrollSupressionThreshold = 15;
      $.event.special.swipe.durationThreshold = 1250;
      $.event.special.swipe.horizontalDistanceThreshold = 25;
      $.event.special.swipe.verticalDistanceThreshold = 50;
    });  
    $("#main").live("swipeleft", function(event) {
      $("#edgebar").attr("style", "top:0px; 
        left:0px").trigger("refresh");
    });
    $("#main").live("swiperight", function(event) {
      $("#edgebar").attr("style", "top:0px; 
        right:0px").trigger("refresh"); 
    });
    ```

## 它是如何工作的...

在`main.html`中，添加`style`标签，并定义`box`、`yellow`、`green`和`blue`类。添加一个空的`div`标签，设置属性`id="movingbox"`，并设置属性`class="box yellow"`。这将创建一个`60px`宽的黄色方块。接下来，添加一个空的`div`标签，设置属性`id="edgebar"`，并设置属性`class="box blue"`。这将在屏幕边缘创建一个`60px`宽的蓝色条，如下面的截图所示。黄色框隐藏在蓝色条下面，因为它具有较低的`z-index`值。

`![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_08_01.jpg)`

现在将给定的脚本添加到`main.html`的`<head>`部分。将五个触摸事件中的每一个绑定到如所示的回调函数。如果触摸持续时间长，则为`taphold`。因此，定义一个布尔值`tapholdflag`来跟踪`tap`事件是否为`taphold`。在`taphold`事件处理程序中将其设置为`true`，并在触发`tap`事件后将其清除。

在`tap`事件的回调中，首先检查` tapholdflag`是否已设置。如果是，则这是一个`taphold`事件。创建一个新的绿色框并调用`"create"`方法，如所示。如果`tapholdflag`为`false`，则这是一个简单的点击。更新黄色框的新位置，并触发`"refresh"`方法。最后，清除`tapholdflag`并将其设置为`false`。

通过使用`event.clientX`和`event.clientY`参数，可以获取触摸位置。将这些值设置为盒子的`left`和`top`样式属性，以更新其位置。在几次`tap`和`taphold`事件后，屏幕看起来类似于以下截图：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_08_02.jpg)

现在，将`swipe`事件绑定到回调函数，并按照代码中所示配置`swipe`事件属性。代码向您展示如何配置`scrollSupressionThreshold`、`durationThreshold`、`horizontalDistanceThreshold`和`verticalDistanceThreshold`属性。

将`swipeleft`事件绑定到回调以设置蓝色条的`left`和`top`样式属性，并调用`"refresh"`方法。这将将条移到屏幕的左边缘。类似地，将`swiperight`事件绑定到回调以设置蓝色条的`right`和`top`样式属性，并调用`"refresh"`。这将把条移到屏幕的右边缘。现在，当您向屏幕的右侧滑动时，该条将移动到右边缘，如以下截图所示；向左侧滑动，则该条将移回左边缘：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_08_03.jpg)

## 还有更多...

在代码中，`swipe`事件的回调向您展示了如何配置`swipe`事件属性。可用的配置如下：

+   `scrollSupressionThreshold`（默认为`10px`）：必须滑动距离超过此值才能触发事件，否则就是`scroll`事件。

+   `durationThreshold`（默认为`1000ms`）：如果滑动持续时间超过此值，则阻止`swipe`事件的触发。

+   `horizontalDistanceThreshold`（默认为`30px`）：水平滑动距离必须超过此值才能触发事件。

+   `verticalDistanceThreshold`（默认为`75px`）：垂直滑动距离必须小于此值才能触发事件。

### `tapholdThreshold`属性

`每当您点击屏幕时，将触发 `tap` 事件。如果点击持续时间超过一定值（默认为 `750ms`），则将其视为 `taphold` 事件。您可以通过设置 `$.event.special.tap.tapholdThreshold` 属性来配置此持续时间，如下所示：`

```js
$("#main").live("tap", function(event) {
  $.event.special.tap.tapholdThreshold = 1000;
});
```

### `注意`

`默认 `tap` 事件配置对大多数平台都很有效。因此，只有在有非常强烈的理由时才修改它们。`

## `另请参阅`

+   `使用虚拟鼠标事件` 示例

`# 虚拟鼠标事件

jQuery Mobile 框架提供虚拟 `mouse` 或 `vmouse` 事件来抽象鼠标和触摸事件。

您无需为每个受支持的平台或设备的触摸和鼠标事件编写单独的处理程序。您只需为 `vmouse` 事件编写事件处理程序，它将在各种平台上正常工作。框架支持七个 `vmouse` 事件：`vmousemove`、`vmouseover`、`vmouseout`、`vmousedown`、`vmouseup`、`vclick` 和 `vmousecancel`。此示例向您展示如何使用这些 `vmouse` 事件。

## 准备工作

从 `code/08/vmouse` 源文件夹中复制此示例的完整代码。您可以通过以下 URL `http://localhost:8080/08/vmouse/main.html` 启动此代码。

## 如何实现...

应遵循以下步骤：

1.  创建包含七个 `div` 标签的 `main.html`，用于展示七个 `vmouse` 事件，如下所示：

    ```js
    <div data-role="content">
      <div id="move"></div>
      <div id="over"></div>        
      <div id="out"></div>        
      <div id="down"></div>
      <div id="up"></div>
      <div id="click"></div>
      <div id="cancel"></div>
    </div>
    ```

1.  将以下脚本添加到 `<head>` 部分以处理 `vmousemove`、`vmouseover` 和 `vmouseout` 事件：

    ```js
    $("#main").live("pageinit", function(e) {
     $("#main").bind("vmousemove", function(e) {
        $("#move").html("<p>Move: " + e.clientX + ", " 
          + e.clientY + "</p>");
      });
     $("#main").bind("vmouseover", function(e) {
        $("#over").html("<p>Over: " + e.clientX + ", " 
          + e.clientY + "</p>");
      });
     $("#header").bind("vmouseout", function(e) {
        $("#out").html("<p>Out: " + e.clientX + ", " + 
          e.clientY + "</p>");
      });
    ```

1.  接下来，按如下方式处理 `vmousedown`、`vmouseup` 和 `vclick` 事件：

    ```js
     $("#main").bind("vmousedown", function(e) {
        var whichbtn;
        switch (e.which) {
          case 1: whichbtn = "Left Button"; break;
          case 2: whichbtn = "Center Button"; break;
          case 3: whichbtn = "Right Button"; break;
          default: whichbtn = "Tap"; break;
        }                        
        $("#down").html("<p>Down: " + e.clientX + ", " 
          + e.clientY + " - " + whichbtn + " </p>");
      });
     $("#main").bind("vmouseup", function(e) {
        $("#up").html("<p>Up: " + e.clientX + ", " + 
          e.clientY + "</p>");
      });
     $("#main").bind("vclick", function(e) {
        $("#click").html("<p>Click: " + e.clientX + ", 
          " + e.clientY + "</p>");
      });
    ```

1.  最后，按如下方式处理 `vmousecancel` 事件：

    ```js
     $("#main").bind("vmousecancel", function(e) {
        $("#cancel").html("<p>Cancel: " + e.clientX + ", 
          " + e.clientY + "</p>");
      });
    });
    ```

## 工作原理...

创建 `main.html`，并添加七个空的 `divs` 来显示七个 `vmouse` 事件的位置。添加给定的脚本，并绑定每个 `vmouse` 事件的回调函数，如 `pageinit` 事件处理程序所示。使用传递给回调函数的事件参数的 `e.clientX` 和 `e.clientY` 值来获取 `vmouse` 事件的位置。当您加载页面并执行描述的各种鼠标操作时，屏幕显示如下：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_08_04.jpg)

当鼠标移动（或在 `touchmove` 事件上）时，将触发 `vmousemove` 事件。当移动操作在事件绑定的元素上完成时，将触发 `vmouseover` 事件。当移动操作移出事件绑定的元素时，将触发 `vmouseout` 事件。在上述代码中，`vmouseout` 事件绑定到 `h1` 标题上。将鼠标移动到标题上，然后移出，以查看屏幕上的此参数是否更新。当鼠标点击（或在 `touchstart` 事件上）时，将触发 `vmousedown` 事件。当点击结束时（`touchend` 事件），`vmouseup` 事件紧随 `down` 事件。在点击或触摸动作时，将同时触发 `vclick` 事件和 `vmousedown`、`vmouseup` 事件。在 `vmousedown` 事件处理程序中，您可以使用 `event.which` 属性来查找点击了哪个鼠标按钮。对于 `tap` 事件，此值为 `0`。您可以尝试点击鼠标上的不同按钮，以相应地查看屏幕更新。最后，当存在被取消的鼠标或触摸事件时，将触发 `vmousecancel` 事件。

## 还有更多...

框架为 `vmouse` 事件提供了以下三个配置：

+   `$.vmouse.moveDistanceThreshold`（默认为 `10px`）：如果移动超过此值，则为 `scroll` 事件。将调用 `vmousecancel` 事件并取消 `TouchMove` 事件。

+   `$.vmouse.clickDistanceThreshold`（默认为 `10px`）：如果已捕获 `vmouse` 点击事件，则它在阻止列表中。然后，所有小于此距离的 `vmouse` 点击都将被忽略。

+   `$.vmouse.resetTimerDuration`（默认为 `1500ms`）：如果 `vmouse` 点击之间的间隔大于此持续时间，则不是触摸事件。`Scroll`、`TouchMove` 和 `TouchEnd` 事件使用此值。阻止列表将被清除。

    ### 注意

    默认的 `vmouse` 配置适用于大多数平台。因此，只有在有很强的理由时才修改它们。

### 鼠标坐标

此配方向您展示如何使用 `event.clientX` 和 `event.clientY` 属性获取鼠标坐标。您还可以使用 `event.pageX`、`event.pageY`、`screen.pageX` 和 `screen.pageY` 属性获取屏幕和页面坐标。

### 在触摸设备上使用 vclick 事件

在触摸设备上，`webkit` 浏览器会在触发 `touchend` 事件后大约 300 毫秒的延迟后处理点击事件。如果在此间隙内更改底层对象或背景，则可能选择不同的目标。另一个问题是由于时间延迟而将事件与相应目标匹配；例如，当使用 `event.preventDefault()` 时。为了避免这些问题，在触摸设备上使用 `click` 事件而不是 `vclick` 事件。

## 另请参阅

+   *使用触摸事件* 配方

# 页面初始化事件

jQuery Mobile 框架提供了**页面插件**，它自动处理页面初始化事件。 `pagebeforecreate`事件在页面创建之前触发。 `pagecreate`事件在页面创建后但在小部件初始化之前触发。 `pageinit`事件在完全初始化后触发。此示例向您展示如何使用这些事件。

## 准备工作

从`code/08/pageinit`源文件夹中复制此配方的完整代码。您可以使用 URL`http://localhost:8080/08/pageinit/main.html`启动此代码。

## 如何操作...

执行以下步骤：

1.  创建`main.html`，其中包含三个空的`<div>`标签，如下所示：

    ```js
    <div id="content" data-role="content">
      <div id="div1"></div>
      <div id="div2"></div>
      <div id="div3"></div>
    </div>
    ```

1.  将以下脚本添加到`<head>`部分以处理`pagebeforecreate`事件：

    ```js
    var str = "<a href='#' data-role='button'>Link</a>";
    $("#main").live("pagebeforecreate", function(event) {
      $("#div1").html("<p>DIV1 :</p>"+str);
    });
    ```

1.  接下来，处理`pagecreate`事件：

    ```js
    $("#main").live("pagecreate", function(event) {
      $("#div1").find("a").attr("data-icon", "star");
    });
    ```

1.  最后，处理`pageinit`事件：

    ```js
    $("#main").live("pageinit", function(event) {
      $("#div2").html("<p>DIV 2 :</p>"+str);
      $("#div3").html("<p>DIV 3 :</p>"+str);
      $("#div3").find("a").buttonMarkup({"icon": "star"});
    });
    ```

## 工作原理...

在`main.html`中，如下所示将三个空的`divs`添加到页面内容中。将给定的脚本添加到页面中。在脚本中，`str`是一个具有`data-role="button"`属性的创建锚链接的 HTML 字符串。

添加`pagebeforecreate`事件的回调，并将`str`设置为`div1`容器。由于页面尚未创建，因此`div1`中的按钮会自动初始化和增强，如下图所示。

添加`pagecreate`事件的回调。使用 jQuery 的`find()`方法选择`div1`中的前一个锚按钮，并设置其`data-icon`属性。由于此更改是在页面初始化之后但在按钮初始化之前进行的，所以`div1`按钮自动显示为`star`图标，如下图所示。最后，添加`pageinit`事件的回调，并将`str`添加到`div2`和`div3`容器中。此时，页面和小部件已经初始化和增强。现在添加一个锚链接将仅显示为`div2`的原生链接，如下图所示。但是，对于`div3`，找到锚链接，并在按钮插件上手动调用`buttonmarkup`方法，并将其图标设置为`star`。现在当您加载页面时，`div3`中的链接将被增强如下所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_08_05.jpg)

## 还有更多...

您可以在插件上触发`"create"`或`"refresh"`，以让 jQuery Mobile 框架增强对页面或小部件进行的动态更改后的初始化。

### 页面初始化事件仅触发一次

页面初始化事件仅触发一次。因此，这是进行任何特定初始化或添加自定义控件的好地方。

### 不要使用$(document).ready()

`$(document).ready()`处理程序仅在加载第一个页面或 DOM 首次准备就绪时起作用。如果通过 Ajax 加载页面，则不会触发`ready()`函数。而`pageinit`事件在页面创建或加载和初始化时触发。因此，这是在应用程序中进行后初始化活动的最佳位置。

```js
$(document).bind("pageinit", callback() {…});
```

# 页面加载和移除事件

jQuery Mobile 框架在将外部页面加载到 DOM 时会触发页面加载事件。它会在加载页面之前触发`pagebeforeload`事件，然后根据页面加载的状态触发`pageload`或`pageloadfailed`事件。当页面从 DOM 中移除时会触发`pageremove`事件。本教程向您展示如何使用页面加载和页面移除事件。

## 准备工作

从`code/08/pageload`源文件夹中复制此配方的完整代码。您可以使用 URL `http://localhost:8080/08/pageload/main.html`启动此代码。

## 如何做...

执行以下步骤：

1.  根据以下代码片段创建带有四个按钮和一个空的`div`元素的`main.html`：

    ```js
    <div id="content" data-role="content">
      <a href="page1.html" data-role="button" data-
        inline="true">Page 1</a>
      <a href="page2.html" data-role="button" data-
        inline="true">Page 2</a>        
      <a href="page3.html" data-role="button" data-
        inline="true">Page 3</a>
      <a href="page4.html" data-role="button" data-
        inline="true">Page 4</a>
      <div id="msgdiv"></div>
    </div>
    ```

1.  在`<head>`部分添加以下脚本来处理`pagebeforeload`事件：

    ```js
    $(document).bind("pagebeforeload", function(event, data) {
      var str = "<p>LOADING PAGE ...</p>"
        + "<p>url: " + data.url + "</p>"
        + "<p>absUrl : " + data.absUrl + "</p>"
        + "<p>dataUrl : " + data.dataUrl + "</p>"
        + "<p>options.type: " + data.options.type + "</p>";
      var re = /page2.html/;
      if ( data.url.search(re) !== -1 ) {
        str += "<p>ABORTED!!! page2.html does not 
          exist.</p>";
        event.preventDefault();
     data.deferred.reject( data.absUrl, data.options);
      }
      re = /page4.html/;
      if ( data.url.search(re) !== -1 ) {
        str += "<p>ABORTED!!! error dialog shown 
          instead.</p>";
        event.preventDefault();
     data.deferred.resolve( data.absUrl, data.options, 
     $("#subpage")); 
      }
      $("#msgdiv").html(str).trigger("refresh");
    });
    ```

1.  接下来，处理`pageload`事件：

    ```js
    $(document).bind("pageload", function(event, data) {
      var str = "<p>PAGE LOADED!</p><p>textStatus: " + data.textStatus 
        +   "</p><p>xhr.status : " + data.xhr.status + "</p>";
      $("#msgdiv").append(str).trigger("refresh");
    });
    ```

1.  接着，处理任何`pageloadfailed`事件中的错误：

    ```js
    $(document).bind("pageloadfailed", function(event, 
     data) {
      var str = "<p>PAGE LOAD FAILED!</p>"+ "<p>textStatus: " + data.textStatus + "</p>"
        + "<p>xhr.status : " + data.xhr.status + "</p>"
        + "<p>errorThrown : " + data.errorThrown + "</p>";
      $("#msgdiv").append(str).trigger("refresh");
    });
    ```

1.  同样处理`pageremove`事件：

    ```js
    $("#page1").live("pageremove", function(event) {
      $("#msgdiv").append("<p>PAGE 
        REMOVED!</p>").trigger("refresh");
    });
    ```

1.  现在，按照以下步骤创建带有`id="dialog"`的对话框：

    ```js
    <div id="dialog" data-role="dialog" data-theme="e" data-add-back-btn="true">
      <div data-role="header">
        <h1>Page Load Failed!</h1>
      </div>
      <div data-role="content">
        <p>There was an error</p>
      </div>      
    </div>
    ```

1.  最后，根据以下代码片段创建带有返回到`#main`按钮的`page1.html`：

    ```js
    <div id="page1" data-role="page" data-theme="e">
      <div data-role="header">
        <h1>Header of Page 1</h1>
      </div>
      <div data-role="content">
        <a href="#" data-role="button" data-
          rel="back">Go to Main Page</a>
      </div>
    </div>
    ```

## 它是如何工作的...

在`main.html`中创建`#main`页面，并添加四个锚链接，带有`data-role="button"`和`data-inline="true"`属性，以创建四个内联按钮。这些链接指向`page1.html`、`page2.html`、`page3.html`和`page4.html`。同时添加一个空的`div`容器，带有`id="msgdiv"`用于显示消息。接着，在`main.html`中添加一个带有`id="dialog"`的对话框。最后，只创建`page1.html`，如下所示，其中包含一个返回主页的链接。其他三个页面不需要创建。将页面加载和页面移除事件绑定到脚本中给出的回调函数。这些回调函数有两个参数可用。第一个是`event`对象，第二个是`data`对象。

在`pagebeforeload`事件的回调中，从`data`对象中获取`url`、`absUrl`（绝对 URL）、`dataUrl`（数据 URL）和`options.type`属性。将它们显示在`msgdiv`容器中。`options`对象与传递给`$.mobile.loadPage()`调用的相同。

在`pageload`事件的回调中，获取`xhr.status`（jQuery `XMLHttpRequest`对象）和`textStatus`属性，指示页面加载成功，并在`msgdiv`容器中显示它们。

添加`pageloadfailed`回调函数以在页面加载错误时显示`data.xhr.status`和`data.errorThrown`属性。最后，添加`pageremove`回调函数并显示页面已被移除的消息。

现在，当您首次加载应用程序并点击**页面 1**按钮打开`page1.html`时，首先触发`pagebeforeload`事件，然后在完全加载页面之后触发`pageload`事件。返回主页时触发`pageremove`事件。您可以看到下面的屏幕截图中显示的这些消息：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_08_06.jpg)

接下来，在`pagebeforeload`事件处理程序中，使用正则表达式搜索来检查所请求的页面或`data.url`是否为`page2.html`（该页面不存在）。如果请求了`page2.html`，则显示自定义错误消息。还通过调用`event.preventDefault()`来阻止对此请求的进一步操作。最后必须调用`data.deferred.reject()`方法来拒绝数据对象中包含的延迟对象引用。现在，当您单击**Page 2**按钮时，不会触发`pageloadfailed`事件，如下面的屏幕截图所示，而是显示自定义错误消息**ABORTED!!! page2.html 不存在。**：

![它的工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_08_07.jpg)

点击**Page 3**按钮；它现在尝试加载`page3.html`，但是找不到，并显示了默认的**Error Loading Page**错误消息，如下面的屏幕截图所示。您还可以在这里看到`pageloadfailed`事件处理程序的消息。在这种情况下没有进行自定义事件处理。

![它的工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_08_08.jpg)

最后，在`pagebeforeload`回调函数中添加代码，以搜索`data.url`对象中的`page4.html`。如果找到字符串，则将请求重定向到加载`#dialog`对话框。还如果请求了`page4.html`，则显示自定义消息。现在，要阻止`pagebeforeevent`上的默认操作，请调用`event.preventDefault()`方法。还必须调用`data.deferred.resolve()`方法来解析`data`对象中包含的延迟对象引用。然后，通过将其作为参数传递给`resolve`方法，打开`#dialog`页面，如代码所示。现在，当您单击**Page 4**按钮时，将显示自定义错误对话框弹出窗口。当关闭对话框时，将显示您的自定义消息**ABORTED!!!显示错误对话框。**，如下面的屏幕截图所示。您会注意到`pageloadfailed`事件回调函数没有被调用。

![它的工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_08_09.jpg)

## 还有更多...

如果通过调用`event.preventDefault()`方法来阻止默认的页面加载事件，那么在完成后，必须通知框架恢复处理其他`changePage()`请求。您可以通过在事件的回调函数中对传递给`data.deferred`对象调用`reject()`或`resolve()`方法来实现这一点。

## 另请参阅

+   在第九章*方法和实用程序*中的*使用 loadPage()加载页面*中的配方

# 页面更改事件

每当`$.mobile.changePage()`方法将页面加载到 DOM 中时，jQuery Mobile 框架都会触发页面更改事件。首先触发`pagebeforechange`事件，然后触发`pagechange`事件（成功时）或`pagechangefailed`事件（失败时）。本节介绍如何使用页面更改事件。

## 准备好了

从 `code/08/pagechange` 源文件夹中复制此配方的完整代码。你可以使用 `http://localhost:8080/08/pagechange/main.html` URL 启动此代码。

## 如何做...

执行以下步骤：

1.  创建 `main.html`，其中包含两个链接以打开两个对话框，并在其页面内容中包含一个空的 `div` 元素，如下所示：

    ```js
    <div id="content" data-role="content">
      <a href="#dialog1" data-role="button">Dialog 1</a>
      <a href="#dialog2" data-role="button">Dialog 2</a>        
      <div id="msgdiv"></div>
    </div>
    ```

1.  将以下脚本添加到 `<head>` 部分以处理 `pagebeforechange` 事件：

    ```js
    $(document).bind("pagebeforechange", function(event, data) {
      var str = "<p>CHANGING PAGE ...</p><p>toPage: ";
      str += (!!data.toPage.attr)? data.toPage.attr("data-
        url") : data.toPage;
      str += "</p>";
      $("#msgdiv").html(str).trigger("refresh");
      $("#dialogdiv").html(str).trigger("refresh");
    });
    ```

1.  接下来，处理 `pagechange` 事件：

    ```js
    $(document).bind("pagechange", function(event, data) {
      var str = "<p>CHANGED PAGE ...</p><p>fromPage: ";
      str += (!!data.options.fromPage && !!data.options.fromPage.attr)? 
      data.options.fromPage.attr("data-url") : "none";
      str += "</p><p>options.transition: " + data.options.transition + "</p>";
      $("#msgdiv").append(str).trigger("refresh");
      $("#dialogdiv").append(str).trigger("refresh");
    });
    ```

1.  接下来，处理 `pagechangefailed` 事件中的任何错误：

    ```js
    $(document).bind("pagechangefailed", function(event, 
     data) {
      var str = "<p>PAGE CHANGE FAILED ...</p>";
      $("#msgdiv").append(str).trigger("refresh");
    });
    ```

1.  最后，按以下方式创建 `#dialog1` 对话框。第二个对话框 `#dialog2` 不会被创建。

    ```js
    <div id="dialog1" data-role="dialog" data-theme="e" 
      data-add-back-btn="true">
      <div data-role="header">
        <h1>Dialog Header</h1>
      </div>
      <div data-role="content">
        <div id="dialogdiv"></div>
      </div>
    </div> 
    ```

## 工作原理...

在 `main.html` 中，将两个锚链接添加到 `#main` 页面的内容中，这些链接指向 `#dialog1` 和 `#dialog2` 对话框。还添加一个带有 `id="msgdiv"` 的空 `div` 容器以显示消息。最后，只向 `main.html` 添加一个带有 `id="dialog1"` 的对话框。将一个空的带有 `id="dialogdiv"` 的 `div` 容器添加到此对话框中。另一个对话框不会被创建。将页面更改事件绑定到给定的脚本中的回调函数。这些回调函数有两个可用参数。第一个是 `event` 对象，第二个是 `data` 对象。

在 `pagebeforechange` 事件的回调中，获取 `data.toPage`（目标页面）属性。这可以是字符串或对象。检查这是否是一个对象（是否具有 `toPage` 属性），然后使用 `data.toPage.data-url` 字符串。在两个消息 `div` 容器中显示 `toPage` 消息。

在 `pagechange` 事件的回调中，获取 `data.fromPage`（源页面）属性。再次检查这是对象还是字符串，并在消息 `div` 容器中显示 `data.fromPage.data-url` 字符串，如果它是一个对象。另外，`data.options` 对象具有属性，例如 `transition`，你可以使用。

最后，在 `pagechangefailed` 事件的回调中，显示自定义错误消息。当页面首次加载时，可以看到以下图像。**main** 文本显示为 **toPage**；这里没有 **fromPage**：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_08_10.jpg)

单击 **Dialog 1** 按钮，将显示以下对话框。 **toPage** 值是 **dialog1**， **fromPage** 是 **main**。所使用的转换显示为 **pop**，这是对话框的默认转换：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_08_11.jpg)

关闭此对话框，然后打开 `#main` 页面，显示与以下截图中显示的消息类似的消息。 **toPage** 是 **main**， **fromPage** 是 **dialog1**。所使用的转换再次显示为 **pop**：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_08_12.jpg)

最后，单击 **Dialog 2** 按钮；由于 `#dialog2` 不存在，所以会显示自定义错误消息 **PAGE CHANGE FAILED**，如你在 `pagechangefailed` 回调中所见：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_08_13.jpg)

## 还有更多...

你可以在`pagebeforechange`事件处理程序中调用`event.preventDefault()`方法来阻止默认的页面更改操作。你可以使用`$.mobile.changePage()`方法将导航重定向到另一个页面。

### 页面转换事件的顺序

在触发`pagebeforechange`事件后, `changePage()` 请求将页面加载到 DOM 中，然后页面过渡发生。此刻触发`pageshow`和`pagehide`事件。最后，只有在此之后才会触发`pagechange`事件。

## 参见

+   第九章中的*使用 changePage()来更改页面*示例，*方法和工具*

# 页面过渡和动画事件

在页面导航期间，当前页面变换出去，新的活动页面变换进来。在支持的情况下会使用动画效果。jQuery Mobile 框架在页面导航期间会触发四个页面转换事件，如下所示：

+   `pagebeforehide`: 在当前页面隐藏之前触发此事件

+   `pagehide`: 当前页面隐藏后触发此事件

+   `pagebeforeshow`: 在新的活动页面显示之前触发此事件

+   `pageshow`: 一旦活动页面显示出来就会触发此事件

你也可以访问`animationComplete`插件，以便在动画完成后立即执行自定义操作。此示例向你展示如何使用页面过渡事件，以及如何使用`animationComplete`插件。

## 准备工作

从`code/08/transition`源文件夹中复制此示例的完整代码。你可以使用 URL`http://localhost:8080/08/transition/main.html`运行此代码。

## 如何做...

执行以下步骤：

1.  创建`main.html`，并添加带有指向打开`#page`页面的链接和一个空的`div`容器`#main`页面的代码片段如下所示：

    ```js
    <div id="main" data-role="page" data-theme="e">
      <div data-role="header">
        <h1>Page Transition and Animation Events</h1>
      </div>
      <div id="content" data-role="content">
        <a href="#page" data-role="button" data-
          transition="slide">Page 1</a>
      <div id="msgdiv"></div>
    </div>
    ```

1.  创建`#page`页面，包括一个回到`#main`的按钮和一个空的`div`容器来显示消息：

    ```js
    <div id="page" data-role="page" data-theme="e">
      <div data-role="header">
        <h1>Page Header</h1>
      </div>
      <div data-role="content">
        <a href="#" data-rel="back" data-role="button">Go Back</a>
      <div id="pagediv"></div>
    </div>
    ```

1.  在`<head>`部分添加以下脚本，以便在点击链接时清除消息`div`容器：

    ```js
    $("#main").live("pageinit", function(event) {
      $("a").bind("click", function(event, ui) {
        $("#msgdiv").html("");
        $("#pagediv").html("");
      });
    });
    ```

1.  处理`pagebeforeshow`事件：

    ```js
    $(document).bind("pagebeforeshow", function(event, data) {
      var str = "<p>BEFORE PAGE SHOW ...</p><p>Previous 
        Page: ";
      str += (!!data.prevPage.attr)? 
        data.prevPage.attr("data-url") : "none";
      str += "</p>";
      $("#msgdiv").append(str).trigger("refresh");
      $("#pagediv").append(str).trigger("refresh");
    });
    ```

1.  处理`pagebeforehide`事件：

    ```js
    $(document).bind("pagebeforehide", function(event, 
     data) {
     $(data.nextPage).animationComplete(anim);
      var str = "<p>BEFORE PAGE HIDE ...</p><p>Current Page: ";
      str += (!!data.nextPage.attr)?
        data.nextPage.attr("data-url") : "none";
      str += "</p>";        
      $("#msgdiv").append(str).trigger("refresh");
      $("#pagediv").append(str).trigger("refresh");
    });
    ```

1.  处理`pageshow`事件：

    ```js
    $(document).bind("pageshow", function(event, data) {
      var str = "<p>PAGE SHOW!</p><p>Previous Page: ";
      str += (!!data.prevPage.attr)? 
        data.prevPage.attr("data-url") : "none";
      str += "</p>";
      $("#msgdiv").append(str).trigger("refresh");
      $("#pagediv").append(str).trigger("refresh");
    });
    ```

1.  处理`pagehide`事件：

    ```js
    $(document).bind("pagehide", function(event, data) {
      var str = "<p>PAGE HIDE!</p><p>Current Page: ";
      str += (!!data.nextPage.attr)? 
        data.nextPage.attr("data-url") : "none";
      str += "</p>";        
      $("#msgdiv").append(str).trigger("refresh");
      $("#pagediv").append(str).trigger("refresh");
    });
    ```

1.  添加`animationComplete()`方法的回调函数：

    ```js
    anim = function() {
      $("#msgdiv").append("ANIMATION 
        DONE!!!").trigger("refresh");
      $("#pagediv").append("ANIMATION 
        DONE!!!").trigger("refresh");          
    }
    ```

## 工作原理...

创建`main.html`，并添加一个带有`data-role="button"`的锚链接到`#main`页面的内容。此链接打开`main.html`中的`#page`页面。创建`#page`页面，如下所示，其中包含返回到`#main`的链接。分别向页面添加空的`#msgdiv`和`#pagediv`容器来显示消息。在`pageinit`事件处理程序中绑定锚链接的`click`事件，并清除先前显示的消息。每当你在应用中点击链接时，都会触发此回调。

现在，按照脚本中给定的方式将四个页面转换事件绑定到它们的回调函数。这些回调函数有两个可用参数。第一个参数是`event`对象，第二个是`data`对象。

在`pagebeforeshow`事件的回调函数中，获取`data.prevPage`（上一页）对象。第一次加载时可能为空。检查是否可用（是否具有`prevPage`属性），并使用`data.prevPage.data-url`字符串。在消息`div`容器中显示`prevPage`消息。在`pagehide`事件的回调函数中使用类似的逻辑。

类似地，在`pagebeforehide`和`pagehide`事件的回调函数中，获取并显示`data.toPage`（源页面）属性。最后，调用`animationComplete`插件，并在`pagebeforehide`事件处理程序中定义`anim`回调函数，如下所示。在`anim()`函数中编写代码，在两个 div 容器中显示简单的**动画完成!!!**消息。

当页面首次加载时，您可以看到以下图片，显示了`pagebeforeshow`和`pageshow`事件处理程序被调用。此时`prevPage`是未定义的。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_08_14.jpg)

点击**Page 1**按钮打开`#page`。您可以看到来自`pagebeforehide`和`pagebeforeshow`事件处理程序的消息，即**当前页**是**page**，**上一页**是**main**。然后，您可以看到来自`animationComplete()`回调的**动画完成!!!**消息。此时页面可见，并且还可以看到来自`pagehide`和`pageshow`事件的消息：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_08_15.jpg)

点击**返回**按钮。现在，`#main`被显示，消息与之前一样显示。这次，**当前页**是**main**，**上一页**是**page**：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_08_16.jpg)

## 还有更多...

第一次加载时，`pagebeforeshow`和`pageshow`事件处理程序显示一个空的`data.nextPage`对象。为了在第一次加载时显示正确的值，这两个事件必须在`mobileinit`处理程序中绑定到它们的回调函数，即在页面加载之前以及加载`jquery.mobile.js`脚本文件之前，如下面的代码片段所示：

```js
<script>
 $(document).bind("mobileinit", function() {
    $(document).bind("pagebeforeshow", function(event, data) {
    alert(data.nextPage);
  });
  $(document).bind("pageshow", function(event, data) {
    alert(data.nextPage);
  });
});
</script>
<script src="img/jquery.mobile-1.1.1.min.js"></script>
```

## 另请参阅

+   在第七章的*Configuring the default transitions*一节中，*配置*

# 使用布局事件

用户交互动态调整大小的组件，例如列表视图和可折叠块，会导致控件重叠或定位问题。为防止此情况发生，这些组件会触发`updatelayout`事件，而 jQuery Mobile 框架会更新整个文档，确保所有组件都正确布局。本文介绍如何使用`updatelayout`事件。

## 准备工作

从`code/08/layout`源文件夹中复制此配方的所有代码。您可以通过使用 URL`http://localhost:8080/08/layout/main.html`来启动此代码。

## 它是如何实现的...

执行以下步骤：

1.  使用以下代码创建 `main.html`，其中包含三个可折叠块和一个 `<div>` 容器，如下面的代码片段所示：

    ```js
    <div data-role="content">
     <div id="msgdiv">Collapsible Blocks</div>
      <div data-role="collapsible" data-theme="a" data-
        collapsed="false">
        <h3>Tallest Mountain</h3>
        Mt. Everest
      </div>
      <div data-role="collapsible" data-theme="a" data-
        collapsed="false">
        <h3>Longest River</h3>
        R. Nile
      </div>
      <div data-role="collapsible" data-theme="a" data-
        collapsed="false">
        <h3>Largest Ocean</h3>
        Pacific
      </div>
    </div>
    ```

1.  在 `<head>` 部分添加以下脚本，来处理 `updatelayout` 事件：

    ```js
    $("#main").live("pageshow", function(event, ui) {
     $("div").bind("updatelayout", function(event) {
        $("#msgdiv").html("updatelayout on : " + event.target.innerHTML);
      });
    });
    ```

## 它是如何工作的...

在 `main.html` 中，向页面内容添加一个 `id="msgdiv"` 的 `div` 容器。添加三个带有 `data-collapsed="false"` 属性的可折叠块。添加下面给出的脚本来绑定 `pageshow` 事件（在页面显示时触发），指向一个事件处理程序。在这里，把 `updatelayout` 事件绑定到一个回调函数。在这个回调函数中，使用 `event.target.innerHTML` 属性来获取触发 `updatelayout` 事件的可折叠块的文本。如所示，显示在 `msgdiv` 块中。现在，当加载页面时，这三个可折叠块都是展开的。

点击第一个块，显示 **最高的山**。你会看到它折叠，并且 `msgdiv` 文本被更新为显示 **更新布局在：珠穆朗玛峰**，如下面的截图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_08_17.jpg)

## 还有更多内容...

jQuery Mobile 框架在你在页面中添加或操作组件或切换它们的可见性的情况下，会根据大多数场景动态更新布局并调整位置。你必须在这些元素上触发 `create` 或 `refresh` 方法。但是在一些情况下，当你添加或操作控件或切换它们的可见性时，框架可能无法正确处理定位。在这种情况下，你可以触发 `updatelayout` 事件，并告诉框架更新所有组件并重新定位它们。你可以通过以下代码来实现：

```js
(yourselector).trigger("updatelayout");
```


# 第九章：方法和实用工具

本章将介绍以下食谱：

+   使用`loadPage()`加载页面

+   使用`changePage()`来更改页面

+   使用`jqmData()`和`jqmRemoveData()`

+   使用`jqmEnhanceable()`

+   使用`jqmHijackable()`

+   使用`$.mobile.base`

+   解析 URL

+   使用`$.mobile.path` 实用方法

+   使用静默滚动

# 介绍

jQuery Mobile 框架提供了许多在`$.mobile`对象上工作的方法和实用工具。 本章向您展示如何使用这些方法和实用工具。

本章所有食谱的源文件都在存档的`code/09`文件夹下。 每个食谱都在自己的子文件夹中列出，其名称相应命名。

# 使用 loadPage()加载页面

使用`$.mobile.loadPage()`方法，您可以将外部页面在后台加载到 DOM 中并增强其内容，而不影响当前页面。 本食谱向您展示如何执行此操作。

## 准备工作

从`code/09/loadpage`源文件夹中复制此食谱的完整代码。 您可以通过 URL:`http://localhost:8080/09/loadpage/main.html`来启动此代码。

## 如何进行...

1.  创建`main.html`，带有页面`id="main"`，并添加一个空的`div`标签和一个指向`#page1`的链接，如下所示：

    ```js
    <div data-role="content">
      <div id="msgdiv"></div>
      <a href="#page1" data-role="button">Show Page 1</a>
    </div>
    ```

1.  为`#main`的`pagebeforeshow`事件添加事件处理程序，并使用`loadPage()`方法加载`#page1`：

    ```js
    $("#main").live("pagebeforeshow", function(event, data) {
      $("#msgdiv").html("<p>Current Active Page : " 
        + $.mobile.activePage.attr("data-url") + "</p>");
     $.mobile.loadPage( "page1.html", {role: "dialog"});
    });
    ```

1.  为`#page1`的`pagebeforeshow`事件添加事件处理程序，以更新显示的消息：

    ```js
    $("#page1").live("pagebeforeshow", function(event, data) {
      $("#page1content").html("<p>Current Active Page : " 
     + $.mobile.activePage.attr("data-url") + "</p>");
    });
    ```

1.  最后，创建`page1.html`，如下所示：

    ```js
    <div id="page1" data-role="page" data-theme="e">
      <div data-role="header">
        <h1>Header of Page 1</h1>
      </div>
      <div id="page1content" data-role="content"></div>
    </div>
    ```

## 它是如何工作的...

创建具有`#main`页面的`main.html`，并添加一个空的`div`，其中`id="msgdiv"`和一个打开其中`#page1`链接的链接。 在`pageinit`期间，`#page1`引用尚不可用，因为它来自外部的`page1.html`文件。 在`#main`页面上添加`pagebeforeshow`事件处理程序。 在这里，使用`$.mobile.activePage()`方法获取当前活动页面，并使用 jQuery 的`attr()`方法将其`data-url`属性显示在`#msgdiv`中。 接下来，使用`$.mobile.loadPage()`调用加载`page1.html`。 同时，设置`loadPage()`选项，并将`role`属性设置为`dialog`。 页面现在在后台加载。

为`#page1`的`pagebeforeshow`事件添加事件处理程序。 获取之前完成的活动页面的`data-url`并在`#page1content` div 容器中显示它。 最后，创建一个带有`id="page1content"`的空 div 的`page1.html`页面。

当`main.html`加载时，您将看到**显示页面 1**按钮。 点击它，`page1.html`将以默认弹出过渡方式显示为对话框。 另外，活动页面的数据 URL 将在这两个页面中正确显示。

## 还有更多...

`$.mobile.loadPage()`返回一个延迟的`promise`对象，一旦页面被增强并加载到 DOM 中，它就会自动解决。

### loadPage()选项

`loadPage()`方法将一个可选的`options`对象作为第二个参数。 可在`options`对象上设置以下属性：

+   `data`：这是 Ajax 页面请求的数据

+   `loadMsgDelay`（默认为 50 秒）：这是显示页面加载消息之前的延迟时间

+   `pageContainer`：这是包含加载页面的元素

+   `reloadPage`（默认为 `false`）：这将强制重新加载页面

+   `role`：这是页面加载的 `data-role` 值

+   `showLoadMsg`（默认为 `false`）：这决定是否显示页面加载消息

+   `type`（默认为 `get`）：这指定了 Ajax 请求的类型（`get` 或 `post`）

## 另请参阅

+   *使用 changePage() 更改页面* 小节

+   在第八章的 *Events* 中的 *使用页面加载和删除事件* 小节

# 使用 changePage() 更改页面

此小节向您展示如何使用 `$.mobile.changePage()` 方法使用 JavaScript 从一个页面切换到另一个页面。此小节扩展了第六章的 *使用分割按钮列表* 小节，*列表视图*，并在新页面中显示所选列表项中的图像。

## 准备工作

从 `code/09/changepage` 源文件夹中复制此小节的完整代码。还要重新查看第六章的 *使用分割按钮列表* 小节。您可以通过以下 URL 启动此代码：`http://localhost:8080/09/changepage/main.html`。

## 如何做...

1.  创建 `main.html`，其中包含一个分割按钮列表，`<img>` 标签的 `href` 属性具有一个 `file` 参数，在左按钮中有图像文件的路径，如下所示：

    ```js
    <div data-role="content">
      <ul data-role="listview" data-inset="true" 
        data-theme="b" data-split-theme="e" 
        data-split-icon="arrow-d">
        <li>
     <a href="#viewphoto&file=img1.png">
            <img style="margin: 10px" 
              src="img/img1.png" />
              <h3>Lal Bagh</h3>
          </a>
          <a href='#' data-rel='dialog'>Download</a>
        </li>
        <li>
     <a href="#viewphoto&file=img2.png">
            <img style="margin: 10px" 
              src="img/img2.png" />
              <h3>Peacock</h3>
          </a>
          <a href='#' data-rel='dialog'>Download</a>
        </li>
        <li>
     <a href="#viewphoto&file=img3.png">
            <img style="margin: 10px"  
              src="img/img3.png"
              height=75% />
              <h3>Ganesha</h3>
          </a>
          <a href='#' data-rel='dialog'>Download</a>
        </li>
      </ul>
    </div>
    ```

1.  添加 `#viewphoto` 页面，并在点击分割按钮的左部时打开它：

    ```js
    <div id="viewphoto" data-role="page" data-theme="e" data-add-back-btn="true">
    ….....
      <div data-role="content">
        <div id="imgid">
        <p>Displaying Image ...</p>
        </div>
      </div>
    </div>
    ```

1.  在 `<head>` 部分添加以下脚本，并在 `pagebeforechange` 事件处理程序中调用 `$.mobile.changePage()`：

    ```js
    $(document).live( "pagebeforechange", function( e, data ) {
      if ( typeof data.toPage === "string" ) {
        var u = $.mobile.path.parseUrl( data.toPage );
        var re = /^#viewphoto&file/;
        if ( u.hash.search(re) !== -1 ) {
     $.mobile.changePage("main.html#viewphoto",
          {
            transition: "pop",
            dataUrl: u.hash.split("=")[1],
            type: "get"
          });
     e.preventDefault();
        }
      }
    });
    ```

1.  在 `#viewphoto` 页面的 `pagebeforeshow` 事件处理程序中显示图像：

    ```js
    $("#viewphoto").live( "pagebeforeshow", function( e, data ) {
      var u = $.mobile.path.parseUrl( document.location.href );
      var re = /^#img/;
      if ( u.hash.search(re) !== -1 ) {
        var str="<img src='../../images/" + u.hash.substr(1) + "' />";
        $("#imgid").html(str).trigger("refresh");
      }
    });
    ```

## 它是如何工作的...

在 `main.html` 中添加分割按钮列表和 `#viewphoto` 页面，如代码所示。在 `#viewphoto` 页面的 `div` 标签中添加一个空的 `#imgid` 属性，以显示完整的图像。分割按钮列表和 `#viewphoto` 页面的代码已在第六章中解释过。右按钮的 `href` 属性只是指向 `#`，因为在此小节中未使用。将左按钮中列表项的 `href` 属性更改为包括文件参数；例如，`href="#viewphoto&file=img1.png"`。启动应用程序时，将显示如下屏幕，其中显示了缩略图，如分割按钮列表所示。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_09_01.jpg)

但是，当你点击分割列表按钮时，没有任何反应，因为框架不理解带有 `href` 属性的文件参数。要打开并显示图像，您将需要手动处理页面更改。要手动调用 `pageChange()`，请为 `pagebeforechange` 事件添加事件处理程序。在这里，检查目标页面（`data.toPage`）是否是 URL 字符串，并使用 `$.mobile.path.parseUrl()` 方法获取 URL 组件。现在，使用正则表达式搜索 URL 哈希中的文件参数 — `#viewphoto&file`。如果找到，则是查看图像的请求。现在，你必须处理页面更改。

调用 `pageChange()` 方法并传递 `main.html#viewphoto` URL。另外，用自定义值设置 `options` 参数的`transition`、`type` 和 `dataUrl`。你可以按照示例将文件名信息存储在 `dataUrl` 中，通过分割 URL 哈希来实现。最后，防止默认的 `pagebeforechange` 事件处理，因为你已经在这里处理页面更改。

接下来，您将需要查询提供给 `pageChange()` 的 URL 字符串，以获取 `file` 参数，并显示图像。要做到这一点，请为 `#viewphoto` 页面的 `pagebeforeshow` 事件添加事件处理程序。使用 `$.mobile.path.parseUrl()` 方法获取 URL 组件。搜索 `img` 表达式；如果找到，从 URL 哈希中获取文件名，并在代码中显示在 `#imgid` div 容器中。现在，如果你点击任何列表项，相应的图像将在 `#viewphoto` 页面中以较大尺寸显示，如下面的截图所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_09_02.jpg)

## 还有更多...

`$.mobile.changePage()` 方法在页面更改期间内部使用 `$.mobile.loadPage()` 方法来获取新页面。

### changePage() 选项

`changePage()` 方法接受可选的 `options` 对象作为第二个参数。可以在 `options` 对象上设置以下属性：

+   `allowSamePageTransition`（默认为`false`）：默认情况下忽略对当前活动页面的转换，但可以通过使用 `allowSamePageTransition` 选项启用

+   `changeHash`（默认为`true`）：这会更新位置栏中的哈希

+   `data`：这是 Ajax 页面请求的数据

+   `dataUrl`：这是页面更改后更新浏览器位置的 URL

+   `pageContainer`：这是包含加载的页面的元素

+   `reloadPage`（默认为`false`）：这会强制重新加载页面

+   `reverse`（默认为`false`）：这是页面显示过渡方向

+   `role`：为页面显示提供 `data-role` 值

+   `showLoadMsg`（默认为`false`）：决定是否显示页面加载消息

+   `transition`：这是用于页面更改的过渡效果

+   `type`（默认为`get`）：指定 Ajax 请求的类型（`get` 或 `post`）

## 另请参见

+   使用 `loadPage()` 加载页面 和 解析 URL 的示例

+   第六章 *列表视图*下的*使用分隔按钮列表*示例

+   第八章 *事件*下的*使用页面加载和移除事件*示例

# 使用 jqmData()和 jqmRemoveData()

`jqmData()`和`jqmRemoveData()`方法可用于向 jQuery 移动应用程序的元素添加或移除数据属性。它们会自动处理自定义命名空间。本节介绍了如何使用这些方法。

## 准备就绪

从`code/09/jqmdata`源文件夹复制此示例的完整代码。你可以通过 URL 访问此代码：`http://localhost:8080/09/jqmdata/main.html`。

## 如何实现...

1.  在包含`jquery.``mobile.js`之前，将以下脚本添加到`main.html`中：

    ```js
    $(document).bind("mobileinit", function() {
     $.mobile.ns = "my-";
    });
    ```

1.  在页面中添加两个文本输入和一个按钮，如下所示：

    ```js
    <div data-my-role="content">
      <div data-role="fieldcontain">
        <label for="pgtheme">Page Theme : </label>
        <input type="text" id="pgtheme" />
      </div>
      <div data-role="fieldcontain">
        <label for="customdata">Custom Data : </label>
        <input type="text" id="customdata" />
      </div>
      <button id="clearbtn">Clear Custom Data</button>
    </div>
    ```

1.  将以下脚本添加到`<head>`部分以调用`jqmData()`和`jqmRemoveData(``)`方法：

    ```js
    $("#main").live("pageinit", function(event) {
     var pg = $("div:jqmData(role='page')");
     pg.jqmData("custom", "Custom data text");
       $("#pgtheme").attr("value", pg.jqmData("theme"));
       $("#customdata").attr("value", pg.jqmData("custom"));
       $("#clearbtn").bind("click", function(event, ui) {
     pg.jqmRemoveData("custom");
     $("#customdata").attr("value", 
     ""+pg.jqmData("custom")); 
       });
    });
    ```

## 工作原理...

在`main.html`中，在包含对`jquery.mobile.js`的引用之前，为`mobileinit`事件添加事件处理程序。这会在应用程序启动时调用。在这里，设置`$.mobile.ns="my-"`命名空间配置。

添加两个文本输入，分别为`id="pgtheme"`和`id="customdata"`，用于显示页面主题和自定义数据。添加一个`id="clearbtn"`的按钮。接下来，将`pageinit`事件绑定到回调函数。在此函数中，使用`div:jqmData(role='page')`自定义选择器获取`page`元素。使用`jqmData()`确保自动处理带有自定义命名空间的数据属性（`data-my-role`）的查找。

使用`jqmData()`方法在页面上设置值为**自定义数据文本**的**自定义数据**属性，如下截图所示。最后，在两个文本输入框中显示**页面主题**和**自定义数据**属性。页面显示如下：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_09_03.jpg)

接下来，为`#clearbtn`添加一个`click`事件处理程序，使用`jqmRemoveData()`方法移除页面上设置的自定义数据属性，并更新**自定义数据**文本字段的值。现在，当你点击**清除自定义数据**按钮时，文本框将显示**未定义**。

## 更多信息...

jQuery 方法`data()`、`hasData()`和`removeData()`不考虑`data-`属性的命名空间。你将需要编写自定义代码来处理它。相反，使用本节中所示的`jqmData()`和`jqmRemoveData()`方法。你可以使用 DOM 检查器来检查代码，以验证对自定义命名空间的使用。

## 另请参阅

+   第七章 *配置*下的*配置默认命名空间*示例

# 使用 jqmEnhanceable()

当在父元素上设置了`data-enhance="false"`时，它会被所有子元素继承。为了搜索可以使用手动增强或用于自定义插件编写的元素，jQuery Mobile 框架提供了一个名为`jqmEnhanceable()`的过滤方法。本配方向您展示如何使用它。

## 准备工作

从`code/09/jqmenhance`源文件夹复制此配方的完整代码。你可以使用 URL `http://localhost:8080/09/jqmenhance/main.html`来启动此代码。

## 怎么做...

1.  在包含`j``query.mobile.js`之前，将以下脚本添加到`main.html`中：

    ```js
    $(document).bind("mobileinit", function() {
     $.mobile.ignoreContentEnabled = true; 
    });
    ```

1.  如所示，在页面中添加两个锚按钮。第二个按钮位于一个具有`data-enhance="false"`的`div`标签内。

    ```js
    <div data-role="content">
      <div>
        <a href="#">Link 1</a>
      </div>
     <div data-enhance="false">
        <a href="#">Link 2</a>
      </div>
    </div>
    ```

1.  在`<head>`部分添加以下脚本来调用`jqmEnha``nceable()`方法：

    ```js
    $("#main").live("pagecreate", function(event) {
     $("a").jqmEnhanceable().attr("data-role", "button");
    });
    ```

## 它的工作原理...

在`main.html`中，在包含对`jquery.mobile.js`的引用之前为`mobileinit`事件添加一个事件处理程序，该事件在应用程序启动时被调用。设置`$.mobile.ignoreContentEnabled=true`配置。

在`#main`的内容中添加两个`div`标签。将一个`#`链接添加到这两个`div`标签中。不要在任何一个链接上设置`data-role="button"`属性。第二个`div`标签设置了`data-enhance="false"`属性。接下来，将`pagecreate`事件绑定到事件处理程序上。此时，页面已经被`initialized`，但是小部件还没有被增强。现在按照所示在锚元素上调用`jqmEnhanceable()`方法。此方法会过滤并提供仅仅不从父级继承`data-enhance="false"`的那些锚元素。所以在代码中，`Link 1`被提供了。使用 jQuery 的`attr()`调用将其`data-role`属性设置为`button`，如代码所示。

现在，当你打开应用程序时，只有**Link 1**被增强为按钮，而**Link 2**没有被增强，如下截图所示：

![它的工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_09_04.jpg)

## 更多内容...

当设置了`$.mobile.ignoreContentEnabled=true`配置时，`jqmEnhanceable()`方法才能工作。将访问每个元素的父节点并检查`data-enhance`值，任何设置为`false`的父节点都将被从过滤集中移除。

### 注意

即使对一小组元素使用`jqmEnhanceable()`也很耗费资源，因为所有父元素都会被检查`data-enhance`的值。

## 参见

+   *使用 jqmHijackable()* 配方

# 使用 jqmHijackable

当在父元素上设置`data-ajax="false"`时，这会被所有子元素继承。有一个名为`jqmHijackable()`的过滤方法可用于搜索可以使用自定义表单和链接绑定的子元素。本配方向您展示如何使用此方法。

## 准备工作

从`code/09/jqmhijack`源文件夹复制此配方的完整代码。你可以使用 URL: `http://localhost:8080/09/jqmhijack/main.html`来启动此代码。

## 怎么做...

1.  在包含`jquery.mobile.js`之前，将以下脚本添加到`main.html`中：

    ```js
    $(document).bind("mobileinit", function() {
      $.mobile.ignoreContentEnabled = true;   
    });
    ```

1.  向页面添加两个锚按钮，如下所示。第二个按钮位于具有`data-ajax="false"`属性的`div`标签内：

    ```js
    <div data-role="content">
      <div>
        <a href="page1.html" data-role="button">Link 1</a>
      </div>
     <div data-ajax="false">
        <a href="page1.html" data-role="button">Link 2</a>
      </div>
    </div>
    ```

1.  将以下脚本添加到`<head>`部分以调用`jqmHijackable()`方法：

    ```js
    $("#main").live("pageinit", function(event) {
     $("a").jqmHijackable().each(function() {
        $(this).attr("data-transition", "flip");
      });
    });
    ```

1.  最后，按下面的代码片段创建`page1.html`：

    ```js
    <div id="page1" data-role="page" data-theme="e">
    ….....
      <div data-role="content">
        <p>Page 1 Content</p>
     <a href="main.html" data-direction="reverse" data-ajax="false"
          data-role="button">Go Back</a>
      </div>
    </div>
    ```

## 它是如何工作的...

在`main.html`中，在包含对`jquery.mobile.js`的引用之前，为`mobileinit`事件添加一个事件处理程序。这在应用程序开始时被调用。设置`$.mobile.ignoreContentEnabled=true`配置。

在`#main`的内容中添加两个`div`标签。在这些`div`标签中都添加一个链接到外部的`page1.html`文件。第二个`div`标签设置了`data-ajax="false"`属性。接下来，将`pageinit`事件绑定到事件处理程序，并在锚元素上调用`jqmHijackable()`方法，如代码所示。这将筛选并提供那些没有继承自父元素的`data-ajax="false"`的锚元素。所以，代码中，`Link 1`被使可用。使用 jQuery 的`attr()`调用，将其`data-transition`属性设置为`flip`，如代码所示。最后，创建`page1.html`，并在**Go Back**链接返回到`#main`页面。

现在，当您点击**Link 1**时，`page1.html`将以翻转转场打开。但是，如果您点击**Link 2**，`page1.html`将以无翻转打开。

## 还有更多...

在该教程中，**Link 2**使用`data-ajax="false"`打开`page1.html`。这将从 DOM 中清除`main.html`。返回到`main.html`将把`main.html`重新加载到 DOM 中，但不会触发`mobileinit`事件。这将导致**Link 1**在打开`page1.html`时不使用翻转转场。为了解决这个问题，在`page1.html`中添加`data-ajax="false"`属性以返回链接。这将重新加载`main.html`到全新的 DOM 中，并触发`mobileinit`事件。现在，通过两个链接从`main.html`到`page1.html`的移动可以顺利进行任意次数。

### $.mobile.ignoreContentEnabled 配置

当设置`$.mobile.ignoreContentEnabled=true`配置时，`jqmHijackable()`方法只能工作。访问每个元素的父节点并检查`data-ajax`值，任何具有`false`设置的父节点及其子元素将从过滤集中删除。

### 注意

即使对一小部分元素使用`jqmHijackable()`也很昂贵，因为要检查所有父元素的`data-ajax`值。

## 参见

+   *使用 jqmEnhanceable()*教程

# 使用$.mobile.base

`$.mobile.base`对象提供对原始文档基础的引用。可以使用`set()`方法在基础对象上设置自定义值。可以使用`reset()`方法恢复原始值。本教程展示了如何使用这些实用方法。

## 准备工作

从`code/09/base`源文件夹中复制此教程的完整代码。可以通过以下网址启动此代码：`http://localhost:8080/09/base/main.html`。

## 如何做...

1.  使用以下代码片段在`main.html`中创建两个按钮：

    ```js
    <div id="content" data-role="content">
      <div id="dispdiv"></div>
      <button id="changebtn">Set Document Base</button>
      <button id="resetbtn">Reset Document Base</button>
    </div>
    ```

1.  添加以下脚本以显示文档基础对象的各个值：

    ```js
    function disp() {
     var str = "<p>Original Document Base: " + $.mobile.getDocumentBase()
        + "</p>" + "<p>Document Base set to : " 
        + $.mobile.base.element.attr("href");
      $("#dispdiv").html(str);
    }
    ```

1.  在`pageinit`事件处理程序中调用`$.mobile.base`实用方法：

    ```js
    $("#main").live("pageinit", function(event) {
      disp();
      $("#changebtn").bind("click", function(event, ui) {
     $.mobile.base.set("http://localhost:8080/");
        disp();
      });
      $("#resetbtn").bind("click", function(event, ui) {
     $.mobile.base.reset();
        disp();
      });
    });
    ```

## 它是如何工作的...

在`main.html`中添加一个空的`div`标签，`id="dispdiv"`，并添加两个按钮(`#changebtn`和`#resetbtn`)，如所示。添加一个`disp()`函数来显示`#dispdiv` div 容器中的当前文档基础和原始文档基础值。您可以使用`$.mobile.getDocumentBase()`方法获取原始文档基础。在`pageinit`事件上调用`disp()`函数。首次加载时，基础值显示如下：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_09_05.jpg)

现在，将`#changebtn`的点击事件绑定到事件处理程序，并使用`$.mobile.base.set()`方法将文档基础设置为自定义值。现在单击**设置文档基础**按钮，自定义基础值将显示，如以下截图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_09_06.jpg)

将`#resetbtn`绑定到事件处理程序，并通过调用`$.mobile.base.reset()`方法重置文档基础。单击**重置文档基础**按钮，您将看到基础值已恢复。

# 解析 URL

`$.mobile.path`对象提供了您可以使用的属性和方法来处理 URL。本配方向您展示了如何使用`$.mobile.path.parseUrl()`方法获取 URL 的各个组件。

## 准备工作

从`code/09/parseurl`源文件夹复制此配方的完整代码。您可以使用以下 URL 启动此代码：`http://localhost:8080/09/parseurl/main.html`。

## 怎么做...

1.  使用空的`div`标签和一个锚链接创建`main.html`，如下面的代码片段所示：

    ```js
    <div data-role="content">
      <div id="msgdiv"></div>
     <a href="http://user:pwd@localhost:8080/09/main.html?img=img1.png#imgview"
        data-role="button">Link 1</a>
    </div>
    ```

1.  将以下脚本添加到`<head>`部分以在单击时获取锚点按钮的 URL：

    ```js
    $("#main").live("pageinit", function(event) {
     dispPath($.mobile.getDocumentUrl());
      $("a").bind("click", function(event, ui) {
        dispPath($(this).attr("href"));
        event.preventDefault();
        event.stopPropagation();
      });
    ```

1.  添加以下方法以显示 URL 的各个组件：

    ```js
      function dispPath(urlstr) {
     var urlcomp = $.mobile.path.parseUrl(urlstr);
        var str = "<p>href: " + urlcomp.href + "</p>"
          + "<p>hrefNoHash: " + urlcomp.hrefNoHash + "</p>"
          + "<p>hrefNoSearch: " + urlcomp.hrefNoSearch + "</p>"
          + "<p>domain: " + urlcomp.domain + "</p>"
          + "<p>protocol: " + urlcomp.protocol + "</p>"
          + "<p>authority: " + urlcomp.authority + "</p>"
          + "<p>username: " + urlcomp.username + "</p>"
          + "<p>password: " + urlcomp.password + "</p>"
          + "<p>host: " + urlcomp.host + "</p>"
          + "<p>hostname: " + urlcomp.hostname + "</p>"
          + "<p>port: " + urlcomp.port + "</p>"
          + "<p>pathname: " + urlcomp.pathname + "</p>"
          + "<p>directory: " + urlcomp.directory + "</p>"
          + "<p>filename: " + urlcomp.filename + "</p>"
          + "<p>hash: " + urlcomp.hash + "</p>"
          + "<p>search: " + urlcomp.search + "</p>";
        $("#msgdiv").html(str);
      }
    });
    ```

## 它是如何工作的...

向`main.html`添加一个空的`div`标签，`id="msgdiv"`。添加一个带有复杂`href`字符串的链接，如代码所示。创建一个`dispPath`函数，接受一个 URL 字符串。在这里，调用`$.mobile.path.parseUrl`方法来获取包含 URL 各个组件的对象(`#urlcomp`)。在`#msgdiv` div 容器中显示这些 URL 组件。当应用程序首次加载时，在`pageinit`事件处理程序中调用`dispPath()`方法，并将其传递给文档 URL 参数`got`，通过调用`$.mobile.getDocumentUrl()`方法。首次加载时显示以下截图：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_09_07.jpg)

接下来，为锚链接的`click`事件添加一个事件处理程序。调用`dispPath()`函数，并将`href`属性作为参数传递给它。通过在锚对象上调用 jQuery 的`attr("href")`方法来获取`href`属性。最后，调用`event.preventDefault()`和`event.stopPropagation()`方法来阻止点击事件的默认操作。现在，当你点击**Link 1**时，复杂`href`属性的 URL 组件将显示如下：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_09_08.jpg)

## 还有更多...

`$.mobile.parseUrl()`方法返回一个包含各种 URL 组件的字符串值的对象，如下所示；当特定的 URL 组件未被使用时，存储空字符串：

+   `href`：这是被解析的原始 URL

+   `hrefNoHash`：这是没有哈希组件的`href`属性

+   `hrefNoSearch`：这是没有查询字符串和哈希的`href`属性

+   `domain`：这包含协议和主机部分

+   `protocol`：这是协议（包括`:`字符）

+   `authority`：这包含用户名、密码和主机部分

+   `username`：这是用户名

+   `password`：这是密码

+   `host`：这是主机和端口

+   `hostname`：这是主机名

+   `port`：这是端口（如果协议使用其默认端口，则可能为空）

+   `pathname`：这是所引用文件或目录的路径

+   `directory`：这是不带文件名的路径名的目录部分

+   `filename`：这是不带目录的路径名的文件名部分

+   `hash`：这是哈希组件（包括`#`字符）

+   `search`：这是查询组件（包括`?`字符）

## 另请参阅

+   *使用$.mobile.path 实用方法*教程

# 使用`$.mobile.path`实用方法

本教程向你展示如何在你的应用程序中使用`$.mobile.path`对象提供的实用方法。

## 准备工作

从`code/09/path`源文件夹中复制本教程的完整代码。你可以使用 URL`http://localhost:8080/09/path/main.html`来启动此代码。

## 如何操作...

1.  使用以下代码片段在`main.html`页面上创建四个锚链接：

    ```js
    <div data-role="content">
      <div id="msgdiv"></div>
      <a href="http://localhost:8080/09/base/main.html"
        data-role="button">
        1: http://localhost:8080/09/base/main.html
      </a>
      <a href="http://localhost:8080/09/base/" data-
        role="button">
        2: http://localhost:8080/09/base/
      </a>
      <a href="page1.html" data-role="button">
        3: page1.html
      </a>
      <a href="../" data-role="button">4: ../</a>
    </div>
    ```

1.  在`<head>`部分添加以下脚本以获取点击链接的 URL。

    ```js
    $("#main").live("pageinit", function(event) {
     var docurl = $.mobile.getDocumentUrl();
      $("a").bind("click", function(event, ui) {
        dispPath($(this).attr("href"));
        event.preventDefault();
        event.stopPropagation();
      });
    ```

1.  添加`disppath()`函数以显示`$.mobile.path`实用方法的输出：

    ```js
    function dispPath(urlstr) {
      var urlcomp = $.mobile.path.parseUrl(urlstr);
      var str = "<p>Base: " + docurl + "</p>" 
        + "<p>Page: " + urlcomp.href + "</p>"
        + "<p>Same Domain: " + $.mobile.path.isSameDomain(
        docurl, urlcomp) + "</p>"
        + "<p>is Absolute: "
        + $.mobile.path.isAbsoluteUrl(urlcomp) + "</p>"
        + "<p>is Relative: "
        + $.mobile.path.isRelativeUrl(urlcomp) + "</p>";
     if ($.mobile.path.isRelativeUrl(urlcomp)) {
          str += "<p>Make Absolute Path: " 
              + $.mobile.path.makePathAbsolute(urlcomp.href, 
                $.mobile.path.parseUrl(docurl).pathname) + "</p>"
              + "<p>Make Absolute Url: " 
              + $.mobile.path.makeUrlAbsolute(urlcomp.href, 
              docurl) + "</p>"
        }
        $("#msgdiv").html(str);
      }
    });
    ```

## 工作原理...

在`main.html`中添加一个带有`id="msgdiv"`的空 div 标签。添加四个不同 URL 的链接，如代码所示。在`<head>`部分添加脚本，以在`pageinit`事件处理程序中使用`$.mobile.getDocumentUrl()`方法获取页面的原始文档 URL（`#docurl`）。使用此 URL 作为本教程中的比较参考点。

接下来，为四个锚链接的`click`事件添加事件处理程序。调用`dispPath()`函数，并将`link`的 href 属性作为参数传递给它。你可以通过调用锚对象上的 jQuery`attr("href")`方法来获取`href`属性。还要在此事件处理程序中调用`event.preventDefault()`和`event.stopPropagation()`方法，以防止`click`事件上的任何进一步操作。

在`dispPath`函数中，调用`$.mobile.path.parseUrl`方法来获取传入 URL 的`href`组件。现在，调用各种`$.mobile.path`实用方法，并在代码中显示它们的输出在`#msgdiv` div 容器中。使用`isRelativeUrl()`方法检查传入的 URL 是否是相对的。使用`makePathAbsolute()`和`makeUrlAbsolute()`方法将其转换为绝对值。原始文档 URL 用作这些转换的参考。

页面加载时，你将看到四个链接按钮。点击第一个链接`http://localhost:8080/09/path/main.html`，将显示类似以下截图的输出。该 URL 与参考 URL 处于同一域中，并且该 URL 也是绝对的。

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_09_09.jpg)

第二个链接，`http://localhost:8080/09/base/`，指向一个文件夹。见下输出；域名相同且 URL 为绝对： 

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_09_10.jpg)

第三个链接，`page1.html`，是一个相对 URL。使用参考 URL 计算并显示绝对路径和绝对 URL，如下截图所示；这里的**Same Domain**值为**false**。

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_09_11.jpg)

最后一个链接指向父目录，`../`，再次是一个相对 URL。使用参考 URL 计算绝对路径和 URL，并如下截图所示显示；**Same Domain**值再次为**false**：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_09_12.jpg)

## 还有更多...

此配方中使用的`$.mobile.path`实用方法如下：

+   `isAbsoluteUrl`：检查给定的 URL 是否为绝对

+   `isRelativeUrl`：检查给定的 URL 是否为相对的

+   `makePathAbsolute`：将相对路径转换为绝对路径；该方法使用参考路径参数进行转换

+   `makeUrlAbsolute`：将相对 URL 转换为绝对 URL；该方法使用参考 URL 参数进行转换

+   `isSameDomain`：检查两个 URL 是否属于同一个域

## 另请参阅

+   *解析 URL*配方

# 使用静默滚动

你可以使用`$.mobile.silentScroll`方法滚动到页面上的任何垂直位置，而不触发滚动事件监听器。此配方向你展示了如何使用静默滚动。

## 准备工作

从`code/09/silentscroll`源文件夹中复制此配方的完整代码。你可以使用 URL`http://localhost:8080/09/silentscroll/main.html`启动此代码。

## 如何做...

1.  创建带有空的 `div` 标签和两个按钮的 `main.html`，这些按钮将用于滚动到页面的顶部和底部：

    ```js
    <div data-role="content">
      <button id="bottombtn">Page Bottom</button>
      <div id="dispdiv"></div>
      <button id="topbtn">Page Top</button>
    </div>
    ```

1.  在 `<head>` 部分添加以下脚本以创建一个长度较长的页面：

    ```js
    $("#main").live("pageinit", function(event) {
      var str="";
      for (var i=0; i<100; i++) {
        str += i + "<br/>";
      }
      $("#dispdiv").html(str);
    ```

1.  现在，根据点击的按钮，滚动到页面的顶部或底部：

    ```js
      $("#topbtn").bind("click", function(event, ui) {
     $.mobile.silentScroll($.mobile.defaultHomeScroll); 
      });
      $("#bottombtn").bind("click", function(event, ui) {
     $.mobile.silentScroll(2000);
      });
    });
    ```

## 它的工作原理...

将两个 ID 分别为 `bottombtn` 和 `topbtn` 的按钮添加到 `main.html`。创建一个空的带有 `id="dispdiv"` 的 `div` 标签，并用一些长度较长的内容填充它。这里，使用 `pageinit` 事件上的脚本在循环中添加 100 行文本到 `#dispdiv`。页面最初显示如下：

![它的工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_09_13.jpg)

将 `#bottombtn` 按钮的 `click` 事件绑定到调用 `$.mobile.silentScroll`，并将一个大值（此处为 2000px）作为 Y 参数。现在，当您点击 **页面底部** 按钮时，页面将滚动到 Y 位置（2000px），该位置位于文档底部，如下面的屏幕截图所示：

![它的工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_09_14.jpg)

接下来，绑定 `#topbtn` 按钮的 `click` 事件，并将 `$.mobile.defaultHomeScroll` 属性作为参数传递给 `$.mobile.silentScroll`。现在，点击 **页面顶部** 按钮，页面将滚动回顶部。

## 还有更多...

`silentScroll` 方法不会触发滚动事件监听器。添加以下代码以验证点击任何按钮时不显示警报。但是使用滚动条时会显示警报。

```js
$(window).bind("scrollstop", function(event) {
  alert("Scroll event was fired");
});
```

### `$.mobile.defaultHomeScroll` 属性

此示例中使用的 `$.mobile.defaultHomeScroll` 属性是 jQuery Mobile 框架内部使用的，用于滚动到页面顶部。此值是使用 `$.support.scrollTop` 属性从浏览器获取的。如果此值不为 `0`，框架会将其设置为 `0`。

## 另请参阅

+   第八章 的 *使用滚动事件* 示例，*事件*
