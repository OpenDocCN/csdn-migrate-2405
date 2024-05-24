# jQueryMobile 秘籍（二）

> 原文：[`zh.annas-archive.org/md5/55209463BC487F6190B6A043F64AEE64`](https://zh.annas-archive.org/md5/55209463BC487F6190B6A043F64AEE64)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：按钮和内容格式化

在本章中，我们将涵盖：

+   编写动态添加按钮的脚本

+   在按钮中使用自定义图标

+   添加自定义图标精灵

+   替换默认的图标精灵

+   在可折叠区域中使用替代图标

+   创建嵌套的手风琴

+   创建自定义布局网格

+   使用 XML 内容

+   使用 JSON 内容

# 介绍

在 jQuery Mobile 应用中，你可以将按钮、表单控件和列表添加为应用的页面内容。页面内容是一个带有属性`data-role="content"`的`div`容器。你可以使用框架提供的就绪样式和布局显示数据并格式化数据。你可以以**可折叠块**和**可折叠集**或**手风琴**的形式分组和显示数据。你可以使用**布局网格**在多列中显示数据。你还可以在你的应用程序中使用表格和其他 HTML 元素。

# 编写动态添加按钮的脚本

按钮是标准的 HTML 表单元素，在 jQuery Mobile 框架中通过**按钮插件**进行增强，使其易于触摸操作，并在各种移动设备上具有良好的外观。你可以使用 `<button>` 标签或 `<input>` 标签向你的应用程序中添加按钮。你也可以通过将`data-role="button"`属性添加到锚元素来将锚元素样式化为按钮。本配方向你展示了如何使用 JavaScript 动态添加按钮到页面并绑定动作到这个新添加的按钮。

## 准备工作

从`code/04/dynamic-button`源文件夹复制此配方的全部代码。你可以使用网址`http://localhost:8080/04/dynamic-button/main.html`来启动此代码。

## 如何做...

在`main.html`中，创建`#main`页面并添加一个按钮。当你点击这个按钮时，使用 JavaScript 创建第二个按钮并为其分配一个动作：

1.  在`main.html`中创建`#main`页面，并将以下代码内容添加到其中：

    ```js
    <div data-role="content">
     <input type="submit" id="addContentBtn" data-inline="true"
     value="Click to add new button"><br>
     <div id="newcontent"></div>
    </div>
    ```

1.  将以下脚本添加到处理按钮的`click`事件中。在回调函数中，创建新按钮并为其分配一个动作。

    ```js
    $("#main").live("pageinit", function(event) {
      $("#addContentBtn").bind("click", function(event, ui) {
        var str="<a href='#page2' data-role='button' data-inline='true'>"
               +"Disable 1st button and Go to Page 2</a>";
     $("#newcontent").html(str).trigger("create")
     .bind("click", function(event, ui) {
          $("#addContentBtn").button("disable");
        });
      });
    });
    ```

1.  根据以下代码添加`#page2`。这是一个多页面文档。当你点击动态添加的按钮时，此页面将被打开。

    ```js
    <div id="page2" data-role="page" data-add-back-btn="true">
      <div data-role="header">
        <h1>Page2 Header</h1>
      </div>
      <div data-role="content">
        <h3>This is Page 2</h3>
      </div>
    </div>
    ```

## 工作原理...

在`main.html`中创建一个带有页面`#main`的页面，并在页面内容中添加一个带有`id="addContentBtn"`的按钮。还在页面上添加一个空的`div`容器，`id="newcontent"`。当你加载这个页面时，你只会看到一个按钮，上面显示着**点击添加新按钮**的文本。

接下来添加给定的脚本。添加一个`pageinit`事件处理程序，该处理程序在页面初始化后被调用。在这里，将按钮的`click`事件绑定到一个回调函数。在回调函数中，将具有`data-role="button"`的锚链接添加到空的`"#newcontent"` div 中。由于页面已经初始化，你必须显式调用`create`方法来触发框架重新访问此链接并将其增强为按钮。现在当你点击第一个按钮时，你会看到第二个按钮，**禁用第一个按钮并转到第 2 页**，被创建并显示。在脚本中还添加代码来绑定新按钮的`click`事件到一个回调函数。在这里，调用第一个按钮的`disable`方法。

最后创建一个`id="page2"`的新页面，当你点击新按钮时会打开该页面。将`#page2`添加`data-add-back-btn="true"`以提供一个**返回**按钮，帮助导航回`#main`页面。现在当你点击第二个按钮时，动态添加的脚本会被调用，第一个按钮被禁用，并且页面导航到打开`page2`。你可以点击`page2`上的**返回**按钮回到`#main`页面。你会发现，你之前添加的动态脚本已经禁用了第一个按钮。

## 还有更多...

按钮插件还提供了`enable`、`disable`和`refresh`按钮的方法：

```js
$(buttonselector).button("enable");
$(buttonselector).button("disable");
$(buttonselector).button("refresh");

```

### 按钮选项

按钮使用`data-`属性提供许多标记选项。它们是**corners**（`data-corners`）、**icon**（`data-icon`）、**iconpos**（`data-iconpos`）、**shadow**（`data-shadow`）、**iconshadow**（`data-iconshadow`）、**inline**（`data-inline`）和**theme**（`data-theme`）。

你可以调用`buttonMarkup`方法来增强锚链接以将其作为按钮使用。以下代码行接受原生锚链接，并将按钮角色添加到它，并设置`data-icon="alert"`和`data-inline="true"`属性：

```js
$("a").buttonMarkup({ icon: "alert", inline: "true"});

```

# 在按钮中使用自定义图标

按钮可以包含文本、图标或两者兼有。图标可以在按钮内的四个方向中的一个位置。jQuery Mobile 框架提供了一组标准图标，你可以在你的应用中使用。这个示例向你展示了如何向按钮添加自定义图标以及框架提供的标准图标。

## 准备工作

从`code/04/custom-icon`源文件夹中复制这个示例的完整代码。你可以使用 URL`http://localhost:8080/04/custom-icon/main.html`启动这个代码。

## 操作方法...  

在这个示例中，使用了名为`square.png`的自定义图标：

![操作方法...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_04_01.jpg)

1.  创建一个新的样式表`jqm-icon.css`，并按照以下代码定义自定义图标样式：

    ```js
    .ui-icon-square {
      background: #fff;
      background: rgba(0,0,0,.4);
     background-image: url("../../resources/images/square.png");
    }
    @media only screen and (-webkit-min-device-pixel-ratio: 1.5),
        only screen and (min--moz-device-pixel-ratio: 1.5), 
        only screen and (min-resolution: 240dpi) {
     .ui-icon-square {
     background-image: url("../../resources/images/square-HD.png");
        background-size: 18px 18px;
      }
    }
    ```

1.  在`main.html`的`<head>`部分包含 CSS，如下所示：

    ```js
    <link rel="stylesheet" href="http://code.jquery.com/mobile/1.1.1/jquery.mobile-1.1.1.min.css" /> 
    <link rel="stylesheet" href="jqm-icon.css" />

    ```

1.  使用自定义图标与提交按钮，并使用以下不同的主题。也添加默认的`"home"`图标以进行比较。

    ```js
    <div data-role="content">
      <h3>Default Icon with text</h3>	
      <input type="submit" data-inline="true" value="Home" data-icon="home" data-theme="a"/>
      <h3>Custom Icon with text</h3>
     <input type="submit" data-inline="true" value="Square" data-icon="square" data-theme="a"/>
      <h3>Default Icon without text</h3>	
      <input type="submit" data-inline="true" data-iconpos="notext" data-icon="home" data-theme="a"/>
      <h3>Custom Icon without text</h3>
     <input type="submit" data-inline="true" data-iconpos="notext" data-icon="square" data-theme="a"/>
    </div>
    ```

## 工作原理...

创建一个 `jqm-icon.css` 样式表，并在其中添加一个新的图标类 `ui-icon-square`。指定 `background-image` 属性并将其指向要使用的图像文件。为图标指定 `background` 颜色，并为具有透明度的 **图标圆盘** 指定背景颜色，如所示。这里，前缀文本 **ui-icon** 表示按钮插件，这是一个自定义图标，并生成一个 `square` 类。现在，您可以在按钮中使用 `data-icon="square"` 属性，框架将获取并显示按钮上的 `square` 图标。

创建 `main.html`，使用 input 标签添加提交按钮，并使用 `data-icon` 属性为这些按钮设置图标。首先使用默认的 `home` 图标，然后使用新添加的自定义 `square` 图标，有时带文本，有时不带文本。为了进行详细比较，您可以添加多个按钮，使用不同的主题色板（`data-theme="a"` 到 `data-theme="e"`）。最终结果如下图所示。自定义图标看起来和默认图标一样好。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_04_02.jpg)

## 还有更多内容...

CSS 中定义的图标 `.ui-icon-square` 是标准分辨率的。今天大多数新设备都支持高清分辨率。因此，为了在高清分辨率上正常工作，您可以创建一个新的高分辨率图像，`square-HD.png`，尺寸为 36 x 36 像素。在 CSS 中使用这个图像，并在 `@media` 查询中指定此高分辨率图标应该适用的目标设备分辨率。有关 `@media` 查询的更多详细信息，请参见 [`jquerymobile.com/demos/1.1.1/docs/buttons/buttons-icons.html`](http://jquerymobile.com/demos/1.1.1/docs/buttons/buttons-icons.html)。

对于标准分辨率的自定义图标，请使用尺寸为 18 x 18 像素的图片，以 **PNG-8** 格式保存，并设置透明度为 `0.4`，背景颜色为 `#666`。现在你的图标将看起来与框架提供的默认图标类似。

### 使用 data-inline

默认情况下，按钮会拉伸以适应其容器的宽度。您可以指定属性 `data-inline="true"` 来显示按钮的紧凑模式。您还可以在同一行中相邻放置多个内联按钮。

### 使用 data-iconpos

通过使用 `data-icon="home"` 属性，按钮可以与图标图像关联。这里，`"home"` 是所使用的图标的名称。`data-iconpos` 属性可用于指定图标应显示在按钮的何处。可能的值为 `top`、`bottom`、`left` 和 `right`。使用 `data-iconpos="notext"` 属性完全隐藏文本，并调整按钮大小以仅显示图标。

### 使用阴影和按钮的圆角

按钮默认使用圆角，可以使用布尔属性`data-corners`进行控制。阴影也默认启用了按钮及其图标。这可以通过使用属性`data-shadow`和`data-iconshadow`进行控制。`data-corners`、`data-shadow`和`data-iconshadow`属性都是布尔类型的，可以取`true`或`false`值。

## 另请参阅

+   *添加自定义图标精灵*示例

+   *替换默认图标精灵*示例

# 添加自定义图标精灵

jQuery Mobile 框架使用默认的**图标精灵**并从中派生所有图标。本示例向您展示如何向默认标准图标集中添加一个自定义图标精灵，其中包含**除法**和**等于**图标，形成一个计算器的键。标准图标集已经包含**加**、**减**和**删除**（**乘**）图标。

## 准备工作

从`code/04/add-icon-sprite`源文件夹中复制此示例的完整代码。您可以使用 URL`http://localhost:8080/04/add-icon-sprite/main.html`启动此代码。

## 如何实现...

在这个示例中，下面的图像`calc-sprite.png`提供了除法和等于图标：

![如何实现...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_04_03.jpg)

1.  创建一个新的`jqm-sprite.css`样式表，并为从自定义图标精灵派生的新图标定义类`.ui-icon-divide`和`.ui-icon-equals`：

    ```js
    .ui-icon-divide, .ui-icon-equals {
      background: #fff;
      background: rgba(0,0,0,.4);
     background-image: url("../../resources/images/calc-sprite.png");
      background-repeat: no-repeat;
      -moz-border-radius: 9px;
      -webkit-border-radius: 9px;
      -o-border-radius: 9px;
      border-radius: 9px;
    }
    @media only screen and (-webkit-min-device-pixel-ratio: 1.5), 
        only screen and (min--moz-device-pixel-ratio: 1.5), 
        only screen and (min-resolution: 240dpi) {
     .ui-icon-divide, .ui-icon-equals {
     background-image: url("../../resources/images/calc-sprite- 
     HD.png");
          -moz-background-size: 36px 18px;
          -o-background-size: 36px 18px;
          -webkit-background-size: 36px 18px;
          background-size: 36px 18px;
      }
    }
    .ui-icon-divide { background-position: -0px 50%; }
    .ui-icon-equals { background-position: -18px 50%; }

    ```

1.  将 CSS 包含在`main.html`的`<head>`部分中，如以下代码所示：

    ```js
    <link rel="stylesheet" href="http://code.jquery.com/mobile/1.1.1/jquery.mobile-1.1.1.min.css" /> 
    <link rel="stylesheet" href="jqm-sprite.css" />

    ```

1.  使用从自定义图标精灵派生的新图标以及默认图标，如以下代码所示。首先显示带有文本的按钮：

    ```js
    <div data-role="content">
      <h3>Default and Custom Icons with Text</h3>
      <input type="submit" data-inline="true" value="plus" data-icon="plus" />
      <input type="submit" data-inline="true" value="minus" data-icon="minus" />
      <input type="submit" data-inline="true" value="delete" data-icon="delete" />
     <input type="submit" data-inline="true" value="divide" data-icon="divide" />
     <input type="submit" data-inline="true" value="equals" data-icon="equals" />

    ```

1.  然后，显示没有文本的按钮以进行比较：

    ```js
    <h3>Default and Custom Icons without Text</h3>
      <input type="submit" data-inline="true" data-iconpos="notext" data-icon="plus" />
      <input type="submit" data-inline="true" data-iconpos="notext" data-icon="minus" />
      <input type="submit" data-inline="true" data-iconpos="notext" data-icon="delete" />
     <input type="submit" data-inline="true" data-iconpos="notext" data-icon="divide" />
     <input type="submit" data-inline="true" data-iconpos="notext" data-icon="equals" />
    </div>
    ```

## 工作原理...

创建一个样式表`jqm-sprite.css`，并在其中添加新的图标类`.ui-icon-divide`和`.ui-icon-equals`。指定`background-image`属性并将其指向要用作图标精灵的图像文件。接下来指定图标和**图标圆盘**的`background`颜色，并指定透明度，如所示。还为图标指定`border-radius`为`9px`。添加供应商前缀以确保它在各种浏览器平台上工作。最后，在 CSS 文件的最后两行中定义每个新图标在图标精灵中的位置。添加`@media`查询以指定图标应在其中工作的目标设备分辨率；这在本章早期的*在按钮中使用自定义图标*示例中已经解释过了。

这里，前缀文本**ui-icon**指示按钮插件这些是自定义图标，这将生成相应的类，不带前缀文本。现在，您可以使用属性`data-icon="divide"`或`data-icon="equals"`在按钮上使用新图标，框架将获取并显示正确的自定义图标。

在`main.html`中，通过添加使用输入标签的提交按钮创建一个简单计算器的按钮。使用`data-icon`属性设置这些按钮的图标，如下所示。为了比较，显示有文本和无文本的按钮。这里，**加**，**减**和**删除**图标来自默认图标精灵。自定义图标精灵贡献了**除以**和**等于**图标。屏幕显示如下图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_04_04.jpg)

## 还有更多...

为了创建一个图标精灵，使用高度为`18px`的 PNG 图像。总宽度是图标精灵中图标数量乘以`18px`的倍数。默认图标精灵使用`0.4`的 alpha 值和`#666`的背景颜色。为了与默认图标保持一致的外观，使用相同的设置来创建您的自定义图标精灵。将图像保存为带有 alpha 透明度的**PNG-8**格式。

### 指定无效的图标名称

在代码中，如果指定一个无效的图标名称，比如`data-icon="random"`，框架会在文本前面添加`.ui-icon-`并尝试在样式表中查找该类。如果这不能解析为有效的图标，则框架现在会从默认图标精灵中选择第一个图标并显示出来。默认精灵中的第一个图标是`plus`图标，并且在无法解析图标名称的所有位置都使用它。

## 另请参阅

+   *替换默认图标精灵*配方

+   *在按钮中使用自定义图标*配方

# 替换默认图标精灵

本配方向您展示了如何替换 jQuery Mobile 提供的默认图标精灵并使用您自己的图标精灵。此处使用的自定义图标精灵包含形成骰子六个面的图标。

## 准备工作

从`code/04/replace-icon-sprite`源文件夹中复制此配方的完整代码。您可以使用 URL `http://localhost:8080/04/replace-icon-sprite/main.html`启动此代码。

## 如何操作...

在这个配方中，下面的图像，`dice.png`是一个包含六个骰子面图标的图标精灵。这个图标精灵用于替换默认图标精灵。

![如何操作...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_04_05.jpg)

1.  创建一个新的样式表`jqm-sprite.css`，并重新定义 jQuery Mobile 框架中可用的默认`.ui-icon`类。将默认图标类替换为从自定义图标精灵派生的新类，如下所示的代码所示：

    ```js
    .ui-icon {
      background: #fff;
      background: rgba(0,0,0,.4);
     background-image: url("../../resources/images/dice.png");
      background-repeat: no-repeat;
      -moz-border-radius: 9px;
      -webkit-border-radius: 9px;
      -o-border-radius: 9px;
      border-radius: 9px;
    }
    @media only screen and (-webkit-min-device-pixel-ratio: 1.5), 
      only screen and (min--moz-device-pixel-ratio: 1.5), 
      only screen and (min-resolution: 240dpi) {
     .ui-icon-one, .ui-icon-two, .ui-icon-three, .ui-icon-four, .ui-icon-five, .ui-icon-six {
     background-image: url("../../resources/images/dice-HD.png");
          -moz-background-size: 108px 18px;
          -o-background-size: 108px 18px;
          -webkit-background-size: 108px 18px;
          background-size: 108px 18px;
      }
    }
    .ui-icon-one { background-position: -0px 50%; }
    .ui-icon-two { background-position: -18px 50%; }
    .ui-icon-three { background-position: -36px 50%; }
    .ui-icon-four { background-position: -54px 50%; }
    .ui-icon-five{ background-position: -72px 50%; }
    .ui-icon-six{ background-position: -90px 50%; }

    ```

1.  在`main.html`的`<head>`部分包含 CSS，如下所示的代码：

    ```js
    <link rel="stylesheet" href="http://code.jquery.com/mobile/1.1.1/jquery.mobile-1.1.1.min.css" /> 
    <link rel="stylesheet" href="jqm-sprite.css" />

    ```

1.  使用替换的图标精灵派生的新图标来显示骰子的六个面，如下所示的代码。显示带文本的按钮：

    ```js
    <div data-role="content">
      <input type="submit" data-inline="true" value="one" data-icon="one" />
      <input type="submit" data-inline="true" value="two" data-icon="two" />
      <input type="submit" data-inline="true" value="three" data-icon="three" />
      <input type="submit" data-inline="true" value="four" data-icon="four" />
      <input type="submit" data-inline="true" value="five" data-icon="five" />
      <input type="submit" data-inline="true" value="six" data-icon="six" />
    ```

1.  然后显示无文本的按钮以进行比较：

    ```js
    <h3>This is how they look without Text</h3>
      <input type="submit" data-inline="true" data-iconpos="notext" data-icon="one" />
      <input type="submit" data-inline="true" data-iconpos="notext" data-icon="two" />
      <input type="submit" data-inline="true" data-iconpos="notext" data-icon="three" />
      <input type="submit" data-inline="true" data-iconpos="notext" data-icon="four" />
      <input type="submit" data-inline="true" data-iconpos="notext" data-icon="five" />
      <input type="submit" data-inline="true" data-iconpos="notext" data-icon="six" />
    </div>
    ```

## 它是如何工作的...

创建一个样式表 `jqm-sprite.css`，并从 `jquery.mobile.css` 文件中直接复制代码片段以保持不变。将图标精灵的 `background-image` URL 更改为指向自定义图标精灵 `dice.png` 图像。添加名为 `.ui-icon-one` 到 `.ui-icon-six` 的单个图标类。指定这些图标在图标精灵中的位置。类 `.ui-icon` 已经为图标指定了 `background` 颜色。它还为需要的供应商前缀指定了图标的 `border radius` 为 `9px`。修改 `@media` 查询并更新新图标的名称，而不是默认图标，如所示。

这里，前缀文本 **ui-icon** 表示按钮插件，这些是自定义图标，这将生成相应的类而不包含前缀文本。您现在可以使用属性 `data-icon="one"` 至 `data-icon="six"` 在按钮上使用替换的图标，框架将获取并显示正确的自定义图标。

在 `main.html` 中，通过使用 input 标签添加提交按钮来创建骰子的六个面的按钮。使用 `data-icon` 属性为这些按钮设置图标，如所示。显示带文本和不带文本的按钮进行比较。骰子的六个面的按钮现在显示如下屏幕截图所示，首先是带有文本的，然后是不带文本的：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_04_06.jpg)

## 还有更多...

本配方向您展示如何用自己的自定义图标精灵替换默认的图标精灵。您将不能再在您的应用程序中使用默认的图标。所以，只有在您有充分的理由并且您的应用程序需要定制所有图标时才替换默认图标集。一个更好的方法是在默认精灵的基础上添加一个自定义精灵，就像前面的配方中所示的那样。

## 另请参阅

+   *在按钮中使用自定义图标* 配方

+   *添加自定义图标精灵* 配方

# 在可折叠块中使用替代图标

**可折叠块** 是带有 `data-role="collapsible"` 属性的容器。您可以在可折叠内容中添加标题和其他控件，当可折叠块折叠时，只显示标题。您可以单击可折叠块旁边的 **+** 图标来展开它。本配方向您展示如何在可折叠块中使用替代图标。

## 准备工作

从 `code/04/collapsible` 源文件夹复制此配方的完整代码。您可以使用 URL `http://localhost:8080/04/collapsible/main.html` 启动此代码。

## 如何做...

1.  在 `main.html` 中使用 `data-role="collapsible"` 添加两个可折叠块，如下所示的代码。默认情况下，第一个可折叠块使用标准图标（**加号** 和 **减号**）。

    ```js
    <div data-role="content">
     <div data-role="collapsible" data-collapsed="false"
          data-theme="c" data-content-theme="c">
        <h3>Header of the collapsible element</h3>
        The header uses the default plus/minus icons
      </div>
     <div id="collapser" data-role="collapsible" 
    data-collapsed="false" data-theme="d" data-content-theme="d">
        <h3>Header of the collapsible element</h3>
        The header uses the alternate expand/collapse icons
      </div>
    </div>
    ```

1.  将以下脚本添加到页面的 `<head>` 部分，以为第二个可折叠块设置替代箭头图标：

    ```js
    //on initial load
    $("#main").live("pagebeforeshow", function(event, data) {      
      $("#collapser").find( ".ui-icon-plus" )
        .toggleClass("ui-icon-arrow-r");
      $("#collapser").find( ".ui-icon-minus")
        .toggleClass("ui-icon-arrow-d");
    });
    // handle expand and collapse events below
    $("#main").live("pageshow", function(event, data) {      
     $("#collapser").bind("expand collapse", function(event) {
        var isCollapse = (event.type === "collapse");
        $(this).find( ".ui-icon" )
          .toggleClass( "ui-icon-arrow-d", !isCollapse )
          .toggleClass( "ui-icon-arrow-r", isCollapse );
      });
    });
    ```

## 它是如何工作的...

在 `main.html` 中，添加两个可折叠块；它们在加载时具有默认的 **加号** 和 **减号** 图标。添加脚本并为 `pagebeforeshow` 事件创建事件处理程序以更改第二个可折叠块（带有 `id="collapser"`）的图标。使用 jQuery 的 `find()` 方法查找类 `.ui-icon-plus`（**加号** 图标）并使用 `toggleClass()` 方法将其替换为类 `.ui-icon-arrow-r`（**右箭头**）。类似地，将类 `.ui-icon-minus`（**减号** 图标）替换为类 `.ui-icon-arrow-d`（**向下箭头**）。在可折叠块上设置 `data-collapsed="false"` 属性以展开显示。当页面显示时，第二个可折叠块现在具有箭头图标而不是默认图标：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_04_08.jpg)

当可折叠块展开或折叠时，框架会使用标准图标切换图标。您可以通过为 `pageshow` 事件添加事件处理程序来覆盖此行为。根据可折叠块上的事件（`expand` 或 `collapse`），找到 `.ui-icon` 类并将其替换为 `.ui-icon-arrow-d` 或 `.ui-icon-arrow-r` 类以显示 **向下** 或 **向右** 箭头。折叠的块现在如下图所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_04_07.jpg)

## 还有更多...

您可以使用 `data-content-theme` 属性为可折叠内容设置主题。标题不受影响。以下代码将可折叠内容主题设置为 `e`：

```js
<div data-role="collapsible" data-content-theme="e">
```

### 为可折叠标题设置主题

使用 `data-theme` 属性并将主题设置为包括标题在内的整个可折叠块。现在，您可以使用 `data-content-theme` 属性为可折叠内容设置不同的主题。现在，它看起来好像您单独为标题设置了样式。以下代码片段将标题主题设置为 `a`，正文主题设置为 `e`：

```js
<div data-role="collapsible" 
  data-theme="a" data-content-theme="e" >
```

## 另请参阅

+   *创建嵌套手风琴* 配方

# 创建嵌套手风琴

**手风琴** 或 **可折叠集** 是一个带有 `data-role="collapsible-set"` 的容器中的可折叠块组。一次只能展开一个可折叠块，其他可折叠块会返回到折叠状态。您不能直接嵌套手风琴。本配方向您展示如何在一个简单的应用程序中创建一个 **嵌套手风琴**，该应用程序显示了可购买的各种房地产属性。

## 准备工作

从 `code/04/nested-accordion` 源文件夹中复制此配方的完整代码。您可以使用 URL `http://localhost:8080/04/nested-accordion/main.html` 启动此代码。

## 如何操作...

1.  在 `main.html` 中添加一个嵌套手风琴，使用 `data-role="collapsible-set"` 如下所示：

    ```js
    <div data-role="content">
      <h4>Our current housing projects</h4>
     <div data-role="collapsible-set" data-theme="d" data-content-
     theme="d"> 
        <div data-role="collapsible" data-collapsed="false">
          <h3>Villas and Row Houses</h3>
     <div data-role="collapsible-set" data-theme="e" data-
     content-theme="e">
            <div data-role="collapsible">
              <h3>ABC Lake View</h3>
              Premium Villas with each villa having its own private 
              beach
            </div>
            <div data-role="collapsible">
              <h3>ABC Nest</h3>
              Serene row houses amidst acres of trees
            </div>
          </div>
        </div>
        <div data-role="collapsible">
          <h3>Apartments</h3>
          <div data-role="collapsible" data-theme="e" data-content-
          theme="e">
            <h3>ABC Sky Rise</h3>
            Luxury 3 bedroom apartments 2 blocks away from ABC Mall
          </div>
        </div>
      </div>
    </div>
    ```

## 工作原理...

在`main.html`中，创建一个折叠集，其中包含两个可折叠块。第一个可折叠块显示**别墅和排屋**，第二个显示**公寓**。您现在可以在**别墅和排屋**可折叠块下嵌套另一个可折叠块，如前面的代码片段所示。

添加两个可折叠块，将它们嵌套在第一个可折叠块内以列出两个属性。使用 `data-theme` 和 `data-content-theme` 属性将嵌套内容与其父可折叠块进行不同主题设置。嵌套可折叠块显示如下截屏所示：

![如何运作...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_04_09.jpg)

现在，为第二个可折叠块**公寓**添加内容以完成代码。在此嵌套手风琴中，任何时候只有一个可折叠块是展开的，如下截屏所示：

![如何运作...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_04_10.jpg)

## 还有更多内容...

在可折叠集中的两个可折叠块之间引入任何其他元素或内容都会破坏该集合。当您展开或折叠它们时，可折叠块不再同步，并且它们变得彼此独立。

### 注意

正如名称所示，可折叠集必须仅包含可折叠块。

## 另请参阅

+   *在可折叠块中使用替代图标* 配方

# 创建自定义布局网格

您可以使用**布局网格**将控件放置在应用程序中相邻的位置。默认情况下，布局网格创建具有相等宽度的列单元格。本配方向您展示如何自定义此功能，并创建具有不同高度和宽度的单元格。

## 准备工作

从`code/04/layoutgrid`源文件夹中复制此配方的完整代码。您可以使用 URL `http://localhost:8080/04/layoutgrid/main.html` 启动此代码。

## 如何执行...

1.  如下代码所示，在`main.html`中添加布局网格，使用 `ui-grid` 和 `ui-block` 类：

    ```js
    <div data-role="content">
     <fieldset class="ui-grid-a">
     <div class="ui-block-a" style="width: 25%">
          <div class="ui-bar ui-bar-e">Col A</div>
        </div>
        <div class="ui-block-b" style="width: 50%">
          <div class="ui-bar ui-bar-e">Col B</div>
        </div>
        <div class="ui-block-c" style="width: 25%">
          <div class="ui-bar ui-bar-e">Col C</div>
        </div>
     <div class="ui-grid-solo">
          <div style="height: 40px" class="ui-bar ui-bar-e">A    Single Cell</div>
        </div>
      </fieldset>
    </div>
    ```

## 如何运作...

通过添加带有属性 `class="ui-grid-a"` 的 `fieldset` 元素来在其页面中为 `main.html` 添加布局网格。这将默认创建具有相等宽度的两列。但是，您可以通过添加如代码所示的 `ui-block-a`、`ui-block-b` 和 `ui-block-c` divs 来添加三个单元格。每个 div 的宽度不同，其中 **Col B** 的宽度为 `50%`，另外两列的宽度分别为 `25%`。总宽度总和为 100%，框架会自动将它们排列在单行中。如果总和超过 100%，则额外的单元格将移到下一行。

现在在第二行添加一个带有类`ui-grid-solo`的单个`div`，这将使单元格的宽度达到 100%。您可以像代码中所示使用`style="height:"`属性来更改此单元格的高度。 `ui-bar` 和 `ui-bar-e` 类样式的单元格具有边框和渐变颜色，并使用 swatch `e`对其进行主题化。网格布局现在如下截屏所示：

![如何运作...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_04_11.jpg)

## 还有更多内容...

你可以通过向其添加 `data-theme` 属性来使单个单元格 `ui-block` 与其他单元格不同的主题化。要使整行与网格中的其他行不同主题化，你需要将相同的 `data-theme` 属性添加到该行的所有单元格。

### 添加内容到布局网格单元格

你可以在布局网格的 `ui-block` 单元格中添加任何类型的元素。你甚至可以在此单元格中添加一个布局网格。你必须明智地选择你想要的屏幕外观，记住移动设备的有限屏幕尺寸。

### 向任何容器添加网格布局

通过将 `ui-grid` 类添加到任何容器中，你可以向任何容器添加网格。以下代码片段将整个页面样式化为两列网格：

```js
<div id="main" data-role="page" class="ui-grid-a">
```

## 另请参见

+   *向页脚添加布局网格*的方法见第三章, *工具栏*

# 使用 XML 内容

你可以在应用程序中显示从各种格式和来源获得的数据。此示例向你展示如何显示从 XML 文件中获取的一组示例**学生记录**。

## 准备工作

从 `code/04/xml-content` 源文件夹中复制此方法的完整代码。你可以使用 URL `http://localhost:8080/04/xml-content/main.html` 启动此代码。

## 如何做...

1.  创建带有具有属性 `name` 和 `age` 的学生节点的 `student.xml` 文件。每个 `student` 节点有多个 `course` 子元素。每个 `course` 元素都有一个 `name` 属性和一个如下所示的子 `marks` 元素：

    ```js
    <?xml version="1.0" encoding="utf-8" ?>
    <students>
     <student name="Alex" age="22">
        <course name="HTML5">
          <marks>89</marks>
        </course>
        <course name="CSS3">
          <marks>88</marks>      
        </course>
        <course name="JavaScript">
          <marks>80</marks>      
        </course>
      </student>
      . . . . 
    </students>
    ```

1.  创建 `main.html` 文件并添加一个隐藏的 `div` 容器。你可以将 XML 数据读取到这个 `div` 中，然后格式化并显示它：

    ```js
    <div id="content" data-role="content" data-theme="b">
      <div id="hiddendiv" hidden="true">hi</div>
    </div>
    ```

1.  在 `main.html` 的 `<head>` 部分中包含以下 JavaScript 代码，以加载 XML 文件，格式化数据，然后显示它：

    ```js
    $("#main").live("pageinit", function(event) {
      var str="";
     $("#hiddendiv").load("student.xml", function() {
        $("#hiddendiv").find("student").each(function() {
          str += "<div data-role='collapsible' data-theme='d'
            data-content-theme='d'>";
          str += "<h3>" + $(this).attr("name") + ", "
              + $(this).attr("age") +" years</h3>";
          str += "<ul data-role='listview'>";
          var i=0;
          $(this).find("course").each(function() {
            str += "<li>" + $(this).attr("name") + " : " 
                + $(this).children("marks").html() + "</li>";
          });
          str += "</ul></div>";
        });
     $("#content").html(str).trigger("create");
      });
    });
    ```

## 工作原理...

在 `main.html` 中，添加一个带有 `id="hiddendiv"` 的 `div` 容器，并通过设置属性 `hidden="true"` 来隐藏它。为 `pageinit` 事件创建事件处理程序，以便在页面初始化和内存可用时处理 XML 数据的加载。使用 jQuery Ajax 的 `load()` 方法将 XML 数据加载到 `hiddendiv` 中。加载成功后，使用 jQuery 的 `find()` 方法找到每个 `student` 节点。对于每个 `student`，通过创建可折叠项（使用 `data-role="collapsible"`）生成 HTML 代码。将可折叠项标题设置为学生的 `name` 和 `age`。你可以使用 jQuery 的 `attr()` 方法从 `student` 节点的属性中获取这些值。接下来，找到 `student` 节点内的每个课程并获取 `course` 的 `name` 和 `marks`。通过使用 `children()` 调用读取 `marks` 值，该调用提取 `course` 节点的第一个子元素。将 `course` 元素添加到无序列表中（使用 `data-role="listview"`）。

一旦 HTML 内容构建完成，将其设置为`"#content"`页面内容 div，并触发`"create"`方法，让 jQuery Mobile 框架发挥其作用并生成增强控件，如下面的屏幕截图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_04_12.jpg)

## 还有更多...

本教程向您展示如何通过 Ajax 从位于相同文件夹中的 XML 文件中读取内容。您也可以向服务器发送 Ajax 请求，获取此 XML 作为响应。jQuery 库有一大堆选择器和操作器，可以用来读取和写入 XML 数据。访问[`docs.jquery.com`](http://docs.jquery.com)了解更多信息。

### 注意

XML 结构需要结束标记，这使它变得臃肿。尽量使用更多的属性，而不是子节点，尽量使您的 XML 尽可能轻巧。您还可以使用诸如*gzip*之类的算法来压缩 XML。

### 使用本机浏览器渲染 XML

几乎所有浏览器都知道如何直接渲染和显示 XML 数据。如果 XML 内容有相关的样式表，还可以对 XML 内容进行格式化和样式化。在您的 jQuery Mobile 应用程序中，您可以在可以使用`target`属性在锚链接上打开内容的情况下，利用此功能，如下面的代码所示：

```js
<a href="student.xml" target="student" data-role="button">Open Student details</a>
```

## 另请参阅

+   *使用 JSON 内容*教程

# 使用 JSON 内容

**JSON**代表**JavaScript 对象表示法**。它是一种轻量级的数据交换格式，非常容易使用。本教程向您展示如何从 JSON 文件中显示**贵金属**的价格。

## 准备工作

从`code/04/json-content`源文件夹中复制此教程的完整代码。您可以使用 URL `http://localhost:8080/04/json-content/main.html` 来启动此代码。

## 如何做...

1.  创建包含五种贵金属数组的`precious.json`文件。名称、符号以及日内`open`，`close`，`high`和`low`价格也可用，如下面的代码所示：

    ```js
    [
      {
        "name": "Gold",
        "symbol": "Au",
        "price": { "open": 1642.46, "close": 1682.42, "high": 1699.66, "low": 1638.51 }
      },
      {
        "name": "Silver",
        "symbol": "Ag",
        "price": { "open": 31.24, "close": 33.11, "high": 33.65, "low": 31.21 }
      },
      {
        "name": "Platinum",
        "symbol": "Pt",
        "price": { "open": 1621.15, "close": 1623.87, "high": 1624.45, "low": 1620.98 }
      },
      {
        "name": "Paladium",
        "symbol": "Pd",
        "price": { "open": 656.05, "close": 657.35, "high": 657.75, "low": 655.25 }
      },
      {
        "name": "Rhodium",
        "symbol": "Rh",
        "price": { "open": 1434.38, "close": 1434.68, "high": 1434.98, "low": 1434.12 }
      }
    ]
    ```

1.  创建`main.html`，并向其中添加一个带有`id="preciousdata"`的空的`div`。您可以在这里读取 JSON 文件，格式化并显示数据：

    ```js
    <div id="content" data-role="content" data-theme="b">
      <div id="preciousdata"></div>
    </div>
    ```

1.  在`main.html`的`<head>`部分中包含以下 JavaScript 代码，以获取和加载 JSON 文件，格式化数据，并在布局网格中显示贵金属的价格表：

    ```js
    $("#main").live("pageinit", function(event) {
     $.getJSON("precious.json", function(metal) { 

    ```

1.  接下来，将用于创建布局网格的 HTML 字符串存储在本地变量中：

    ```js
        var blocka = "<div class='ui-block-a' style='width: 40%'>";
        var blockb = "<div class='ui-block-b' style='width: 15%'>";
        var blockc = "<div class='ui-block-c' style='width: 15%'>";
        var blockd = "<div class='ui-block-d' style='width: 15%'>";
        var blocke = "<div class='ui-block-e' style='width: 15%'>";
        var title = "<div class='ui-bar ui-bar-a' style='text-align: right'>";
        var uibarc = "<div class='ui-bar ui-bar-c' style='text-align: right'>";
        var uibare = "<div class='ui-bar ui-bar-e' style='text-align: right'>";
    ```

1.  使用上面定义的本地变量构建布局网格标题的 HTML 内容：

    ```js
        var str="<div class='ui-grid-d'>";
        str += blocka + title + "Precious Metal (USD)</div></div>";
        str += blockb + title + "Open</div></div>";
        str += blockc + title + "High</div></div>";
        str += blockd + title + "Low</div></div>";
        str += blocke + title + "Close</div></div>";
    ```

1.  现在为每个金属创建包括其价格详细信息的 HTML 内容：

    ```js
        for (var i in metal) {
          str += blocka + uibare + metal[i].name 
              + " (" + metal[i].symbol + ")</div></div>";
          str += blockb + uibarc + metal[i].price.open 
              + "</div></div>";
          str += blockc + uibare + metal[i].price.high 
              + "</div></div>";
          str += blockd + uibarc + metal[i].price.low 
              + "</div></div>";
          str += blocke + uibare + metal[i].price.close 
              + "</div></div>";
        }
        str += "</div>";
    ```

1.  最后，将这些数据添加到`#preciousdata` div 中，并触发`"create"`方法来显示格式化的 JSON 数据：

    ```js
     $("#preciousdata").html(str).trigger("create");
      });
    });
    ```

## 它是如何工作的...

在 `main.html` 中，添加一个空的 `div` 容器，其 `id="preciousdata"`。您可以使用此容器稍后显示格式化的 JSON 数据。为 `pageinit` 事件创建事件处理程序，以在页面初始化并在内存中可用时处理 JSON 数据的加载。使用 `$.getJSON()` jQuery 调用通过 GET 请求从服务器获取 JSON 编码的数据。现在，JSON 数据可用在 `metal` 对象中。

在 `getJSON` 方法的回调函数中，使用 `ui-grid-d` 类创建一个五列布局网格的 HTML 内容。五列标题分别是 **贵金属（美元）**、**开盘价**、**最高价**、**最低价** 和 **收盘价**。使用 `ui-block` 类为每个列单元格创建标题行。接下来，循环遍历 `metal` 中的对象，并构造列单元格，如下所示。

使用样式 `e` 和样式 `c` 交替为列设置主题。您可以使用样式 `a` 不同地设置标题。最后，将生成的 HTML 内容设置为 `#preciousdata` div，并触发 `create` 方法以让 jQuery Mobile 增强布局网格。现在，以以下截图所示的方式显示了包含贵金属价格数据的 JSON：

![它的工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_04_13.jpg)

## 还有更多...

本方法向您展示如何使用 `jQuery.getJSON()` 方法从服务器获取 JSON 数据。jQuery 库还提供了一个 `jQuery.parseJSON()` 方法，您可以使用它将 JSON 字符串直接解析为 JavaScript 对象，如下面的代码所示：

```js
var preciousobject= jQuery.parseJSON('{"name":"Gold"}');
```

### 用于数据存储和数据传输的 JSON

JSON 在今天非常流行，用于存储和传输数据。JSON 是 JavaScript 的一个子集，正如本示例所示，使用 JavaScript 读取 JSON 数据非常简单。与 XML 相比，JSON 轻量且使用的带宽较少（例如，没有开始和结束标记）。JSON 还得到了许多面向文档的数据库的原生支持，如 CouchDB 和 MongoDB。

### JSON 解析器

JSON 数据也可以使用 JavaScript 的 `eval()` 方法加载。但是，只有在绝对必要且非常确定 JSON 文本文件的来源时才能这样做。使用 **JSON 解析器** 加载数据始终更安全，因为这将仅接受有效的 JSON 数据，并防止潜在的恶意代码运行。有关更多详细信息以及访问各种可用的 JSON 解析器，请参阅 [www.json.org](http://www.json.org)。通常首选 jQuery JSON 方法，因为它们非常方便且安全可靠。

### 注意

始终使用正确实现的 JSON 解析器来读取和写入 `.json` 文件。避免使用 `eval()` 方法，这是不安全的。

## 另请参见

+   使用 XML 内容的方法


# 第五章：表单

在本章中，我们将介绍：

+   表单控件的原生样式

+   禁用文本控件

+   在网格中分组单选按钮

+   自定义复选框组

+   创建动态翻转开关和滑块控件

+   使用选项来自动初始化选择菜单

+   验证表单

+   使用 POST 提交表单

+   使用 GET 获取数据

+   创建一个可访问的表单

# 介绍

jQuery Mobile 框架默认增强标准 HTML 表单元素，使其触摸友好，同时在多个设备和平台上运行。表单可以包含多个控件，而你可以使用在其上设置 `data-role='controlgroup'` 的 `fieldset` 来对这些控件进行分组。默认情况下，控件以垂直方式列出。你可以使用 `data-type='horizontal'` 属性将它们水平排列。表单支持 **HTTP GET** ，**POST** 和其他操作。在适当的情况下，使用 Ajax 进行表单提交。

# 表单控件的原生样式

jQuery Mobile 框架默认增强表单及其控件。这个配方向你展示了设置表单控件原生样式的不同方法，以及如何自动初始化这些控件。

## 准备工作

从 `code/05/native-style` 源文件夹中复制此配方的全部代码。可以使用 URL `http://localhost:8080/05/native-style/main.html` 启动此代码。

## 如何进行...

1.  在 `<head>` 部分中，向 `main.html` 添加以下脚本以使所有按钮以原生样式呈现：

    ```js
    $(document).bind('mobileinit', function() {
     $.mobile.page.prototype.options.keepNative = 'button';
    });
    ```

1.  在页面内容中添加一个表单，以设置控件的原生样式：

    ```js
    <form action='#' method='post'>
      <p><label for='button1'>Button 1</label></p>
      <button name='button1'>Button: keepNative configuration</button>
      <p><label for='button2'>Button 2</label></p>
     <button name='button2' data-role='button'>Button: data-role='button'</button>
      <p><label for='button3'>Button 3</label></p>
      <button id='button3' name='button3'>Button: buttonMarkup()</button>
     <script>$('#button3').buttonMarkup(); </script>
      <p><label for='input1'>Input 1</label></p>
      <input type='submit' name='input1' value='Input: default'></input>
      <p><label for='input2'>Input 2</label></p>
      <input type='submit' name='input1' data-role='none' value="Input: data-role='none'"></input><p>
      <a href='#'>Default anchor link</a></p>
     <a href='#' data-role='button'>Anchor: data-role='button'></a>
    </form>
    ```

## 它是如何工作的...

在 `main.html` 中，添加一个事件处理程序，处理应用程序启动时触发的 `mobileinit` 事件。在这里，将页面插件的 `keepNative` 属性设置为 `'button'`。现在，框架将不会增强按钮控件，而是以原生样式呈现它们。现在在表单中添加 `button1` ，它将以原生样式呈现。要覆盖这种原生样式，添加 `button2` 并设置属性 `data-role='button'`。类似地，添加 `button3` 并在脚本中调用 `buttonMarkup（）` 方法，如前面的代码中所示。现在，`button2` 和 `button3` 都通过覆盖默认的原生样式来进行增强。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_05_1.jpg)

框架默认增强所有其他控件。添加一个输入按钮 `input1`，你会看到它已被增强。要使用原生样式控件，可以像上面代码中显示的那样使用 `data-role='none'` 属性来设置输入控件 `input2`。

对于锚链接，默认情况下使用原生样式。你可以用 `data-role='button'` 属性来增强锚链接。创建的表单如上所示。

## 还有更多...

如前所述，框架会增强表单控件，使其在所有平台上都能轻松使用手指操作。但这些控件可能在其他小容器（如工具栏）中使用时会显得稍大。您可以通过在控件上设置`data-mini='true'`属性，使用控件的**迷你版本**。控件现在变小了一点，但仍然是手指友好的。您可以直接在`controlgroup`上设置此属性，所有子元素将自动缩小。访问 jQuery Mobile 在线文档，查看各种控件的比较：[`jquerymobile.com/test/docs/forms/forms-all-compare.html`](http://jquerymobile.com/test/docs/forms/forms-all-compare.html)。

### 设置多个控件使用原生样式

您可以使用**页面插件**指定多个控件以使用原生样式。下面一行代码会原生样式化表单中的所有按钮、输入控件和选择菜单：

```js
$.mobile.page.prototype.options.keepNative = 'button, input, select';
```

### `data-role='none'`属性

根据控件类型，框架通过使用相应的插件来初始化和增强控件。当指定`data-role='none'`时，控件不会被框架增强，并且控件会使用原生样式。使用`data-theme`属性设置控件主题等操作将被忽略。

### 注意

jQuery Mobile 提供的增强样式是轻触友好的，非常适合移动设备。尽量避免在应用程序中使用原生样式。

# 禁用文本控件

此教程向您展示了在表单中启用和禁用文本控件的不同方法。

## 准备就绪

从`code/05/text-controls`源文件夹中复制此教程的全部代码。可以使用 URL `http://localhost:8080/05/text-controls/main.html`启动此代码。

## 如何做...

1.  在`main.html`中，在表单中创建以下文本控件：

    ```js
    <form action='#' method='post'>
      <input type='search' id='searchitem' name='searchitem' autofocus
          placeholder='Enter search text' value='' />
      <input type='text' id='textitem' name='textitem' 
          placeholder='Enter text item' value='' />
      <textarea id='textarea' name='textarea' 
          placeholder='Enter description'></textarea>
     <a href='#' data-role='button' class='ui-disabled'>More Details</a>
    </form>
    ```

1.  将以下脚本添加到`<head>`部分以禁用所有控件：

    ```js
      $('#main').live('pageinit', function(event) {
     $('#textitem').prop('disabled', true);
     $('#textarea').textinput('disable');

    ```

1.  然后处理搜索文本控件的`change`事件来启用所有表单控件：

    ```js
       $('#searchitem').bind('change', function(event, ui) {
          var str = $(this).attr('value');
     $('#textitem').prop('disabled', true);
     $('#textarea').textinput('enable').append(str
     + ' is absolutely awesome!');
          $('a').removeClass('ui-disabled');
       });
    });
    ```

## 它的运作方式...

在`main.html`中，添加一个带有`type='search'`的搜索控件，并添加一个带有`type='text'`的文本。现在，按照上面的代码添加一个空的`textarea`。添加一个链接并通过设置`class='ui-disabled'`属性来禁用它。在脚本中，添加一个`pageinit`事件处理程序，在页面初始化后调用。在这里，通过调用`prop('disabled', true)`方法来设置其`disabled`属性来禁用文本输入。然后通过调用**textinput 插件**的`textinput('disable')`方法来禁用`textarea`。现在，当应用程序加载时，除搜索输入外，表单上的所有控件都被禁用，如下面的屏幕截图所示：

![它的运作方式...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_05_2.jpg)

### 注意

您不能在使用`data-role='button'`将增强为按钮的锚链接上使用`disabled`属性。此属性会被忽略。

现在，为了启用控件，将搜索控件的 `change` 事件绑定到事件处理程序上。在这里，通过调用 `prop('disabled', false)` 方法来启用 `textitem` 控件。接下来，在 `textarea` 上调用 `textinput('enable')` 方法来调用其 **textinput 插件** 上的 enable 方法。在 `textarea` 上调用 `append()` 方法以向其添加文本。最后，在锚链接上调用 jQuery `removeClass()` 方法来移除 '`ui-disabled'` 类。现在，一旦您在搜索字段中输入内容，表单控件都会被启用，如下图所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_05_3.jpg)

## 更多内容...

您还可以通过使用 `attr()` 和 `removeAttr()` jQuery 方法将 `disabled` 属性添加到控件来启用或禁用控件，如下所示：

```js
$('#textitem').attr('disabled', 'disabled'); // to disable
$('#textitem').removeAttr('disabled'); // to enable
```

### 文本控件的自动初始化

文本区域和文本输入控件（`input type='text'`）会自动由框架增强。您还可以使用 `data-theme` 属性为文本控件设置主题。

# 将单选按钮分组到网格中

jQuery Mobile 框架允许您在水平或垂直方向上分组单选按钮。本示例向您展示如何在简单的座位预订表单中将单选控件分组为 3 x 3 网格。

## 准备工作

从 `code/05/radiobutton-grid` 源文件夹中复制此示例的完整代码。此代码可使用 URL `http://localhost:8080/05/radiobutton-grid/main.html` 运行。

## 如何执行...

1.  在 `main.html` 中，使用 3 x 3 布局网格创建九个单选控件。这些单选按钮是同一个控件组的一部分。

    ```js
    <form action='#' method='post'>
      <fieldset data-role='controlgroup' data-type='horizontal' 
          class='ui-grid-a'>
        <div class='ui-block-a' style='width: 30%'>
            <legend>First Row</legend></div>
        <div class='ui-block-b' style='width: 70%'>
          <input type='radio' name='radio-1' id='radio-11' value='Seat-A1' checked />
          <label for='radio-11'>A-1</label>
          <input type='radio' name='radio-1' id='radio-12' value='Seat-A2' />
          <label for='radio-12'>A-2</label>
          <input type='radio' name='radio-1' id='radio-13' value='Seat-A3'/>
     <label id='l-13' for='radio-13' class='ui-corner-right'>A-3</label>
        </div>
        <div class='ui-block-a' style='width: 30%'>
            <legend>Mid Row</legend></div>
        <div class='ui-block-b' style='width: 70%'>
          <input type='radio' name='radio-1' id='radio-21' value='Seat-B1' />
     <label id='l-21' for='radio-21' class='ui-corner-left'>B-1</label>
          <input type='radio' name='radio-1' id='radio-22' value='Seat-B2' />
          <label for='radio-22'>B-2</label>
          <input type='radio' name='radio-1' id='radio-23' value='Seat-B3'/>
     <label id='l-23' for='radio-23' class='ui-corner-right'>B-3</label>
        </div>
        <div class='ui-block-a' style='width: 30%'>
            <legend>Last Row</legend></div>
          <div class='ui-block-b' style='width: 70%'>
            <input type='radio' name='radio-1' id='radio-31' value='Seat-C1' />
     <label id='l-31' for='radio-31' class='ui-corner-left'>C-1</label>
            <input type='radio' name='radio-1' id='radio-32' value='Seat-C2' />
            <label for='radio-32'>C-2</label>
            <input type='radio' name='radio-1' id='radio-33' value='Seat-C3'/>
            <label for='radio-33'>C-3</label>
        </div>
      </fieldset>
    </form>
    ```

1.  将以下脚本添加到 `<head>` 部分以修复边缘单选按钮的样式：

    ```js
    $('#main').live('pageshow', function(event) {
      $('#l-13').children('span').addClass('ui-corner-right ui-controlgroup-last');
      $('#l-23').children('span').addClass('ui-corner-right ui-controlgroup-last');
      $('#l-21').children('span').addClass('ui-corner-left');
      $('#l-31').children('span').addClass('ui-corner-left');
    });
    ```

## 工作原理...

在 `main.html` 中，通过指定 `data-role='controlgroup'` 和 `data-type='horizontal'` 来添加水平单选控件组。现在将 `ui-grid-a` 类添加到此 `fieldset` 容器中，以创建两列布局网格。对于每一行，通过将 `class='ui-block-a'` 指定给 `div` 容器，在第一列添加图例，并通过 `class='ui-block-b'` 在第二列添加单选按钮。根据上述代码，添加九个具有适当标签的单选按钮，每行包含三个单选按钮。这将创建一个 3 x 3 单选按钮组的网格。

在上面的代码中，你会发现网格中的第一个和最后一个单选按钮样式正确，但所有其他边缘单选按钮（带有标签 l-13、l-21、l-23 和 l-31）样式不正确。它们具有矩形边缘而不是圆角。为了解决这个问题，你需要将框架为第一个单选按钮的标签生成的样式（`class='ui-corner-left'`）复制到标签 l-21 和 l-31 的内部`span`中。同样地，将框架为最后一个单选按钮的标签生成的样式（`class='ui-corner-right ui-controlgroup-last'`）复制到标签 l-13 和 l-23 的内部`span`中。现在单选按钮网格的样式已经正确，如下截图所示，你现在可以一次仅选择整个网格中的一个单选按钮：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_05_4.jpg)

## 还有更多...

当框架遇到一个带有`type='radio'`的`input`控件时，它会自动使用**checkboxradio 插件**将其增强为样式化的单选按钮。你可以通过在初始化期间使用`data-theme`属性来为单选按钮设置主题。你可以通过使用`data-role='none'`属性来关闭自动初始化并使用原生样式。

## 另请参阅

+   *自定义复选框控件组* 示例

# 自定义复选框控件组

默认的水平分组复选框控件没有图标，垂直分组的复选框控件不使用活动状态主题。这个示例向你展示了如何自定义复选框并添加这些样式。它还向你展示了如何调整布局以处理不同的屏幕尺寸。在这个示例中，你将创建一个简单的**博客订阅**表单。

## 准备工作

从`code/05/custom-checkbox`源文件夹中复制这个示例的全部代码。你可以使用`http://localhost:8080/05/custom-checkbox/main.html`网址来运行这段代码。

## 如何实现...

首先创建一个包含水平和垂直复选框控件组的表单。通过 JavaScript 在`pageshow`事件处理程序中向水平复选框控件添加图标来自定义水平复选框控件。复选框控件的`change`事件指示复选框`checked`状态是否已更改。使用`change`事件处理程序来添加和切换复选框的活动状态。

1.  在`main.html`中，创建一个带有垂直复选框控件组的表单：

    ```js
    <form action='#' method='post'>
      <div data-role='fieldcontain'>
        <fieldset data-role='controlgroup'>
          <legend>Subscribe to:</legend>
          <input type='checkbox' name='posts' id='posts' />
     <label for='posts' id='postslbl'>New Posts</label>
          <input type='checkbox' name='comments' id='comments' />
     <label for='comments' id='commentslbl'>Comments</label>
        </fieldset>
      </div>
    ```

1.  接下来添加两个水平切换集或复选框组：

    ```js
      <div data-role='fieldcontain'>
        <fieldset data-role='controlgroup' data-type='horizontal'>
          <legend>Notify Me:</legend>
          <input type='checkbox' name='notify' id='notify' />
          <label for='notify'>Immediate</label>
          <input type='checkbox' name='digest' id='digest' />
          <label for='digest'>Daily Digest</label>
        </fieldset>
      </div>
      <div data-role='fieldcontain'>
        <fieldset data-role='controlgroup' data-type='horizontal'>
          <legend>Share To:</legend>
          <input type='checkbox' name='twitter' id='twitter' />
     <label for='twitter' id='twitterlbl'>Twitter</label>
          <input type='checkbox' name='facebook' id='facebook' />
     <label for='facebook' id='facebooklbl'>Facebook</label>
        </fieldset>
      </div>
    </form>
    ```

1.  将以下脚本添加到`<head>`部分以向水平组添加图标：

    ```js
    $('#main').live('pageshow', function(event, data) {
      $('#twitterlbl').children('span').append("<span class='ui-icon ui-icon-shadow ui-icon-checkbox-off'>").trigger('create');
      $('#twitterlbl').addClass('ui-btn-icon-left').trigger('refresh');
      $('#facebooklbl').children('span').append("<span class='ui-icon ui-icon-shadow ui-icon-checkbox-off'>").trigger('create');
      $('#facebooklbl').addClass('ui-btn-icon-left').trigger('refresh');
      updatePosts();
      updateComments();
      $('#posts').bind('change', updatePosts);
      $('#comments').bind('change', updateComments);
    });
    ```

1.  接下来，绑定`change`事件来处理控件的`checked`状态变化：

    ```js
    function updatePosts(event, ui) {
     if($('#posts').prop('checked')) {
        $('#postslbl').addClass('ui-btn-active').trigger('refresh');
      } else {
        if($('#postslbl').hasClass('ui-btn-active'))
          $('#postslbl').removeClass('ui-btn-active').trigger('refresh');
      }
    }
    ```

1.  最后，根据垂直复选框的`checked`状态切换活动状态：

    ```js
    function updateComments(event, ui) {
     if($('#comments').prop('checked')) {
        $('#commentslbl').addClass('ui-btn-active').trigger('refresh');
      } else {
        if($('#commentslbl').hasClass('ui-btn-active'))
          $('#commentslbl').removeClass('ui-btn-active').trigger('refresh');
      }
    }
    ```

## 工作原理...

在`main.html`中，向**博客订阅**表单添加三个具有`data-role='controlgroup'`的`fieldset`元素。向第一个`fieldset`元素添加一个垂直复选框组，其中包含**文章**和**评论**的复选框。第二个控制组是用于选择博客通知的水平切换集合（**立即**和**作为每日摘要**）。第三组复选框也是水平的，选项包括在**Twitter**和**Facebook**上分享。

默认情况下，水平切换集合不带图标。你可以自定义并向其添加图标。为`pageshow`事件创建事件处理程序，并将所需的样式添加到第三个水平切换集合的标签中。在具有`id='twitterlbl'`和`id='facebooklbl'`的标签中添加具有`class='ui-icon ui-icon-shadow ui-icon-checkbox-off'`的内部 span，并且还将`ui-btn-icon-left`类添加到标签中。这将在两个复选框的左侧添加一个图标，类似于垂直复选框控件提供的图标。将其与其他水平切换集合进行比较。

默认情况下，垂直复选框具有图标，并且在选中时这些图标显示为勾号。垂直复选框不会获得`btn-active`样式（与水平复选框不同）。要添加活动按钮样式，请为两个垂直复选框（具有`id='posts'`和`id='comments'`）创建`change`事件的事件处理程序。对于这两个复选框，使用`prop('checked')`调用来查找控件是否被`checked`，然后添加或删除`ui-btn-active`类以为垂直复选框设置样式，类似于水平复选框。屏幕显示如下截图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_05_5.jpg)

## 更多内容...

在上述代码中，每个复选框组都包装在具有属性`data-role='fieldcontain'`的容器中。此属性将使框架根据屏幕大小动态调整控件的布局和其标签的位置。还添加了一个小的水平分隔线以显示分隔。在较宽的屏幕或使用横向方向时，显示如下截图所示：

![更多内容...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_05_6.jpg)

### 复选框控件的自动初始化

当框架遇到具有`type='checkbox'`的`input`控件时，它会自动使用**checkboxradio 插件**将其增强为样式化复选框。您可以在初始化期间使用`data-theme`属性为复选框设置主题。您可以通过使用`data-role='none'`属性关闭自动初始化并使用原生样式。

## 另请参阅

+   *在网格中对单选按钮进行分组* 的方法

# 创建动态翻转开关和滑块控件

本方法向您展示了如何使用 JavaScript 将**翻转开关**和**滑块**控件动态添加到页面，并处理其事件。在这里，您将创建一个简单的**音量控制**表单，其中包含一个音量滑块，在音量非常高时会向用户发出警告。

## 准备就绪

从`code/05/dynamic-slider`源文件夹中复制这个配方的全部代码。可以使用 URL `http://localhost:8080/05/dynamic-slider/main.html`启动这段代码。

## 如何做...

1.  在`main.html`中，向页面内容添加以下空表单：

    ```js
    <form id='volumeForm' action='#' method='post'></form>
    ```

1.  在`<head>`部分添加以下脚本，动态添加一个开关和一个滑块：

    ```js
    $('#main').live('pageinit', function(event) {
      var str="<div data-role='fieldcontain' style='width: 50%'><label for='flipswitch'>Volume:</label>"
        + "<select name='flipswitch' id='flipswitch' data-role='slider' data-track-theme='d'>"
        + "<option value='no'>Off</option><option value='yes'>On</option></select></div>"
        + "<div id='volcontainer' data-role='fieldcontain' style='width: 100%'>"
        + "<input type='range' name='volume' id='volume' value='8' min='0' max='15' data-track-theme='b' disabled /></div>";
     $('#volumeForm').html(str).trigger('create');

    ```

1.  处理翻转开关的`change`事件以启用音量滑块控件：

    ```js
      $('#flipswitch').bind('change', function(event, data) {
     if ($(this).slider().val() == 'no') {
          $('#volume').slider('disable');
        } else {
          $('#volume').slider('enable');
        }
      });
    });
    ```

1.  处理音量滑块的`change`事件以根据其值设置滑块样式：

    ```js
    $('#main').live('pageshow', function(event) {
     $('#volume').bind('change', function(event, data) {
        if ($(this).slider().val() > 10) {
          $('#volcontainer').find('.ui-btn-down-b')
          .removeClass('ui-btn-down-b').addClass('ui-btn-down-e');
        } else {
          $('#volcontainer').find('.ui-btn-down-e')
          .removeClass('ui-btn-down-e').addClass('ui-btn-down-b');
        }
      });
    });
    ```

## 它是如何工作的...

在`main.html`中添加一个空表单`id='volumeForm'`。为`pageinit`事件创建一个事件处理程序，该事件在页面初始化后触发。在这里，生成表单的 HTML 内容。使用带有`data-role='slider'`的选择控件添加一个翻转开关控件（`id='flipswitch'`）。这个翻转开关将切换音量**On**和**Off**。添加一个带有`type='range'`的输入控件以创建滑块控件（`id='volume'`）。在启动时将`disabled`属性添加到滑块上，以便控件在启动时被禁用。将此 HTML 内容设置为空表单并触发`'create'`方法以让框架初始化和增强控件。当页面加载时，您将看到**音量控制**表单，其中包含动态添加的翻转开关和禁用的滑块控件，如下图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_05_7.jpg)

接下来添加代码来处理`#flipswitch`的`change`事件，在事件处理程序中，使用`slider().val()`调用检查翻转开关是**on**还是**off**。根据这个值，通过调用`slider('enable')`或`slider('disable')`来启用或禁用滑块音量控制。现在当你切换翻转开关的值时，你会看到滑块在屏幕截图中启用或禁用，如下所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_05_8.jpg)

在`pageshow`事件处理程序中绑定音量滑块控件的`change`事件，并在此处使用`slider().val()`调用检查滑块的值。如果值大于**10**的阈值音量，则将滑块设置为主题`'e'`，如果尚未设置样式，则设置。如果值低于**10**的阈值，则将主题设置回主题`'b'`。您可以使用 jQuery 的`find()`方法并将`ui-btn-down-b`类替换为`ui-btn-down-e`类，反之亦然。现在当您设置一个高音量时，滑块会变成黄色，如下图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_05_9.jpg)

## 还有更多...

您可以使用`data-theme`属性为翻转开关和滑块控件设置主题，使用`data-theme-track`属性在初始化时使用滑块轨道。要在初始化后操作这些控件，您将不得不操作底层本机控件，然后在它们上调用`'refresh'`方法。

### 滑块的自动初始化

当框架遇到一个带有 `type='range'` 的 `input` 控件时，它会自动使用 **滑块插件** 将其增强为滑块控件。同样地，滑块插件会将带有 `data-role='slider'` 的选择控件增强为翻转开关。你可以通过使用 `data-role='none'` 属性关闭自动初始化并使用原生样式。

# 使用选项自动初始化选择菜单

原生 HTML 选择菜单被 jQuery Mobile 框架增强，使其对移动设备更加友好。本示例展示了如何通过 JavaScript 设置其控件选项以自动初始化 **选择菜单**。

## 准备工作

从 `code/05/select-menu` 源文件夹复制本示例的完整代码。可以使用 URL `http://localhost:8080/05/select-menu/main.html` 启动此代码。

## 怎样做...

1.  在 `main.html` 中，添加以下代码以创建选择菜单：

    ```js
    <form action='#' method='post'>
      <div data-role='fieldcontain'>
        <label for='selectid' class='select'>Sample Select Menu</label>
        <select name='selectid' id='selectid' multiple data-native-menu='false' data-overlay-theme='e'>
          <option value='Sample Select Menu' data-placeholder='true'>Sample Select Menu</option>
          <option value='opt1'>Option 1</option>
     <option value='disabledopt' disabled>Disabled Option</option>
          <option value='opt2'>Option 2</option>
     <optgroup label='Options in Group1'>
            <option value='grp1'>&nbsp;&nbsp;&nbsp;&nbsp;Group Option1</option>
            <option value='grp2'>&nbsp;&nbsp;&nbsp;&nbsp;Group Option2</option>
          </optgroup>
     <optgroup label='Options in GroupA'>
            <option value='grpA'>&nbsp;&nbsp;&nbsp;&nbsp;Group OptionA</option>
            <option value='grpB'>&nbsp;&nbsp;&nbsp;&nbsp;Group OptionB</option>
          </optgroup>
        </select>
      </div>
    </form>
    ```

1.  将以下脚本添加到 `<head>` 部分以设置选择菜单控件选项：

    ```js
    $('#main').live('pageinit', function(event) {
     $('#selectid').selectmenu({ 
        theme: 'd', 
        inline: false, 
        corners: true,
        icon: 'star',
        iconpos: 'left',
        shadow: true,
        iconshadow: true
      });
    });
    ```

## 它是如何工作...

在 `main.html` 中，创建一个表单，并向表单添加一个带有 `multiple` 属性的选择控件以启用多选。设置属性 `data-native-menu='false'` 表示选择菜单应由框架增强。还设置 `data-overlay-theme='e'` 属性以指定应该使用 `e`（黄色）的样式覆盖层。

添加第一个带有 `data-placeholder` 属性的选项元素，表示此选项元素的文本必须用作选择菜单的标题。现在按照前面的代码所示添加不同的选项元素。`opt1` 和 `opt2` 元素是常规选项项目。通过向选项元素添加 `disabled` 属性来禁用 `disableopt` 元素。然后使用 `optgroup` 元素添加两个选项组（**Group1** 和 **GroupA**），如前面的代码所示。这些可以包含子选项元素。`选择菜单显示如下截图所示：`

`![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_05_10.jpg)`

`在 `pageinit` 事件处理程序中添加脚本，该事件处理程序在启动时初始化页面后被调用。在这里，通过将选项值传递给 **selectmenu 插件** 来设置选择菜单控件的初始配置选项。在代码中，设置选择菜单的 `theme`、`inline`、`corners`、`icon`、`iconpos`、`shadow` 和 `iconshadow` 属性的值。现在当你点击选择菜单时，样式化的菜单选项如下截图所示：`

`![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_05_11.jpg)`

## `更多内容...`

当框架遇到一个 `select` 元素时，它会自动使用 **selectmenu 插件** 将其增强为选择菜单。你可以通过使用 `data-role='none'` 属性关闭自动初始化并使用原生样式。

### `打开和关闭选择菜单`

`您可以调用`selectmenu`插件上的`open`和`close`方法，并以以下屏幕截图所示的方式以编程方式打开或关闭选择菜单：`

```js
$('#selectid').selectmenu('open'); // open select menu
$('#selectid').selectmenu('close'); // close select menu
```

`#验证表单

在提交到服务器之前验证表单可以节省带宽和时间，因为错误可以在客户端捕获。因此可以避免服务器请求。在 jQuery Mobile 应用程序中，可以使用 JavaScript 验证表单。此配方向您展示了如何验证**博客评论表单**中输入的条目。

## 准备就绪

从`code/05/validate-form`源文件夹中复制此配方的完整代码。可以使用 URL `http://localhost:8080/05/validate-form/main.html`启动此代码。

## 如何做...

1.  在`main.html`中，添加以下代码以创建一个表单：

    ```js
    <form id='commentform' action='#' method='post'>
      <div data-role='fieldcontain'>
        <label for='username'>Name</label>
        <input id='username' name='username' type='text' required placeholder='Enter Name' />
      </div>
      <div data-role='fieldcontain'>
        <label for='email'>Email ID</label>
        <input id='email' name='email' type='email' required placeholder='Enter Email' />
      </div>
      <div data-role='fieldcontain'>
        <label for='comments'>Comments</label>
        <textarea id='comments' name='comments' required placeholder='Enter Comments <10-100 chars long>'></textarea>
      </div>
      <div id='errmsg' style='color: #f00'></div>
      <input id='submitid' type='submit' data-transition='pop' value='Submit Comment'/>
    </form>
    ```

1.  添加以下脚本来验证评论字段：

    ```js
    $('#main').live('pageinit', function(event) {
     $('#commentform').submit(function() {
        var len = $('#comments').val().length;
        if ( len < 10 || len > 100 ) {
          $('#errmsg').text('Invalid comments. Length must be between 10-100 chars').show().fadeOut(5000);
          return false;
        }
        else
          return true;
      });
    });
    ```

## 它是如何工作的...

在`main.html`中，添加一个表单（`id='commentform'`），并向表单添加以下三个字段，**用户名**（`type='text'`），**电子邮件**（`type='email'`）和**评论**（`textarea`）。对所有三个字段添加`required`属性以将它们指定为必填项。通过使用`placeholder`属性添加适当的提示给用户，如前述代码所示。向表单添加一个空的 div（`id='errmsg'`）以在表单验证时显示任何错误消息。

当您加载表单并单击**提交评论**按钮而不输入**姓名**字段时，将显示以下错误消息：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_05_12.jpg)

单击提交按钮而不输入有效的**电子邮件 ID**时，将显示以下错误：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_05_13.jpg)

如上一个脚本中所示，添加`pageinit`事件处理程序。这将在页面在启动时被初始化后调用。在这里定义表单的`submit()`方法来验证评论的长度。如果评论长度无效，则在五秒后显示错误消息，然后淡出。现在因为有错误，所以从`submit`方法返回`false`；表单将不会被提交。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_05_14.jpg)

在成功验证后，从`submit()`方法返回`true`以成功将表单提交到服务器。

## 还有更多...

在此配方中，表单的`action`设置为`#`或与当前 HTML 页面相同的 URL。这种表单称为**自提交表单**。在这种情况下的默认响应是表单内容本身。如果表单由 Web 服务器提供，则可以自定义生成 post 的响应。如果您使用的是随本书源代码一起提供的 nodejs Web 服务器，则会得到自定义成功响应，而不是表单内容。

### 表单中的唯一 ID

在 jQuery Mobile 应用程序中，由于多个页面可以同时存在于 DOM 中，因此应确保表单控件的 ID 是唯一的。ID 应该在整个应用程序中是唯一的，而不仅仅是在单个页面中。如果不遵循此规则，查找和表单行为可能会失败或表现不同。一些浏览器可能仍然在一定程度上支持重复的 ID，但这并不保证。

## 另请参阅

+   使用 POST 提交表单 的方法

+   *使用 GET 获取数据* 的方法

# 使用 POST 提交表单

这个方法向你展示了如何使用 Ajax **POST** 并提交表单，也展示了不使用 Ajax 时如何提交同一个论坛。在上一个方法中使用的**博客评论**表单在此用于提交。

## 准备工作

从 `code/05/submit-form` 源文件夹中复制此方法的完整代码。此代码可以使用 URL `http://localhost:8080/05/submit-form/main.html` 启动。要尝试此方法，您还需要启动随本书源代码一起提供的简单 nodejs web 服务器。使用以下命令启动服务器：

```js
node jqmserver.js

```

## 怎么做...

1.  在 `main.html` 中，按照以下代码创建**博客评论**表单：

    ```js
    <form id='commentform' action='/postComment' data-transition='pop' method='post'>
      <div data-role='fieldcontain'>
        <label for='username'>Name</label>
        <input id='username' name='username' type='text' required placeholder='Enter Name' />
      </div>
      <div data-role='fieldcontain'>
        <label for='email'>Email ID</label>
        <input id='email' name='email' type='email' required placeholder='Enter Email' />
      </div>
      <div data-role='fieldcontain'>
        <label for='comments'>Comments</label>
        <textarea id='comments' name='comments' required placeholder='Enter Comments <10-100 chars long>'></textarea>
      </div>
      <div id='errmsg' style='color: #f00'></div>
      <input id='submitid' type='submit' value='Submit Comment'/>
    </form>
    ```

1.  将以下脚本添加到 `<head>` 部分以验证评论字段：

    ```js
    $('#main').live('pageinit', function(event) {
     $('#commentform').submit(function() {
        var len = $('#comments').val().length;
        if ( len < 10 || len > 100 ) {
          $('#errmsg').text('Invalid comments. Length must be between 10-100 chars').show().fadeOut(5000);
          return false;
        }
        else
          return true;
      });
    });
    ```

## 如何运作...

在 `main.html` 中，创建**博客评论**表单。将表单的 `action` 设置为 `'/postComment'`，并且还要指定 `data-transition='pop'` 属性。其余的代码和表单验证与前一个方法中的相同，并在那里详细解释。当你启动应用程序时，表单会显示如下截图所示：

![如何运作...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_05_15.jpg)

填写表单，然后点击**提交评论**按钮。如果没有发现错误，表单将通过 Ajax 提交。自定义的 nodejs web 服务器响应 `/postComment` 请求，生成以下 HTML 内容作为带有 mime 类型 `'text/html'` 的响应：

```js
<div data-role='page' data-theme='a'>
  <div data-role='header'>
    <h1>Comments Added</h1>
  </div>
  <div data-role='content'>
    Hi {User name entered}!
    <p>Your Email ID: {Email ID entered}</p>
    <p>Added your comment: {Comments entered}</p>
    <a href='#' data-role='button' data-rel='back'>Back</a>
  </div>
</div>
```

框架渲染响应如下截图所示：

![如何运作...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_05_16.jpg)

页面过渡平稳，使用了 `pop` 动画。你可以点击**返回**按钮并导航回原始页面，因为也指定了 `data-rel='back'` 属性。

## 还有更多...

你可以通过向表单元素指定 `data-ajax='false'` 属性来提交此表单而不使用 Ajax。此代码在与 `main.html` 相同文件夹中的 `non-ajax.html` 文件中提供：

```js
<form id='commentform' action='/postComment' method='post' data-ajax='false'>
```

当不使用 Ajax 时，响应会触发整个页面的刷新。在此方法中，服务器响应仅返回页面 `div` 容器，并且不返回具有任何链接到 jQuery Mobile 样式表的 `<head>` 元素。此外，响应中缺少对 jQuery 和 jQuery Mobile 库的引用。因此，结果页面如下截图所示。在此响应页面中没有样式，如果点击**返回**链接，它不起作用。

![还有更多...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_05_17.jpg)

### Ajax 响应

通过 Ajax 的服务器响应会替换请求表单的内容，就像本篇食谱中所示。您可以通过使用 DOM 检查器来查看此响应。但是，如果您查看页面源代码，则仍会显示原始页面。POST 请求不能被书签标记，因为它们在哈希中不包含任何查询参数。对 POST 请求的响应将返回与请求相同的 URL，并且不会更新 URL 哈希。

### 其他非 Ajax 提交表单的方式

本篇食谱向您展示了如何通过设置属性 `data-ajax='false'` 来提交表单，而不使用 Ajax。另一种不使用 Ajax 的方法是向表单指定一个 `target` 属性，如下所示：

```js
<form id='commentform' action='/postComment' method='post' target='sometarget'>
```

这适用于 POST 和 GET 服务器请求。

Ajax 还可以通过使用 `mobileinit` 事件处理程序中以下代码中显示的全局配置来关闭应用程序：

```js
$.mobile.ajaxEnabled = false;
```

## 参见

+   *验证表单* 食谱

+   *使用 GET 获取数据* 食谱

+   *在 第七章 中的*配置 ajaxEnabled* 食谱，*配置*

# 使用 GET 获取数据

本篇食谱向您展示了如何使用 Ajax **GET** 请求并从服务器获取数据。在本篇食谱中，服务器会通过来自 **足球联赛分数** 表单的 GET 请求返回足球比分。

## 准备工作

从`code/05/get-request`源文件夹中复制本篇食谱的完整代码。这段代码可以通过 URL `http://localhost:8080/05/get-request/main.html` 运行。要尝试这个食谱，您需要启动随本书源代码一起提供的简单 nodejs web 服务器。使用以下命令启动服务器：

```js
node jqmserver.js

```

## 如何操作...

1.  在`main.html`中，添加以下代码以创建一个表单：

    ```js
    <div id='scores' data-role='fieldcontain'>
     <form id='scoreform' action='/getScores' method='get'>
        The latest scores are now available!
        <input id='submitid' type='submit' name='submitid' data-inline='true' value='Fetch Scores' />
      </form>
    </div>
    ```

1.  将以下脚本添加到 `<head>` 部分以使用 Ajax 获取并显示分数：

    ```js
    $('#main').live('pageshow', function(event) {
      $('#scoreform').submit(function() {
     $.get('/getScores').success(showScores).error(errMsg);
        return false; // cancel the default submit
      });
    });
    function showScores(data) { // on success
     $('#scores').html(data).trigger('create');
    }
    function errMsg() { // on error
      $('#scores').html('Unable to fetch scores, try later');
    }
    ```

## 它是如何工作的...

在`main.html`中，添加一个`<div>`容器，其`id='scores'`，并设置其属性`data-role='fieldcontain'`。这个`<div>`容器将显示分数。向页面添加一个表单（`id='scoreform'`），并将其`action`设置为`'/getScores'`，`method`设置为`'get'`。在表单中添加一个文本为 **获取分数** 的提交按钮，以从服务器获取分数。您可以向页面添加一个装饰的页脚，使用`class='ui-bar ui-bar-e'`。加载应用程序后，显示以下屏幕：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_05_18.jpg)

如前面代码所示，添加`pageshow`事件处理程序。当您单击`submit`按钮时，它调用 jQuery `submit()`方法。默认表单`submit()`的服务器响应将用新的内容替换整个页面。要获取部分页面更新，请调用 jQuery 的`.get()` Ajax 方法来从`'/getScores'`服务器 URL 获取数据。然后通过返回`false`取消默认的`submit()`方法。`.get()`方法指定了`success`和`error`的回调函数，如前面的代码所示。在成功的回调函数`showScores()`中，用从服务器获得的 HTML 响应替换`#scores` div 的内容。触发`'create'`方法以让 jQuery Mobile 框架初始化和增强新添加的内容。任何错误都由`errMsg()`错误处理程序处理，如前面的代码所示。

自定义的 Nodejs Web 服务器通过生成以下 HTML 内容作为响应来响应`/getScores` get 请求，MIME 类型为`'text/html'`：

```js
<ul data-role='listview'>
  <li data-role='list-divider'>Group A</li>
    <li>Team A beat Team B [ 5 - 3 ]</li>
    <li>Team C lost to Team D [ 1 - 2 ]</li>
  <li data-role='list-divider'>Group B</li>
    <li>Team E drew Team F [ 0 - 0 ]</li>
    <li>Team G lost to Team H [ 3 - 4 ]</li>
</ul>
```

现在，仅通过此服务器响应替换了`#scores <div>`容器的内容。标题和页脚保持不变。结果显示如下截图所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_05_19.jpg)

## 还有更多...

您可以通过向表单元素指定`data-ajax='false'`属性来提交不使用 Ajax 的表单，如下代码所示。当不使用 Ajax 时，响应会触发完整页面刷新。因此确保服务器响应中返回一个正确的 jQuery Mobile 页面，否则结果页面可能存在样式和其他问题。

```js
<form action='/someAction' method='get' data-ajax='false'>
```

### Ajax 响应

服务器通过 Ajax 响应完全替换了请求表单的内容。您可以使用 DOM 检查器查看响应。但如果您查看页面源代码，原始页面仍然会显示。GET 请求可以被收藏夹添加为它们支持哈希中的查询参数。GET 响应允许更新 URL 哈希。

### 表单提交默认值

您也可以提交一个没有指定任何动作或方法属性的表单，如下代码中所示：

```js
<form>
```

表单将使用动作和方法属性的默认值。方法将默认为`'get'`，动作将默认为当前页面的相对路径。您可以通过调用`$.mobile.path.get()`方法访问此路径。

### 注意

始终为表单指定`action`和`method`属性。

## 另请参阅

+   *验证表单* 配方

+   使用 POST 提交表单的 *配方*

+   第七章中*配置 ajaxEnabled* 配方，*配置*

# 创建一个可访问的表单

jQuery Mobile 框架对无障碍功能（如**WAI-ARIA**）提供了很好的支持。这为无障碍工具（如屏幕阅读器）提供了支持。这使得您的应用程序屏幕可以被依赖这些辅助技术的用户阅读。此外，现在一些浏览器（如使用 Webkit 引擎的 Chrome）已经提供了语音输入控件。这些控件接受语音输入。本文介绍了如何生成支持语音输入并支持屏幕阅读器的无障碍表单控件。

## 准备工作

从 `code/05/accessible-controls` 源文件夹中复制本文的完整代码。您可以使用 URL `http://localhost:8080/05/accessible-controls/main.html` 启动此代码。

## 如何做…

1.  在 `main.html` 中，添加以下代码以创建一个表单：

    ```js
    <form action='#' method='post'>
     <div data-role='fieldcontain' class='ui-hide-label'>
        <input type='text' name='username' id='username' placeholder='Enter Name' speech x-webkit-speech/>
        <label for='username'>Name</label>
      </div>
      <div data-role='fieldcontain'>
     <input type='number' name='age' id='age' placeholder='Enter Age' speech x-webkit-speech/>
        <label for='age' class='ui-hidden-accessible'>Age</label>
      </div>
      <div data-role='fieldcontain'>
        <input type='text' name='city' id='city' placeholder='Enter City' class='custom' speech x-webkit-speech/>
     <label for='city' class='ui-hidden-accessible'>City</label>
      </div>
      <input type='submit' name='submit' id='submit' value='Submit' />
    </form>
    ```

## 它是如何工作的…

在 `main.html` 中，按如下方式添加三个字段，**用户名**（输入 `type='text'`）、**年龄**（输入 `type='number'`）和 **城市**（输入 `type='text'`）。为每个字段关联一个标签，并为每组标签和输入控件添加一个 `div` 容器，该容器具有属性 `data-role='fieldcontain'`。这有助于框架根据平台和设置动态重新排列和调整布局。`placeholder` 属性用于为用户提供适当的输入提示。

要启用语音输入，请按照之前代码中所示为每个输入控件添加 `speech` 和 `x-webkit-speech` 属性。语音输入的支持完全取决于浏览器的实现，一些浏览器仍然没有实现它们。当页面加载时，您将看到以下截图：

![它是如何工作的…](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_05_20.jpg)

您将在每个输入控件的右上角看到一个小麦克风图标。用户可以点击此图标，然后会提示用户为输入控件说出值。一旦用户说完，**语音转文字引擎**会将声音转换为文本，并在控件中显示输入值文本。虽然不是完全准确，但语音转文字技术正在日益改进。

## 还有更多…

正如前面提到的，jQuery Mobile 框架对 WAI-ARIA 等无障碍功能提供了很好的支持。因此，请为所有表单元素添加有意义的标签。当页面初始化时，框架会自动向屏幕阅读器公开这些标签。如果您已经使用占位符为用户提供提示，那么标签可能是多余的。但如果您希望建立一个支持无障碍功能的应用程序，那么您也应该定义标签。

如果你想使用占位符功能并支持辅助功能，jQuery Mobile 提供了一个简单的选项，通过在表单控件上使用样式`'ui-hidden-accessible'`隐藏标签。你也可以通过在表单字段容器中添加样式`'ui-hide-label'`来隐藏标签，代码中已经展示。现在标签不会显示在屏幕上，但依然可以被屏幕阅读器访问。你可以通过运行你喜欢的屏幕阅读器并访问创建的页面来验证这一点。

### 移动设备的受欢迎的语音阅读器

当今市场上有许多语音阅读器，你可以根据你的平台尝试任何受欢迎的语音阅读器。苹果手机有**VoiceOver** (见 [`www.apple.com/accessibility/iphone/vision.html`](http://www.apple.com/accessibility/iphone/vision.html)), 安卓手机有**TalkBack** , **Spiel** , **Mobile Accessibility** for Android, 以及安卓应用商店中的其他应用。

### 桌面语音阅读器

对于 Chrome 桌面浏览器，可以从 [`code.google.com/p/google-axs-chrome`](http://code.google.com/p/google-axs-chrome) 安装**ChromeVox** 扩展，一旦启用，它将开始为你朗读表单控件。你可以验证屏幕阅读器是否也读出了隐藏的标签内容。


# 第六章：列表视图

在本章中我们将涵盖：

+   使用嵌入式和非嵌入式列表

+   创建自定义编号列表

+   使用嵌套列表

+   使用只读的嵌套列表

+   格式化列表中的内容

+   使用分隔按钮列表

+   使用图标

+   创建自定义搜索过滤器

+   用 JavaScript 修改列表

# 介绍

通过以下代码创建 jQuery Mobile 中的简单列表：

```js
<ul data-role='listview'>
  <li><a href='link1'>Item 1</a></li>
  <li><a href='link2'>Item 2</a></li>
</ul>
```

前面的代码是一个普通的 HTML 无序列表，你可以在其中添加属性`data-role='listview'`。框架现在可以增强、美化并移动端友好地呈现该列表。它为锚点元素添加了右箭头，并且当你点击列表中的任何项目时，链接的页面会被加载到 DOM 中，并在可能时使用 AJAX 过渡打开。

# 使用嵌入式和非嵌入式列表

**嵌入式列表**是嵌入在容器（页面、表单或其他列表）中的列表。本教程向你展示了如何创建嵌入式和非嵌入式列表，并强调了在使用非嵌入式列表与其他表单控件时需要注意的事项。

## 准备工作

从`code/06/inset-list`源文件夹中复制本教程的完整代码。该代码可通过以下 URL 启动：`http://localhost:8080/06/inset-list/main.html`。

## 如何实现...

1.  按如下代码在`main.html`中创建三个列表和几个按钮：

    ```js
    <div data-role='content'>
      <a href='#' data-role=button data-theme='b'>Button 1</a>
     <ul data-role='listview' data-inset='true'>
        <li data-theme='e'><a href='#'>Item 1</a></li>
        <li data-theme='e'><a href='#'>Item 2</a></li>
      </ul>
      <a href='#' data-role=button data-theme='b'>Button 2</a>
     <ul data-role='listview'>
        <li data-theme='e'><a href='#'>Item A</a></li>
        <li data-theme='e'><a href='#'>Item B</a></li>
      </ul>
      <a href='#' data-role=button data-theme='b'>Button 3</a>
     <ul data-role='listview' style='margin: 15px'>
        <li data-theme='e'><a href='#'>Item 3</a></li>
        <li data-theme='e'><a href='#'>Item 4</a></li>
      </ul>
      <a href='#' data-role=button data-theme='b'>Button 4</a>
    </div>
    ```

## 工作原理...

在代码中，第一个列表是嵌入式列表，其他两个是非嵌入式列表。你可以通过在列表中添加属性`data-inset='true'`来创建嵌入式列表。这样可以使列表的四周都有`15px`的美化边距。如果你将按钮或其他形式控件放在嵌入式列表旁边，布局会自动调整。

代码中的下一个列表是非嵌入式列表，没有`data-inset`属性。框架会给该列表加上`-15px`的填充，让它拉伸至整个屏幕宽度。如果你将按钮或其他表单控件放在该列表旁边，由于负填充，这些控件会重叠在一起。该列表具有矩形角落。

代码中的第三个列表也是非嵌入式列表。但这里通过使用属性`style='margin: 15px'`来处理控件重叠的问题。这样可以为列表增加`15px`的边距，并抵消默认填充。三个列表显示如下截图所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_06_01.jpg)

### 注意

当使用非嵌入式列表与其他表单控件时，添加额外的边距以避免控件重叠。

## 更多内容...

你可以配置框架在你的应用中默认使用嵌入式列表。通过在`listview`插件的`mobileinit`事件中将`inset`选项设置为`true`来实现这一点，如下代码所示：

```js
$(document).bind('mobileinit',function(){
  $.mobile.listview.prototype.options.inset = 'true';
});
```

### 设置列表视图主题

你可以使用`data-theme`属性并像以下代码中所示为列表设置主题。以下代码中列表使用`e`色块：

```js
<ul data-role='listview' data-theme='e'>
```

### 设置列表项主题

可以使用 `data-theme` 属性并为每个列表项设置不同的主题。以下代码将 swatch `e` 设置给列表项 **Item 1**，而列表项 **Item 2** 将使用 swatch `d`。

```js
<ul data-role='listview' data-theme='e'>
  <li>Item 1</a>
  <li data-theme='d'>Item 2</li>
</ul>
```

# 创建自定义编号列表

默认情况下，**有序列表** 在 jQuery Mobile 中使用十进制数。框架使用 CSS 添加编号。JavaScript 用于无法使用 CSS 的地方。本示例向您展示如何使用 JavaScript 为列表添加字母编号。

## 准备工作

从 `code/06/custom-numbered-list` 源文件夹中复制此示例的全部代码。可以使用 URL `http://localhost:8080/06/custom-numbered-list/main.html` 启动此代码。

## 如何做…

1.  在 `main.html` 中，按照以下代码创建一个有序列表和一个无序列表：

    ```js
    <div data-role='content'>
     <ol data-role='listview' data-theme='e' data-inset='true'>
        <li>Soccer</li>
        <li>Basketball</li>
        <li>Hockey</li>
        <li>Tennis</li>
      </ol>
     <ul id='alphalist' data-role='listview' data-theme='e' data-inset='true'>
        <li>Soccer</li>
        <li>Basketball</li>
        <li>Hockey</li>
        <li>Tennis</li>
      </ul>
    </div>
    ```

1.  添加以下脚本以为无序列表添加字母编号：

    ```js
    $('#main').live('pageinit', function(event) {
      var alph = 'a';
      $('#alphalist').find('li').each(function() {
        var str = "<span style='font-weight: normal'>" + alph 
            + '.&nbsp;</span>' + $(this).html();
        $(this).html(str);
        alph = String.fromCharCode(alph.charCodeAt(0)+1);
      });
    });
    ```

## 工作原理…

代码中的第一个列表是一个有序列表，默认情况下使用十进制数。接下来的列表具有 `id='alphalist'`，是一个无序列表。将给定的脚本添加到页面容器或 `main.html` 的 `<head>` 部分。

在脚本中，将 `pageinit` 事件绑定到一个函数，该函数注入字母编号。在这个函数中，使用 jQuery 的 `find('li')` 方法获取列表中的所有列表项。使用 jQuery 的 `each()` 方法循环遍历每个列表项。在 `each()` 的回调函数中，使用 `$(this).html()` 获取列表项的当前文本，并在此文本前添加字母（使用 `normal` 字体重量）。通过使用 `$(this).html(str)` 将这个新字符串（`str`）设置给列表项。最后，通过使用 JavaScript 的 `charCodeAt()` 和 `fromCharCode()` 方法在循环中增加字母。当页面显示时，两个列表现在显示如下截图中所示：

![工作原理…](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_06_02.jpg)

## 更多内容…

您可以使用 JavaScript 创建任何类型的编号列表（例如罗马数字、小写或大写字母、项目符号等）。但是，您必须确保处理这些列表的所有情况（例如，处理嵌套列表的项目编号）。

# 使用嵌套列表

**嵌套列表** 是一个嵌套在另一个列表项中的列表。默认情况下，列表项上显示右箭头图标，当您点击它时，框架会打开一个单独的子页面来显示嵌套列表。默认情况下，显示的子页面使用主题 `b` 作为页面标题。框架可以处理到 n 级的嵌套。本示例向您展示如何使用嵌套列表，并且还向您展示如何使用 JavaScript 获取嵌套列表的子页面。

## 准备工作

从 `code/06/nested-list` 源文件夹中复制此示例的全部代码。可以使用 URL `http://localhost:8080/06/nested-list/main.html` 启动此代码。

## 如何做…

1.  在 `main.html` 中，添加以下代码以创建作者列表。将书名添加到某些作者的嵌套列表中。

    ```js
    <div data-role='content'>
      <ul data-role='listview' data-theme='b' data-inset='true'>
        <li><a href='#'>H.G. Wells</a></li>
        <li><a href='#'>Rabindranath Tagore</a>
     <ul data-role='listview' data-theme='a' data-inset='true'>
            <li><a href='#'>The Gardener</a></li>
            <li><a href='#'>Gitanjali</a></li>
          </ul>
        </li>
        <li><a href='#'>William Shakespeare</a>
     <ul data-role='listview' data-theme='a' data-inset='true'>
            <li><a href='#'>Merchant of Venice</a></li>
            <li><a href='#'>Romeo and Juliet</a></li>
          </ul>
        </li>
      </ul>
     <div id='nestedlists'></div>
    </div>
    ```

1.  添加以下脚本以获取嵌套列表的子页面：

    ```js
    $('#main').live('pageinit', function(event) {
      var str = '';
     $('ul').listview('childPages').each(function() {
        str = $(this).find("div[class$='ui-title']").html() + ', ' + str;
      });
      $('#nestedlists').html('Books available for authors : ' + str);
    });
    ```

## 工作原理...

在代码中，使用作者姓名作为带有锚链接的列表项添加作者**拉宾德拉纳特·泰戈尔**和**威廉·莎士比亚**的书名的嵌套列表。作者**H.G.威尔斯**没有嵌套列表。

将给定的脚本添加到页面容器或`main.html`中的`<head>`标签中。在脚本中，将`pageinit`事件绑定到事件处理程序以调用**listview 插件**的`childPages`方法。使用 jQuery 的`each()`方法遍历子页面数组。在`each()`的回调函数中，使用 jQuery 的`find()`方法获取子页面的标题文本。查找具有属性`class='ui-title'`的标题 div。将此文本连接到字符串中，一旦获取了所有作者子页面，将此字符串设置为空的`'nestedlists'` div 的内容。这将显示具有书籍嵌套列表的作者列表。作者**H.G.威尔斯**没有嵌套列表，不会显示。

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_06_03.jpg)

嵌套列表嵌入在列表项`<li>`标签中的锚链接`<a>`标签之后。当您单击此列表项时，它会打开子页面，如以下屏幕截图所示。锚链接文本被设置为子页面的标题，并且标题默认使用主题`b`。

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_06_04.jpg)

## 更多内容...

您将注意到与主页面相比，子页面的主题差异。主页面使用主题`a`作为页面内容和标题的主题。它使用主题`b`作为列表的主题。子页面标题默认设置为主题`b`。由于嵌套列表使用了`data-theme='a'`属性，因此整个子页面，包括嵌套列表，都使用样式`a`。在您的应用程序中使用嵌套列表时，这可能不是理想的情况。请参阅第十章中的 *主题化嵌套列表* 示例，*主题框架*，了解如何正确设置嵌套列表的主题。

### 主题化嵌套列表的子页面标题

如本示例所示，默认情况下，嵌套列表的子页面标题设置为样式`b`。您可以使用以下代码中显示的`data-header-theme`属性来设置子页面的标题主题：

```js
<ul data-role='listview' data-theme='d' data-header-theme='a'>
```

### 配置列表视图的标题主题选项

你可以通过设置`listview`插件的`headerTheme`选项来配置应用程序中嵌套列表的默认标题主题。以下代码将其设置为主题`a`并绑定到`mobileinit`事件：

```js
$(document).bind('mobileinit',function(){
  $.mobile.listview.prototype.options.headerTheme = 'a';
});
```

## 另请参阅

+   *使用只读嵌套列表* 示例

+   第十章中的 *主题化嵌套列表* 示例，*主题框架*

# 使用只读嵌套列表

**只读列表**是包含非交互式项目或不包含锚链接的项目的列表。框架将只读项目与常规项目样式不同。只读项目具有主题颜色较浅的颜色，并且它们的大小也较小，因为预期用户不会点击它们。

此配方演示了如何创建只读嵌套列表，并使用**选项**配置列表视图。它还演示了如何将嵌套列表显示为插入式列表。

## 准备工作

从`code/06/read-only-list`源文件夹复制此配方的完整代码。可以使用 URL `http://localhost:8080/06/read-only-list/main.html` 启动此代码。

## 它的操作方法...

1.  在`main.html`中，添加以下代码以创建作者列表。为一些作者添加嵌套的书名列表。

    ```js
    <div data-role='content'>
      <ul data-role='listview'>
        <li>H.G. Wells</li>
     <li><a href='#'>Mark Twain</a></li>
        <li>Rabindranath Tagore
     <ul data-role='listview'>
            <li>The Gardener</li>
            <li>Gitanjali</li>
          </ul>
        </li>
        <li>William Shakespeare
     <div><ul data-role='listview'>
              <li>Merchant of Venice</li>
              <li>Romeo and Juliet</li>
     </ul></div>
        </li>
      </ul>
    </div>
    ```

1.  将以下脚本添加到页面以配置列表视图选项:

    ```js
    <script>
     $.mobile.listview.prototype.options.theme = 'e';
     $.mobile.listview.prototype.options.headerTheme = 'a';
     $.mobile.listview.prototype.options.inset = true;
    </script>
    ```

## 工作原理...

在代码中，将作者名字作为无锚链接的列表项添加。为**拉宾德拉纳特·泰戈尔**和**威廉·莎士比亚**添加嵌套书籍列表。作者**H.G.威尔斯**没有嵌套列表。作者**马克·吐温**有一个锚链接。该列表使用主题`e`，即黄色。没有嵌套列表或锚链接的项目以浅一些的色调和较小的字体显示。具有嵌套列表或锚链接的项目以常规颜色显示，并具有更大的字体。

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_06_05.jpg)

将上述脚本添加到页面或`main.html`的`<head>`标签中，如代码所示。该脚本配置了`listview`插件的默认选项。在此配方中，配置了`theme`，`headerTheme`和`inset`选项。使用`headerTheme`选项将子页面头的主题设置为`a`，如上面的代码所示。现在，当您单击列表项**拉宾德拉纳特·泰戈尔**时，嵌套列表的子页面将打开。具有头部主题`a`的嵌套列表如下图所示:

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_06_06.jpg)

## 还有更多...

有时，您可能想要将嵌套列表显示为插入式列表。您可以通过将内部列表包装在`<div>`标签中来实现这一点。框架现在不会为嵌套列表创建子页面。

### 注

在`listview`插件上调用`childPages`方法将不返回嵌入了`<div>`标签的列表。

**威廉·莎士比亚**的书籍列表在此配方中嵌入在`<div>`标签中，因此没有创建嵌套列表。

### 注

使用插入嵌套列表会使您的列表垂直拉伸，用户将不得不滚动页面以查看所有内容。因此，请有选择地使用它们。

## 另请参阅

+   *使用嵌套列表* 配方

+   第十章中的 *主题化嵌套列表* 配方, *主题框架*

# 在列表中格式化内容

这个配方向你展示了如何在列表项中格式化文本。它还向你展示了如何使用可折叠项目和**计数气泡**在列表项中。

## 准备工作

从`code/06/format-content`源文件夹中复制此配方的完整代码。可以使用 URL `http://localhost:8080/06/format-content/main.html`启动此代码。

## 怎么做...

1.  在`main.html`中，添加以下代码以创建一个交通方式列表：

    ```js
    <div data-role='content'>
      <ul data-role='listview'>
        <li>
     <p class='ui-li-aside' style='font-size: 15px'>
              <strong>High Speed</strong></p>
          <div data-role='collapsible' data-theme='e'>
            <h2>Air</h2>
            <ul data-role='listview'>
              <li>Aeroplane</li><li>Helicopter</li>
            </ul>
          </div>
     <p class='ui-li-count'>2</p>
        </li>
        <li  data-theme='e'>
          <p class='ui-li-aside' style='font-size: 15px'>
              <strong>Moderate Speed</strong></p>
          <div data-role='collapsible' data-theme='e'>
            <h2>Land</h2>
            <ul data-role='listview'>
              <li>Bus</li><li>Car</li><li>Bike</li><li>Train</li>
            </ul>
          </div>
     <p class='ui-li-count'>4</p>
        </li>
        <li>
          <p class='ui-li-aside' style='font-size: 15px'>
              <strong>Slow Speed</strong></p>
          <div data-role='collapsible' data-theme='e'>
            <h2>Water</h2>
            <ul data-role='listview'>
              <li>Ship</li><li>Submarine</li><li>Boat</li>
            </ul>                
          </div>
     <p class='ui-li-count'>3</p>
        </li>
      </ul>
    </div>
    ```

1.  将以下脚本添加到页面以配置列表视图选项：

    ```js
    <script>
     $.mobile.listview.prototype.options.theme = 'e';
     $.mobile.listview.prototype.options.countTheme = 'a';
     $.mobile.listview.prototype.options.inset = true;
    </script>
    ```

## 它是如何工作的...

将上一个代码中显示的三种交通方式作为列表项添加。为每个列表项添加一个`data-role='collapsible'`的可折叠块。为每个可折叠块添加一个标题文本，并创建一个带有不同车辆类型的列表作为其内容。添加一个样式设置为`class='ui-li-aside'`的字符串。这将创建一个字符串，并将其位置设置在列表项的右上角。最后，通过使用`class='ui-li-count'`将所列车辆的数量设置为**计数气泡**的样式。对每个列表项都这样做。

将代码中显示的脚本添加到页面或`main.html`的`<head>`标签中，以配置列表选项`theme`，`inset`和`countTheme`的默认值。现在列表显示如下所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_06_07.jpg)

以下图片显示了展开了一个可折叠块的列表：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_06_08.jpg)

## 还有更多...

您可以使用`countTheme`选项对计数气泡进行主题设置，如本配方中已提到的。您还可以在列表上设置属性`data-count-theme`，如下面的代码所示：

```js
<ul data-role='listview' data-count-theme='a'>
```

### 在列表项中使用表单控件

这个配方向你展示了如何向列表项添加具有列表的可折叠内容。您还可以像下面的代码中所示向列表项添加任何表单控件。框架通过在列表项内添加所需的填充和边距来增强表单控件，并使表单控件更易于点击。

```js
<li><input type='text' name='username' placeholder='Enter name'/></li>
```

## 请参阅

+   *使用分隔按钮列表*配方

# 使用分隔按钮列表

**分隔按钮列表**是一个为同一列表项提供两种不同操作的列表。这是通过向列表项添加两个锚链接来创建的。然后，框架会自动将列表项转换为分隔按钮。添加到第一个链接的任何图像都会缩小为`80 x 80px`大小的缩略图。第二个链接将替换为一个称为**分隔图标**的图标，并位于分隔按钮的右上角。这个配方向你展示了如何创建一个分隔按钮列表来显示列表中的图像。

## 准备工作

从`code/06/split-button-list`源文件夹中复制此配方的完整代码。可以使用 URL `http://localhost:8080/06/split-button-list/main.html`启动此代码。

## 怎么做...

1.  将`main.html`作为多页面模板应用程序创建。在`#main`页面中添加一个分隔按钮列表，如下面的代码所示：

    ```js
    <div data-role='content'>
     <ul data-role='listview' data-inset='true' data-theme='b' 
     data-split-theme='e' data-split-icon='arrow-d'>
        <li>
     <a href='#viewphoto' data-rel='dialog'>
            <img style='margin: 10px' 
                src='../../resources/images/img1.png' />
            <h3>Lal Bagh</h3>
            <p>Bangalore, India</p>
          </a>
     <a href='#download' data-rel='dialog'>Lal Bagh, Bangalore</a>
        </li>
        <li>
          <a href='#viewphoto' data-rel='dialog'>
            <img style='margin: 10px' 
                src='../../resources/images/img2.png' />
            <h3>Peacock</h3>
            <p>Mysore, India</p>
          </a>
          <a href='#download' data-rel='dialog'>Peacock, Mysore</a>
        </li>
        <li>
          <a href='#viewphoto' data-rel='dialog'>
            <img style='margin: 10px' height=75%
              src='../../resources/images/img3.png' />
            <h3>Ganesha</h3>
            <p>Bangalore, India</p>
          </a>
          <a href='#download' data-rel='dialog'>Ganesha, Bangalore</a>
        </li>
      </ul>
    </div>
    ```

1.  添加将在点击拆分按钮左侧时打开的`#viewphoto`页面。

    ```js
    <div id='viewphoto' data-role='page' data-theme='e' >
      <div data-role='header' data-theme='e'>
        <h1>Photo View</h1>
      </div>
      <div data-role='content'>
        Showing photo here ...
      </div>
    </div>
    ```

1.  添加将在点击拆分图标时打开的`#download`页面。

    ```js
    <div id='download' data-role='page' data-theme='e' >
      <div data-role='header' data-theme='e'>
        <h1>Download</h1>
      </div>
      <div data-role='content'>
          Downloading file ...
      </div>
    </div>
    ```

## 工作原理...

在`#main`页面的列表中添加列表项，如前面的代码所示。每个列表项都有两个链接，通过设置`data-rel='dialog'`属性，这两个链接都会作为对话框打开。将第一个链接指向`#viewphoto`页面。添加指向照片的图像，并为锚链接文本添加格式化描述。根据缩略图像的大小，您可以像前面的代码所示添加填充。

将第二个链接指向`#download`页面。第二个链接会自动转换为拆分图标。默认情况下，拆分图标使用右箭头。您可以通过在列表视图上使用`data-split-icon`属性来配置这一点。使用`data-split-theme`属性对拆分图标进行主题设置。拆分按钮列表显示如下图所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_06_09.jpg)

点击照片图像或列表项中的左按钮会打开**照片查看**对话框，如下图所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_06_10.jpg)

点击拆分图标会打开**下载**对话框，如下图所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_06_11.jpg)

## 更多信息...

要在`#viewphoto`对话框中显示照片图像，您将需要编写一些 JavaScript 代码来处理`pagechange`事件。此在第九章 *方法和实用程序*中的 *使用 changePage()更改页面* 配方中有所介绍。

### 使用 listview 选项配置拆分按钮列表

您可以使用`listview`插件的`splitTheme`和`splitIcon`选项配置拆分图标和拆分图标主题的默认值，并将其绑定到`mobileinit`事件。以下代码将星形图标和主题`e`设置为列表视图选项的默认值：

```js
$(document).bind('mobileinit',function(){
  $.mobile.listview.prototype.options.splitIcon = 'star';
  $.mobile.listview.prototype.options.splitTheme = 'e';
});
```

## 另请参见

+   *在列表中格式化内容* 配方

+   *使用图像图标*配方

+   第九章 *方法和实用程序* 中的 *使用 changePage( )更改页面* 配方

# 使用图像图标

jQuery Mobile 框架将图标添加到交互式列表项（具有链接的列表项）的右侧。您还可以将图标添加到列表项文本中，框架会将此图标大小调整为`40 x 40px`。此配方向您展示如何在列表项中显示图标。

## 准备工作

从`code/06/list-icons`源文件夹中复制此配方的完整代码。可以使用 URL `http://localhost:8080/06/list-icons/main.html` 启动此代码。

## 如何操作...

1.  在`main.html`中，添加一个包含如下代码的列表：

    ```js
    <div data-role='content'>
      <ul data-role='listview' data-theme='b' data-inset='true'>
        <li data-icon='star'>
          <a href='#'>
     <img src='../../resources/images/img1.png' class='ui-li-icon'
     alt='Lal Bagh'/>
            <h3 style='margin-left: 25px'>Lal Bagh, Bangalore</h3>
          </a>
        </li>
        <li data-icon='star'>
          <a href='#'>
     <img src='../../resources/images/img2.png' class='ui-li-icon' 
     alt='Peacock'/>
            <h3 style='margin-left: 25px'>Peacock, Mysore</h3>
          </a>
        </li>
        <li data-icon='star'>
          <a href='#'>
     <img src='../../resources/images/img3.png' class='ui-li-icon'            alt='Ganesha'/>
            <h3 style='margin-left: 25px'>Ganesha, Bangalore</h3>
          </a>
        </li>
      </ul>
    </div>
    ```

## 工作原理...

在列表项的锚链接中为每个列表项添加图像。将 `class='ui-li-icon'` 属性设置为此图像元素。这会指示框架将图像样式化为图标，并且图像会自动缩小以适应列表项内。您可以设置所需的边距以便文本在调整图像大小后正确显示。列表显示如下截图所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_06_12.jpg)

## 还有更多...

对于具有链接的交互式列表项，默认情况下，框架会在列表项的右侧添加一个右箭头图标。可以使用列表项上的 `data-icon` 属性进行更改。本步骤中的代码使用 `star` 图标作为列表项。

## 另请参阅

+   *在列表中格式化内容* 的步骤

+   *使用分割按钮列表* 的步骤

# 创建自定义搜索过滤器

当使用 **列表搜索过滤器** 时，框架会遍历列表项并显示与过滤文本匹配的项。备用文本也可以与搜索过滤器一起使用。当使用备用文本时，将忽略列表项文本。搜索是一种通用匹配，文本中的任何出现都将显示在结果中。

本步骤向您展示如何使用可以同时搜索列表项文本和备用文本的搜索过滤器。它还向您展示了如何配置搜索过滤器，以及如何实现使用自定义搜索逻辑的自定义搜索回调函数。

## 准备工作

从 `code/06/custom-search` 源文件夹复制此步骤的完整代码。可以使用 URL `http://localhost:8080/06/custom-search/main.html` 启动此代码。

## 如何做...

1.  在 `main.html` 中，创建以下移动平台列表。列表项还包含属性 `data-filtertext` 中的操作系统制造商名称。

    ```js
    <div data-role='content' data-theme='e'>
      <ul id='oslist' data-role='listview'>
     <li data-role='list-divider'>Open Source</li>
        <li data-filtertext='Google'>Android</li>
        <li data-filtertext='HP'>WebOS</li>
        <li data-filtertext='Samsung Intel'>Tizen</li>
        <li data-filtertext='Linux Foundation'>LiMo</li>
        <li data-filtertext='Mozilla'>Boot2Gecko</li>    
     <li data-role='list-divider'>Closed</li>
        <li data-filtertext='Apple'>iOS</li>
        <li data-filtertext='Nokia'>Symbian</li>
        <li data-filtertext='Nokia'>S40</li>
        <li data-filtertext='RIM'>Blackberry OS</li>
        <li data-filtertext='Microsoft'>Windows Phone</li>
        <li data-filtertext='Samsung'>Bada</li>
      </ul>
    </div>
    ```

1.  将以下脚本添加到页面以配置默认列表选项：

    ```js
    $.mobile.listview.prototype.options.theme = 'e';
    $.mobile.listview.prototype.options.inset = true;      
    $.mobile.listview.prototype.options.dividerTheme = 'e';
    $.mobile.listview.prototype.options.filter = true;
    $.mobile.listview.prototype.options.filterTheme = 'e';
    $.mobile.listview.prototype.options.filterPlaceholder = 'Search for ...';
    $.mobile.listview.prototype.options.filterCallback = customFilter;

    ```

1.  以下代码片段包含搜索文本中的列表项文本：

    ```js
    $('#main').live('pageinit', function(event) {
      $('#oslist').find('li').each(function() {
        $(this).attr('data-filtertext', 
            $(this).attr('data-filtertext') + ' ' + $(this).html());
      });
    });
    ```

1.  自定义搜索回调定义如下代码：

    ```js
    function customFilter(text, searchValue) {
      var regx='\\b'+searchValue;
     return !(text.match(new RegExp(regx, 'i')));
    }
    ```

## 工作原理...

在 `main.html` 中，创建一个带有 `id='oslist'` 的列表。按照代码所示为各种移动操作系统平台添加列表项。使用属性 `data-role='list-divider'` 创建列表项，并将列表项分为 **开源** 和 **闭源**。使用 `data-filtertext` 属性将操作系统制造商名称作为备用搜索文本。

将给定的脚本添加到页面或 `main.html` 的 `<head>` 标签中。设置各种列表视图配置选项，如 `theme='e'` 和 `inset='true'`。这是一个 **只读列表**，列表项着以浅黄色阴影。使用 `dividerTheme='e'` 选项来对列表分隔符项进行主题化。列表分隔符项由框架以较深色调样式化。

接下来，添加 `filter='true'` 和 `filterTheme='e'` 选项，为列表添加搜索过滤器，并使用 `e` 主题对其进行主题化。使用 `filterPlaceholder` 选项指定搜索过滤器文本控件的自定义文本（默认为 '`Filter Items...`'）。最后，通过设置选项 `filterCallback=customFilter` 设置自定义搜索回调函数。列表显示如下所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_06_13.jpg)

列表中的默认搜索功能匹配文本中搜索字符串的任何出现。要覆盖此行为，请按照前面的代码所示定义自定义过滤器回调。该函数接受两个参数，`text` 和 `searchValue`。创建一个正则表达式来搜索给定文本中单词开头处的 `searchValue` 出现。忽略单词之间的搜索值出现。使用 `match()` 方法将正则表达式与文本进行匹配。参数 `i` 使其大小写不敏感。

如果使用 `filtertext` 属性与列表项，那么默认搜索仅使用此文本，忽略列表项文本。要同时使用列表项文本和过滤文本，请添加 `pageinit` 事件处理程序，如前面的代码所示。在此函数中，使用 jQuery `find('li).each()` 方法找到每个列表项，并在 `each()` 的回调中，获取列表项文本并将其添加到过滤文本中。这不会对列表项产生任何可见影响。但是列表项文本现在是过滤文本的一部分，因此可供搜索过滤器使用。因此，搜索 **a** 将列出 **Android** 和 **iOS**（filtertext 的值为 **Apple**）。但这不会列出 **Symbian** 或 **Bada**，因为它们的单词中间包含 **a**，如下屏幕截图所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_06_14.jpg)

如果搜索 **Bo**，则仅将 **Boot2Gecko** 作为候选项，如下屏幕截图所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_06_15.jpg)

## 还有更多...

搜索回调函数返回一个布尔值，指示是否应通过搜索过滤器隐藏文本。因此，搜索过滤器回调应为所有匹配元素返回 `false`。不匹配的文本元素返回 `true`，并由搜索过滤器隐藏。

### 使用数据属性配置列表分隔主题

该示例使用 `dividerTheme` 选项对列表分隔项进行主题化。您还可以使用 `data-divider-theme` 属性，如下面的代码所示：

```js
<ul data-role='listview' data-theme='e' data-divider-theme='e'>
```

### 使用数据属性配置列表搜索过滤器

该示例向您展示如何使用 `filter`、`filterTheme` 和 `filterPlaceholder` 选项来配置列表视图。这些选项也可以使用 `data-filter`、`data-filter-theme` 和 `data-filter-placeholder` 属性进行设置，如下面的代码所示：

```js
<ul data-role='listview' data-filter='true' data-filter-theme='e' data-filter-placeholder='Search for...'>
```

# 使用 JavaScript 修改列表

您可以使用 JavaScript 动态修改列表及其内容。本示例向您展示如何使用 JavaScript 在只读列表中添加或删除列表项。

## 准备工作

从 `code/06/scripting-lists` 源文件夹复制此配方的完整代码。此代码可以使用网址 `http://localhost:8080/06/scripting-lists/main.html` 运行。

## 如何做...

1.  在 `main.html` 中，添加以下代码以在布局网格中创建一个空列表：

    ```js
    <div data-role='content'>
      <div data-role='fieldcontain'>
        <fieldset class='ui-grid-b'>
          <div class='ui-block-a' style='width: 65%'>
     <ul id='numlist' data-role='listview' data-theme='e' 
     data-inset='true'>
     </ul>
          </div>
          <div class='ui-block-b'>
            <button data-theme='b' id='addBtn'>Add</button>
            <button data-theme='b' id='removeBtn'>Remove</button>
          </div>
        </fieldset>
      </div>
    </div>
    ```

1.  添加以下脚本以动态添加或删除列表项：

    ```js
    var count = 0;
    $('#main').live('pagecreate', function(event) {
     $('#numlist').listview({create: function(event, ui) {
        $('#addBtn').bind('click', function(event, ui) {
          var str = "<li><a href='#'>Item " + (++count) + '</a></li>';
          $('#numlist').append(str);
     $('#numlist').listview('refresh');
        });
        $('#removeBtn').bind('click', function(event, ui) {
          if (--count < 0) {
            count = 0;
            return;
          }
          $('#numlist').find('li').last().remove();
     $('#numlist').listview('refresh');
        });
      }});
    });
    ```

## 它是如何工作的...

在 `main.html` 中使用 `class='ui-grid-b'` 属性在 `fieldset` 容器上添加一个两列布局网格。在第一列中添加一个空列表，其 `id='numlist'`。在第二列中添加两个按钮，ID 分别为 `addBtn` 和 `removeBtn`。单击这些按钮时，列表项会动态更新到第一列的空列表中。

将给定的脚本添加到页面或 `main.html` 的 `<head>` 部分。在脚本中，为 `pagecreate` 事件创建一个事件处理程序，在页面完全初始化之前触发。在此处，为 `listview` 元素的 `create` 事件添加一个事件处理程序。当创建 `listview` 元素时，将触发此事件。在其回调函数中，绑定 `addBtn` 和 `removeBtn` 按钮的 `click` 事件，如前述代码所示。

按下 `addBtn` 时，将一个列表项添加到列表中。列表项文本保存在内存中，并在添加新元素时递增。按下 `removeBtn` 时，通过调用 jQuery 的 `find('li').last()` 方法获取最近添加的列表项元素。通过调用 `remove()` 方法移除此最后一个元素。在对列表进行任何修改后，调用 **listview 插件** 上的 `refresh()` 方法来更新列表。

当启动应用时，显示如下截图所示，其中包含一个空列表：

![它的工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_06_16.jpg)

按下**添加**按钮会向列表中添加新的列表项，如下面的截图所示：

![它的工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_06_17.jpg)

按下**删除**按钮会删除最近添加的列表项。

![它的工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_06_18.jpg)

## 还有更多...

正如此配方中所述，您必须在对列表进行任何修改后调用 **listview 插件** 上的 `refresh()` 方法。在添加新列表项或删除列表项时，`refresh()` 方法会触发列表的更新，并在列表项上应用必要的样式和增强效果。

```js
$('#numlist').listview('refresh');
```
