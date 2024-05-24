# Sencha Touch2 JavaScript 移动框架（二）

> 原文：[`zh.annas-archive.org/md5/04504CE3000052C183ADF069B1AD3206`](https://zh.annas-archive.org/md5/04504CE3000052C183ADF069B1AD3206)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：组件和配置

在本章中，我们将更深入地查看 Sencha Touch 中可用的各个组件。我们将检查布局配置选项以及它们如何影响每个组件。

在本章中，我们将使用简单的基组件作为学习更复杂组件的起点。我们还会稍微谈谈如何在组件创建后访问它们。

最后，我们将总结如何使用 Sencha Touch API 文档来查找每个组件的详细配置、属性、方法和事件信息。

本章将涵盖以下主题：

+   基组件类

+   布局重新审视

+   标签面板和轮播组件

+   表单面板组件

+   消息框和弹幕

+   地图组件

+   列表和嵌套列表组件

+   在哪里查找有关组件的更多信息

# 基组件类

当我们谈论 Sencha Touch 中的组件时，我们通常是指按钮、面板、滑块、工具栏、表单字段和其他我们可以在屏幕上看到的实际项目。然而，所有这些组件都继承自一个具有惊人原创名称的单一基础组件`component`。这显然可能会导致一些混淆，所以我们将把这个称为`Ext.Component`。

理解最重要的一点是，你并不总是直接使用`Ext.Component`。它更常作为 Sencha Touch 中所有其他组件的构建块。然而，熟悉基组件类是很重要的，因为只要它能做，所有其他组件都能做。学习这个类可以让你在所有其他事情上有一个巨大的优势。`Ext.Component`一些最有用的配置选项如下：

+   `border`

+   `cls`

+   `disabled`

+   `height`/`width`

+   `hidden`

+   `html`

+   `margin`

+   `padding`

+   `scroll`

+   `style`

+   `ui`

像我们将在本章后面覆盖的其他组件一样，继承自基组件类，它们都会有这些相同的配置选项。这些配置中最关键的是`layout`。

# 再次审视布局

当你开始创建自己的应用程序时，你需要充分理解不同的布局如何影响你在屏幕上看到的内容。为此，我们将从演示应用程序开始，展示不同的布局是如何工作的。

### 注意

为了这个演示应用程序的目的，我们将一次创建不同的组件，作为单独的变量。这样做是为了可读性，不应被视为最佳编程风格。记住，以这种方式创建的任何项目都会占用内存，即使用户从未查看组件：

```js
var myPanel = Ext.create('Ext.Panel', { …
```

始终创建你的组件，使用`xtype`属性，在你的主容器内，如下面的代码片段所示，是一个更好的做法：

```js
items: [{ xtype: 'panel', …
```

这允许 Sencha Touch 在需要时渲染组件，而不是在页面加载时一次性渲染所有组件。

## 创建一个卡片布局

首先，我们将创建一个简单的应用程序，其包含一个配置为使用`card`布局的容器：

```js
var myApp = Ext.create('Ext.Application', {
    name:'TouchStart',
    launch:function () {
        var mainPanel = Ext.create('Ext.Container', {
            fullscreen:true,
            layout:'card',
            cardSwitchAnimation:'slide',
            items:[hboxTest]
        });

        Ext.Viewport.add(mainPanel);
    }
});
```

这设置了一个名为`mainPanel`的单一容器，具有`card`布局。这个`mainPanel`容器是我们将在本节中添加我们布局示例容器的剩余部分的地方。

`card`布局将其项目安排得类似于卡片堆叠。这些卡片中只有一张是激活的并一次显示。`card`布局将任何额外的卡片保留在后台，并在面板接收到`setActiveItem()`命令时仅创建它们。

列表中的每个项目可以通过使用`setActiveItem(n)`激活，其中*n*是项目编号。这可能会有些令人困惑，因为项目的编号是基于零的，这意味着你从 0 开始计数，而不是从 1 开始。例如，如果你想要激活列表中的第四个项目，你会使用：

```js
mainPanel.setActiveItem(3);
```

在此案例中，我们起初只有一个名为`hboxTest`的单一卡片/项目。我们需要添加这个容器以使我们的程序运行。

## 创建一个 hbox 布局

在前面的部分的代码中，在`var mainPanel = Ext.create('Ext.Container', {`行上方，添加以下代码：

```js
var hboxTest = Ext.create('Ext.Container', {
    layout:{
        type:'hbox',
        align:'stretch'
    },
    items:[
        {
            xtype:'container',
            flex:1,
            html:'My flex is 1',
            margin:5,
            style:'background-color: #7FADCF'
        },
        {
            xtype:'container',
            flex:2,
            html:'My flex is 2',
            margin:5,
            style:'background-color: #7FADCF'
        },
        {
            xtype:'container',
            width:80,
            html:'My width is 80',
            margin:5,
            style:'background-color: #7FADCF'
        }
    ]
});
```

这给了我们一个具有`hbox`布局和三个子项目的容器。

### 提示

**子项与父项**

在 Sencha Touch 中，我们经常发现自己处理非常大量的项目，这些项目被嵌套在容器中，而这些容器又被嵌套在其他容器中。通常，将容器称为其包含的任何项目的父容器是有帮助的。这些项目被称为容器的子项目。

`hbox`布局将其项目横向堆叠，并使用`width`和`flex`值来确定其每个子项目将占据多少横向空间。`align: 'stretch'`配置导致项目拉伸以填充所有可用的垂直空间。

![创建一个 hbox 布局](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_04_01.jpg)

你应该尝试调整`flex`和`width`值，看看它们如何影响子容器的尺寸。你还可以更改`align`（`center`、`end`、`start`和`stretch`）的可选配置选项，以查看可用的不同选项。完成之后，让我们继续向我们的卡片布局添加更多项目。

## 创建一个 vbox 布局

在我们的`var hboxTest = Ext.create('Ext.Container',{`行上方，添加以下代码：

```js
var vboxTest = Ext.create('Ext.Container', {
    layout:{
        type:'vbox',
        align:'stretch'
    },
    items:[
        {
            xtype:'container',
            flex:1,
            html:'My flex is 1',
            margin:5,
            style:'background-color: #7FADCF'
        },
        {
            xtype:'container',
            flex:2,
            html:'My flex is 2',
            margin:5,
            style:'background-color: #7FADCF'
        },
        {
            xtype:'container',
            height:80,
            html:'My height is 80',
            margin:5,
            style:'background-color: #7FADCF'
        }
    ]
});
```

这代码与我们的之前的`hbox`代码几乎一模一样，一个具有三个子容器的容器。然而，这个父容器使用`layout: vbox`，`items`列表中的第三个子容器使用`height`而不是`width`。这是因为`vbox`布局是垂直堆叠其项目，并使用`height`和`flex`的值来确定子项目将占据多少空间。在这个布局中，`align: 'stretch'`配置导致项目伸展以填满水平空间。

现在我们已经有了我们的`vbox`容器，我们需要将其添加到我们主`layoutContainer`中的项目。将`layoutContainer`中的`items`列表更改为以下内容：

```js
items: [hboxTest, vboxTest]
```

如果我们现在运行代码，它看起来会和之前一模一样。这是因为我们的卡片布局`layoutContainer`中只能有一个活动项目。您可以通过向我们的`layoutContainer`添加以下配置来设置`layoutContainer`显示我们的新`vbox`：

```js
activeItem: 1,
```

记住我们的项目是从零开始编号的，所以项目`1`是我们列表中的第二个项目：`items: [hboxTest, vboxTest]`。

现在您应该能够看到我们应用程序的`vbox`布局：

![创建一个 vbox 布局](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_04_02.jpg)

与`hbox`一样，您应该花点时间调整`flex`和`width`值，看看它们如何影响容器的大小。您还可以更改`align`（`center`、`end`、`start`和`stretch`）的可选配置选项，以查看不同的选项。完成后，让我们继续向我们的`card`布局添加更多项目。

## 创建合适的布局

`fit`布局是最基本的布局，它只是使任何子项目填满父容器。虽然这看起来相当基础，但它也可能有一些 unintended consequences，正如我们在例子中所见。

在我们之前的`var vboxTest = Ext.create(`'`Ext.Container', {`行上，添加以下代码：

```js
var fitTest = Ext.create('Ext.Container', {
    layout:'fit',
    items:[
        {
            xtype:'button',
            ui:'decline',
            text:'Do Not Press'
        }
    ]
});
```

这是一个具有`fit`布局的单容器和按钮。现在，我们只需要在我们的主`layoutContainer`组件上设置`activeItem`配置，将`activeItem: 1`更改为`activeItem: 2`。

如果您现在重新加载页面，您将看到我们所说的 unintended consequences：

![创建一个适合布局](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_04_03.jpg)

正如您所看到的，我们的按钮已经扩展到填满整个屏幕。我们可以通过为按钮（以及我们放置在这个容器中的任何其他项目）声明一个特定的高度和宽度来更改此情况。然而，适合布局通常最适合单个项目，该项目旨在占据整个容器。这使得它们成为子容器的一个很好的布局，在这种情况下，父容器控制整体大小和位置。

让我们看看这可能如何工作。

## 增加复杂度

在这个例子中，我们将创建一个嵌套容器并添加到我们的卡片堆叠中。我们还将添加一些按钮，以便更容易切换卡片堆叠。

我们两个新容器是我们当前应用程序中已经拥有的变体。第一个是我们`hbox`布局的副本，有几个小的变化：

```js
var complexTest = Ext.create('Ext.Container', {
    layout:{
        type:'vbox',
        align:'stretch'
    },
    style:'background-color: #FFFFFF',
    items:[
        {
            xtype:'container',
            flex:1,
            html:'My flex is 1',
            margin:5,
            style:'background-color: #7FADCF'
        },
        hboxTest2,
        {
            xtype:'container',
            height:80,
            html:'My height is 80',
            margin:5,
            style:'background-color: #7FADCF'
        }
    ]
});
```

你可以复制并粘贴我们旧的`vboxTest`代码，并将第一行更改为说`complexTest`而不是`vboxTest`。你还需要删除我们`items`列表中的第二个容器（包括所有括号）并用`hboxTest2`替换它。这是我们将在其中嵌套具有自己布局的另一个容器的位置。

现在，我们需要通过复制我们之前的`hboxTest`代码来定义`hboxTest2`，并进行一些小的修改。你需要将这段新代码粘贴到你放置`complexTest`代码的地方；否则，在我们实际定义它之前尝试使用`hboxTest2`时，你会得到错误：

```js
var hboxTest2 = Ext.create('Ext.Container', {
    layout:{
        type:'hbox',
        align:'stretch'
    },
    flex:2,
    style:'background-color: #FFFFFF',
    items:[
        {
            xtype:'container',
            flex:1,
            html:'My flex is 1',
            margin:5,
            style:'background-color: #7FADCF'
        },
        {
            xtype:'container',
            flex:2,
            html:'My flex is 2',
            margin:5,
            style:'background-color: #7FADCF'
        },
        {
            xtype:'container',
            width:80,
            html:'My width is 80',
            margin:5,
            style:'background-color: #7FADCF'
        }
    ]
});
```

粘贴代码后，你需要将变量名更改为`hboxTest2`，并且我们需要为主父容器添加一个`flex`配置。由于这个容器嵌套在我们的`vbox`容器中，`flex`配置需要定义`hboxTest2`将占据多少空间。

在我们查看这个新的复杂布局之前，让我们通过添加一些按钮来简化我们的工作，以便在各种布局卡之间切换。

定位`mainPanel`，在它下面，定义`items`列表的地方，在`items`列表的最上面添加以下代码：

```js
{
    xtype:'toolbar',
    docked:'top',
    defaults:{
        xtype:'button'
    },
    items:[
        {
            text:'hbox',
            handler:function () {
                mainPanel.setActiveItem(0);
            }
            text:'vbox',
            handler:function () {
                mainPanel.setActiveItem(1);
            }
        },
        {
            text:'fit',
            handler:function () {
                mainPanel.setActiveItem(2);
            }
        },
        {
            text:'complex',
            handler:function () {
                mainPanel.setActiveItem(3);
            }
        }
    ]
}
```

这段代码在`mainPanel`的顶部添加了一个工具栏，每个布局卡片都有一个按钮。

### 提示

在 Sencha Touch 的早期版本中，`toolbar`项是独立于其他项定义的，并使用一个名为`dock`的配置来控制其位置。在当前版本中，`toolbar`组件与其他项一起内联定义，而工具栏的位置则由`docked`配置控制。

每个按钮都有一个文本配置，作为按钮的标题，还有一个`handler`配置。`handler`配置定义了按钮被点击时会发生什么。对于我们每个按钮，我们在代码中使用之前设置的`mainPanel`变量：

```js
var mainPanel = Ext.create('Ext.Container', {…
```

这让我们可以使用容器及其`card`布局可用的任何方法。在每按钮的代码中，我们通过使用以下代码行来设置活动项（哪个标签页是可见的）：

```js
mainPanel.setActiveItem(x);
```

在此情况下，`x`值将被替换为我们想要激活的项的索引（记住这些是按顺序排列的，从 0 开始，而不是 1）。

注意我们还在`mainPanel`组件的`activeItem`初始配置选项中留下了空位。这将控制我们的应用程序启动时显示哪个项。

如果你刷新页面，你应该能够点击按钮并看到我们的各种布局，包括新的复杂布局。

![增加复杂性](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_04_04.jpg)

从这个例子中，您可以看到我们的`vbox`布局将窗口分为三行。第二行的`hbox`布局将其分为三列。使用这些嵌套布局类型可以非常容易地创建传统布局，例如电子邮件或社交网络应用程序中使用的布局。

![增加复杂性](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_04_05.jpg)

在这个例子中，我们有一个典型电子邮件应用程序的布局。这个布局可以从概念上分解为以下几个部分：

+   具有**工具栏**菜单的应用程序容器和一个称为**主**的单个容器，具有适合布局。

+   **主**容器将有一个`hbox`布局和两个子容器，分别称为**左侧**和**右侧**。

+   **左侧**容器将有一个`flex`值为`1`和一个`vbox`布局。它将有两个子容器，分别称为**邮箱**（具有`flex`为`3`）和**活动**（具有`flex`为`1`）。

+   **右侧**容器将有一个`flex`值为`3`和一个`vbox`布局。它还将有两个子容器，分别称为**消息**（具有`flex`为`1`）和**消息**（具有`flex`为`2`）。

构建此类容器布局是一种良好的实践。要查看此容器布局的示例代码，请查看代码包中的`TouchStart2b.js`文件。创建这些基本布局作为模板以快速启动构建您未来的应用程序也是一个好主意。

现在我们已经更好地了解了布局，让我们来看看我们可以在布局中使用的某些组件。

# 标签面板和轮播组件

在我们最后一个应用程序中，我们使用按钮和`card`布局创建了一个可以在不同的子项之间切换的应用程序。虽然应用程序经常需要以这种方式（使用您自己的按钮和代码）进行编程，但您也可以选择让 Sencha Touch 自动设置此操作，使用`TabPanel`或`Carousel`。

## 创建标签面板组件

当您需要让用户在多个视图之间切换时，`TabPanel`组件非常有用，例如联系人、任务和设置。`TabPanel`组件自动生成布局的导航，这使其成为应用程序主要容器的非常有用功能。

在我们第二章的早期示例应用程序中，*创建一个简单应用程序*，使用了一个简单的`TabPanel`来形成我们应用程序的基础。以下是一个类似的代码示例：

```js
Ext.application({
    name:'TouchStart',
    launch:function () {
        var myTabPanel = Ext.create('Ext.tab.Panel', {
            fullscreen:true,
            tabBarPosition:'bottom',
            items:[
                {
                    xtype:'container',
                    title:'Item 1',
                    fullscreen:false,
                    html:'TouchStart container 1',
                    iconCls:'info'
                },
                {
                    xtype:'container',
                    html:'TouchStart container 2',
                    iconCls:'home',
                    title:'Item 2'
                },
                {
                    xtype:'container',
                    html:'TouchStart container 3',
                    iconCls:'favorites',
                    title:'Item 3'
                }
            ]
        });
        Ext.Viewport.add(myTabPanel);
    }
});
```

在这段代码中，`Ext.tab.Panel`会自动生成一个卡片布局；您不需要声明一个布局。您可能希望为组件声明一个`tabBarPosition`值。这是您的标签将自动出现的地方；默认情况下在屏幕的顶部。

这将为`items`列表中的每个子项生成一个大的正方形按钮。按钮还将使用`iconCls`值分配一个图标给按钮。`title`配置用于给按钮命名。

### 提示

有关可用的图标和样式信息，请参阅上一章关于`tab panel`的更多信息。还应注意的是，这些图标只在`tabBarPosition`值设置为`bottom`时使用。

如果你将`tabBarPosition`值设置为顶部（或者留空），它会使按钮变小且变圆。它还会消除图标，即使你在子项目中声明了`iconCls`值。

![创建一个 TabPanel 组件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_04_06.jpg)

## 创建一个 Carousel 组件

`Carousel`组件与`tabpanel`类似，但它生成的导航更适合于幻灯片展示等事物。它可能不会像应用程序的主界面那样出色，但它确实作为在一个可滑动的容器中显示多个项目的方式表现良好。

与`tabpanel`类似，`Carousel`收集其子项目，并自动将它们安排在一个`card`布局中。实际上，我们实际上可以对我们之前的代码进行一些简单的修改，使其成为一个`Carousel`组件：

```js
Ext.application({
    name:'TouchStart',
    launch:function () {
        var myCarousel = Ext.create('Ext.carousel.Carousel', {
            fullscreen:true,
            direction:'horizontal',
            items:[
                {
                    html:'TouchStart container 1'
                },
                {
                    html:'TouchStart container 2'
                },
                {
                    html:'TouchStart container 3'
                }
            ]
        });
        Ext.Viewport.add(myCarousel);
    }
});
```

我们首先使用`Ext.create`创建了一个新的`Ext.carousel.Carousel`类，而不是一个新的`Ext.tab.Panel`类。我们还添加了一个`direction`配置，可以是`horizontal`（从左到右滚动）或`vertical`（向上或向下滚动）。

我们移除了停靠工具栏，因为正如我们将看到的，`Carousel`不需要它。我们还将每个子项目的图标类和标题移除，原因相同。最后，我们移除了`xtype`配置，因为`Carousel`组件会为每个子项目自动创建一个`Ext.Container`类。

![创建一个 Carousel 组件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_04_07.jpg)

与`tabpanel`不同，`carousel`没有按钮，只在底部有一系列圆点，每个子项目都有一个圆点。虽然使用圆点进行导航是可能的，但`carousel`组件会自动设置以响应触摸屏上的滑动。你可以在浏览器中通过点击并按住鼠标指针，同时水平移动它来复制这个手势。如果你在`carousel`中声明了一个`direction: vertical`配置，你还可以垂直滑动以在子项目之间移动。

与章节开头我们的示例中的卡片布局类似，`tabpanel`和`carousel`组件都理解`activeItem`配置。

这让你可以设置应用程序首次加载时显示哪个项目。此外，它们都理解`setActiveItem()`方法，该方法允许你在应用程序加载后更改选中的子项目。

`Carousel`组件还有`next()`和`previous()`方法，允许你按顺序遍历项目。

需要注意的是，由于`tabpanel`和`carousel`都继承自`Ext.Container`，它们也理解容器理解的所有方法和配置。

与容器一样，`tabpanel`和`carousel`将是大多数应用程序的主要起点。然而，在某个时候，你可能还想使用另一种容器：`FormPanel`组件。

# 创建 FormPanel 组件

`FormPanel`组件是`Ext.Container`组件的一个非常特殊的版本，正如名称暗示的那样，它被设计用来处理表单元素。与面板和容器不同，您不需要为`formpanel`指定布局。它自动使用自己的特殊表单布局。

创建`formpanel`组件的基本示例如下：

```js
var form = Ext.create('Ext.form.FormPanel', {
 items: [
  {
   xtype: 'textfield',
   name : 'first',
   label: 'First name'
  },
  {
   xtype: 'textfield',
   name : 'last',
   label: 'Last name'
  },
  {
   xtype: 'emailfield',
   name : 'email',
   label: 'Email'
  }
 ]
});
```

在这个例子中，我们只是创建了一个面板，并为表单中的每个字段添加了项目。我们的`xtype`告诉表单要创建什么类型的字段。我们可以将此添加到我们的`carousel`中，替换我们的第一个容器，如下所示：

```js
Ext.application({
    name:'TouchStart',
    launch:function () {
        var myCarousel = Ext.create('Ext.carousel.Carousel', {
            fullscreen:true,
            direction:'horizontal',
            items:[
                form, {
                    html:'TouchStart container 2'
                }, {
                    html:'TouchStart container 3'
                }]
        });
        Ext.Viewport.add(myCarousel);
    }
});
```

![创建 FormPanel 组件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_04_08.jpg)

任何曾经在 HTML 中处理表单的人都应该熟悉所有标准的字段类型，因此熟悉标准 HTML 表单的人都会理解以下的`xtype`属性名称：

+   `checkboxfield`

+   `fieldset`

+   `hiddenfield`

+   `passwordfield`

+   `radiofield`

+   `selectfield`

+   `textfield`

+   `textareafield`

这些字段类型在很大程度上与它们的 HTML 同类相匹配。Sencha Touch 还提供了一些特殊的文本字段，可以帮助验证用户输入：

+   `emailfield`：此字段只接受有效的电子邮件地址，在 iOS 设备上，它会弹出另一个电子邮件地址和 URL 友好型键盘

+   `numberfield`：此字段只接受数字

+   `urlfield`：此字段只接受有效的网络 URL，并且还会弹出特殊键盘

这些特殊字段只有在输入有效时才会允许提交操作。

所有这些基本表单字段都继承自主容器类，因此它们具有所有标准的`height`、`width`、`cls`、`style`和其他容器配置选项。

它们还有一些字段特定的选项：

+   `label`：这是与字段一起使用的文本标签

+   `labelAlign`：这是标签出现的位置；可以是顶部或左侧，默认为左侧

+   `labelWidth`：这告诉我们标签应该有多宽

+   `name`：这对应于 HTML 的 name 属性，这是字段值提交的方式

+   `maxLength`：这告诉我们字段中可以使用多少个字符

+   `required`：这告诉我们字段是否为必须的，以便表单能够提交

### 小贴士

**表单字段位置**

虽然`FormPanel`通常是在显示表单元素时使用的容器，但它理解`submit()`方法，该方法将通过 AJAX 请求或`POST`提交表单值。

如果您在不是`FormPanel`组件的东西中包含一个表单字段，您将需要使用您自己的自定义 JavaScript 方法来获取和设置字段的值。

除了标准的 HTML 字段外，Sencha Touch 中还提供了一些特殊字段，包括`DatePicker`、`slider`、`spinner`和`toggle`字段。

## 添加日期选择器组件

`datepickerfield`组件（这个名称正确吗？）在表单中放置一个可点击的字段，字段右侧有一个小三角形。

你可以在`emailfield`项之后添加以下代码来向我们的表单中添加一个日期选择器：

```js
{
 xtype: 'datepickerfield',
 name : 'date',
 label: 'Date'
}
```

当用户点击字段时，将出现一个`DatePicker`组件，用户可以通过旋转月份、日期和年份轮盘，或通过向上或向下滑动来选择日期。

![添加日期选择器组件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_04_09.jpg)

`datepickerfield`还具有`configs`选项，如下所示：

+   `yearFrom`：日期选择器的开始年份。

+   `yearTo`：日期选择器的结束年份。

+   `slotOrder`：使用字符串数组来设置插槽顺序。默认值为`['month', 'day', 'year']`。

## 添加滑块、微调器和切换按钮

滑块允许从指定的数值范围内选择一个值。`sliderfield`值显示一个带有指示器的条，可以通过水平滑动来选择值。这可以用于设置音量、颜色值和其他范围选项。

与滑块类似，微调器允许从指定的数值范围内选择一个值。`spinnerfield`值显示一个带有数字值和**+**和**-**按钮的表单字段。

切换按钮允许在 1 和 0 之间进行简单选择（开和关），并在表单上显示一个切换风格的按钮。

在以下组件列表的末尾添加以下新组件：

```js
{
 xtype: 'sliderfield',
 label: 'Volume',
 value: 5,
 minValue: 0,
 maxValue: 10
},
{
 xtype: 'togglefield',
 name : 'turbo',
 label: 'Turbo'
},
{
 xtype: 'spinnerfield',
 minValue: 0,
 maxValue: 100,
 incrementValue: 2,
 cycle: true
}
```

![添加滑块、微调器和切换按钮](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_04_10.jpg)

我们的`sliderfield`和`spinnerfield`具有`minValue`和`maxValue`配置选项。我们还向`spinnerfield`添加了一个`incrementValue`属性，当点击**+**或**-**按钮时，它将按`2`的增量移动。

### 注意

我们将在第六章中介绍表单的发送和接收数据，获取数据。

# 消息框和表单组件

在某些时候，您的应用程序可能需要向用户反馈、询问用户问题或提醒用户事件。这就是`MessageBox`和`Sheet`组件发挥作用的地方。

## 创建消息框组件

`MessageBox`组件在页面上创建一个窗口，可用于显示警告、收集信息或向用户展示选项。`MessageBox`可以通过三种不同的方式调用：

+   `Ext.Msg.alert`接受一个标题、一些消息文本，以及一个可选的回调函数，当点击警告框的**确定**按钮时调用。

+   `Ext.Msg.prompt`带有标题、一些消息文本和一个当按下**OK**按钮时调用的回调函数。该`prompt`命令创建一个文本字段并自动添加到窗口中。在此例中，函数接收字段的文本进行处理。

+   `Ext.Msg.confirm`带有标题、一些消息文本和一个当任一按钮被按下时调用的回调函数。

### 提示

**回调函数**

回调函数是一个在用户或代码采取特定行动时自动调用的函数。这是程序员让代码说“当你完成这个，回调我并告诉我你做了什么”的基本方式。这个回调允许程序员根据函数中发生的事情做出额外的决定。

让我们尝试一些例子，从一个简单的消息框开始：

```js
Ext.application({
    name:'TouchStart',
    launch:function () {
        var main = Ext.create('Ext.Container', {
            fullscreen:true,
            items:[
                {
                    docked:'top',
                    xtype:'toolbar',
                    ui:'light',
                    items:[
                        {
                            text:'Panic',
                            handler:function () {
                                Ext.Msg.alert('Don\'t Panic!', 'Keep Calm. Carry On.');
                            }
                        }
                    ]
                }
            ]
        });

        Ext.Viewport.add(main);
    }
});
```

这段代码设置了一个带有工具栏和单个按钮的简单面板。按钮有一个处理程序，使用`Ext.Msg.alert()`来显示我们的消息框。

### 提示

**转义引号**

在我们的上一个示例中，我们使用字符串`Don\'t Panic`作为消息框的标题。`\`告诉 JavaScript 我们的第二个单引号是字符串的一部分，而不是字符串的结束。正如在示例中看到的那样，`\`在我们的消息框中消失了。

![创建一个 MessageBox 组件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_04_11.jpg)

现在，让我们在我们的`toolbar`组件中的`items`中添加一个第二个按钮，以`Ext.Msg.prompt`样式的消息框：

```js
{
    text:'Greetings',
    handler:function () {
        Ext.Msg.prompt('Greetings!', 'What is your name?', function (btn, text) {
            Ext.Msg.alert('Howdy', 'Pleased to meet you ' + text);
        });
    }
}
```

这个消息框有点更复杂。我们创建了一个带有标题、信息和函数的`Ext.Msg.prompt`类。提示将自动创建我们的文本字段，但我们需要使用函数来确定用户在字段中输入的文本要做什么。

该函数接收按钮的值和文本的值。我们的函数抓取文本并创建一个新的警告框来响应，还包括用户在字段中输入的名称。

![创建一个 MessageBox 组件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_04_12.jpg)

`MessageBox`的`Ext.Msg.confirm`类用于用户需要做出决定，或确认系统将要采取的特定行动。

让我们把我们下面的组件添加到`toolbar`组件的`items`列表中：

```js
{
 text: 'Decide',
 handler: function() {
  Ext.Msg.confirm('It\'s Your Choice...', 'Would you like to proceed?', function(btn) {
   Ext.Msg.alert('So be it!', 'You chose '+btn);
  });
 }
}
```

与`Ext.Msg`组件的提示函数类似，确认版本也带有标题、信息和回调函数。回调函数接收用户按下的按钮（作为值`btn`），然后可以用来确定系统接下来应该采取哪些步骤。

在这种情况下，我们只是弹出一个警告框来显示用户所做的选择。你也可以使用`if...then`语句来根据点击哪个按钮采取不同的行动。

![创建一个 MessageBox 组件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_04_13.jpg)

## 创建一个 Sheet 组件

`Sheet`组件与`Ext.Msg`组件类似，通常用于在屏幕上弹出新的信息或选项。它也通过出现在现有屏幕之上来展示这些新信息。与`MessageBox`一样，在`Sheet`关闭或以某种方式响应之前，无法进行进一步的操作。

让我们在我们的`toolbar`组件的`items`部分添加另一个按钮。这个按钮将弹出一个新的`Sheet`组件：

```js
{
    text:'Sheet',
    handler:function () {
        var mySheet = Ext.create('Ext.Sheet', {
            height:250,
            layout:'vbox',
            stretchX:true,
            enter:'top',
            exit:'top',
            items:[
                {
                    xtype:'container',
                    layout:'fit',
                    flex:1,
                    padding:10,
                    style:'color: #FFFFFF',
                    html:'A sheet is also a panel. It can do anything the panel does.'
                },
                {
                    xtype:'button',
                    height:20,
                    text:'Close Me',
                    handler:function () {
                        this.up('sheet').hide();
                    }
                }
            ],
            listeners:{
                hide:function () {
                    this.destroy();
                }
            }
        });
    }
}
Ext.Viewport.add(mySheet);
mySheet.show();
```

这里有很多新东西，但有些应该看起来很熟悉。我们的按钮从按钮要显示的`text`值开始，然后创建了一个`handler`值，告诉按钮在点击时应该做什么。

然后我们创建了一个新的`Ext.Sheet`类。由于`Sheet`继承自面板，我们有一些熟悉的配置选项，如`height`和`layout`，但我们还有一些新的选项。`stretchX`和`stretchY`配置将导致`Sheet`组件扩展到屏幕的整个宽度（`stretchX`）或高度（`stretchY`）。

`enter`和`exit`的值控制了`Sheet`组件如何在屏幕上滑动到位。你可以使用`top`、`bottom`、`left`和`right`。

我们的表单使用`vbox`布局，包含两个项目，一个用于我们的文本的`container`对象和一个用于用户阅读完毕后隐藏`Sheet`组件的`button`对象。`button`组件本身包含了一段有趣的代码：

```js
this.up('sheet').hide();
```

当我们提到`this`关键字时，我们是指`button`对象，因为函数发生在`button`本身内部。然而，我们实际上需要到达包含按钮的`Sheet`，以便在按钮被点击时关闭它。为了做到这一点，我们使用了一个巧妙的小方法，叫做`up`。

`up`方法基本上会向上遍历代码结构，寻找所需的项。在这种情况下，我们通过`xtype`进行搜索，并请求搜索中遇到的第一个表单。然后我们可以使用`hide()`方法隐藏表单。

### 提示

**Ext.ComponentQuery**

当你想要获取一个组件，并且已经给它指定了一个 ID，你可以使用`Ext.getCmp()`，正如我们之前讨论的那样。如果你想要获取多个组件，或者根据它相对于另一个组件的位置来获取一个组件，你可以使用`query()`、`up()`和`down()`。要隐藏一个位于面板内的工具栏，你可以使用以下代码：

```js
panel.down('toolbar').hide();
```

此外，要获取您应用程序中所有的工具栏，您可以使用以下命令：

```js
var toolbars = Ext.ComponentQuery.query('toolbar');
```

一旦我们隐藏了`Sheet`组件，我们仍然有一个问题。现在`Sheet`组件是隐藏的，但它仍然存在于页面中。如果我们返回并再次点击按钮，而不销毁`Sheet`，我们就会不断创建越来越多的新的表单。这意味着越来越多的内存使用，这也意味着你的应用程序最终会走向死亡螺旋。

我们需要做的是确保我们清理好自己的东西，这样表格就不会堆积起来。这让我们来到了我们代码的最后部分和最后的`listeners`配置：

```js
listeners: {
 hide: {
  fn: function(){ this.destroy(); }
 }
}
```

监听器监听特定事件，在这个例子中，是`hide`事件。当`hide`事件发生时，监听器然后运行`fn`配置中列出的附加代码。在这个例子中，我们使用`this.destroy();`来销毁`Sheet`组件。

在下一章，我们将详细介绍监听器和事件。

### 提示

**关于 this 变量的一点说明**

当我们在程序中使用变量`this`时，它总是指的是当前项目。在前面的例子中，我们在两个不同的地方使用了`this`，它指的是两个不同的对象。在我们最初的用法中，我们在按钮的配置选项中，所以`this`指的是按钮。当我们后来将`this`作为监听器的一部分时，我们在表格的配置中，所以`this`指的是表格。

如果您发现自己感到困惑，使用`console.log(this);`可以非常有帮助，以确保您正在 addressing 正确的组件。

你现在应该能够点击**表格**按钮并查看我们新的表格了。

![创建一个表格组件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_04_14.jpg)

## 创建行动表格组件

`ActionSheet`是标准表格的一种变体，设计用于显示一系列按钮。当您只需要用户做出快速决策，有明显的选择且不需要过多解释时，这是一个很好的选择。例如，删除确认屏幕就是行动表格的一个很好的用途。

让我们在我们的布局中添加一个新的按钮，用于弹出一个用于删除确认的`ActionSheet`组件：

```js
{
 text: 'ActionSheet',
 handler: function() {
  var actionSheet = Ext.create('Ext.ActionSheet', {
   items: [
   {
    text: 'Delete',
    ui  : 'decline'
   },
   {
    text: 'Save',
    ui  : 'confirm'
   },
   {
    text: 'Cancel',
    handler: function() {
     this.up('actionsheet').hide();
    }
   }
   ],
   listeners: {
    hide: {
     fn: function(){ this.destroy(); }
    }
   }
  });
  Ext.Viewport.add(actionSheet);
   actionSheet.show();
  }
}
```

`ActionSheet`对象以与我们的上一个表格示例非常相似的方式创建。然而，行动表格假设其所有项目都是按钮，除非您指定了不同的`xtype`值。

我们的例子有三个简单的按钮：**删除**、**保存**和**取消**。**取消**按钮将隐藏`ActionSheet`组件，其他两个按钮只是装饰。

与我们的上一个示例一样，我们希望在隐藏它时也销毁`ActionSheet`组件。这可以防止`ActionSheet`组件的副本在后台堆积并造成问题。

点击我们应用程序中的**行动表格**按钮现在应该会显示我们创建的行动表格：

![创建一个行动表格组件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_04_15.jpg)

# 创建一个 Map 组件

`Map`组件是一个非常特殊的容器，旨在与 Google Maps API 一起使用。该容器可用于显示 Google Maps 显示的大部分信息。

我们将为这个部分创建一个`Map`容器的非常基础的例子，但我们将在此返回第九章，*高级主题*，并介绍一些更高级的技巧。

为了这个例子，让我们创建一个新的 JavaScript 文件：

```js
Ext.application({
 name: 'TouchStart',
 launch: function() {
  var map = Ext.create('Ext.Container', {
  fullscreen: true,
  layout: 'fit',
  items: [
   {
    xtype: 'map',
    useCurrentLocation: true
   }
  ]
  });
  this.viewport = map;
 }
});
```

在这个例子中，我们只是创建了一个带有单个项目的`Container`组件。这个项目是一个地图，并且配置了`useCurrentLocation: true`。这意味着浏览器将尝试使用我们的当前位置作为地图显示的中心。当这种情况发生时，用户总是会被警告，并且会被提供拒绝的选项。

在我们了解这是如何工作的之前，我们需要对我们的标准`index.html`文件进行一项更改。在包含我们其他 JavaScript 文件的行下面，我们需要包含来自 Google 的一个新文件：

```js
  <!-- Google Maps API -->
  <script type="text/javascript" src="img/js?sensor=true"></script>
```

这将包括我们使用 Google Maps API 所需的所有函数。

如果您重新加载页面，系统会询问您是否允许当前位置被应用程序使用。一旦您接受，您应该会看到一个新的地图，您的当前位置在中心。

![创建一个地图组件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_04_16.jpg)

您还可以使用`map`属性以及`mapOptions`配置选项来访问 Google Maps 的其他功能。我们将在第九章*高级主题*中探索一些这些选项，并且进行更详细的讲解。

### 提示

**Google Maps API** **文档**

完整的 Google Maps API 文档可以在[`code.google.com/apis/maps/documentation/v3/reference.html`](http://code.google.com/apis/maps/documentation/v3/reference.html)找到。

# 创建列表

Sencha Touch 提供了几种不同的`list`组件。每个这些`list`组件都由三个基本部分组成：

+   **列表面板**：它负责收集其配置选项中的其他项目。

+   **XTemplate**：这决定了列表中每一行的显示方式。

+   **数据存储**：这里包含将在列表中使用的所有数据。

### 注意

还应该注意的是，一个存储区可以（并且通常会）与一个模型相关联，以定义存储区的数据记录。然而，也可以简单地将字段作为存储区的一部分定义，这在接下来的例子中我们会这样做。我们将在本书关于数据的章节中介绍模型和存储区。

在我们第一个例子中，我们创建了一个与这个类似的列表对象：

```js
Ext.application({
name: 'TouchStart',
launch: function() {

var myDudeList = Ext.create('Ext.Container', {
 fullscreen: true,
 layout: 'fit',
 items: [
 {
   xtype: 'list',
   itemTpl: '{last}, {first}',
   store: Ext.create('Ext.data.Store', {
    fields: [
     {name: 'first', type: 'string'},
     {name: 'last', type: 'string'}
    ],
    data: [
     {first: 'Aaron', last: 'Karp'},
     {first: 'Baron', last: 'Chandler'},
     {first: 'Bryan', last: 'Johnson'},
     {first: 'David', last: 'Evans'},
     {first: 'John', last: 'Clark'},
     {first: 'Norbert', last: 'Taylor'}
    ]
   })
 }]
});
Ext.Viewport.add(myDudeList);
}
});
```

我们首先像以前一样创建我们的应用程序。然后我们创建了一个带有列表项目的单个容器。列表项目需要一个数据存储，而数据存储需要一组字段或数据模型。在这个例子中，我们将使用一组字段以简化操作。

```js
fields: [
 {name: 'first', type: 'string'},
 {name: 'last', type: 'string'}
]
```

这段代码为我们每个数据记录提供了两个潜在的值：`first`和`last`。它还告诉我们每个值的`type`；在这个例子中，两个都是`strings`。这使得数据存储知道如何处理数据的排序，并且让 XTemplate 知道数据如何被使用。

在这个示例中，我们设置了`itemTpl: '{last}, {first}'`。这个`itemTpl`值作为模板或 Sencha Touch 中的 XTemplate。XTemplate 从存储中的每个记录中获取数据，并告诉列表显示每个数据记录：姓氏，后面跟着一个逗号，然后是名字。我们将在第七章，*获取数据外*中详细介绍 XTemplates。

![创建列表](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_04_17.jpg)

请注意，目前我们的列表没有按字母顺序排序。我们需要在模型的配置选项下方添加一个排序器到存储中：

```js
sorters: 'last'
```

这将按`last`（人的姓氏）值对我们的列表进行排序。

## 添加分组列表

分组列表也常见于许多应用程序中。通常，分组用于人员或其他字母顺序的物品列表。电话簿或长字母顺序数据列表是分组列表的好地方。分组列表在屏幕上放置一个`indexBar`组件，允许用户跳转到列表中的特定点。

为了对我们的当前列表进行分组，我们需要向我们的`list`组件添加两个配置设置。在声明`xtype: 'list'`下方添加以下代码：

```js
grouped: true,
indexBar: true,
```

我们还需要向我们的存储添加一个函数，以获取显示我们字母`indexBar`的字符串。在`store`组件的`sorters`配置处替换以下代码：

```js
grouper: {
  groupFn : function(record) {
    return record.get('last').substr(0, 1);
  },
  sortProperty: 'last'
}
```

这段代码使用`record.get('last').substr(0,1)`来获取我们联系人的姓氏的第一个字母。这让列表知道当点击`indexBar`组件上的字母时应该滚动到哪里。

![添加分组列表](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_04_18.jpg)

## 添加嵌套列表

`NestedList`组件自动化嵌套数据集的布局和导航。这对于您有一个项目列表和列表中每个项目的详细信息的情况非常有用。例如，假设我们有一个办公室列表，每个办公室都有一组部门，每个部门都由一些人组成。

我们可以首先将此显示为办公室列表。点击一个办公室会带你到该办公室内的部门列表。点击一个部门会带你到该部门的人员列表。

我们需要做的第一件事是一组用于此列表的数据：

```js
var data = {
    text:'Offices',
    items:[
        {
            text:'Atlanta Office',
            items:[
                {
                    text:'Marketing',
                    items:[
                        {
                            text:'David Smith',
                            leaf:true
                        },
                        {
                            text:'Alex Wallace',
                            leaf:true
                        }
                    ]
                },
                {
                    text:'Sales',
                    items:[
                        {
                            text:'Jane West',
                            leaf:true
                        },
                        {
                            text:'Mike White',
                            leaf:true
                        }
                    ]
                }
            ]
        },
        {
            text:'Athens Office',
            items:[
                {
                    text:'IT',
                    items:[
                        {
                            text:'Baron Chandler',
                            leaf:true
                        },
                        {
                            text:'Aaron Karp',
                            leaf:true
                        }
                    ]
                },
                {
                    text:'Executive',
                    items:[
                        {
                            text:'Bryan Johnson',
                            leaf:true
                        },
                        {
                            text:'John Clark',
                            leaf:true
                        }
                    ]
                }
            ]
        }
    ]
};
```

这是一个相当庞大且看起来很丑的数据数组，但它可以分解为几个简单的部分：

+   我们有一个名为`Offices`的主要项目。

+   `Offices`有一个包含两个项目的列表，`Atlanta Office`和`Athens Office`。

+   这两项各有两个部门。

+   每个部门有两个人。

这个列表中的每个人都有一个特殊的属性叫做`leaf`。`leaf`属性告诉我们的程序已经到达嵌套数据的末端。此外，我们列表中的每个项目都有一个名为`text`的属性。这个`text`属性是我们`store`中的`fields`列表的一部分。

然后我们可以创建我们的存储并将其数据添加到其中：

```js
var store = Ext.create('Ext.data.TreeStore', {
 root: data,
 fields: [{name: 'text', type: 'string'}],
 defaultRootProperty: 'items',
 autoLoad: true
});
```

对于`NestedList`组件，我们需要使用`TreeStore`类，并将`root`配置指向我们之前定义的`data`数组变量。这将告诉存储器在我们数据的第一组项目中最开始查找的位置。

最后，我们需要创建我们的`NestedList`：

```js
var nestedList = Ext.create('Ext.NestedList', {
    fullscreen: true,
    title: 'Minions',
    displayField: 'text',
    store: store
});
```

我们将`NestedList`组件设置为`全屏`，同时也设置了`title`值，告诉它要显示哪个字段，最后，我们将其指向我们的存储，以便它可以获取我们创建的数据。

![添加嵌套列表](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_04_19.jpg)

如果你点击嵌套列表，你会注意到点击动作已经被自动添加。这同样适用于上导航和标题。

`NestedList`组件为在小型屏幕上快速有效地显示层次化数据提供了一个很好的起点。

# 使用 Sencha Docs 查找更多信息

在本章中，我们覆盖了很多信息，但它只是 Sencha Touch API 文档中可用信息的一小部分。

![使用 Sencha Docs 查找更多信息](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_04_20.jpg)

起初，API 可能会让人感到有些不知所措，但如果你理解了其组织结构，你就可以快速找到所需的信息。这里有一些帮你入门的小贴士。

## 查找组件

API 的左侧包含五个标签页，内容如下：

+   主屏幕包含 Sencha Touch 的一般营销信息。

+   带有列表中每个可用组件的 API 文档。

+   **指南**部分，其中包含有关各种组件及其用途的更详细文章。

+   **视频**部分，其中包含多个视频演讲，详细介绍布局和 MVC 等主题。

+   **示例**部分，其中包含许多 Sencha Touch 组件及其功能的多项示例。

![查找组件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_04_21.jpg)

如果你点击 API 标签，可以浏览一个组件列表。你还可以在文档页面上方右侧的搜索框中快速查找组件。

当你点击 API 列表中的项目时，标签页将打开屏幕的主要部分，并详细介绍组件的信息。

## 理解组件页面

单个组件页面顶部的信息为理解组件的工作提供了巨大的跳板。

![理解组件页面](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_04_22.jpg)

快速扫描右侧的组件层次结构，会告诉你组件继承了哪些其他项目。如果你理解了基本组件，如容器和面板，你可以迅速利用这些知识来指导你使用新组件。

顶部标题还列出了组件的`xtype`值。

在标题下方，有一系列菜单，包括：

+   **Config**：组件创建时使用的初始选项。

+   **属性**：创建组件后您可以从组件中获取的信息

+   **方法**：组件创建后知道如何执行的操作

+   **事件**：组件创建后关注的事情

+   **CSS 变量**：可用于样式化组件（仅在某些组件上）的可用的 CSS 变量列表

+   **CSS 混合**：组件可用的混合列表（仅在某些组件上）

还有一个文本框用于过滤类成员，一个菜单用于控制列表中出现的类成员类型，以及一个按钮用于展开页面上的所有项。

大多数常见组件在页面的顶部都包含示例。当在 WebKit 浏览器（Safari 或 Chrome）中查看时，这些示例包括一个**实时预览** / **代码编辑器**选项，可以切换。这将显示用户看到的组件，或者是创建组件的实际代码。

正如名称所暗示的，**代码编辑器**选项实际上可以编辑以测试不同的配置选项。还有一个**选择代码**选项，它将允许你复制代码并将其粘贴到自己的应用程序中。

这些信息应该为您学习 API 中的任何组件提供了一个起点。

# 总结

在本章中，我们首先查看了一个基本组件，名为`Ext.Component`。我们还研究了组件是如何创建的。然后我们详细探讨了容器的布局，展示了它是如何影响容器内部的子项的。

本章还描述了 Sencha Touch 中一些更常见且实用的组件，包括：容器、面板、TabPanel、Carousel、FormPanel、FormItem、MessageBox、Sheet、列表和嵌套列表。我们在章节的最后提供了一些使用 Sencha Touch API 的建议。

在下一章中，我们将介绍 Sencha Touch 中事件的使用。


# 第五章：事件和控制器

在上一章中，我们详细查看了 Sencha Touch 中可用的组件。然而，仅仅创建组件还不足以构建一个应用程序。组件仍然需要彼此通信，以便我们的应用程序做些真正有用的事情。事件和控制器就在这里发挥作用。

在本章中，我们将探讨 Sencha Touch 中的事件和控制器：它们是什么，为什么我们需要它们，以及它们是如何工作的。我们将讨论如何使用监听器和处理程序使您的应用程序对用户的触摸以及后台发生的事件做出反应。我们还将介绍一些有用的概念，例如可观察的捕获和事件代理。最后，我们将通过查看触摸特定事件和如何从 Sencha Touch API 获取更多信息来完成本章。

本章将涵盖以下内容：

+   事件

+   监听器和处理程序

+   控制器

+   监听器选项

+   作用域

+   移除事件

+   处理程序和按钮

+   常见事件

+   关于事件的其他信息

# 探索事件

作为程序员，我们倾向于将代码视为一个有序的指令序列，逐行执行。很容易忽视的事实是，我们的代码实际上花费了很多时间坐着等待用户做些什么。它正在等待用户点击一个按钮，打开一个窗口，或者从列表中选择。代码正在等待一个事件的发生。

通常，事件发生在组件执行特定任务之前或立即之后。当任务执行时，事件被广播到系统其余部分，在那里它可以触发特定的代码，或者可以被其他组件用来触发新的动作。

例如，在 Sencha Touch 中，每当点击按钮时，按钮就会触发一个事件。这个点击可以执行按钮内的代码，创建一个新的对话框，或者一个面板组件可以“监听”按钮正在做什么，并在听到按钮触发`tap`事件时改变其颜色。

由于大多数应用程序都是为了人机交互而设计的，所以说程序的大部分功能都来自于对事件的响应是安全的。从用户的角度来看，事件是使程序实际“做”事情的东西。程序正在响应用户的请求。

除了响应请求外，事件在确保事情按正确顺序发生方面也起着重要的作用。

## 异步与同步操作

爱因斯坦曾经说过：

> 时间存在的唯一原因是让一切不同时发生。

虽然这可能看起来像是一个随意的评论，但实际上在编写代码时与之有很大的关联。

在 Sencha Touch 中编写代码时，我们正在指导网络浏览器在用户的屏幕上创建和销毁组件。这个过程的明显限制是，我们既不能在组件创建之前操纵它，也不能在它被销毁之后操纵它。

这看起来在第一眼似乎相当直接。你永远不会在实际创建组件之前写一行试图与组件交谈的代码，那么问题是什么？

这个问题与代码中的异步动作有关。尽管我们的大部分代码将按顺序或以同步方式执行，但有许多情况我们需要发出一个请求并得到回应才能继续。这在基于 web 的应用程序中尤为正确。

例如，假设我们有一行代码，它使用来自 Google 地图的请求来构建一个地图。我们需要等待我们从 Google 那里得到回应并渲染我们的地图，然后我们才能开始在地图上工作。然而，我们不想让我们的应用程序的其他部分在我们等待回应时冻结。因此我们发起一个异步请求，这个请求在后台进行，而我们的应用程序的其他部分继续它的业务。

这种异步请求称为 Ajax 请求。"**Ajax**"代表**异步 JavaScript 和 XML**。如果我们配置我们其中一个按钮发出一个 AJAX 请求，用户在应用程序等待回应时仍然可以执行其他操作。

在界面方面，你可能想要让用户知道我们已经发出了请求，并正在等待回应。在大多数情况下，这意味着显示一个加载信息或一个动画图形。

在 Sencha Touch 中使用事件，我们可以通过绑定到 Ajax 组件的`beforerequest`事件来显示加载图形。由于我们需要知道何时让加载信息消失，因此我们的组件将等待来自 Ajax 请求的`requestcomplete`事件。一旦这个事件触发，我们就可以执行一些代码来告诉加载信息消失。我们还可以使用`requestexception`事件来告知用户在请求过程中是否出现错误。

使用这种事件驱动的设计允许你快速响应用户的操作，而不需要让他们等待你的代码需要执行的一些更耗时的请求。你还可以用事件来告知用户关于错误的信息。事件的关键在于让你的其他组件“监听”到这个事件，然后告诉他们如何处理收到的信息。

# 添加监听器和处理程序

**每个 Sencha Touch 组件都能生成一大串事件。** 鉴于你应用中可能会有大量的组件，你可以预期会有很多交互。

想象一个有 100 个人的聚会，每个人都在进行着许多不同的对话。现在想象一下，试图从每个对话中提取所有有用的信息。这是不可能的。你必须专注于某个特定的对话，才能收集到有用的信息。

同样的，组件也需要被告知要监听什么，否则我们可怜的聚会参与者很快就会感到不知所措。幸运的是，我们有针对这一点的配置。

`listeners`配置告诉组件需要关注哪些事件。监听器可以像 Sencha Touch 中的任何其他配置选项一样添加。例如，面板的配置选项可能如下所示：

```js
listeners: {
 singletap: {
  element: 'element',
  fn: function(){ Ext.Msg.alert('Single Tap'); }
 }
}
```

这个配置选项告诉面板在用户在面板内部元素上单击一次时监听`singletap`事件。当`singletap`事件发生时，我们执行`fn`配置选项中列出的函数（这通常被称为处理程序）。在这种情况下，我们弹出一个带有消息警告`Single Tap`的消息框。

请注意，我们`listeners`配置中的项目总是作为一个对象的一部分（无论是否只有一个事件我们正在监听），即使我们只监听一个事件也是如此。如果我们添加第二个事件，它将如下所示：

```js
listeners: {
 singletap: {
  element: 'element',
  fn: function(){ Ext.Msg.alert('Single Tap'); }
 },
 hide: {
  fn: function(){ this.destroy(); }
 }
}
```

### 注意

如果事件没有其他属性，你也可以像这样缩短事件声明：`hide: function(){ this.destroy(); }`

我们还可以从监听器中获取信息并用在我们的处理函数中。例如，`singletap`事件会返回`event`对象，被点击的 DOM 元素以及我们如果在面板上有以下监听器的话，还会返回`listener`对象本身：

```js
listeners: {
  singletap: {
    element: 'element',
    fn: function(event, div, listener) {
      console.log(event, div, listener);
    }
  }
}
```

当用户在面板内单击时，我们将在控制台上获得一个视图，类似于以下内容：

![Adding listeners and handlers](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/748OS_05_1.jpg)

### 提示

**事件参数**

您会注意到某些默认值会被传递到我们的事件中。这些默认值可以在每个组件的[`docs.sencha.com/touch/2.2.1/`](http://docs.sencha.com/touch/2.2.1/)中找到。

每个事件都将有它自己的默认值。选择一个组件从 Sencha API 文档，然后点击页面顶部的`Events`查看组件的所有事件。每个事件的描述将包括其默认参数。

从控制台可以看出，我们的`event`对象包含了一个在单击发生时的 Unix`timeStamp`，以及单击本身`pageX`和`pageY`坐标，还有被单击的`div`标签的整个内容。您可能还注意到我们的`tap`事件在我们的调试输出中被称为`mouseup`事件。在 Sencha Touch 中，`singletap`和`mouseup`事件是彼此的别名。这保留了与桌面浏览器传统的`mouseup`事件和移动浏览器`singletap`事件之间的兼容性。

我们可以在我们函数内部使用所有这些信息。

为了这个例子，我们将创建一个带有红色容器的简单面板。我们的`singletap`监听器将改变红色盒子的尺寸以匹配我们屏幕上的单击位置，如下代码片段所示：

```js
Ext.application({
 name: 'TouchStart',
 launch: function() {
  var eventPanel = Ext.create('Ext.Panel', {
   fullscreen: true,
   layout: 'auto',
   items: [{
    xtype: 'container',
    width: 40,
    height: 40,
    id: 'tapTarget',
    style: 'background-color: #800000;'
   }],
   listeners: {
    singletap: {
     element: 'element',
     fn: function(event, div, listener) {
      var cmp = Ext.getCmp('tapTarget');
      cmp.setWidth(event.pageX);
      cmp.setHeight(event.pageY);
      console.log(event.pageX, event.pageY);
     }
    }
   }
  });
  Ext.Viewport.add(eventPanel);
 }
});
```

如果我们打开控制台运行这段代码，我们可以看到我们单击的位置的 x 和 y 坐标会在控制台出现。我们的盒子也会根据这些值来匹配大小。

![Adding listeners and handlers](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/748OS_05_2.jpg)

正如您在前面代码中看到的，我们监听了`tap`事件。然后我们使用`Ext.getCmp('tapTarget');`获取`container`组件，并根据从`tap`事件返回的值改变红色盒子的尺寸：

```js
singletap: {
 element: 'element',
 fn: function(event, div, listener) {
  var cmp = Ext.getCmp('tapTarget');
  cmp.setWidth(event.pageX);
  cmp.setHeight(event.pageY);
 }
} 
```

这是一个使用 Sencha Touch 事件的基本示例。然而，我们的大多数应用程序通常会做不止一件简单的事情。我们还可以使用 ID 和`Ext.getCmp()`获取它们。在大型应用程序中，不小心创建具有相同 ID 的组件或在已由 Sencha Touch 使用的 ID 创建组件是非常容易的。这通常会导致应用程序的螺旋死亡和大量扯头发。

### 提示

作为一种最佳实践，避免为 addressing components 使用 ID 是个好主意。在接下来的几节中，我们将开始向您展示更可靠的方法来引用我们各个组件。

如果我们打算构建比这种“单招马”更复杂的应用程序，我们可能想要开始考虑将我们的事件和动作分离到适当的控制器中，并找到一种更好地引用我们不同组件的方法。

# 控制器

在第三章 *用户界面样式*中，我们稍微谈到了**模型视图控制器**（**MVC**）架构。这种架构将我们的文件划分为数据文件（`Models`和`Stores`）、界面文件（`Views`）以及处理功能（`Controllers`）的文件。在本节中，我们将重点关注 MVC 的控制器部分。

在最基本层面上，控制器在应用程序中分配监听器和动作。与我们的前一个示例不同，在那里单个组件负责处理事件，控制器将处理我们应用程序中每个组件的事件。

这种劳动分工在创建应用程序时提供了几个不同的优势，如下所述：

+   当我们知道我们的函数都在控制器中，并且与显示逻辑分离时，代码更容易导航。

+   控制器为应用程序中各个显示组件提供了一个更简单的通信层。

+   控制器可以根据功能划分为不同的文件。例如，我们可以有一个用户控制器，它处理用户数据的事件和监听器，还有一个单独的公司控制器，它处理公司数据的事件和监听器。这意味着如果一个用于保存新用户的表单不能正确工作，我们知道要查看哪个文件来尝试找出问题所在。

让我们通过一个例子来看看我们在谈论什么。我们将从使用 Sencha Cmd 生成的基本启动应用程序开始，使用以下命令行：

```js
sencha generate app TouchStart /Path/to/Save/Application

```

![Controllers](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/748OS_05_3.jpg)

路径将根据您的设置而变化，但这将给我们提供我们将添加控制器的基本应用程序。

### 注意

想回顾一下 Sencha Cmd 和 MVC 的基础知识，请参见第三章，*用户界面样式*。

如果我们查看我们新创建的应用程序的`app`/`controller`文件夹，我们会发现它是空的。让我们先在这里创建一个`Main.js`文件。在新文件中，我们将添加：

```js
Ext.define('TouchStart.controller.Main', {
 extend: 'Ext.app.Controller',

});
```

这扩展了基本的`Ext.app.Controller`组件，但其他什么也没做。我们的控制器需要理解一些基本的东西，以便正确地工作；它们如下：

+   控制器控制了应用程序的哪些部分？

+   它应该监听哪些组件事件？

+   当其中一个事件被触发时，它应该做什么？

这个谜题的第一部分是由引用（`refs`）处理的。

## Refs and control

`refs`部分使用`ComponentQuery`语法来创建对应用程序中组件的内部引用。`ComponentQuery`语法允许我们根据 ID、xtype 和其他任何配置选项来查找组件。

例如，在我们的`app/view`目录中有一个`Main.js`文件（它是由 Sencha Cmd 自动生成的）。`view`组件有一个`xtype`值为`main`。我们可以像以下这样将这个视图文件添加到我们的控制器中：

```js
Ext.define('TouchStart.controller.Main', {
 extend: 'Ext.app.Controller',
 views: ['TouchStart.views.Main'],
 config: {
  refs: {
   mainView: 'main'
  }
 }
});
```

这告诉我们的控制器，它控制着`TouchStart.views.Main`视图文件，并且我们将用一个简写 m（这是我们的选择）来引用这个特定的组件。通过创建这个引用，我们自动为该组件创建了一个 getter 函数。这意味着当我们在控制器中需要引用这个组件的其他地方时，例如如果我们需要向我们的标签面板添加一个新的标签，我们只需使用`this.getMainView()`来获取组件。

### Tip

这里又是大小写可以悄无声息地攻击你的另一个地方。你会注意到，尽管我们用小写的`m`给我们的引用命名，但 get 函数使用的是大写的`M`。如果我们给我们的引用命名为`mainPanel`，get 函数将是`this.getMainPanel()`。第一个字母总是是大写的。

让我们向我们的基本应用程序添加一些元素，以确切了解这是如何工作的。首先我们需要在`Main.js`视图文件中添加一个按钮。在我们第一个面板（带有标题的那个）中，将项目部分修改如下以添加一个按钮：

```js
items: [{
 docked: 'top',
 xtype: 'titlebar',
 title: 'Welcome to Sencha Touch 2',
 items: [
  { 
   text: 'Add Tab',
   action: 'addtab',
  }
 ]
}] 
```

请注意，这次我们没有在这里添加处理程序，但我们确实有一个`action`的`addtab`，我们将用它来在我们的控制器中引用按钮：

![Refs and control](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/748OS_05_4.jpg)

回到我们位于`app/controller/`的`Main.js`文件，我们将添加一个`refs`和`control`部分如下：

```js
Ext.define('TouchStart.controller.Main', {
 extend: 'Ext.app.Controller',
 config: {
 views: ['TouchStart.view.Main'],
  refs: {
   m: 'main',
   addBtn: 'button[action=addtab]'
  },
  control: {
   addBtn: {
    tap: 'addNewTab'
   }
  }
 }
});
```

现在我们有了按钮的新引用：

```js
addBtn: 'button[action=addtab]'
```

### Tip

需要注意的是，我们按钮上的`action`配置完全是任意的。我们可以称它为`myPurposeInLife: 'addtab'`，这对组件本身没有任何影响。在这种情况下，我们只是将按钮引用为`addBtn: 'button[myPurposeInLife = addtab]'`。术语`action`通常是按惯例使用的，但它不是按钮的默认配置选项。它只是我们稍后将在控制器中使用`ComponentQuery`查找按钮的值。

现在我们已经有了引用，我们可以在设置控制时使用`addBtn`。这个`control`部分是我们为这个特定按钮设置监听器的地方：

```js
 control: {
   addBtn: {
    tap: 'addNewTab'
   }
  }
```

这个`control`部分表示我们希望我们的控制器监听`addBtn`按钮的轻触事件，并在用户轻触按钮时触发`addNewTab`函数。接下来，我们需要将这个`addNewTab`函数添加到我们控制器的底部，位于`config`部分之后（不要忘记在`config`部分的末尾和新的函数之间加上逗号），如下面的代码片段所示：

```js
addNewTab: function() {
  this.getMainView().add({
   title: 'My New Tab',
   iconCls: 'star',
   html: 'Some words of wisdom...'
  });
 }
```

这个函数使用我们的`this.getMainView()`函数来获取我们的主标签面板，并向其添加一个新的标签。现在我们点击按钮，我们应该会看到一个带有星形图标和我们 HTML 文本的新标签：

![Refs 和 control](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/748OS_05_5.jpg)

每个控制器文件可以包含任意数量的视图、引用和函数。然而，通常最好将您的控制器根据它们处理的数据类型分成单独的文件（一个用于用户，一个用于公司，另一个用于消息，等等）。这种代码组织完全取决于程序员，但它有助于大大减少寻找问题的难度。

## 使用 ComponentQuery 引用多个项目

正如我们之前的示例所看到的，`refs`部分为我们组件提供了简写式的引用名称，而`control`部分允许我们将监听器和函数分配给我们的组件。尽管我们可以使用`control`部分将单个函数分配给多个组件，但我们在`refs`部分包含的项目只能是单数的。我们无法在`refs`部分为多个组件创建一个单一的引用。

然而，我们可以通过使用`Ext.ComponentQuery`来解决这个问题。

为了演示这一点，让我们来看一个真实世界的例子：一个带有添加、编辑和删除按钮的条目列表。**添加**按钮应该始终是可用的，而**编辑**和**删除**按钮只有在列表中选择了某个项目时才应该是活动的。

![使用 ComponentQuery 引用多个项目](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/748OS_05_6.jpg)

我们将创建一个名为`PersonList.js`的列表，位于`view`文件夹中，如下面的代码片段所示：

```js
Ext.define('TouchStart.view.PersonList', {
    extend: 'Ext.dataview.List',
    xtype: 'personlist',
    config: {
        itemTpl: '{last}, {first}',
        store: Ext.create('Ext.data.Store', {
            sorters: 'last',
            autoLoad: true,
            fields: [
                {name: 'first', type: 'string'},
                {name: 'last', type: 'string'}
            ],
            data: [
                {first: 'Aaron', last: 'Karp'},
                {first: 'Baron', last: 'Chandler'},
                {first: 'Bryan', last: 'Johnson'},
                {first: 'David', last: 'Evans'},
                {first: 'John', last: 'Clark'},
                {first: 'Norbert', last: 'Taylor'},
                {first: 'Jane', last: 'West'}
            ]
        })
    }
});
```

这类似于我们在第五章，*事件和控制器*中创建的列表，只不过我们通过使用`Ext.define`并扩展`Ext.dataview.List`对象，将其变成了一个独立的`view`组件。我们本可以将它简单地作为我们的`Main.js`视图文件的一部分，但将其分离出来允许我们定义一个自定义的`xtype`为`personlist`，这将使我们在控制器中引用它变得更容易。

### 注意

为了简化，我们将`store`作为我们视图的一部分，而不是将其分离到`store`目录中的单独文件中。我们将在第七章，*获取数据*和第八章，*创建 Flickr 查找器应用程序*中讨论如何实现，其中我们将介绍存储和模型。

现在我们已经有了`personlist`视图，我们需要将其添加到我们的`Main.js`视图文件中。让我们替换`Main.js`文件中的第二个面板（其中包含视频链接的那个）。新面板将看起来像这样：

```js
{
    title: 'Advanced',
    iconCls: 'action',
    layout: 'fit',
    items: [{
        docked: 'top',
        xtype: 'toolbar',
        items: [
            {
                text: 'Add',
                action: 'additem'
            },
            {
                text: 'Edit',
                action: 'edititem',
                enableOnSelection: true,
                disabled: true
            },
            {
                text: 'Delete',
                action: 'deleteitem',
                enableOnSelection: true,
                disabled: true
            }
        ]
    },
        { xtype: 'personlist'}
    ]
}
```

这段代码创建了一个带有`fit`布局和两个项目的新面板。第一个项目是一个工具栏，固定在面板的顶部。第二个项目（在非常底部）是我们的`personlist`组件。

工具栏有自己的项目，包括三个带有文本`添加`、`编辑`和`删除`的按钮。每个按钮都有自己的独立`action`配置，而`编辑`和`删除`按钮有一个额外的配置：

```js
enableOnSelection: true
```

### 注意

请注意，与`action`一样，`enableOnSelection`配置是任意值，而不是按钮组件的默认配置。

单个`action`配置将允许我们将函数分配给每个按钮。共享的`enableOnSelection`配置将允许我们用一个引用抓取`编辑`和`删除`按钮。让我们回到我们的`Main.js`控制器看看这是如何工作的。

我们首先想要做的是让`Main.js`控制器知道它负责我们的新`personlist`视图。我们通过将其添加到控制器中的`views`列表来实现，如下面的代码片段所示：

```js
views: ['TouchStart.view.Main', 'TouchStart.view.PersonList']
```

接下来，我们需要在`refs`部分创建我们的引用，如下面的代码片段所示：

```js
refs: {
    mainView: 'main',
    addBtn: 'button[action=addtab]',
    addItem: 'button[action=additem]',
    editItem: 'button[action=edititem]',
    deleteItem: 'button[action=deleteitem]',
    personList: 'personlist'
}
```

然后，我们将修改我们的`control`部分，使其如下所示：

```js
control:{
    addBtn:{
        tap:'addNewTab'
    },
    personList:{
        select:'enableItemButtons'
    },
    addItem:{
        tap: 'tempFunction'
    },
    editItem:{
        tap: 'tempFunction'
    },
    deleteItem:{
        tap: 'tempFunction'
    }
}
```

在这里，我们将我们的`personList`组件设置为监听`select`事件，并在事件发生时触发`enableItemButtons`函数。我们还为我们的三个按钮的`tap`事件分配了一个单独的`tempFunction`函数。

我们的`tempFunction`在现有的`addNewTab`函数之后添加，如下所示：

```js
tempFunction:function () {
    console.log(arguments);
}
```

这只是为了演示目的而暂时使用的函数（我们将在第七章，*获取数据*和第八章，*创建 Flickr 查找器应用程序*中更详细地介绍添加、编辑和删除操作）。现在，这个临时函数只是记录发送给它的参数。

### 提示

在 JavaScript 中，`arguments`是一个特殊的变量，它包含了传递给函数的许多变量。这对于使用控制台日志来说非常棒，因为你可能不清楚你的函数接收到的变量，它们的顺序，或者它们的格式。

第二个函数将处理我们的列表选择：

```js
enableItemButtons:function () {
     var disabledItemButtons =   Ext.ComponentQuery.query('button[enableOnSelection]');
     Ext.each(disabledItemButtons, function(button) {
        button.enable();
     });
}
```

正如我们之前所提到的，我们不能简单地为我们的两个禁用按钮创建一个`refs`列表。如果我们尝试在我们的`refs`部分使用`myButtons: 'button[enableOnSelection]'`，我们只能得到第一个按钮。

然而，我们可以使用完全相同的选择器`Ext.ComponentQuery.query('button[enableOnSelection]');`，得到两个按钮作为一个按钮对象的数组。然后我们可以使用`Ext.each`逐一遍历每个按钮，并在它们上面运行一个函数。

在这种情况下，我们只是在每个按钮上运行`button.enable();`。现在当列表中选择一个项目时，我们的两个按钮都将被启用。

![使用 ComponentQuery 引用多个项目](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/748OS_05_7.jpg)

通过使用`Ext.ComponentQuery`，一个事件可以轻松地根据它们的属性影响多个组件。

# 从事件中获取更多内容

既然我们已经了解了事件和控制器是如何结合在一起的，我们需要看看事件的其他用途和可用选项。

## 自定义事件

虽然 Sencha Touch 组件响应大量的事件，但有时在应用程序内部触发自定义事件可能会有所帮助。

例如，你可以触发一个名为`vikinginvasion`的自定义事件，这可能会触发你应用程序中的其他操作。在这个例子中，我们将假设我们有一个名为`cmp`的组件。我们可以通过调用这个组件来触发事件：

```js
cmp.fireEvent('vikinginvasion');
```

然后，你可以在控制器的`control`部分为`vikinginvasion`添加一个监听器，以及一个处理事件的函数。如果我们想为自定义事件添加监听器到名为`trebuchet`的组件，它可能如下所示：

```js
control: {
 trebuchet: {
  vikinginvasion: 'fireAtWill'
 }
}
```

你还可以检查一个组件是否具有特定的监听器，使用`hasListener()`方法：

```js
if(this.getTrebuchet.hasListener('vikinginvasion') {
  console.log('Component is alert for invasion');
} else {
  console.log('Component is asleep at its post');
}
```

还有许多有用的选项，你可以使用它们来控制监听器如何检查事件。

## 探索监听器选项

在大多数情况下，监听器可以通过事件名称、处理程序和作用域来配置，但有时你需要更多的控制。Sencha Touch 提供了一系列有用的选项来修改监听器的工作方式；它们包括：

+   `delay`：这将延迟事件触发后处理程序的执行。它以毫秒为单位给出。

+   `single`: 这提供了一个一次性处理器，在下一个事件触发后执行，然后将自己移除。

+   `buffer`：这会导致处理器作为`Ext.util.DelayedTask`组件的一部分被调度运行。这意味着如果一个事件被触发，我们在执行处理器之前等待一段时间。如果在我们的延迟时间内再次触发相同的事件，我们在执行处理器之前重置计时器（只执行一次）。这在对文本字段的变化事件进行监控时可能很有用——在用户最后一次更改后等待 300 毫秒才触发事件的功能。

+   `element`：这允许我们在组件内指定一个特定的元素。例如，我们可以在面板的`tap`事件上指定一个正文。这将忽略附着项的点击，只监听面板正文的点击。

+   `target`：这将限制监听器仅接收来自目标的事件，并忽略来自其子元素的同类事件。

使用不同的监听器选项，代码可能看起来像以下这样：

```js
this.getTrebuchet.on('vikinginvasion', this.handleInvasion, this, {
 single: true,
 delay: 100
});
```

这个示例将为`vikinginvasion`添加一个监听器，并在本作用域中执行一个名为`handleInvasion`的函数。处理器只会执行一次，在 100 毫秒的延迟后。然后将自己从组件中移除。

如果你在一个控制器内，你可以这样在`control`部分完成同样的事情：

```js
control:{
 Trebuchet:{
  vikinginvasion: {
   fn: this.handleInvasion,
   single: true,
   delay: 100
  }
 }
}
```

由于我们在`vikinginvasion`的事件监听器上设置选项，它变成了自己的配置对象。反过来，我们的`handleInvasion`函数变成了一个名为`fn`的配置选项。

这些基本的配置选项在添加监听器时给你带来了相当大的灵活性。然而，在监听器中还有一个可用的附加配置选项，需要稍作解释。它叫做`scope`。

## 仔细查看作用域

在你的处理函数中有一个特殊的变量叫做`this`。通常，`this`指的是触发事件的组件，在这种情况下，`scope`通常设置为`scope: this`。然而，在监听器配置中指定`scope`的不同值是可能的：

```js
Ext.application({
 name: 'TouchStart',
 launch: function() {
  var btn = Ext.create('Ext.Button', {
   xtype: 'button',
   centered: true,
   text: 'Click me'
  });
  var Mainpanel = Ext.create('Ext.Panel', {
   html: 'Panel HTML'
  });
  btn.on({ 
   painted: {
    fn: function() {
     console.log('This should show our button %o', this)
    }
   },
   tap: {
    scope: Mainpanel,
    fn: function() {
     console.log('This should show our main panel %o', this)
    }
   }
  });
  Ext.Viewport.add(btn);
  Ext.Viewport.add(Mainpanel);
 }
});
```

在此我们创建了一个名为`btn`的按钮和一个名为`Mainpanel`的面板。然后附上两个监听器。第一个是在按钮的`painted`事件上。这个事件在按钮“绘制”（出现在）屏幕上时立即触发。在这种情况下，函数的作用域是`button`，这是我们可以预期的默认情况。

第二个是在`button`的`tap`事件上。`tap`事件的`scope`是`Mainpanel`。这意味着，尽管监听器附着在按钮上，但函数将`this`视为`Mainpanel`组件，而不是按钮。

虽然`scope`这个概念可能难以理解，但它是监听器配置中的一个非常实用的部分。

## 移除监听器

通常，当组件被销毁时，监听器会自动移除。然而，有时您会在组件被销毁之前想要移除监听器。为此，你需要一个你创建监听器时创建的处理函数的引用。

到目前为止，我们一直使用匿名函数来创建我们的监听器，但如果我们想要移除监听器，我们需要稍有不同的方法：

```js
var myPanel = Ext.create('Ext.Panel', {…});

var myHandler = function() {
  console.log('myHandler called.');
};

myPanel.on('click', myHandler);
```

这是一个好习惯，因为它允许你一次性定义处理函数，并在需要的地方重复使用它们。它还允许你稍后移除处理程序：

```js
myPanel.removeListener('click', myHandler);
```

### 提示

在 Sencha 的术语中，`on()`是`addListener()`的别名，而`un()`是`removeListener()`的别名，这意味着它们做完全相同的事情。在处理事件时，你可以自由选择使用你喜欢的方法。

还应注意的是，作为控制器`control`部分添加的监听器永远不会被移除。

## 使用处理程序和按钮

正如您可能从我们之前的某些代码中注意到的，按钮有一个默认配置称为`handler`。这是因为按钮的一般目的是被点击或轻触。`handler`配置只是添加`tap`监听器的有用简写。因此，下面的两段代码完全相同：

```js
var button = Ext.create('Ext.Button', {
  text: 'press me',
  handler: function() {
    this.setText('Pressed');
  }
})
var button = Ext.create('Ext.Button', {
  text: 'press me',
  listener: {
   tap: {
      fn: function() {
        this.setText('Pressed');
     }
    }
  }
});
```

接下来，我们将查看一些常见事件。

## 探索常见事件

让我们看看我们的老朋友`Ext.Component`，并了解一些我们可以使用的一些常见事件。记住，由于我们的大多数组件将继承自`Ext.Component`，这些事件将贯穿我们使用的大多数组件。这些事件中的第一个与组件的创建有关。

当 Web 浏览器执行你的 Sencha Touch 代码时，它将组件写入网页作为一系列`div`、`span`和其他标准 HTML 标签。这些元素还与 Sencha Touch 中的代码链接在一起，以标准化所有支持 Web 浏览器的组件的外观和功能。这个过程通常被称为渲染组件。在 Sencha Touch 中控制这个渲染的事件称为`painted`。

其他一些常见事件包括：

+   `show`：当在组件上使用`show`方法时触发

+   `hide`：当在组件上使用`hide`方法时触发

+   `destroy`：当组件被销毁时触发

+   `disabledchange`：当通过`setDisabled`更改`disabled`配置时触发

+   `widthchange`：当在组件上调用`setWidth`时触发

+   `heightchange`：当在组件上调用`setHeight`时触发

这些事件为您提供了一种基于组件正在执行或对组件执行的操作来编写代码的方法。

### 提示

名称以`changed`结尾的每个事件都是由于`config`选项已更改而触发的；例如，`setWidth`、`setHeight`和`setTop`。虽然监听这些事件与监听任何其他事件类似，但了解这个约定是有用的。

每个组件还将有一些与之关联的特定事件。有关这些事件的列表，请参阅可用的文档[`docs.sencha.com/touch/2.2.1`](http://docs.sencha.com/touch/2.2.1)。在左侧列表中选择一个组件，然后点击页面顶部的**事件**按钮。

# 更多信息

关于事件的信息可以在 Sencha Docs 中找到[`docs.sencha.com/touch/2.2.1`](http://docs.sencha.com/touch/2.2.1)。在左侧列表中选择一个组件，然后在顶部寻找**事件**按钮。您可以点击**事件**以跳转到该部分的开始，或者将鼠标悬停在上面以查看完整的事件列表并从中选择特定事件。

点击事件旁边的向下箭头将显示事件的参数列表以及关于如何使用事件的任何可用示例。

另一个了解触摸特定事件的好地方是 Kitchen Sink 示例应用程序([`dev.sencha.com/deploy/touch/examples/kitchensink/`](http://dev.sencha.com/deploy/touch/examples/kitchensink/))。在应用程序中有一个**触摸事件**部分。这个部分允许您轻触或点击屏幕以查看不同轻触和手势生成的哪些事件。

Sencha Touch 的 WebKit 团队还创建了一个用于 Android 的事件记录器。您可以在[`www.sencha.com/blog/event-recorder-for-android-web-applications/`](http://www.sencha.com/blog/event-recorder-for-android-web-applications/)找到更多信息。

# 总结

在本章中，我们介绍了事件的基本概述，以及如何使用监听器和处理程序使程序对这些事件做出响应。我们深入探讨了控制器及其如何使用引用和`control`部分来附加监听器到组件。我们介绍了`Ext.ComponentQuery()`，用于在事件处理程序中获取组件。我们谈论了自定义事件、按钮中的处理程序，并列出了一些常见事件。

在下一章中，我们将介绍如何在 Sencha Touch 中获取和存储数据，使用 JSON、数据存储、模型和表单。


# 第六章：获取数据

任何应用程序的关键方面之一是处理数据——将数据输入应用程序，以便您可以操作和存储它，然后再次获取以供显示。我们将用接下来的两章来讨论 Sencha Touch 中的数据处理。本章将重点介绍如何将数据输入您的应用程序。

我们将从讨论用于描述您数据的模型开始。然后，我们将讨论收集数据的读取器以及用于在应用程序中保存数据的存储。一旦我们了解了数据去了哪里，我们将介绍如何使用表单来获取数据。我们将查看如何验证您的数据，并为您提供一些表单提交示例。最后，我们将介绍如何将数据回填到表单中以进行编辑。这将是下一章关于数据的起点，该章节将涵盖如何获取数据以供显示。

本章涵盖了以下主题：

+   数据模型

+   数据格式

+   数据存储

+   使用表单和数据存储

# 模型

在 Sencha Touch 应用程序中处理数据的第一步是创建数据的模型。如果您习惯于数据库驱动的应用程序，将模型视为数据库架构会有所帮助；这是一个定义我们将要存储的数据的构造，包括数据类型、验证和结构。这为我们的应用程序的其余部分提供了一个共同的映射，用于理解来回传递的数据。

在 Sencha Touch 2 中，模型还可以用于保存单个数据记录的信息。这意味着我们可以使用已经内置到 Sencha Touch `Ext.data.Model`组件中的函数来创建、读取、更新和删除单个记录。

## 基本模型

在最基本的情况下，模型使用`Ext.define()`描述数据字段，如下所示：

```js
Ext.define('User', {
extend: 'Ext.data.Model',
config: {
  fields: [
    {name: 'firstname', type: 'string'},
    {name: 'lastname', type: 'string'},
    {name: 'username', type: 'string'},
    {name: 'age', type: 'int'},
    {name: 'email', type: 'string'},
    {name: 'active', type: 'boolean', defaultValue: true},
  ]
 }
}
```

第一行声明我们已经将新模型命名为`User`，并且我们正在扩展默认的`Ext.data.Model`。我们在`config`部分内设置模型的配置选项。

### 提示

在版本 2 中，模型设置有所变化。我们现在使用`Ext.define`和扩展，而不是通过旧的模型管理器创建事物。我们还将模型的选项包裹在一个`config`部分内。在`extend`设置外，您的模型选项的其余部分应该用这个`config`部分包裹起来。

在`config`部分内，我们将描述我们的数据字段作为一个`fields`数组，包括`name`、`type`和可选的`defaultValue`字段。`name`字段就是我们希望在代码中引用数据的方式。`type`的有效值是：

+   `auto`：这是一个默认值，它接受原始数据而不进行转换

+   `string`：这将数据转换为字符串

+   `int`：这将数据转换为整数

+   `float`：这将数据转换为浮点整数

+   `boolean`：这将数据转换为真或假的布尔值

+   `date`：这将数据转换为 JavaScript `Date`对象

`defaultValue`字段可以用来设置一个标准值，如果该字段没有收到数据，就可以使用这个值。在我们的例子中，我们将`active`的值设置为`true`。我们可以在使用`Ext.create()`创建新的用户实例时使用这个值：

```js
var newUser = Ext.create('User', {
  firstname: 'Nigel',
  lastname: 'Tufnel',
  username: 'goes211',
  age: 39,
  email: 'nigel@spinaltap.com'
});
```

请注意，我们在新的用户实例中没有为`active`提供值，所以它只是使用了我们的模型定义中的`defaultValue`字段。这也可以在用户忘记输入值时帮助用户。我们还可以通过使用`validations`来验证用户输入的信息。

## 模型验证

模型验证确保我们得到我们认为得到的数据。这些验证有两个功能。第一个是提供数据输入的指导方针。例如，我们通常希望用户名只包含字母和数字；验证可以强制这个约束，并在用户使用错误字符时通知用户。

第二个是安全性；恶意用户也可以通过表单字段发送可能对我们数据库有害的信息。例如，如果数据库没有得到适当保护，将`DELETE * FROM users;`作为用户名发送可能会造成问题。始终验证数据是个好主意。

我们可以将`validations`作为数据模型的一部分来声明，就像我们声明字段一样。例如，我们可以在我们的`User`模型中添加以下代码：

```js
Ext.define('User', { 
extend: 'Ext.data.Model',
 config: {
  fields: [
    {name: 'firstname', type: 'string'},
    {name: 'lastname', type: 'string'},
    {name: 'age', type: 'int'},
    {name: 'username', type: 'string'},
    {name: 'email', type: 'string'},
    {name: 'active', type: 'boolean', defaultValue: true},
  ],
  validations: [
    {type: 'presence',  field: 'age'},
    {type: 'exclusion', field: 'username', list: ['Admin', 'Root']},
     {type: 'length', field: 'username', min: 3},
    {type: 'format', field: 'username', matcher: /([a-z]+)[0-9]{2,3}/}
  ]
 }
}
```

在我们的例子中，我们增加了四个验证。第一个测试`age`值的存在。如果没有`age`的值，我们会得到一个错误。第二个验证器`exclusion`测试我们不希望在此字段中看到的值。在这个例子中，我们有一个用户名的列表，我们不希望看到的是`Admin`和`Root`。第三个验证器确保我们的用户名至少有三个字符长。最后一个验证器使用正则表达式检查我们的用户名格式。

### 提示

**正则表达式**

**正则表达式**，也称为**正则表达式**或**正则表达式**，是匹配字符串结构的极其强大的工具。您可以使用正则表达式在字符串中搜索特定的字符、单词或模式。正则表达式的讨论需要一本自己的书，但网上有许多好的资源。

好的教程可以在以下位置找到：

[`www.zytrax.com/tech/web/regex.htm`](http://www.zytrax.com/tech/web/regex.htm)。

一个可搜索的正则表达式数据库可以在以下位置找到：

[`regexlib.com`](http://regexlib.com)。

一个出色的正则表达式测试器也在此处提供：

[`www.rexv.org/`](http://www.rexv.org/)。

我们可以通过使用我们新`User`实例的`validate`方法来测试我们的验证：

```js
var newUser = Ext.create('User', {
  firstname: 'Nigel',
  lastname: 'Tufnel',
  username: 'goes211',
  email: 'nigel@spinaltap.com'
});

var errors = newUser.validate();
console.log(errors);
```

请注意，我们故意这次省略了`age`字段，以给我们一个错误。如果我们查看我们的控制台，我们可以看到我们返回的`Ext.data.Errors`对象，如下面的屏幕截图所示：

![模型验证](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_06_01.jpg)

这是我们`errors`对象的控制台输出。`errors`对象包括一个名为`isValid()`的方法，它将返回一个`true`或`false`值。我们可以使用这个方法来测试错误并向用户返回消息，例如：

```js
  if(!errors.isValid()) {
    alert("The field: "+errors.items[0].getField()+ " returned an error: "+errors.items[0].getMessage());
  }
```

这里，我们测试`errors`是否有效，如果不有效，则显示第一个错误的信息。然后我们使用`getField()`和`getMessage()`在用户的警报中显示信息。这些详细的错误信息包含在`errors`对象的`items`列表中。在实际使用中可能会有多个错误，因此我们需要遍历`items`列表以获取所有错误。

我们还可以通过在验证上设置额外的配置选项来更改默认错误消息：

+   `exclusionMessage`：当我们在字段中得到一个被排除的值时使用。

+   `formatMessage`：当我们在字段中得到格式不正确的值时使用。

+   `inclusionMessage`：当我们在字段中没有得到包含的值时使用。

+   `lengthMessage`：当字段的值不符合我们所需的长度时使用此功能。

+   `presenceMessage`：当我们在字段中没有保留所需的值时使用。

定制这些错误将帮助用户了解到底出现了什么问题以及需要采取什么措施来解决问题。

## 模型方法

我们的模型还可以包含可以对模型实例调用的方法。例如，我们可以在`User`模型的`fields`列表之后添加一个名为`deactivate`的方法。

```js
deactivate: function() {
 if(this.get('active')) {
  this.set('active', false);
 }
}
```

这个函数检查我们当前的`active`值是否为`true`。如果是，我们将其设置为`false`。一旦我们像以前那样创建了`newUser`，我们可以像以下方式调用该函数：

```js
newUser.deactivate();
```

这些模型方法为在模型中实现常见功能提供了很好的方式。

### 提示

**CRUD**

尽管模型方法可能看起来是一个添加函数以保存我们模型的不错选择，但实际上你真的不需要这样做。这些类型的函数—`Create`、`Read`、`Update`和`Destroy`—通常被称为不吸引人的缩写**CRUD**，它们由 Sencha Touch 自动处理。我们将在本章后面稍后再讨论这些功能。

现在我们已经定义了模型的字段、验证和函数，我们需要一种方法来在模型之间传递数据以存储和检索我们的用户。这时代理和读取器就派上用场了。

## 代理和读取器

在该模型中，代理和读取器合作存储和检索模型要使用的数据。代理告诉模型其数据将存储在哪里，读取器告诉模型正在使用哪种格式来存储数据。

代理主要有两种类型：本地和远程。本地代理在其设备上以两种代理类型之一存储其数据：

+   `LocalStorageProxy`：通过浏览器将数据保存到本地存储。除非用户删除，否则这些数据在会话之间是持久的。

+   `MemoryProxy`：本地内存中保存数据。页面刷新时，数据会被删除。

远程代理有两个基本类型：

+   `AjaxProxy`：将请求发送到当前域内的服务器。

+   `JsonP`：这会将请求发送到不同域上的服务器（在先前版本中这被称为`scripttag`代理）。

此外，还有一些特殊化的代理，包括：

+   `Direct`：这是一种专有的 Sencha 技术，与 Ajax 一样，允许与远程服务器进行异步通信。然而，与 Ajax 不同，`Direct`不需要保持一个到远程服务器的套接字打开，等待响应。这使得它非常适合任何可能需要服务器长时间响应延迟的过程。有关`Direct`的更多信息，请访问：

    [Ext.direct.Manager api](http://docs.sencha.com/touch/2.2.0/#!/api/Ext.direct.Manager).

+   `Rest`：`Rest`代理采用基本代理功能（`Create`、`Read`、`Edit`和`Delete`），并将这些映射到 HTTP 请求类型（分别是`POST`、`GET`、`PUT`和`DELETE`）。这种通信方式在商业 API 中非常常见。有关其他代理的更多信息，请访问：

    [Ext.data.proxy.Rest api](http://docs.sencha.com/touch/2.2.0/#!/api/Ext.data.proxy.Rest)。

    有关 REST 协议本身的更多信息，请访问：

    [HTTP 和 REST 的初学者介绍](http://net.tutsplus.com/tutorials/other/a-beginners-introduction-to-http-and-rest/)。

+   `Sql`：此代理允许您在本地 SQL 数据库中存储数据。这不应与实际的 SQL 服务器混淆。Sencha Touch SQL 代理将模型数据输出到 HTML5 本地数据库中，使用 WebSQL。

在本章及下一章中，我们将主要处理本地代理。我们将在第九章高级主题中覆盖远程代理和数据同步，*高级主题*。

代理可以作为模型的一部分声明，如下所示：

```js
proxy: {
  type: 'localstorage'
  id: 'userProxy'
}
```

所有代理都需要一个类型（本地存储、会话存储等）；然而，一些代理将需要附加信息，例如`localstorage`代理所需的唯一 ID。

我们还可以向此代理配置中添加一个读者。读者的任务是告诉我们的代理发送和接收数据时应使用哪种格式。读者理解以下格式：

+   `array`：一个简单的 JavaScript 数组

+   `xml`：可扩展标记语言格式

+   `json`：一种 JavaScript 对象表示法格式

读者作为代理的一部分被声明：

```js
proxy: {
  type: 'localstorage',
  id: 'userProxy',
  reader: {
    type: 'json'
  }
}
```

### 小贴士

**声明代理和读者**

代理和读取器也可以作为数据存储和模型的一部分声明。如果为存储和模型声明了不同的代理，那么调用`store.sync()`将使用存储的代理，而调用`model.save()`将使用模型的代理。通常只有在复杂情况下才需要在模型和存储上使用不同的代理。这也可以是令人困惑的，所以最好只在模型中定义代理，除非你确切知道你在做什么。

# 介绍数据格式

在我们将数据存储前进之前，我们需要简要地查看一下数据格式。Sencha Touch 目前支持的三种数据格式是数组、XML 和 JSON。对于每个示例，我们将查看一个简单的`contact`模型，其中包含三个字段：ID、姓名和电子邮件 ID，数据将如何显示。

## 数组

`ArrayStore`数据格式使用标准的 JavaScript 数组，对于我们这个`contact`示例，它看起来像这样：

```js
[ 
  [1, 'David', 'david@gmail.com'],
  [2, 'Nancy', 'nancy@skynet.com'],
  [3, 'Henry', 'henry8@yahoo.com']
]
```

这种数组的一个首要特点是没有字段名包括在 JavaScript 数组中。这意味着如果我们想通过名称在我们的模板中引用字段，我们必须通过使用`mapping`配置选项来设置我们的模型，使其理解这些字段应该映射到数据数组的哪个位置：

```js
Ext.define('Contact', {
 extend: 'Ext.data.Model',
  config: {
   fields: [
        'id',
        {name: 'name', mapping: 1},
        {name: 'email', mapping: 2}
    ],
    proxy: {
      type: 'memory',
      reader: {
        type: 'array'
      }
    }
   }
});
```

这设置我们的`id`字段为数据索引`0`，这是默认值。然后我们使用`mapping`配置将`name`和`email`分别设置为数据数组索引`1`和`2`，然后我们可以使用配置设置模板值：

```js
itemTpl: '{name}: {email}'
```

尽管数组通常用于简单的数据集，但对于更大的或嵌套的数据集，使用简单的 JavaScript 数组结构可能会变得非常难以管理。这就是我们的其他格式发挥作用的地方。

## XML

**可扩展标记语言**（**XML**）对于那些过去曾与 HTML 网页一起工作的人来说，应该是一个熟悉的格式。XML 由一系列嵌套在标签中的数据组成，这些标签标识数据集的每个部分的名字。如果我们把之前的例子转换成 XML 格式，它将如下所示：

```js
<?xml version="1.0" encoding="UTF-8"?>
<contact>
  <id>1</id>
  <name>David</name>
  <email>david@gmail.com</email>
</contact>
<contact>
  <id>2</id>
  <name>Nancy</name>
  <email>nancy@skynet.com</email>
</contact>
<contact>
  <id>3</id>
  <name>Henry</name>
  <email>henry8@yahoo.com</email>
</contact>
```

注意，XML 总是以版本和编码行开始。如果没有设置这一行，浏览器将无法正确解释 XML，请求将会失败。

我们还包括用于定义各个联系人的标签。这种格式的一个优点是我们现在可以嵌套数据，如下面的代码所示：

```js
<?xml version="1.0" encoding="UTF-8"?>
<total>25</total>
<success>true</success>
<contacts>
  <contact>
    <id>1</id>
    <name>David</name>
    <email>david@gmail.com</email>
  </contact>
  <contact>
    <id>2</id>
    <name>Nancy</name>
    <email>nancy@skynet.com</email>
  </contact>
  <contact>
    <id>3</id>
    <name>Henry</name>
    <email>henry8@yahoo.com</email>
  </contact>
</contacts>
```

在这个嵌套示例中，我们每个单独的`contact`标签都嵌套在一个`contacts`标签内。我们还为我们的`total`和`success`值设置了标签。

由于我们有一个嵌套数据结构，我们也需要让读取器知道去哪里寻找我们需要的片段。

```js
reader: {
    type: 'xml',
    root: 'contacts',
    totalProperty  : 'total',
    successProperty: 'success'
}
```

`root`属性告诉读取器从哪里开始查找我们的单个联系人。我们在`contacts`列表之外也设置了一个`totalProperty`值。这告诉存储器总共有 25 个联系人，尽管存储器只接收前三个。`totalProperty`属性用于分页数据（即显示 25 个中的 3 个）。

我们`contacts`列表之外的另一个属性是`successProperty`。这告诉存储器在哪里检查请求是否成功。

XML 的唯一缺点是它不是原生 JavaScript 格式，因此当系统解析它时会有一些开销。通常，只有在非常庞大或深度嵌套的数组中才会注意到这一点，但对于某些应用程序来说可能是个问题。

幸运的是，我们也可以使用 JSON。

## JSON

**JavaScript 对象表示法**（**JSON**）具有 XML 的所有优点，但由于它是原生 JavaScript 结构，因此与解析 XML 相比，它具有更少的开销。如果我们把我们的数据集看作是 JSON，我们会看到以下内容：

```js
[
  {
    "id": 1,
    "name": "David",
    "email": "david@gmail.com"
  },
  {
    "id": 2,
    "name": "Nancy",
    "email": "nancy@skynet.com"
  },
  {
    "id": 3,
    "name": "Henry",
    "email": "henry8@yahoo.com"
  }
]
```

我们也可以以与处理 XML 相同的方式嵌套 JSON：

```js
{ 
  "total": 25,
  "success": true,
  "contacts": [
   {
    "id": 1,
    "name": "David",
    "email": "david@gmail.com"
   },
   {
    "id": 2,
    "name": "Nancy",
    "email": "nancy@skynet.com"
   },
   {
    "id": 3,
    "name": "Henry",
    "email": "henry8@yahoo.com"
   }
  ]
}
```

然后，读取器会像我们的 XML 读取器一样设置，但将类型列为 JSON：

```js
reader: {
    type: 'json',
    root: 'contacts',
    totalProperty  : 'total',
    successProperty: 'success'
}
```

与之前一样，我们为`totalProperty`和`successProperty`设置了属性。我们还为读取器提供了一个开始查找我们的`contacts`列表的地方。

### 提示

还应注意的是，`totalProperty`和`successProperty`的默认值分别是`total`和`success`。如果你在自己的 JSON 返回值中使用了`total`和`success`，你实际上不需要在`reader`上设置这些配置选项。

## JSONP

JSON 还有一种替代格式，称为 JSONP，即带填充的 JSON。这种格式用于你需要从远程服务器获取数据时。我们需要这个选项，因为大多数浏览器在处理 JavaScript 请求时遵循严格的同源策略。

同源策略意味着 web 浏览器只允许 JavaScript 在与 web 页面相同的服务器上运行，只要 JavaScript 在运行。这将防止许多潜在的 JavaScript 安全问题。

然而，有时你会出于正当理由从远程服务器发起请求，例如查询 Flickr web service 的 API。因为你的应用可能不会在[flickr.com](http://flickr.com)上运行，你需要使用 JSONP，它简单地告诉远程服务器将 JSON 响应封装在一个函数调用中。

幸运的是，Sencha Touch 为我们处理所有这些事情。当你设置你的代理和读取器时，将代理类型设置为`jsonp`，并像设置常规 JSON 读取器一样设置你的读取器。这告诉 Sencha Touch 使用`Ext.data.proxy.JsonP`来执行跨域请求，而 Sencha Touch 处理其余部分。

### 注释

如果您想看看 JSONP 和`Ext.data.proxy.JsonP`的实际应用，我们在第八章，*创建 Flickr Finder 应用程序*中使用两者来构建**Flickr Finder**应用程序。

虽然我们有多种格式可供选择，但本章余下的例子我们将使用 JSON 格式。

# 介绍存储

顾名思义，存储用于存储数据。正如我们在前几章所看到的，列表组件需要一个存储来显示数据，但我们也可以使用存储从表单中获取信息并将其保存在我们应用程序的任何地方。

存储、模型和代理一起工作，与传统数据库非常相似。模型为我们数据提供结构（如传统数据库中的架构），代理提供通信层，以便将数据进出存储。存储本身持有数据，并为排序、筛选、保存和编辑数据提供强大的组件接口。

存储还可以绑定到许多组件，如列表、嵌套列表、选择字段和面板，以提供显示数据。

我们将在第七章，*获取数据外*中覆盖显示、排序和筛选内容，但目前，我们将着手查看使用存储来保存和编辑数据。

## 简单的存储

由于本章关注的是将数据导入存储，我们将从一个非常简单的本地存储示例开始：

```js
var contactStore = Ext.create('Ext.data.Store', {
  model: 'Contact',
  autoLoad: true
});
```

这个示例告诉存储使用哪个模型，这反过来定义了存储知道的字段以及存储应该使用的代理，因为存储将采用字段列表和代理从其模型中。我们还设置存储为`autoLoad`，这意味着一旦创建存储，它就会加载数据。

### 注意

如果您在存储配置中声明了一个代理，那么将使用该代理而不是模型的代理。在某些情况下这很有用，例如您想要存储关于记录集合的信息，如一组管理员用户。在这种情况下，模型用于存储用户详细信息，但存储用于收集特定类型（管理员用户）的多个用户。

我们还需要确保我们的模型设置正确，以便使用此存储。由于我们在存储中没有列出代理，我们需要确保模型有一个，如果我们想要保存我们的数据：

```js
Ext.define('Contact', {
 extend: 'Ext.data.Model',
  config: { 
   fields: [
        {name: 'id', type:'int'},
        {name: 'name', type: 'string'},
        {name: 'email',  type: 'string'}
    ],
    proxy: {
        type: 'localstorage',
        id: 'myContacts',
        reader: {
          type: 'json'
        }
    }
  }
});
```

这是一个包含三个项目的简单模型：一个 ID、一个名称和一个电子邮件地址。我们然后像以前一样创建一个新的联系人：

```js
  var newContact = Ext.create('Contact', {
    name: 'David',
    email: 'david@msn.com'
  });
```

请注意，这次我们没有设置 ID。我们希望存储为我们设置 ID（这与典型数据库中的自动递增类似）。然后我们可以将这个新联系人添加到存储中并保存它：

```js
var addedUser = contactStore.add(newContact);
contactStore.sync();
```

第一行将用户添加到商店，第二行保存商店的内容。通过将 `add` 和 `sync` 功能分开，你可以向商店添加多个用户，然后执行一次保存，如下面的代码所示：

```js
  var newContact1 = Ext.create('Contact', {
    name: 'David',
    email: 'david@msn.com'
  });

  var newContact2 = Ext.create('Contact',
    name: 'Bill',
    email: 'bill@yahoo.com'
  });

var addedContacts = contactStore.add(newContact1, newContact2);
contactStore.sync();
```

在这两种情况下，当我们向商店添加联系人时，我们设置一个返回变量来获取 `add` 方法的返回值。这个方法返回一个联系人数组，现在每个 `contact` 对象都将有一个唯一的 ID。我们可以在我们的同步之后添加几个控制台日志来查看这些值：

```js
console.log(addedContacts);
console.log(addedContacts[0].data.name+': '+addedContacts[0].data.id);
console.log(addedContacts[1].data.name+': '+addedContacts[1].data.id);
```

这将显示返回两个 `contact` 对象的数组。它还显示了如何通过使用数组中特定联系人的索引号来获取我们需要的数据。然后我们可以深入到数据中，获取姓名和我们在同步时分配的新 ID。

![一个简单的商店](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_06_02.jpg)

既然我们已经大致了解了如何将数据输入商店的方法，那么让我们来看看如何使用表单来完成它。

## 表单和商店

在这个例子中，我们将使用与上一个例子相同的商店和模型，但我们将添加一个列表和一个表单，这样我们就可以添加新的联系人并查看我们添加了什么。让我们从列表开始：

```js
this.viewport = Ext.create('Ext.Panel', {
    fullscreen: true,
    layout: 'fit',
    items: [
  {
        xtype: 'toolbar',
        docked: 'top',
        items: [{
            text: 'Add',
            handler: function() {
              Ext.Viewport.add(addNewContact);
              addNewContact.show()
            }
        }]
    },
    {
      xtype: 'list',
      itemTpl: '{name}: {email}',
      store: contactStore
    }]
});
```

你会得到类似于以下屏幕截图的东西：

![表单和商店](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_06_03.jpg)

这里的大部分代码与之前的例子非常相似。我们有一个带有 `list` 组件的单个子面板。我们的列表有一个使用与我们的 `contact` 模型相同的字段名的模板 `itemTpl`，它决定了它们将如何显示。我们还添加了一个带有我们新 **添加** 按钮的固定工具栏。

### 提示

`toolbar` 组件也发生了变化，与 Sencha Touch 的以前版本不同。在版本 2 中，`toolbar` 是 `items` 列表的一部分，而不是作为一个单独的 `dockedItem`。此外，`toolbar` 的位置以前是通过 `dock` 配置选项来设置的。在 Sencha Touch 2 中，这被改为了 `docked`。还应该注意的是，如果你尝试使用旧的 `dockedItem` 和 `dock` 配置，你不会得到任何错误。你也不会得到工具栏。这可能会导致你扯掉很多头发并说出粗糙的语言。

按钮有一个非常简单的函数，它将一个名为 `addNewContact` 的 Ext.Sheet 添加到我们的视口，然后显示该表单。现在我们需要实际创建这个表单：

```js
var addNewContact = Ext.create('Ext.Sheet', {
  height: 250,
  layout: 'fit',
  stretchX: true,
  enter: 'top',
  exit: 'top',
  items: […]
});
```

这给了我们一个新表单，当我们点击 **添加** 按钮时会出现。现在，我们需要将我们的表单字段添加到我们刚刚创建的表单的 `items` 部分：

```js
{
  xtype: 'formpanel',
  padding: 10,
  items: [
    {
     xtype: 'textfield',
     name : 'name',
     label: 'Full Name'
    },
    {
     xtype: 'emailfield',
     name : 'email',
     label: 'Email Address'
   }
  ]
}
```

我们首先创建一个 `formpanel` 组件，然后将 `textfield` 和 `emailfield` 添加到 `formpanel` 的 `items` 列表中。

### 专业文本字段

Sencha Touch 使用了如 `emailfield`、`urlfield` 和 `numberfield` 等专业文本字段，以控制移动设备使用哪种键盘，如下面的 iPhone 示例所示：

![专业文本字段](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_06_04.jpg)

前述图表中所示的键盘类型如下解释：

+   **URL 键盘**用点（`.`）、斜杠（`/**`）和`.com`的键替换了传统的空格键。

+   **电子邮件键盘**缩短了空格键，并为`@`和点（`.`）腾出了空间。

+   **数字键盘**最初显示数字键盘，而不是标准的 QWERTY 键盘。

这些特殊字段不会自动验证用户输入的数据。那些验证是通过模型验证处理的。

### 提示

**特殊键盘**

安卓和 iOS 拥有略微不同的特殊键盘，因此你可能会在这两者之间找到一些变化。通常，运行你的应用程序通过安卓和 iOS 模拟器，以确保正确使用键盘类型。

## 将字段映射到模型

你还会注意到我们表单中的每个字段名称与我们`contact`模型的名称相匹配；这将允许我们轻松创建联系信息并将它们添加到商店中。然而，在我们到达那里之前，我们需要添加两个按钮（**保存**和**取消**），以告诉表单要做什么。

在我们表单中的`emailfield`对象之后，我们需要添加以下内容：

```js
{
  xtype: 'button',
  height: 20,
  text: 'Save',
  margin: 10,
  handler: function() {
    this.up('sheet').hide();
  }
  }, {
  xtype: 'button',
  height: 20,
  margin: 10,
  text: 'Cancel',
  handler: function() {
    this.up('sheet').hide();
  }
}
```

这给了我们在表单底部两个按钮。现在，我们的**保存**和**取消**按钮做相同的事情：它们调用一个函数来隐藏包含我们表单的弹出窗口。这是一个很好的起点，但我们还需要更多功能来让**保存**按钮保存我们的数据。

![将字段映射到模型](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_06_05.jpg)

由于我们是很棒的程序员，并且给我们的字段命名以匹配我们的模型，我们只需要在我们按钮处理程序中使用以下代码就可以将我们的表单添加到我们的商店中：

```js
handler: function() {
  var form = this.up('formpanel');
  var record = Ext.create('Contact', form.getValues());
  contactStore.add(record);
  contactStore.sync();
  form.reset();
  this.up('sheet').hide();
 }
```

第一行使用`up`方法获取围绕按钮的表单。第二行使用`form.getValues()`，并将输出直接传递到一个新`Contact`模型中，使用我们之前示例中的`create()`方法。然后我们可以将新联系信息添加到商店并同步，就像我们之前做的那样。

我们需要做的最后一点清理工作是通过使用`form.reset()`来清除所有表单值，然后像之前一样隐藏表单。如果我们不清除字段，下次我们显示表单时数据仍然会存在。

当我们同步商店时，与商店关联的列表将会刷新，我们的新联系信息会出现。

![将字段映射到模型](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_06_06.jpg)

由于这个商店使用本地存储来保存数据，我们的列表在我们退出 Safari 浏览器后仍然会保持原位。当你测试应用程序时，这可能会让你感到有些烦恼，所以让我们来看看如何清除商店中的数据。

## 清除商店数据

本地存储和会话存储在我们本地计算机上保存信息。由于我们计划在编码时进行大量测试，知道如何清除这类数据而又不删除可能仍然需要的其他数据是个好主意。要清除您本地或会话存储中的数据，请按照以下步骤操作：

1.  从**开发**菜单中打开**网络检查器**，并选择**资源**标签。![清除存储数据](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_06_07.jpg)

1.  在**本地存储**或**会话存储**部分（取决于您使用的方法），您应该看到您应用程序的数据库。一旦您选择了数据库，您可以删除特定的记录或完全清空数据库。只需在屏幕右侧选择记录，然后点击底部的**X**以删除记录。

1.  您还可以通过双击它并更改数字来重置计数器的值。小心不要创建具有相同数字的多个记录。这将造成大问题。

1.  在**资源**部分完成后，让我们继续使用我们的表单编辑数据。

## 使用表单编辑

现在我们已经了解了将数据传入存储的基本知识，让我们来看看如何使用对我们当前表单进行一些修改来编辑这些数据。

我们想要添加的第一个是一个`itemsingletap`监听器到我们的列表上。这将让我们点击列表中的一个项目并弹出包含所选条目的表单，以便我们进行编辑。监听器如下所示：

```js
listeners: {
 itemsingletap: {
  fn: function(list, index, target, record){
   addNewContact.down('form').setRecord(record);
   Ext.Viewport.add(addNewContact);
   addNewContact.show();
  }
 }
} 
```

我们的`itemsingletap`监听器将自动返回`list`的副本、项目的`index`属性、`target`元素以及被点击项背后的`record`。然后我们可以获取我们表单内的表单并在其中设置记录。

经常以这种方式链接函数很有用，特别是如果你需要用到的部分只需使用一次。例如，我们可以这样做：

```js
var form = addNewContact.down('form');
form.setRecord(record);
```

这样也可以让我们在函数的许多地方使用那个`form`变量。由于我们只需要用它来设置记录，我们可以将这两行合并为一行：

```js
addNewContact.down('form').setRecord(record);
```

以下方式将数据加载到我们的表单中：

![使用表单编辑](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_06_08.jpg)

还有一个问题需要解决：我们的**保存**按钮硬编码到向存储中添加新记录。如果我们现在点击**保存**，我们最终会得到同一个联系人的多个副本。我们需要对我们的表单进行更改，以便让我们可以根据我们是在编辑还是创建新联系人来切换**保存**按钮的行为。

### 切换处理程序

为了更改处理程序，按钮触发保存我们的联系人；我们需要将代码的主体与按钮本身分开。首先，找到我们的**保存**按钮的处理程序，并将当前函数复制到剪贴板。接下来，我们想要用外部函数的名称替换那个函数：

```js
handler: addContact
```

我们还将以以下方式向我们的按钮添加一个额外的`config`选项：

```js
action: 'saveContact'
```

这将使我们稍后用组件查询更容易地获取我们的按钮。

### 小贴士

`action`配置选项是一个完全任意的名称。您不受限于 Sencha 定义的选项。您可以为组件定义任何其他选项，并在处理程序和控制器中像其他任何配置选项一样引用它们。

现在，我们需要为这个处理程序创建一个新的`addContact`函数。在我们创建`addNewContact`表单的 JavaScript 文件中，在创建`addNewContact`表单之前，添加一个名为`addContact`的新函数，并粘贴我们旧`handler`函数的代码。它应该如下所示：

```js
var addContact = function() {
  var form = this.up('formpanel');
  var record = Ext.create('Contact', form.getValues());
  contactStore.add(record);
  contactStore.sync();
  form.reset();
  this.up('sheet').hide();
};
```

这是我们之前在按钮上使用过的表单保存函数，它添加新联系人正好合适。现在，我们需要创建一个类似的函数，当我们在列表中点击它们时更新我们的联系人。

在我们的`addContact`函数顶部，添加以下代码：

```js
var updateContact = function() {
  var form = this.up('formpanel');
  var rec = form.getRecord();
  var values = form.getValues();
  rec.set(values);
  contactStore.sync();
  form.reset();
  this.up('sheet').hide();
};
```

这个函数几乎做了我们另一个函数的所有事情。然而，不同的是，它不是获取表单字段并创建一个新的记录，而是使用`form.getRecord()`从表单本身获取记录。这个记录是我们需要用新信息更新的记录。

然后，我们使用`form.getValues()`获取表单的当前值。

我们的`rec`变量现在设置为数据存储中的旧记录。然后，我们可以使用`rec.set(values)`将该记录传递给新数据，这将用我们当前表单值覆盖存储记录中的旧信息。由于我们没有传递新值，ID 将保持不变。

更新记录后，我们只需执行以下早期所做的操作：

+   `sync`

+   `reset`

+   `hide`

现在我们的两个函数的代码已经就位，我们需要根据用户是否点击了我们列表顶部的**添加**按钮或选择了列表中的项目来切换**保存**按钮的处理程序。

让我们从**添加**按钮开始。在`list`对象的顶部找到**添加**按钮的处理程序。我们需要向这个按钮添加一些代码，以更改**保存**按钮的处理程序：

```js
handler: function() {
  var button = addNewContact.down('button[action=saveContact]');
  button.setHandler(addContact);
  button.setText('Add');
  Ext.Viewport.add(addNewContact);
  addNewContact.show();
}
```

由于我们的`addNewContact`表单已经在代码的其他地方定义为一个变量，我们可以使用`down()`方法获取`button`并做一些更改。首先，更新处理程序以查看我们的新`addContact`函数，第二个更改是将按钮的文本更改为`创建`。然后，我们可以在视口中添加我们的`addNewContact`表单并调用`addNewContact.show()`，就像以前一样。

我们的**添加**按钮现在设置为显示表单并更改按钮的文本和处理程序。

现在，我们需要对列表中的`itemsingletap`处理程序做类似的事情：

```js
itemsingletap: {
  fn: function(list,index, target, record){
    addNewContact.down('formpanel').setRecord(record);
    var button = addNewContact.down('button[action=saveContact]');
    button.setHandler(updateContact);
    button.setText('Update');
    Ext.Viewport.add(addNewContact);
    addNewContact.show();
  }
}
```

在这里，我们仍然获取记录并将其加载到表单中，但我们要获取`button`带有`action`值为`saveContact`的元素，并更改处理程序和文本。更改将**保存**按钮指向我们的`updateContact`函数，并将文本更改为`更新`。

![Switching handlers](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_06_09.jpg)

# 从数据存储中删除

如果你还记得之前我们讨论 CRUD 功能的时候，你会发现我们已经成功覆盖了`Create`（创建）、`Read`（读取）和`Update`（更新）。这些操作都是由存储自动完成的，几乎不需要编写任何代码。那么`Delete`（删除）呢？

结果表明，`Delete`（删除）与其他存储方法一样简单。我们可以使用两个方法中的任意一个：第一个是`remove()`—它需要一个记录作为参数—第二个是`removeAt`，它需要一个索引来确定要删除的记录。我们可以将其中任何一个作为我们编辑表单的一部分，通过在表单底部添加一个新按钮来实现，如下所示：

```js
{
  xtype: 'button',
  height: 20,
  margin: 10,
  text: 'Delete',
  ui: 'decline',
  handler: function() {
    var form = this.up('formpanel');
    contactStore.remove(form.getRecord());
    contactStore.sync();
    form.reset();
    this.up('sheet').hide();
  }
}
```

使用`remove`需要存储记录，因此我们从表单面板中获取记录：

```js
contactStore.remove(form.getRecord());
```

这样就处理了所有基本的`Create`（创建）、`Read`（读取）、`Edit`（编辑）和`Delete`（删除）功能。只要你记得设置你的模型并匹配你的字段名，存储会自动处理大多数基本操作。

### 注意

**更多信息**

Sencha 提供了许多关于使用表单、模型和存储的优秀教程，请访问[`docs.sencha.com/touch/2.2.1/#!/guide`](http://docs.sencha.com/touch/2.2.1/#!/guide)。

# 总结

在本书的第四章，我们介绍了在 Sencha Touch 中构成所有数据基本结构的数据模型。我们查看了代理和读取器，它们处理数据存储与其他组件之间的通信。我们还讨论了在 Sencha Touch 中持有所有数据的存储。最后，我们查看了如何使用表单将数据进出存储，以及如何在数据不再需要时删除数据。

在下一章中，我们将查看一旦我们把数据从存储中取出后可以做的所有其他事情。
