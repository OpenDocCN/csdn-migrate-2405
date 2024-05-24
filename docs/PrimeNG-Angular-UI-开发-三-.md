# PrimeNG：Angular UI 开发（三）

> 原文：[`zh.annas-archive.org/md5/F2BA8B3AB075A37F3A10CF12CD37157B`](https://zh.annas-archive.org/md5/F2BA8B3AB075A37F3A10CF12CD37157B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：令人惊叹的覆盖和消息

令人惊叹的覆盖和消息展示了模态或非模态覆盖（如对话框、灯箱和覆盖面板）中显示的各种内容的不同变体。当内容显示在上述覆盖中时，用户不会离开页面流。覆盖组件会覆盖页面上的其他组件。PrimeNG 还提供通知组件来显示各种消息或咨询信息。这些消息组件也将被描述。

在本章中，我们将涵盖以下主题：

+   在弹出模式下显示内容

+   OverlayPanel 的多功能场景

+   在灯箱中显示内容

+   使用消息和 Growl 通知用户

+   表单组件的工具提示

# 在弹出模式下显示内容

网站的附加信息可以以弹出格式表示。这将通过最佳视口改善用户体验。存在两种类型的弹出格式：**对话框**和**确认对话框**。

# 对话框

对话框是一个容器组件，用于在覆盖窗口中显示内容。为了保存网页的视口，对话框非常有用，可以以弹出格式显示附加信息。对话框的可见性通过`visible`属性控制。

默认情况下，对话框以`false`的`visibility`隐藏，并启用`visible`属性显示对话框。由于对话框具有双向绑定的特性，使用关闭图标关闭对话框后，`visible`属性会自动变为`false`。`closeOnEscape`属性用于使用*Esc*键关闭对话框。

对话框组件的基本示例与源按钮将如下所示：

```ts
<p-dialog header="PrimeNG" [(visible)]="basic"> 
  PrimeNG content goes here.... </dialog>

```

`visible`属性在用户操作时被启用。以下屏幕截图显示了基本对话框示例的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/ee678b76-d822-4e80-9466-775720dc4553.png)

对话框组件支持两个名为`onShow`和`onHide`的事件回调，当对话框显示或隐藏时将被调用。

# 可用性功能

通过使用`draggable`、`resizable`、`closable`和`responsive`属性，对话框组件的用户体验将得到改善，具有可拖动、可调整大小、可关闭和响应式功能。除了这些交互功能，`modal`属性通过透明背景防止用户在主页面上执行操作，而`dismissableMask`在用户点击透明背景时隐藏对话框。

这些属性的默认值如下：

+   `draggable = true`

+   `resizable = true`

+   `closable = true`

+   `responsive = false`

+   `modal = false`

+   `dismissableMask = false`

# 自定义标题和页脚

对话框的标题通过`header`属性定义，并且可以通过`showHeader`属性进行控制。对话框组件的页眉和页脚部分可以使用`p-header`和`p-footer`标签以更灵活的方式进行定义。为了使用它们，需要导入页眉和页脚组件，并在指令部分声明它。

具有自定义标题和页脚的对话框组件的自定义示例将如下所示：

```ts
<p-dialog[(visible)]="custom" modal="true">
 <p-header>
    PrimeNG License declaration
  </p-header>
  All widgets are open source and free to use under MIT License.
  If agree with the license please click 'Yes' otherwise click 'No'.
  <p-footer>
    <div class="ui-dialog-buttonpane ui-widget-content 
      ui-helper-clearfix">
      <button type="button" pButton icon="fa-close" (click)="onComplete()" label="No"></button>
      <button type="button" pButton icon="fa-check" (click)="onComplete()" label="Yes"></button>
    </div>
  </p-footer>
</p-dialog>

```

以下截图显示了自定义对话框示例的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/310d8d0e-9d09-475f-8687-c4e8aa2d2fdf.png)

前面的快照显示了如何根据需要或要求自定义标题、消息和页脚图标。默认情况下，对话框组件在视口中居中对齐，但可以使用`positionLeft`和`positionTop`属性进行自定义。

# ConfirmDialog

ConfirmDialog 是一个用于同时显示多个操作的确认窗口的组件。在这种情况下，它将由使用可观察对象的确认服务支持。需要导入使用多个操作的确认方法的服务。

使用源按钮（或对话框生成器按钮）的 ConfirmDialog 组件的基本示例将如下所示：

```ts
<p-confirmDialog></p-confirmDialog>
    <button type="button" (click)="confirmAccept()" pButton
      icon="fa-check" label="Confirm"></button>
    <button type="button" (click)="confirmDelete()" pButton
      icon="fa-trash" label="Delete"></button>

```

在上面的示例中，确认方法将确认一个实例，用于自定义对话框 UI 以及接受和拒绝按钮。例如，`accept`函数调用确认服务的确认方法，决定需要执行什么操作：

```ts
confirmAccept() {
 this.confirmationService.confirm({
    message: 'Do you want to subscribe for Angular news feeds?',
    header: 'Subscribe',
    icon: 'fa fa-question-circle',
    accept: () => {
      this.msgs = [];
      this.msgs.push({severity:'info', summary:'Confirmed',
                     detail: 'You have accepted'});
    }
  });
}

```

点击按钮组件后，对话框出现。以下截图显示了基本确认对话框示例的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/15c967c5-65dd-400a-8862-e12aa1bd8386.png)

页脚的接受和拒绝按钮决定是否订阅 Angular 新闻订阅系统。

# 自定义

提供确认对话框的标题、消息和图标有两种方式。一种是声明性的方式，通过属性（`header`、`message`和`icon`）提供所有功能，而另一种方式是程序化的方式，通过确认实例属性使值可以动态变化。甚至页脚部分的按钮也可以通过它们自己的 UI（`acceptLabel`、`acceptIcon`、`acceptVisibility`、`rejectLabel`、`rejectIcon`和`rejectVisibility`）进行自定义，以及本地`ng-template`变量的接受和拒绝方法。

一个带有标题和页脚的自定义确认对话框组件的示例将如下编写：

```ts
<p-confirmDialog header="Confirmation" message="Do you like to use  
  DataTable component" icon="fa fa-question-circle" width="400" 
  height="200" #confirmation>
  <p-footer>
    <button type="button" pButton icon="fa-close" label="No" 
    (click)="confirmation.reject()"></button>
    <button type="button" pButton icon="fa-check" label="Yes" 
    (click)="confirmation.accept()"></button> </p-footer>
</p-confirmDialog>

```

以下截图显示了自定义确认对话框示例的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/83c1baf1-f5e6-4dd1-ad21-e32eae92e14a.png)

在上面的快照中，所有标题、消息和图标都是以声明性的方式进行自定义的。确认对话框提供了默认的`closable`、`responsive`和`closeOnEscape`属性，这与对话框组件类似。

完整的演示应用程序及说明可在 GitHub 上找到：

+   [`github.com/ova2/angular-development-with-primeng/tree/master/chapter6/dialog`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter6/dialog)

+   [`github.com/ova2/angular-development-with-primeng/tree/master/chapter6/confirm-dialog.`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter6/confirm-dialog)

# OverlayPanel 的多用途场景

OverlayPanel 是一个容器组件，可以在页面的其他组件上方显示附加信息。使用本地`ng-template`变量的`show`或`toggle`方法来显示该元素，使用`hide`或`toggle`方法来隐藏它。请记住，`show`方法将允许第二个参数作为目标元素，它必须显示 Overlay（而不是源）。Overlay 组件与源按钮生成器的基本示例将如下所示：

```ts
<p-overlayPanel #overlaybasic>
 <img src="/assets/data/images/primeng.png" alt="PrimeNG Logo" />
</p-overlayPanel>
<button type="button" pButton label="Logo" (click)="overlaybasic.toggle($event)"></button>

```

在上面的示例中，Overlay 将在单击按钮组件时出现。以下截图显示了基本 Overlay 示例的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/95ece15c-06b5-4dc8-8721-99dbffc6c840.png)

在上面的快照中，Overlay 在点击 logo 按钮时显示 PrimeNG logo 作为图像。默认情况下，OverlayPanel 附加到页面的 body 上，但可以使用 `appendTo` 属性更改目标。

# 与其他组件集成

OverlayPanel 组件也可以与其他 PrimeNG 组件集成。例如，下面的快照显示了如何使用 `ng-template` 将 Overlay 组件与 DataTable 组件集成。在这种情况下，按钮需要放置在 DataTable `ng-template` 内，并通过 `toggle` 事件触发 Overlay：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/032d5765-fa89-40c7-b0b8-676ec555d49c.png)

在上面的快照中，Overlay 面板用于通过点击每行的结果按钮以弹出格式显示聚合信息，如标记和百分比。

# 可关闭属性

默认情况下，Overlay 面板外部的交互会立即关闭 Dialog。可以使用 `dismissable` 属性阻止此行为。同时，还可以使用 `showCloseIcon` 属性在右上角显示关闭选项。

Dialog 组件支持四个事件回调，分别为 `onBeforeShow`、`onAfterShow`、`onBeforeHide` 和 `onAfterHide`，当 Dialog 被显示或隐藏时将被调用。

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter6/overlaypanel.`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter6/overlaypanel)

# 在 Lightbox 中显示内容

LightBox 组件用于以模态 Overlay 模式显示图像、视频、内联 HTML 内容，以及 iframe 集合。存在两种类型的 LightBox 模式：一种是默认的 `image` 类型，另一种是 `content` 类型。在图像模式中，将显示图像集合，其中每个条目代表一个图像对象，代表图像的来源、缩略图和标题。一个带有 Angular 会议集合（或数组）的 LightBox 的基本示例如下：

```ts
<p-lightbox [images]="images" name="image"></p-lightbox>

```

组件将呈现如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/3a961c4b-84f5-47ca-a0cb-f59bc6e8f855.png)

在上面的快照中，所有图像都显示为图像库，并通过下一个和上一个图标进行导航。

# 自定义内容模式

通过将`type`属性设置为`content`来启用内容模式，这将提供一个锚点（或链接）来打开 LightBox 并在其中显示内容。一个自定义内容的 LightBox 示例，包含一系列 Angular 会议，如下所示：

```ts
<p-lightbox type="content" name="content">
 <a class="group" href="#">
    Watch PrimeNG Video
  </a>
  <iframe width="500" height="300" 
    src="https://www.youtube.com/watch?v=Jf9nQ36e0Fw&t=754s" frameborder="0" allowfullscreen></iframe>
</p-lightbox>

```

该组件将作为 iframe 视频呈现在覆盖面板内，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/b8764662-39e0-4380-86f4-b2bb6390cd2d.png)

如上面的快照所示，视频列表被显示出来，并且可以在弹出模式下观看视频，以获得更好的体验。

# 过渡效果

LightBox 组件在图片之间的过渡效果更加强大。这可以通过`easing`属性实现。在这里，默认值是`ease-out`（即，使用`easing`属性自定义效果）。还有许多其他效果可用，支持整个 CSS3 效果列表。此外，默认情况下，效果持续时间为`500ms`。这也可以通过`effectDuration`属性进行自定义。

作为 LightBox 的过渡效果的一个示例，包含一系列 Angular 会议的效果如下：

```ts
<p-lightbox [images]="images" name="effects" easing="ease-out"  
  effectDuration="1000ms">
</p-lightbox>

```

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter6/lightbox.`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter6/lightbox)

# 通过消息和 Growl 通知用户

消息组件用于以内联格式显示消息，以通知用户。这些消息是作为特定操作的结果而通知的。PrimeNG API 中的每条消息都是使用`Message`接口定义的，该接口定义了`severity`、`summary`和`detail`属性。

通知用户的消息的基本示例如下：

```ts
<p-messages ([value])="messages" name="basic"></p-messages>

```

在上面的例子中，消息使用`value`属性显示，该属性定义了`Message`接口的数组。该组件将如下截图所示呈现：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/ddfaf6df-6ad7-4ec0-8479-f502b2fc8ab9.png)

消息的严重程度由`class`属性表示。消息严重程度的可能值如下：

| **严重程度** | **类名** |
| --- | --- |
| `success` | `.ui-button-success` |
| `info` | `.ui-button-info` |
| `warn` | `.ui-button-warn` |
| `error` | `.ui-button-error` |

消息默认情况下可以通过位于右上角的关闭图标关闭。这种行为可以通过`closable`属性进行修改，即`[closable]="false"`会禁用消息的可关闭性。

# Growl - 另一种通知信息的方式

与消息组件类似，Growl 用于以覆盖模式而不是内联模式显示特定操作的消息。每条消息通过`Message`接口表示，具有`severity`、`summary`和`details`。Growl 通知用户的基本示例如下：

```ts
<p-growl ([value])="messages" name="basic"></p-growl>

```

`value`属性在后台组件模型中定义了`Message`接口的数组。组件将呈现如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/713cf270-975f-43af-a988-10a28b617fec.png)

与消息组件类似，Growl 中也可以定义相同的严重类型。PrimeNG 4.1 版本引入了`onClick`事件回调，当单击消息时将被调用。

# 粘性行为

默认情况下，Growl 消息在一定时间后会被移除。Growl 消息的默认寿命是`3000ms`。这可以使用`life`属性进行自定义（即`life="5000"`）。要使消息成为粘性消息，无论提到的寿命如何，您都应该启用粘性行为，即`sticky="true"`。

PrimeNG 版本 4.0.1 支持 Growl 消息的双向绑定功能。由于这个特性，每当消息从 UI、后端实例或消息中被手动移除时，数组将立即更新。完整的演示应用程序及说明可在 GitHub 上找到

+   [`github.com/ova2/angular-development-with-primeng/tree/master/chapter6/messages`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter6/messages)

+   [`github.com/ova2/angular-development-with-primeng/tree/master/chapter6/growl.`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter6/growl)

# 表单组件的工具提示

工具提示为组件提供了咨询信息。这在使用目标组件之前给出了简要的见解。工具提示通过`pTooltip`指令应用，其值定义要显示的文本。除此之外，还可以使用`escape`属性显示 HTML 标签，而不是常规文本信息。工具提示的基本示例是为输入提供咨询信息，如下所示：

```ts
<input type="text" pInputText pTooltip="Enter your favourite component   
  name" >

```

工具提示显示在输入框的右侧，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/cc180360-109f-4d65-bf15-7dfd2fe66bd6.png)

默认情况下，工具提示位置显示在目标组件的右侧。可以使用`tooltipPosition`属性将此行为更改为其他值，例如`top`、`right`和`bottom`，例如，具有`top`值的`tooltipPosition`将导致如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/14ee580a-3a7f-42db-b6b7-4f009b7ea4d0.png)

默认情况下，工具提示在悬停在目标元素上时显示（即，调用工具提示信息的默认事件是悬停）。可以使用`tooltipEvent`属性进行自定义，该属性提供焦点事件以显示和模糊事件以隐藏工具提示。请记住，工具提示也可以使用`tooltipDisabled`属性禁用。

输入的工具提示事件示例如下：

```ts
<input type="text" pInputText pTooltip="Enter your favourite component 
  name" tooltipEvent="focus" placeholder="Focus inputbox"/>

```

默认情况下，工具提示分配给文档主体。如果工具提示的目标放置在滚动容器内（例如，溢出的`div`元素），则将工具提示附加到具有相对位置的元素。可以使用`appendTo`属性实现这一点（即`appendTo="container"`）。

PrimeNG 版本 4.1 提供了`showDelay`和`hideDelay`属性，以便在显示和隐藏工具提示时添加延迟（以毫秒为单位的数字值）。延迟功能将应用如下：

```ts
<input type="text" pInputText pTooltip="Enter your favourite component 
  name" tooltipEvent="focus" placeholder="Focus inputbox" 
  showDelay="1000" hideDelay="400"/>

```

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter6/tooltips.`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter6/tooltips)

# 摘要

通过阅读本节，您将能够了解如何在不离开当前页面流的情况下在覆盖窗口中显示图像、视频、iframe 和 HTML 内容。最初，您将看到如何使用对话框、确认对话框、灯箱和覆盖组件。之后，您将学习如何通过消息和生长组件在覆盖中显示内联消息或消息。

最后一个示例介绍了用于显示咨询信息的工具提示组件。所有这些组件都是通过逐步方法解释的，具有所有可能的功能。在下一章中，您将看到如何使用菜单模型 API、导航和菜单变体，如菜单、超级菜单、菜单栏、滑动菜单、面板菜单、分层菜单等，具有各种功能。


# 第七章：无尽的菜单变体

在本章中，您将了解到几种菜单变体。PrimeNG 的菜单满足所有主要要求。如今，每个网站都包含菜单。通常，菜单被呈现给用户作为要导航或执行的命令的链接列表。菜单有时是按层次组织的，允许通过菜单结构的不同级别进行导航。

将菜单项排列成逻辑组，使用户可以快速找到相关任务。它们具有各种方面，如静态、动态、分层、混合、iPod 风格等，无所不包。读者将面临许多讨论菜单结构、配置选项、自定义以及与其他组件集成的示例。

在本章中，我们将涵盖以下主题：

+   使用 MenuModel API 创建程序化菜单

+   静态和动态定位的菜单

+   通过 MenuBar 访问命令

+   带有嵌套项的上下文菜单

+   SlideMenu - iPod 风格的菜单

+   TieredMenu - 嵌套覆盖中的子菜单

+   MegaMenu - 多列菜单

+   PanelMenu - 手风琴和树的混合

+   TabMenu - 菜单项作为选项卡

+   Breadcrumb - 提供有关页面层次结构的上下文信息

# 使用 MenuModel API 创建程序化菜单

PrimeNG 提供了一个`MenuModel` API，它将被所有菜单组件共享，用于指定菜单项和子菜单。`MenuModel` API 的核心项目是`MenuItem`类，具有`label`、`icon`、`url`、带有`items`选项的子菜单项等选项。

让我们以菜单组件为例，代表常见的工具栏用户界面。菜单组件通过`model`属性绑定`MenuItem`类的数组作为项目，如下所示：

```ts
<p-menu [model]="items"></p-menu>

```

`MenuItem`是`MenuModel` API 中的关键项目。它具有以下属性列表。每个属性都用类型、默认值和描述进行描述：

| **名称** | **类型** | **默认** | **描述** |
| --- | --- | --- | --- |
| `label` | `字符串` | `null` | 项目的文本。 |
| `icon` | `字符串` | `null` | 项目的图标。 |
| `command` | `函数` | `null` | 单击项目时要执行的回调。 |
| `url` | `字符串` | `null` | 单击项目时要导航到的外部链接。 |
| `routerLink` | `数组` | `null` | 用于内部导航的 RouterLink 定义。 |
| `items` | `数组` | `null` | 子菜单项的数组。 |
| `expanded` | `boolean` | `false` | 子菜单的可见性。 |
| `disabled` | `boolean` | `false` | 当设置为`true`时，禁用菜单项。 |
| `visible` | `boolean` | `true` | 菜单项的 DOM 元素是否已创建。 |
| `target` | `string` | `null` | 指定打开链接文档的位置。 |

表 1.0

# 菜单操作

具有纯文本只读标签和图标的菜单项并不是真正有用的。具有用户操作的菜单组件需要执行业务实现或导航到其他资源。菜单操作的主要组件是命令调用和导航。这可以通过`MenuItem`接口的`url`和`routerLink`属性来实现。

`MenuItem` API 的 URL 和路由链接选项的示例用法如下：

```ts
{label: 'View', icon: 'fa-search', command: 
  (event) => this.viewEmployee(this.selectedEmployee)}

{label: 'Help', icon: 'fa-close', url: 
 'https://www.opm.gov/policy-data- oversight/worklife/employee-
  assistance-programs/'}

```

在接下来的部分，您将看到`MenuModel` API 将如何在各种菜单组件中使用。

# 静态和动态定位的菜单

菜单是一个支持动态和静态定位的导航或命令组件。这是所有菜单组件中的基本菜单组件。菜单默认是静态定位的，但通过提供`target`属性可以使其变为动态定位。静态定位的菜单附加到页面主体作为目标（即`appendTo="body"`），而分配给其他元素则创建动态定位的菜单。

一个基本的菜单示例，包含项目文档或文件类型的菜单项，如下所示：

```ts
<p-menu [model]="items"></p-menu>

```

菜单项列表需要在一个组件类中进行组织。例如，名为“编辑”的根菜单项将有如下嵌套项：

```ts
this.items=[
{
    label: 'Edit',
    icon: 'fa-edit',
    items: [
        {label: 'Undo', icon: 'fa-mail-forward'},
        {label: 'Redo', icon: 'fa-mail-reply'}
    ]
},
//More items ...
}

```

以下截图显示了基本菜单（包含所有菜单项）示例的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/075dec88-b8b0-43b3-b3e7-1510ddec1bb1.png)

从上面的快照中，您可以观察到菜单组件以内联格式显示。但是，通过启用`popup`属性可以改变此行为，以便以覆盖的形式显示。

菜单组件为`Menu` API 定义了`toggle`、`show`和`hide`方法。每个方法的详细描述如下表所示：

| **名称** | **参数** | **描述** |
| --- | --- | --- |
| `toggle` | `event: 浏览器事件` | 切换弹出菜单的可见性。 |
| `show` | `event: 浏览器事件` | 显示弹出菜单。 |
| `hide` | - | 隐藏弹出菜单。 |

表 2.0 完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter7/menu`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter7/menu).

# 通过 MenuBar 访问命令

MenuBar 组件是一组水平菜单组件，带有嵌套子菜单（或用于页面导航的下拉菜单组件）。与任何其他菜单组件一样，MenuBar 使用一个包含`MenuItem`接口列表的常见菜单模型 API。嵌套子菜单的级别没有限制。让我们看一个用于窗口或应用程序特定菜单的基本 MenuBar 示例。这提供了对常见功能的访问，例如打开文件，编辑操作，与应用程序交互，显示帮助文档等，如下所示：

```ts
<p-menubar [model]="items"></p-menubar>

```

菜单项列表需要在组件类中进行组织。例如，名为“编辑”的根菜单项将具有如下所示的嵌套项：

```ts
this.items = [
  {
    label: 'Edit',
    icon: 'fa-edit',
    items: [
      {label: 'Cut', icon: 'fa-cut'},
      {label: 'Copy', icon: 'fa-copy'},
      {label: 'Paste', icon: 'fa-paste'},
      {label: 'Undo', icon: 'fa-mail-forward'},
      {label: 'Redo', icon: 'fa-mail-reply'},
      {label: 'Find', icon: 'fa-search', items: [
        {label: 'Find Next'},
        {label: 'Find Previous'}
      ]}
    ]
  },
  // more items......
];

```

以下屏幕截图显示了基本 MenuBar（带有所有菜单项）示例的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/c3fbf422-2a5b-4d58-8d1c-0e4e60f02b44.png)

组件皮肤可以通过`style`和`styleClass`属性实现。PrimeNG 4.1 允许通过将其放置在 MenuBar 标签内部来使用自定义内容（表单控件）。

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter7/menubar`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter7/menubar).

# 带有嵌套项的上下文菜单

ContextMenu 是一个具有**图形用户界面** **(GUI)**表示的菜单，通过右键单击即可出现在页面顶部。通过右键单击，会在目标元素上显示一个覆盖菜单。有两种类型的上下文菜单，一种用于文档，另一种用于特定组件。除了这两种之外，还有与组件（如 DataTable）的特殊集成。

默认情况下，ContextMenu 附加到具有全局设置的文档。一个基本的上下文菜单示例，显示文档或文件类型菜单，如下所示：

```ts
<p-contextMenu [global]="true" [model]="documentItems"></p-contextMenu>

```

菜单项列表需要在组件类中进行组织。例如，名为“文件”的根菜单项将具有如下所示的嵌套项：

```ts
this.documentItems = [
  {
    label: 'File',
    icon: 'fa-file-o',
    items: [{
      label: 'New',
      icon: 'fa-plus',
      items: [
        {label: 'Project'},
        {label: 'Other'},
      ],
      expanded: true
  },
    {label: 'Open'},
    {label: 'Quit'}
    ],
  },
  // more items ...
];

```

以下屏幕截图显示了基本上下文菜单（带有所有菜单项）示例的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/5a208bbd-9fa6-4fc7-8ace-415efde36062.png)

一旦单击此组件之外，上下文菜单将消失。

# ContextMenu 的自定义目标

可以使用`target`属性更改上下文菜单的默认全局设置（即，上下文菜单将显示在全局文档目标以外的其他元素上）。让我们来看一个上下文菜单示例，在右键单击图像元素时，覆盖或弹出窗口会出现在上面，如下所示：

```ts
<p-contextMenu [target]="image" [model]="targetItems" >
</p-contextMenu>
<img #image src="/assets/data/images/primeng.png" alt="Logo">

```

在这种情况下，只需定义菜单项数组，就可以从上下文菜单执行下一个和上一个操作。

# DataTable 集成

在前一节中，您已经看到如何使用`target`属性将上下文菜单与其他元素集成。但是与 DataTable 组件的集成是一个不同的情况，需要特殊处理。这种组合是 Web 开发中经常使用的用例之一。

DataTable 使用`contextMenu`属性提供对上下文菜单的引用（即，上下文菜单的模板引用变量应分配给 DataTable 的`contextMenu`属性）。上下文菜单与 DataTable 的集成将如下所示编写：

```ts
<p-contextMenu #contextmenu [model]="tableItems"></p-contextMenu>
<p-dataTable [value]="employees" selectionMode="single" [(selection)]="selectedEmployee" [contextMenu]="contextmenu">
 <p-header>Employee Information</p-header>
  <p-column field="id" header="Employee ID"></p-column>
  <p-column field="name" header="Name"></p-column>
  <p-column field="email" header="Email"></p-column>
  <p-column field="contact" header="Telephone"></p-column>
</p-dataTable>

```

上下文菜单模型绑定到菜单项数组，例如`View`和`Delete`选项，如下所示：

```ts
this.tableItems = [
 {label: 'View', icon: 'fa-search', command: (event) => 
   this.viewEmployee(this.selectedEmployee)},
 {label: 'Delete', icon: 'fa-close', command: (event) => 
   this.deleteEmployee(this.selectedEmployee)},
 {label: 'Help', icon: 'fa-close',
 url: 'https://www.opm.gov/policy-data-oversight/worklife/
   employee-assistance-programs/'}
];

```

在上面的例子中，我们执行了通知用户消息的命令操作。但在实时中，所有 CRUD 操作都与数据库同步。以下截图显示了上下文菜单与 DataTable 组件集成的快照结果。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/0797425e-5793-40b3-bcd5-339753234bf1.png)

根据上面的快照，在右键单击并在行上出现覆盖时，表格行被选中。菜单项选择可以执行业务逻辑或导航到各种网页。

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter7/contextmenu`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter7/contextmenu)。

# SlideMenu - iPod 样式菜单

SlideMenu 是一个显示带有滑动动画效果的子菜单的组件。这种滑动菜单组件是 iPod 样式菜单小部件的最佳示例。默认情况下，滑动菜单显示为内联菜单组件。显示文档或文件类型菜单的基本滑动菜单示例如下：

```ts
<p-slideMenu [model]="items"></p-slideMenu>

```

菜单项列表需要在组件类中进行组织。例如，名为“文件”的根菜单项将具有如下嵌套项：

```ts
this.items = [
  {
    label: 'File',
    icon: 'fa-file-o',
    items: [
    {
      label: 'New',
      icon: 'fa-plus',
      items: [
        {label: 'Project'},
        {label: 'Other'},
      ]
    },
    {label: 'Open'},
    {label: 'Quit'}
    ]
  },
  // more items ...
]

```

以下截图显示了基本幻灯片菜单的快照结果，例如，单击文件菜单项时显示文件菜单项：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/1bd4f028-7ae4-419f-949a-64a45e994549.png)

如前面的快照所示，幻灯片菜单以内联格式显示。通过启用`popup`属性，可以以弹出模式显示。在幻灯片菜单弹出窗口底部，会出现一个带有“返回”标签的返回按钮，但也可以使用`backLabel`属性进行自定义。

可以使用`toggle`、`show`和`hide`等 API 方法访问幻灯片菜单。幻灯片菜单提供各种动画效果，默认效果为`easing-out`。可以使用`effect`属性更改此默认行为。同样，幻灯片菜单的默认效果持续时间为 500 毫秒，但可以使用`effectDuration`属性进行自定义。

任何可视组件的尺寸都是非常重要的，必须进行配置。考虑到这一标准，菜单尺寸是可配置的。子菜单宽度通过`menuWidth`属性控制，默认为 180（通常以像素为单位）。同时，可滚动区域的高度通过`viewportHeight`属性控制，默认值为 175 像素（即，如果菜单高度超过此默认值，则会出现滚动条）。

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter7/slidemenu`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter7/slidemenu).

# 分层菜单 - 嵌套叠加的子菜单

TieredMenu 组件以嵌套叠加模式显示子菜单。默认情况下，幻灯片菜单显示为内联菜单组件。一个基本的分层菜单示例，显示文档或文件类型菜单，如下所示：

```ts
<p-tieredMenu [model]="items"></p-tieredMenu>

```

菜单项列表需要在组件类中进行组织。例如，名为“文件”的根菜单项将具有如下嵌套项：

```ts
this.items = [
 {
   label: 'File',
   icon: 'fa-file-o',
   items: [
 {
   label: 'New',
   icon: 'fa-plus',
   items: [
   {label: 'Project'},
   {label: 'Other'},
 ]
 },
   {label: 'Open'},
   {label: 'Quit'}
 },
 // more items
]

```

以下截图显示了基本分层菜单示例的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/64eb76e8-e9d2-46fe-8b0d-c76751eba177.png)

如前面的快照所示，滑动菜单以内联格式显示。通过启用`popup`属性，它将以弹出模式显示。PrimeNG 4.1 引入了`appendTo`属性以附加覆盖。可以使用 API 方法（如`toggle`、`show`和`hide`）访问滑动菜单。

滑动菜单和分层菜单组件之间的主要区别在于，滑动菜单通过替换父菜单显示子菜单，而分层菜单以覆盖模式显示子菜单。有关滑动菜单和分层菜单的 API 方法以及更详细的表格格式，请参阅菜单部分*表 2.0*。

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter7/tieredmenu`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter7/tieredmenu)。

# MegaMenu - 多列菜单

MegaMenu 类似于一个下拉菜单，它展开成一个相对较大和复杂的界面，而不是一个简单的命令列表。它一起显示根项目的子菜单。MegaMenu 由嵌套菜单项组成，其中每个项目的根项目是定义覆盖菜单中列的二维数组。

一个零售商应用程序的基本 MegaMenu 示例，用于购买服装项目，将如下所示：

```ts
<p-megaMenu [model]="items"></p-megaMenu>

```

菜单项列表需要在组件类中进行组织。例如，名为“家居与家具”的根菜单项将具有如下嵌套项：

```ts
this.items = [
  {
    label: 'HOME & FURNITURE', icon: 'fa-home',
    items: [
    [
      {
        label: 'Home Furnishing',
        items: [{label: 'Cushions'}, {label: 'Throws'}, 
        {label: 'Rugs & Doormats'},
               {label: 'Curtains'}]
      },
     {
       label: 'Home Accessories',
       items: [{label: 'Artificial Flowers'}, {label: 'Lighting'}, 
               {label: 'Storage'}, {label: 'Photo Frames'}]
     }
   ],
   [
     {
       label: 'Cooking & Dinner',
       items: [{label: 'Cookware'}, {label: 'Dinnerware'}, 
       {label: 'Bakerware'}]
     },
     {
       label: 'Bed & Bath',
       items: [{label: 'Towels'}, {label: 'Bath Mats'}]
     }
   ]
   ]
  },
  // more items...
];

```

以下截图显示了基本 MegaMenu（带有所有菜单项）示例的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/fdfeabdf-f978-427a-8536-2341726aef75.png)

MegaMenu 的默认方向是水平的。也可以使用`orientation`属性（即`orientation="vertical"`）以垂直方式定位。垂直 MegaMenu 如下快照所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/ecc6ecc5-94ad-4f88-8694-e8b5559bf42c.png)

PrimeNG 4.1 允许通过将它们放置在 MegaMenu 标签内来使用自定义内容（表单控件）。

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter7/megamenu`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter7/megamenu)。

# PanelMenu - 手风琴和树的混合体

PanelMenu 是垂直堆叠的手风琴和分层树组件的混合体。每个父菜单项都有一个可切换的面板；面板显示子菜单项以分层树格式显示。一个基本的面板菜单示例，显示文档或文件类型菜单，如下所示：

```ts
<p-panelMenu [model]="items" ></p-panelMenu>

```

菜单项列表需要在组件类中组织。例如，名为帮助的根菜单项将具有如下所示的嵌套项：

```ts
this.items = [
  {
 label: 'Help',
    icon: 'fa-question',
    items: [
           {label: 'Contents'},
           {label: 'Search', icon: 'fa-search',
             items: [{label: 'Text', items: [{label: 'Workspace'}]}, 
             {label: 'File'}]}
    ]
  },
  //more items ...
];

```

以下屏幕截图显示了基本面板菜单示例的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/d465a7d3-8147-42c3-b3e8-db4f1fcf8358.png)

每个菜单项的初始状态通过`expanded`属性（即`expanded="true"`）进行控制，该属性在`MenuItem`接口级别上可用。

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter7/panelmenu`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter7/panelmenu)。

# TabMenu - 菜单项作为选项卡

TabMenu 是一个导航/命令组件，它将项目显示为选项卡标题（即，父根项目以水平堆叠的选项卡形式表示）。单击每个选项卡时，可以执行各种菜单操作。

一个基本的选项卡菜单示例，以各种选项卡的形式显示 PrimeNG 网站信息，如下所示：

```ts
<p-tabMenu [model]="items"></p-tabMenu>

```

菜单项列表需要在组件类中组织。例如，使用菜单项如下，解释了 PrimeNG 的各种详细信息：

```ts
this.items = [
  {label: 'Overview', icon: 'fa-bar-chart', routerLink: 
  ['/pages/overview']},
  {label: 'Showcase', icon: 'fa-calendar', command: (event) => {
    this.msgs.length = 0;
    this.msgs.push({severity: 'info', summary: 'PrimeNG Showcase', 
    detail:'Navigate all components'});}
  },
  {label: 'Documentation', icon: 'fa-book', 
    url:'https://www.primefaces.org/documentation/'},
  {label: 'Downloads', icon: 'fa-download', routerLink: 
    ['/pages/downloads']},
  {label: 'Support', icon: 'fa-support', 
    url:'https://www.primefaces.org/support/'},
  {label: 'Social', icon: 'fa-twitter', 
    url:'https://twitter.com/prime_ng'},
  {label: 'License', icon: 'fa-twitter', 
    url:'https://www.primefaces.org/license/'}
];

```

以下屏幕截图显示了选项卡面板菜单示例的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/e5385a16-c2b4-4f4e-8568-754c9545bfcd.png)

默认情况下，TabMenu 显示或激活第一个选项卡。但是，可以通过`activeItem`属性来更改选项卡的默认可见性或初始显示。

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter7/tabmenu`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter7/tabmenu)。

# 面包屑 - 提供有关页面层次结构的上下文信息

面包屑组件提供有关页面层次结构的上下文信息。它允许您跟踪程序、文档和网站中的位置。这通常显示为水平的，位于网页顶部，由大于号(>)作为层次分隔符。这种菜单变体由一个常见的菜单模型 API 来定义其项目。这些菜单项（菜单项的集合）与`model`属性相连。

一个电子商务应用程序的基本面包屑示例，用于购买电器，如下所示：

```ts
<p-breadcrumb [model]="items"></p-breadcrumb>

```

项目的`model`属性是`MenuItem`类型的数组。`MenuModel` API 的可能选项或属性在本节的开头进行了描述。在这个例子中，我们为菜单项定义了标签和命令操作。菜单项的列表需要组织起来，以显示如下所示的项目：

```ts
this.items.push({
  label: 'Categories', command: (event) => {
    this.msgs.length = 0;
    this.msgs.push({severity: 'info', summary: event.item.label});
  }
});
this.items.push({
  label: 'Best Buy', command: (event) => {
    this.msgs.length = 0;
    this.msgs.push({severity: 'info', summary: event.item.label});
  }
});
this.items.push({
  label: 'TV & Video', command: (event) => {
    this.msgs.length = 0;
    this.msgs.push({severity: 'info', summary: event.item.label});
  }
});
this.items.push({
  label: 'TVs', command: (event) => {
    this.msgs.length = 0;
    this.msgs.push({severity: 'info', summary: event.item.label});
  }
});
this.items.push({
  label: 'Flat Panel TVs', command: (event) => {
    this.msgs.length = 0;
    this.msgs.push({severity: 'info', summary: event.item.label});
  }
});
this.items.push({label: 'LED Flat-Panel', url: 'https://en.wikipedia.org/wiki/LED_display'});

```

以下屏幕截图显示了基本面包屑的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/001b9beb-a621-49aa-b994-9a023816d7ce.png)

主页图标也是菜单项的一部分，可以使用`MenuItem`类型的`home`属性进行自定义。因此，所有菜单项的功能也适用于主页菜单项。`home`属性必须为面包屑组件定义如下：

```ts
<p-breadcrumb [model]="items" [home]="home"></p-breadcrumb>

```

组件类如下所示包含主页菜单项：

```ts
home: MenuItem;
 this.home = {
 label: 'Home',icon: 'fa-globe', command: (event) => {
    this.msgs.length = 0;
    this.msgs.push({severity: 'info', summary: "Home"});
  }
};

```

这是一个支持自定义图标属性的组件，可以从`MenuItem`中定义。

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter7/breadcrumb`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter7/breadcrumb).

# 摘要

在本章结束时，您现在知道如何处理各种菜单组件，以及如何将它们放在页面上以满足特定的用例。首先，我们从 MenuModel API 开始创建一个项目数组，然后介绍了菜单组件作为基本组件，然后将 MenuBar 移动到具有嵌套复杂子菜单的 MegaMenu 组件，然后是其他菜单变体，如滑动菜单、分层菜单和面板菜单。

稍后，我们将转向上下文菜单和面包屑组件，作为另一种菜单操作。在下一章中，您将看到一个图表模型作为 API，以及如何为数据的可视表示创建出色的图表和地图。所有这些组件都是通过逐步方法解释的，包括所有可能的功能。


# 第八章：创建图表和地图

在本章中，我们将介绍如何使用 PrimeNG 的丰富图表功能和基于谷歌地图的地图来创建可视化图表的方法。PrimeNG 提供了基本和高级的图表功能，其易于使用和用户友好的图表基础设施。除了标准图表外，还有一种特殊的图表用于可视化分层组织数据。在本章中，还将解释绘制折线、多边形、处理标记和事件等地图功能。

在本章中，我们将涵盖以下主题：

+   使用图表模型

+   用线图和条形图表示数据

+   用饼图和圆环图表示数据

+   用雷达和极地区域图表表示数据

+   绘制关系层次的组织图表

+   与谷歌地图 API 的基本集成

+   GMap 组件的各种用例

# 使用图表模型

图表组件通过在网页上使用图表来对数据进行可视化表示。PrimeNG 图表组件基于**Charts.js 2.x**库（作为依赖项），这是一个 HTML5 开源库。图表模型基于`UIChart`类名，并且可以用元素名`p-chart`表示。

通过将图表模型文件（`chart.js`）附加到项目中，图表组件将有效地工作。它可以配置为 CDN 资源、本地资源或 CLI 配置：

+   **CDN 资源配置**：

```ts
 <script src="https://cdnjs.cloudflare.com/ajax/libs/
        Chart.js/2.5.0/Chart.bundle.min.js"></script>

```

+   **Angular CLI 配置**：

```ts
 "scripts":  [  "../node_modules/chart.js/dist/
        Chart.js",  //..others  ]

```

有关图表配置和选项的更多信息，请参阅 Chart.js 库的官方文档（[`www.chartjs.org/`](http://www.chartjs.org/)）。

# 图表类型

图表类型通过`type`属性定义。它支持七种不同类型的图表，并提供自定义选项：

+   `饼图`

+   `条形图`

+   `行`

+   `圆环图`

+   `极地区域图`

+   `雷达图`

+   `水平条形图`

每种类型都有自己的数据格式，可以通过`data`属性提供。例如，在圆环图中，类型应该是`doughnut`，`data`属性应该绑定到数据选项，如下所示：

```ts
<p-chart type="doughnut" [data]="doughnutdata"></p-chart>

```

组件类必须使用`labels`和`datasets`选项定义数据，如下所示：

```ts
this.doughnutdata = {
  labels: ['PrimeNG', 'PrimeUI', 'PrimeReact'],
  datasets: [
    {
      data: [3000, 1000, 2000],
      backgroundColor: [
        "#6544a9",
        "#51cc00",
        "#5d4361"
  ],
      hoverBackgroundColor: [
        "#6544a9",
        "#51cc00",
        "#5d4361"
  ]
    }
  ]
};

```

除了标签和数据选项之外，还可以应用与皮肤相关的其他属性。

图例默认是可关闭的（也就是说，如果您只想可视化特定的数据变体，那么可以通过折叠不需要的图例来实现）。折叠的图例用一条删除线表示。在图例上点击操作后，相应的数据组件将消失。

# 自定义

每个系列都是基于数据集进行自定义的，但您可以通过`options`属性来自定义通用的选项。例如，自定义默认选项的折线图将如下所示：

```ts
<p-chart type="line" [data]="linedata" [options]="options">
</p-chart>

```

该组件需要使用自定义的`title`和`legend`属性来定义图表选项，如下所示：

```ts
this.options = {
 title: {
    display: true,
    text: 'PrimeNG vs PrimeUI',
    fontSize: 16
  },
  legend: {
    position: 'bottom'
  }  };

```

根据上面的示例，`title`选项使用动态标题、字体大小和条件显示标题进行自定义，而`legend`属性用于将图例放置在`top`、`left`、`bottom`和`right`位置。默认的图例位置是`top`。在这个例子中，图例位置是`bottom`。

具有上述自定义选项的折线图将产生以下快照：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/7bb09002-bafe-4a47-a1d8-438f8cf27443.png)

`Chart` API 还支持这里显示的实用方法：

| **方法** | **描述** |
| --- | --- |
| `refresh` | 用新数据重新绘制图表 |
| `reinit` | 销毁现有图表，然后重新创建 |
| `generateLegend` | 返回该图表图例的 HTML 字符串 |

# 事件

图表组件提供了对数据集的点击事件，以使用`onDataSelect`事件回调处理所选数据。

让我们通过传递`event`对象来使用`onDataSelect`事件回调来看一个折线图的例子：

```ts
<p-chart type="line" [data]="linedata" 
  (onDataSelect)="selectData($event)"></p-chart>

```

在组件类中，事件回调用于以以下消息格式显示所选数据信息：

```ts
selectData(event: any) {
  this.msgs = [];
  this.msgs.push({
    severity: 'info',
    summary: 'Data Selected',
    'detail': this.linedata.datasets[event.element._datasetIndex]
    .data[event.element._index]
  });
}

```

在上述事件回调（`onDataSelect`）中，我们使用数据集的索引来显示信息。还有许多其他来自`event`对象的选项：

+   `event.element`：选定的元素

+   `event.dataset`：选定的数据集

+   `event.element._datasetIndex`：图表数据系列的索引

+   `event.element._index`：图表系列内数据元素的索引

# 使用折线图和条形图进行数据表示

折线图是一种以一系列数据点（称为*标记*）通过直线段连接来显示信息的图表类型。折线图通常用于可视化定期时间间隔或时间序列中的实时数据。

关于 Prime 库下载量的线图使用的基本示例如下：

```ts
<p-chart type="line" [data]="linedata" width="300" height="100">
</p-chart>

```

组件类应该定义一条线图数据，其中一条是指 PrimeNG 系列，另一条是指过去一年的 PrimeUI 系列，如下所示：

```ts
this.linedata = {
 labels: ['January', 'February', 'March', 'April', 'May', 
 'June', 'July', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
    datasets: [
    {
      label: 'PrimeNG',
      backgroundColor: '#ffb870',
      borderColor: '#cc4e0e',
      data: [13, 22, 15, 38, 41, 42, 25, 53, 53, 63, 77, 93]
     },
     {
      label: 'PrimeUI',
      backgroundColor: '#66ff00',
      borderColor: '#6544a9',
      data: [15, 11, 18, 28, 32, 32, 42, 52, 48, 62, 77, 84]
     }
  ]
};

```

根据上述代码片段，除了数据和标签之外，我们还可以定义背景和边框颜色，使线图变得像我们喜欢的那样花哨和可定制。以下截图显示了线图的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/ffdb9569-4a3d-45d9-ad44-6eceac177cd8.png)

条形图或柱状图是一种呈现分组数据的图表，其中用矩形条表示的值是成比例的。PrimeNG 还支持图表中条的水平表示。

关于 Prime 库下载量的条形图使用的基本示例如下：

```ts
<p-chart type="bar" [data]="bardata" width="300" height="100">
</p-chart>

```

组件类应该定义条形图数据，其中一条是指 PrimeNG 数据，另一条是指过去一年的 PrimeUI 系列，如下所示：

```ts
this.bardata = {
  labels: ['January', 'February', 'March', 'April', 'May', 
 'June', 'July', 'Aug', 'Sep',
 'Oct', 'Nov', 'Dec'],
    datasets: [
    {
      label: 'PrimeNG',
      backgroundColor: '#66ff00',
      borderColor: '#6544a9',
      data: [10, 15, 13, 27, 22, 34, 44, 48, 42, 64, 77, 89]
    },
    {
      label: 'PrimeUI',
      backgroundColor: '#ffb870',
      borderColor: '#cc4e0e',
      data: [5, 14, 15, 22, 26, 24, 32, 42, 48, 62, 66, 72]
    }
  ]
};

```

以下截图显示了一年时间内 PrimeNG 和 PrimeUI 下载量的条形图的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/3522fac5-2b59-46bc-a5e7-91630bbce406.png)

在上面的图表中，只有两个数据集在一个固定的时间段内进行比较。这也可以应用于多个数据集。

# 使用饼图和圆环图表示数据

饼图（或圆环图）是一种将圆形分成片段以说明复合数据的数值比例的圆形统计图。每个片段的弧长等于数据实体的数量。关于 Prime 库下载量的饼图使用的基本示例如下：

```ts
<p-chart #pie type="pie" [data]="piedata" width="300" height="100">
</p-chart>

```

组件类应该定义饼图数据，其中有三个片段分别代表了三个 Prime 库在一段时间内的情况，如下所示：

```ts
this.piedata = {
  labels: ['PrimeNG', 'PrimeUI', 'PrimeReact'],
  datasets: [
    {
      data: [3000, 1000, 2000],
      backgroundColor: [
        "#6544a9",
        "#51cc00",
        "#5d4361"
  ],
      hoverBackgroundColor: [
        "#6544a9",
        "#51cc00",
        "#5d4361"
  ]
    }
  ]
};

```

以下截图显示了一年时间内 PrimeNG、PrimeUI 和 PrimeReact 下载量的饼图的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/d5913a24-d645-4136-89e5-42fbea2d8685.png)

通过悬停在每个饼图的片段上，您可以观察到相应的数据标签及其值。

甜甜圈图是饼图的一种变体，中间有一个空心中心，可以提供有关完整数据的附加信息（即，每个切片代表特定的唯一数据，中心圆表示所有切片的一般附加信息）。

Prime 库下载的甜甜圈图使用的基本示例如下：

```ts
<p-chart type="doughnut" [data]="doughnutdata" width="300" 
  height="100">
</p-chart>

```

组件类应该定义饼图数据，其中包括三个切片，用于一段时间内的三个 Prime 库，如下所示：

```ts
this.doughnutdata = {
 labels: ['PrimeNG', 'PrimeUI', 'PrimeReact'],
  datasets: [
    {
      data: [3000, 1000, 2000],
      backgroundColor: [
        "#6544a9",
        "#51cc00",
        "#5d4361"
  ],
      hoverBackgroundColor: [
        "#6544a9",
        "#51cc00",
        "#5d4361"
  ]
    }
  ]
};

```

以下是一个示例，显示了在一年的时间内使用 PrimeNG、PrimeUI 和 PrimeReact 下载的甜甜圈图的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/ecb71e44-f16b-42c7-9953-3ad839d3e516.png)

默认情况下，甜甜圈图的切除百分比为`50`（而饼图为`0`）。这可以通过`cutoutPercentage`图表选项进行自定义。

# 雷达和极地区域图的数据表示

雷达图是以二维图表的形式显示多变量数据的图形表示。它至少有三个或更多的定量变量，这些变量表示在从同一点开始的轴上。这种图表也被称为**蜘蛛图**或**星形图**。它在衡量任何正在进行的程序的绩效指标方面非常有用，以控制改进的质量。

PrimeNG 和 PrimeReact 项目进展的雷达图使用的基本示例如下：

```ts
<p-chart type="radar" [data]="radardata" width="300" height="100">
</p-chart>

```

组件类应该定义雷达图数据，其中包括两个数据集（PrimeNG 和 PrimeReact），用于 SDLC 过程的六个阶段，如下所示：

```ts
this.radardata = {
  labels: ['Requirement', 'Design', 'Implementation', 'Testing', 
 'Deployment', 'Maintainance'],
  datasets: [
    {
      label: 'PrimeNG',
      backgroundColor: 'rgba(162,141,158,0.4)',
      borderColor: 'rgba(145,171,188,1)',
      pointBackgroundColor: 'rgba(145,171,188,1)',
      pointBorderColor: '#fff',
      pointHoverBackgroundColor: '#fff',
      pointHoverBorderColor: 'rgba(145,171,188,1)',
      data: [76, 55, 66, 78, 93, 74]
    },
    {
      label: 'PrimeReact',
      backgroundColor: 'rgba(255,99,132,0.2)',
      borderColor: 'rgba(255,99,132,1)',
      pointBackgroundColor: 'rgba(255,99,132,1)',
      pointBorderColor: '#fff',
      pointHoverBackgroundColor: '#fff',
      pointHoverBorderColor: 'rgba(255,99,132,1)',
      data: [30, 43, 38, 17, 89, 33]
    }
  ]
};

```

在上面的示例中，数据集不仅指的是数据组件，还为图表提供了背景、边框颜色等皮肤。以下截图显示了雷达图的快照结果，其中包括 PrimeNG 和 PrimeReact 项目在 SDLC 生命周期过程的六个阶段的进展：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/3637f524-12da-4e0e-b04b-f19c9af43c66.png)

极地区域图类似于饼图，但每个部分的角度相同（即，部分的半径根据值的不同而不同）。当我们想要显示与饼图类似的比较数据时，这种类型的图表通常很有用。但是，您也可以为给定上下文显示一组值的比例。

Prime 产品库下载的极坐标图使用的基本示例如下：

```ts
<p-chart type="polarArea" [data]="polardata" width="300" height="100">
</p-chart>

```

组件类应该定义各种 Prime 库的极地图下载数据，如下所示：

```ts
this.polardata = {
  datasets: [{
    data: [45, 35, 10, 15, 5],
    backgroundColor: ["#6544a9", "#51cc00", "#5d4361", "#E7E9ED", 
 "#36A2EB"],
    label: 'Prime Libraries'
  }],
  labels: ["PrimeFaces", "PrimeNG", "PrimeReact", "PrimeUI", 
 "PrimeMobile"]
}

```

组件类创建了数据选项以及外观属性。以下屏幕截图显示了使用 PrimeFaces、PrimeNG、PrimeUI、PrimeReact 和 PrimeMobile 下载的极地图的快照结果，作为一年时间段的示例：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/d9b74d4b-f070-43ea-b525-d5e887e2ebb5.png)

根据数据集，提供了`min`和`max`值，并且极地图数据段值将被调整（1、2、3、4、50）。

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter8/charts`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter8/charts)。

# 绘制关系层次结构的组织图

组织图是一种可视化分层组织数据的图表。PrimeNG 提供了一个名为`OrganizationChart`的组件，用于显示这种自上而下的关系层次结构。该组件需要`TreeNode`实例的模型作为其值。`TreeNode` API 在第五章中的*数据迭代组件*的*使用树形可视化数据*部分进行了解释。在本节中，我们将介绍`OrganizationChart`组件的详细信息，并开发一个图表，用于说明组织中的一个项目。

# 零配置的分层数据

绘制简单图表很容易--只需要`value`属性：

```ts
<p-organizationChart [value]="data"></p-organizationChart>

```

在组件类中，我们需要创建一个嵌套的`TreeNode`实例数组。在简单的用例中，提供标签就足够了：

```ts
data: TreeNode[];

ngOnInit() {
  this.data = [
    {
      label: 'CEO',
      expanded: true,
      children: [
        {
          label: 'Finance',
          expanded: true,
          children: [
            {label: 'Chief Accountant'},
            {label: 'Junior Accountant'}
          ]
        },
        {label: 'Marketing'},
        {
          label: 'Project Manager',
          expanded: true,
          children: [
            {label: 'Architect'},
            {label: 'Frontend Developer'},
            {label: 'Backend Developer'}
          ]
        }
      ]
    }
  ];
}

```

默认情况下，具有子节点（叶子）的树节点不会展开。要将树节点显示为展开状态，可以在模型中设置`expanded: true`。用户可以通过单击节点连接点处的小箭头图标来展开和折叠节点。

简单用例如下图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/db6471f0-e4cf-43dd-9168-3ea64b5d7fe4.png)

# 高级自定义

通过使用`ng-template`标签进行模板化，可以启用自定义。`TreeNode`具有`type`属性，用于匹配`pTemplate`属性的值。这种匹配允许您为每个单个节点自定义 UI。没有`type`属性的节点匹配`pTemplate="default"`。

下一个代码片段有两个`ng-template`标签。第一个匹配具有`type`属性`department`的节点。第二个匹配没有类型的节点。当前节点对象通过微语法`let-node`公开：

```ts
<p-organizationChart  [value]="data" styleClass="company">
 <ng-template  let-node pTemplate="department">
    <div  class="node-header ui-corner-top">
      {{node.label}}
    </div>
    <div  class="node-content ui-corner-bottom">
      <img  src="/assets/data/avatar/{{node.data.avatar}}" width="32">
      <div>{{node.data.name}}</div>
    </div>
  </ng-template>
  <ng-template  let-node pTemplate="default">
    {{node.label}}
  </ng-template>
</p-organizationChart>

```

我们只会展示`data`数组的一部分来传达这个想法。

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter8/orgchart`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter8/orgchart)。

```ts
this.data = [
  {
    label: 'CEO',
    expanded: true,
    type: 'department',
    styleClass: 'org-dept',
    data: {id: '1', name: 'Alex Konradi', avatar: 'man.png'},
    children: [
      {
        label: 'Finance',
        expanded: true,
        type: 'department',
        styleClass: 'org-dept',
        data: {id: '2', name: 'Sara Schmidt', avatar: 'women.png'},
        children: [
          {
            label: 'Chief Accountant',
            styleClass: 'org-role'
  },
          {
            label: 'Junior Accountant',
            styleClass: 'org-role'
  }
        ]
      },
      ...
    ]
  }
];

```

自定义的组织图如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/824a5462-8344-4089-96d6-692ea7c83fd0.png)

我们指定了自定义样式类来设置节点和切换器的颜色。例如：

```ts
.org-role {
 background-color: #00b60d;
 color: #ffffff;
}

.org-dept .ui-node-toggler {
 color: #bb0066 !important;
}

```

完整的样式设置可在 GitHub 上找到。

# 选择和事件

选择是通过将`selectionMode`设置为可能的值之一来启用的：`single`或`multiple`。在`single`模式下，预期`selection`属性的值是单个`TreeNode`。在`multiple`模式下，预期是一个数组。例如：

```ts
<p-organizationChart [value]="data"
  selectionMode="single" [(selection)]="selectedNode">
</p-organizationChart>

```

组织图支持两个事件：

| **名称** | **参数** | **描述** |
| --- | --- | --- |
| `onNodeSelect` |

+   `event.originalEvent`：浏览器事件

+   `event.node`：选定的节点实例

| 当通过单击选择节点时调用的回调。 |
| --- |
| `onNodeUnselect` |

+   `event.originalEvent`：浏览器事件

+   `event.node`：取消选择的节点实例

| 当通过单击取消选择节点时调用的回调。 |
| --- |

让我们扩展如下所示的先前开发的组织图：

```ts
<p-organizationChart  [value]="data" styleClass="company"
 selectionMode="single" [(selection)]="selectedNode"
  (onNodeSelect)="onNodeSelect($event)">
  ...
</p-organizationChart>

```

在 GitHub 上的演示应用程序中，我们定义了一个代表个人 VCard 的`VCard`接口：

```ts
export interface VCard {
 id: string;
  fullName: string;
  birthday: string;
  address: string;
  email: string;
}

```

所有 VCard 实例都是在`onNodeSelect`回调中延迟获取的。之后，VCard 会显示在 PrimeNG 对话框中：

```ts
display: boolean = false; selectedVCard: VCard;
private availableVCards: VCard[];

onNodeSelect(event: any) {
 if (this.availableVCards == null) {
    this.vcardService.getVCards().subscribe(
      (vcards: VCard[]) => {
        this.availableVCards = vcards;
        this.showInfo(event);
      });
  } else {
    this.showInfo(event);
  }
}

private showInfo(event: any) {
 this.selectedVCard = null;

  this.availableVCards.some((element: VCard) => {
    if (event.node.data && element.id === event.node.data.id) {
      this.selectedVCard = element;
      return true;
    }
  });

  if (this.selectedVCard) {
    // show VCard in dialog
  this.display = true;
  } else {
    // show node label in growl
  this.msgs = [];
    this.msgs.push({severity: 'Label', summary: event.node.label});
  }
}

```

对话框本身如下所示：

```ts
<p-dialog  header="VCard" [(visible)]="display"
 modal="modal" width="320" [responsive]="true">
 <i  class="fa fa-address-card-o"></i>
  <ul  style="padding: 0.2em 0.8em;">
    <li>Full name: {{selectedVCard?.fullName}}</li>
    <li>Birthday: {{selectedVCard?.birthday}}</li>
    <li>Address: {{selectedVCard?.address}}</li>
    <li>E-mail: {{selectedVCard?.email}}</li>
 </ul>
</p-dialog>

```

结果真是令人惊叹：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/deea3d60-994e-4401-8a05-f6896dd74ec1.png)

# 与 Google Maps API 的基本集成

GMap 组件提供了与 Google Maps API 的集成，以便以更少的配置高效地使用它。它涵盖了诸如绑定选项、各种覆盖物、事件等主要功能。该组件需要 Google Maps API，因此需要在`script`部分中引用它。

JS 资源文件需要在脚本部分中添加，这需要由 GMap 组件利用，如下所示：

```ts
<script type="text/javascript"   
  src="https://maps.google.com/maps/api/js?
  key=AIzaSyA6Ar0UymhiklJBzEPLKKn2QHwbjdz3XV0"></script>

```

使用地图选项的 GMap 的基本示例如下：

```ts
<p-gmap [options]="options" [styleClass]="'dimensions'">
</p-gmap>

```

在页面加载期间，必须使用坐标/位置尺寸（*纬度*和*经度*）、缩放选项等来定义选项，如下所示：

```ts
this.options = {
 center: {lat: 14.4426, lng: 79.9865},
  zoom: 12 };

```

以下屏幕截图显示了 GMap 示例的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/a77f55ff-2206-468a-a0d0-3cee377db71f.png)GMap 示例的快照结果

根据前面的快照，根据提供的坐标和缩放设置的可见性模式，显示确切的区域位置。

# GMap 组件的各种用例

除了基本的 Google 地图用法之外，GMap 还可以用于各种用例。使用不同类型的覆盖物、地图上的事件、覆盖物等，地图将更加交互。

# 覆盖物

覆盖物是地图上绑定到纬度/经度坐标或尺寸的对象。覆盖实例数组通过`overlays`属性进行绑定。由于单向绑定的性质，当数组发生变化时，地图将自动更新。

GMap 支持各种类型的覆盖物，如下所示：

+   **标记**：地图上的单个位置。标记还可以显示自定义图标图像。

+   **折线**：地图上的一系列直线。

+   **多边形**：地图上的一系列直线，但形状是“闭合的”。

+   **圆形和矩形**：表示特定区域的圆形/矩形。

+   **信息窗口**：在地图顶部的气球中显示内容。

使用覆盖选项的 GMap 示例用法将被编写如下：

```ts
<p-gmap [options]="options" [overlays]="overlays"  
  [styleClass]="'dimensions'"></p-gmap>

```

让我们定义一个覆盖实例数组，例如标记、折线、多边形、圆形等，如下所示：

```ts
this.overlays = [
 new google.maps.Marker({position: {lat: 14.6188043, 
 lng: 79.9630253}, title:"Talamanchi"}),
  new google.maps.Marker({position: {lat: 14.4290442, 
 ng: 79.9456852}, title:"Nellore"}),
  new google.maps.Polygon({paths: [
    {lat: 14.1413809, lng: 79.8254154}, {lat: 11.1513809, 
 lng: 78.8354154},
    {lat: 15.1313809, lng: 78.8254154},{lat: 15.1613809, 
 lng: 79.8854154}
    ], strokeOpacity: 0.5, strokeWeight: 1,
 fillColor: '#1976D2', fillOpacity: 0.35
  }),
  new google.maps.Circle({center: {lat: 14.1413809, lng: 79.9513809},  
 fillColor: '#197642', fillOpacity: 0.25, strokeWeight: 1, 
 radius: 25000}), new google.maps.Polyline({path: [{lat: 14.1413809,  
 lng: 79.9254154}, {lat: 14.6413809, lng: 79.9254154}], 
 geodesic: true, strokeColor: '#F0F000', strokeOpacity: 0.5,  
 strokeWeight: 2})
];

```

以下屏幕截图显示了 GMap 的快照结果，其中包含各种覆盖物作为示例：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/596d843f-6c1c-4c73-8828-1cb40d7fc438.png)

在上述地图中，您可以观察到基于提供的坐标以及其他覆盖物特定配置的标记、多边形和圆形。

# 事件

GMap 在地图上的交互事件中更加强大。有许多可用的回调函数可以钩入事件，例如单击地图、覆盖物单击和拖动覆盖物。

具有各种类型的覆盖物事件以及事件回调的地图组件示例将被编写如下：

```ts
<p-gmap #gmap [options]="options" [overlays]="overlaysEvents"
 (onMapReady)="handleMapReady($event)"  
  (onMapClick)="handleMapClick($event)"(onOverlayClick)="handleOverlayClick($event)" 
  (onOverlayDragStart)="handleDragStart($event)"
  (onOverlayDragEnd)="handleDragEnd($event)" 
  [styleClass]="'dimensions'"> 
</p-gmap>

```

可以通过单击覆盖物来更新现有事件，也可以通过单击地图并使用对话框组件来创建新事件，如下所示：

```ts
<p-dialog showEffect="fade" [(visible)]="dialogVisible" 
  header="New Location">
 <div class="ui-grid ui-grid-pad ui-fluid" *ngIf="selectedPosition">
    <div class="ui-grid-row">
      <div class="ui-grid-col-2"><label for="title">Label</label></div>
      <div class="ui-grid-col-10"><input type="text" 
        pInputText id="title"
        [(ngModel)]="markerTitle"></div> . 
      </div>
      <div class="ui-grid-row">
        <div class="ui-grid-col-2"><label for="lat">Lat</label></div>
        <div class="ui-grid-col-10"><input id="lat" 
          type="text" readonly pInputText
          [ngModel]="selectedPosition.lat()"></div> 
        </div>
        <div class="ui-grid-row">
          <div class="ui-grid-col-2"><label for="lng">Lng</label></div>
          <div class="ui-grid-col-10"><input id="lng" 
            type="text" readonly pInputText
            [ngModel]="selectedPosition.lng()"></div> 
        </div>
        <div class="ui-grid-row">
          <div class="ui-grid-col-2"><label for="drg">Drag</label> 
          </div>
          <div class="ui-grid-col-10">
            <p-checkbox [(ngModel)]="draggable" binary="true">
            </p-checkbox></div>     
        </div>
     </div>
    <p-footer>
      <div class="ui-dialog-buttonpane ui-widget-content 
        ui-helper-clearfix">
        <button type="button" pButton label="Add Marker" 
          icon="fa-plus" (click)="addMarker()">
        </button>
      </div>
    </p-footer>
</p-dialog>

```

组件类必须在初始页面加载时定义各种覆盖类型，如下所示：

```ts
if (!this.overlaysEvents || !this.overlaysEvents.length) {
 this.overlaysEvents = [
    new google.maps.Marker({position: {lat: 14.6188043, 
 lng: 79.9630253}, title:'Talamanchi'}),  
    new google.maps.Marker({position: {lat: 14.4290442, 
 lng: 79.9456852}, title:'Nellore'}),
    new google.maps.Polygon({paths: [
      {lat: 14.1413809, lng: 79.8254154}, 
      {lat: 11.1513809, lng: 78.8354154},
      {lat: 15.1313809, lng: 78.8254154}, 
      {lat: 15.1613809, lng: 79.8854154}], 
 strokeOpacity: 0.5, strokeWeight: 1, 
 fillColor: '#1976D2', fillOpacity: 0.35
  }),
    new google.maps.Circle({center: {lat: 14.1413809, 
 lng: 79.9513809}, fillColor: '#197642', 
 fillOpacity: 0.25, strokeWeight: 1, radius: 25000}),
    new google.maps.Polyline({path: [{lat: 14.1413809, 
 lng: 79.9254154}, {lat: 14.6413809, lng: 79.9254154}], 
 geodesic: true, strokeColor: '#F0F000',
      strokeOpacity: 0.5, strokeWeight: 2})];
}

```

以下快照显示了如何创建或更新叠加层事件：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/45f32ea0-14f6-40f3-a612-71d5008bd82a.png)

地图组件支持以下列出的事件回调：

| **名称** | **参数** | **描述** |
| --- | --- | --- |
| `onMapClick` | `event`: Google 地图鼠标事件 | 当地图被点击时，除了标记。 |

| `onOverlayClick` | `originalEvent`: Google 地图鼠标事件 `overlay`: 点击的叠加层

`地图`: 地图实例 | 当叠加层被点击时。|

| `onOverlayDragStart` | `originalEvent`: Google 地图鼠标事件 `overlay`: 点击的叠加层

`地图`: 地图实例 | 当叠加层拖动开始时。|

| `onOverlayDrag` | `originalEvent`: Google 地图鼠标事件 `overlay`: 点击的叠加层

`地图`: 地图实例 | 当叠加层被拖动时。|

| `onOverlayDragEnd` | `originalEvent`: Google 地图鼠标事件 `overlay`: 点击的叠加层

`地图`: 地图实例 | 当叠加层拖动结束时。|

| `onMapReady` | `event.map`: Google 地图实例 | 当地图加载后地图准备就绪时。 |
| --- | --- | --- |
| `onMapDragEnd` | `originalEvent`: Google 地图 `dragend` | 当地图拖动（即平移）结束时调用的回调。 |
| `onZoomChanged` | `originalEvent`: Google 地图 `zoom_changed` | 当缩放级别发生变化时调用的回调。 |

有两种访问地图 API 的方式。其中一种是 GMap 组件的 `getMap()` 函数 (`gmap.getMap()`)，另一种是通过事件对象访问 (`event.map`)。一旦地图准备就绪，那么根据我们的需求就可以使用所有地图函数。例如，`getZoom()` 方法可用于从当前状态增加或减少。

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter8/gmap`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter8/gmap).

# 摘要

通过完成本章，您将能够使用 PrimeNG 图表和 GMap 组件可视化数据表示。最初，我们从图表组件开始。首先，我们从图表模型 API 开始，然后学习如何使用各种图表类型（如饼图、柱状图、折线图、圆环图、极坐标图和雷达图）以编程方式创建图表。我们已经看到，组织图表完美地适应了关系层次的可视化。

接下来，我们转向基于谷歌地图的 GMap 组件。GMap 组件提供了一个方便的 API，用于与谷歌地图 API 进行交互，包括绘制标记、多边形、圆形，注册事件等等。在下一章中，我们将看一些其他用例和需要遵循的最佳实践。


# 第九章：杂项用例和最佳实践

杂项用例和最佳实践介绍了 PrimeNG 库的更多有趣功能。您将了解文件上传、拖放功能、显示图像集合、实际 CRUD 实现、推迟页面加载、阻止页面片段、显示带有受保护路由的确认对话框等。尽管组件集合全面，用户有时对现有组件的功能有特殊要求，或者需要新的自定义组件。

本章的目的也是专门为了在 PrimeNG 基础架构之上方便组件开发的开始。我们将经历构建可重用组件和开发自定义向导组件的完整过程。该向导可用于涉及多个步骤完成任务的工作流。此外，在阅读本章后，读者将了解 Angular 应用程序中的最新状态管理。

在本章中，我们将涵盖以下主题：

+   文件上传的全部功能

+   学习可拖放指令

+   使用 Galleria 显示图像集合

+   带有 DataTable 的 CRUD 示例实现

+   推迟机制以优化页面加载

+   在长时间运行的 AJAX 调用期间阻止页面片段

+   流程状态指示器的操作

+   使用 ColorPicker 选择颜色

+   显示带有受保护路由的确认对话框

+   使用步骤实现自定义向导组件

+   介绍使用@ngrx/store 进行状态管理

# 文件上传的全部功能

FileUpload 组件提供了一个文件上传机制，具有比基本的 HTML `<input type="file">`文件上传定义更强大的功能。该组件提供了一个基于 HTML5 的 UI，具有拖放、上传多个文件、进度跟踪、验证等功能。

文件上传组件在所有现代浏览器以及 IE 10 及更高版本中均可使用。

# 基本、多个和自动文件上传

为了能够使用文件上传，需要两个属性--用于在后端标识上传文件的请求参数的名称以及上传文件的远程 URL。例如：

```ts
<p-fileUpload name="demofiles[]" url="http://demoserver.com/upload">
</p-fileUpload>

```

该组件呈现为一个带有三个按钮的面板：Choose、Upload、Cancel，以及一个带有选定文件的内容部分。Choose 按钮显示一个文件对话框，用于选择一个或多个文件。一旦选择，文件可以通过下面的两个按钮上传或取消。默认情况下始终显示文件名和大小。此外，对于图像，您还将看到预览：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/78ae9854-3b08-4ab8-ad72-3c6b316006e0.png)预览图像的宽度可以通过`previewWidth`属性进行调整。

文件上传还提供了一个更简单的 UI，只有一个按钮 Choose，没有内容部分。您可以通过将`mode`属性设置为`"basic"`来激活此 UI：

```ts
<p-fileUpload mode="basic" name="demofiles[]"  
              url="http://demoserver.com/upload">
</p-fileUpload>

```

默认情况下，只能从文件对话框中选择一个文件。将`multiple`选项设置为`true`允许一次选择多个文件。将`auto`选项设置为`true`会立即开始上传，无需按任何按钮。在自动上传模式下，上传和取消按钮是隐藏的：

```ts
<p-fileUpload name="demofiles[]" url="http://demoserver.com/upload" 
              [multiple]="true" [auto]="true">
</p-fileUpload>

```

文件选择也可以通过从文件系统中拖动一个或多个文件并将它们放到 FileUpload 组件的内容部分来完成。

在撰写本文时，FileUpload 组件的后端无法使用 Angular 的模拟 API 进行模拟。在 GitHub 上的演示应用程序中，我们使用一个简单的本地服务器`json-server`（[`github.com/typicode/json-server`](https://github.com/typicode/json-server)）来伪造后端。否则，您将面临异常。安装后，可以使用以下命令启动服务器：

```ts
json-server db.json --port 3004

```

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/a5560d89-9e9e-4c47-853f-62a86546fe3c.png)

项目根目录中的`db.json`文件只有一个端点的定义：

```ts
{
  "fake-backend": {}
}

```

现在，您可以使用伪造的远程 URL 而不会出现任何异常：

```ts
<p-fileUpload name="demofiles[]" url="http://localhost:3004/
              fake-backend">
</p-fileUpload>

```

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter9/fileupload`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter9/fileupload)。

# 文件类型和大小限制

默认情况下，可以上传任何文件类型。文件大小也没有限制。您可以通过分别设置`accept`和`maxFileSize`选项来限制文件类型和大小：

```ts
<p-fileUpload name="demofiles[]" url="http://localhost:3004/
              fake-backend" multiple="true" accept="image/*"     
              maxFileSize="50000">
</p-fileUpload>

```

在这个例子中，只有最大大小为`50000`字节的图像才能被上传。违反这些规则会导致验证消息出现在内容部分。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/b7b2e59f-1f93-46c0-8fa4-654a24b21359.png)

`accept`属性的可能值：

| **值** | **描述** |
| --- | --- |
| `<文件扩展名>` | 以点开头的文件扩展名，例如`.gif`、`.png`、`.doc`等。 |
| `audio/*` | 所有音频文件。 |
| `video/*` | 所有视频文件。 |
| `image/*` | 所有图像文件。 |
| `<媒体类型>` | 根据 IANA 媒体类型（[`www.iana.org/assignments/media-types/media-types.xhtml`](http://www.iana.org/assignments/media-types/media-types.xhtml)）的有效媒体类型。例如，`application/pdf`。 |

要指定多个值，请使用逗号分隔值，例如，`accept="audio/*,video/*,image/*"`。

# 自定义

验证消息可以使用以下四个选项进行自定义：

| **属性名称** | **描述** | **默认值** |
| --- | --- | --- |
| `invalidFileSizeMessageSummary` | 无效文件大小的摘要消息。占位符`{0}`指的是文件名。 | `{0}：无效文件大小，` |
| `invalidFileSizeMessageDetail` | 无效文件大小的详细消息。占位符`{0}`指的是文件大小。 | `最大上传大小为{0}。` |
| `invalidFileTypeMessageSummary` | 无效文件类型的摘要消息。占位符`{0}`指的是文件类型。 | `{0}：无效文件类型，` |
| `invalidFileTypeMessageDetail` | 无效文件类型的详细消息。占位符`{0}`指的是允许的文件类型。 | `允许的文件类型：{0}` |

下一个代码片段和屏幕截图演示了自定义消息。它们还展示了如何为按钮设置自定义标签：

```ts
<p-fileUpload name="demofiles[]" url="http://localhost:3004/
              fake-backend"
              multiple="true" accept="image/*" maxFileSize="50000"
              invalidFileSizeMessageSummary="{0} has wrong size, "
              invalidFileSizeMessageDetail="it exceeds {0}."
              invalidFileTypeMessageSummary="{0} has wrong file type, "
              invalidFileTypeMessageDetail="it doesn't match: {0}."
              chooseLabel="Select file"
              uploadLabel="Upload it!"
              cancelLabel="Abort">
</p-fileUpload>

```

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/4a0b5240-b316-4cf0-8c01-c5d79b20c19e.png)

UI 可以通过三个命名的`ng-template`标签进行完全自定义。您可以自定义工具栏、内容部分和已选择文件的区域。下一个代码片段显示了一个完全可定制的 UI：

```ts
<p- name="demofiles[]" url="http://localhost:3004/fake-backend"
    multiple="true" accept=".pdf" maxFileSize="1000000">
  <ng-template pTemplate="toolbar">
    <div style="font-size: 0.9em; margin-top: 0.5em;">
      Please select your PDF documents
    </div>
  </ng-template>
  <ng-template let-file pTemplate="file">
    <div style="margin: 0.5em 0 0.5em 0;">
      <i class="fa fa-file-pdf-o" aria-hidden="true"></i>
      {{file.name}}
    </div>
  </ng-template>
  <ng-template pTemplate="content">
    <i class="fa fa-cloud-upload" aria-hidden="true"></i>
    Drag and drop files onto this area
  </ng-template>
</p-fileUpload>

```

屏幕截图显示了当没有选择文件时的初始 UI 状态：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/ee31c045-cea1-4256-bbba-fdf0e6382d30.png)

从文件对话框中选择后，UI 看起来如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/a5f74e9a-b298-4421-8c5a-a5e8f5c9dd14.png)

请注意，只能选择 PDF 文件。`ng-template`与`pTemplate="file"`一起使用时，会将`File`实例作为隐式变量。此实例具有`name`属性，我们在自定义 UI 中利用它。

请参阅官方文档，了解有关`File`的更多信息，网址为[`developer.mozilla.org/en-US/docs/Web/API/File`](https://developer.mozilla.org/en-US/docs/Web/API/File)。

下一级别的定制是回调事件，它们在特定时间点触发。有`onBeforeUpload`、`onBeforeSend`、`onUpload`、`onError`、`onClear`、`onSelect`和`uploadHandler`事件。下一个代码片段演示了其中两个：

```ts
<p-fileUpload name="demofiles[]" url="http://localhost:3004/
              fake-backend" accept="image/*" maxFileSize="1000000"
              (onBeforeSend)="onBeforeSend($event)" 
              (onUpload)="onUpload($event)">
</p-fileUpload>

```

`onBeforeUpload`事件在上传前不久触发。注册的回调会得到一个具有两个参数的事件对象：

+   `xhr`：`XMLHttpRequest`实例（[`developer.mozilla.org/en/docs/Web/API/XMLHttpRequest`](https://developer.mozilla.org/en/docs/Web/API/XMLHttpRequest)）。

+   `formData`：`FormData`对象（[`developer.mozilla.org/en/docs/Web/API/FormData`](https://developer.mozilla.org/en/docs/Web/API/FormData)）。

我们可以使用此回调来自定义请求数据，例如提交参数或标头信息。例如，我们可以设置一个令牌`jwt`并将其发送到服务器。只需在组件类中编写以下回调方法：

```ts
onBeforeSend(event: any) {
  (<XMLHttpRequest>event.xhr).setRequestHeader('jwt', 'xyz123');
}

```

你看，令牌已经发送了：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/26e47c65-840a-45f4-a456-e92b49a2e667.png)

当所有选定的文件都上传完成时，将触发`onUpload`事件。传递的事件对象具有上述`XMLHttpRequest`实例和类型为`File`的对象数组。我们可以遍历文件并将它们收集在一起进行进一步处理：

```ts
uploadMsgs: Message[] = [];
uploadedFiles: any[] = [];

onUpload(event: any) {
  for (let file of event.files) {
    this.uploadedFiles.push(file);
  }

  // produce a message for growl notification
  this.uploadMsgs = [];
  this.uploadMsgs.push({severity: 'info', 
    summary: 'File Uploaded', detail: ''});
}

```

通过设置`customUpload="true"`并定义自定义上传处理程序，可以提供自定义上传实现。例如：

```ts
<p-fileUpload name="demofiles[]" customUpload="true"
              (uploadHandler)="smartUploader($event)">
</p-fileUpload>

```

如何实现`smartUploader`回调取决于您。回调可以访问`event.files`，这是一个类型为`File`的对象数组。

# 学习可拖动和可放置指令

拖放是一种动作，意味着抓取一个对象并将其放到不同的位置。能够被拖放的组件丰富了网络，并为现代 UI 模式打下了坚实的基础。PrimeNG 中的拖放实用程序允许我们高效地创建可拖放的用户界面。它们使开发人员在浏览器级别处理实现细节变得抽象。

在本节中，您将了解`pDraggable`和`pDroppable`指令。我们将介绍一个包含一些虚构文档的 DataGrid 组件，并使这些文档可拖动以便将它们放到回收站中。回收站实现为一个 DataTable 组件，显示放置文档的属性。为了更好地理解开发的代码，首先是一张图片：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/2e80f0fd-6adf-4d31-a4a1-ee8ff9990472.png)

这张图片展示了拖放三个文档后发生的情况。

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter9/dragdrop`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter9/dragdrop)。

# 可拖动

`pDraggable` 附加到一个元素上以添加拖动行为。`pDraggable` 属性的值是必需的，它定义了与可放置元素匹配的范围。默认情况下，整个元素都是可拖动的。我们可以通过应用 `dragHandle` 属性来限制可拖动的区域。`dragHandle` 的值可以是任何 CSS 选择器。在 DataGrid 中，我们只使面板的标题可拖动：

```ts
<p-dataGrid [value]="availableDocs">
  <p-header>
    Available Documents
  </p-header>
  <ng-template let-doc pTemplate="item">
    <div class="ui-g-12 ui-md-4" pDraggable="docs"
      dragHandle=".ui-panel-titlebar" dragEffect="move"
      (onDragStart)="dragStart($event, doc)" 
        (onDragEnd)="dragEnd($event)">
      <p-panel [header]="doc.title" [style]="{'text-align':'center'}">
        <img src="/assets/data/images/docs/{{doc.extension}}.png">
      </p-panel>
    </div>
  </ng-template>
</p-dataGrid>

```

可拖动元素在拖动过程开始、进行和结束时可以触发三个事件，分别是 `onDragStart`、`onDrag` 和 `onDragEnd`。在组件类中，我们在拖动过程开始时缓冲被拖动的文档，并在结束时重置它。这个任务在两个回调函数中完成：`dragStart` 和 `dragEnd`。

```ts
class DragDropComponent {
  availableDocs: Document[];
  deletedDocs: Document[];
  draggedDoc: Document;

  constructor(private docService: DocumentService) { }

  ngOnInit() {
    this.deletedDocs = [];
    this.docService.getDocuments().subscribe((docs: Document[]) =>
      this.availableDocs = docs);
  }

  dragStart(event: any, doc: Document) {
    this.draggedDoc = doc;
  }

  dragEnd(event: any) {
    this.draggedDoc = null;
  }

  ...
}

```

在所示的代码中，我们使用了 `Document` 接口，具有以下属性：

```ts
interface Document {
  id: string;
  title: string;
  size: number;
  creator: string;
  creationDate: Date;
  extension: string;
}

```

在演示应用程序中，当鼠标移动到任何面板的标题上时，我们将光标设置为 `move`。这个技巧为可拖动区域提供了更好的视觉反馈：

```ts
body .ui-panel .ui-panel-titlebar {
  cursor: move;
}

```

我们还可以设置 `dragEffect` 属性来指定拖动操作允许的效果。可能的值有 `none`、`copy`、`move`、`link`、`copyMove`、`copyLink`、`linkMove` 和 `all`。请参考官方文档以获取更多细节：[`developer.mozilla.org/en-US/docs/Web/API/DataTransfer/effectAllowed`](https://developer.mozilla.org/en-US/docs/Web/API/DataTransfer/effectAllowed)。

# 可放置

`pDroppable` 附加到一个元素上以添加放置行为。`pDroppable` 属性的值应该与 `pDraggable` 的范围相同。

放置区域的范围也可以是一个数组，以接受多个可放置元素。

可放置元素可以触发四个事件：

| **事件名称** | **描述** |
| --- | --- |
| `onDragEnter` | 当可拖动元素进入放置区域时调用。 |
| `onDragOver` | 当可拖动元素被拖动到放置区域时调用。 |
| `onDrop` | 当可拖动元素放置到放置区域时调用。 |
| `onDragLeave` | 当可拖动元素离开放置区域时调用。 |

在演示应用程序中，可放置区域的整个代码如下所示：

```ts
<div pDroppable="docs" (onDrop)="drop($event)" 
     [ngClass]="{'dragged-doc': draggedDoc}">
  <p-dataTable [value]="deletedDocs">
    <p-header>Recycle Bin</p-header>
    <p-column field="title" header="Title"></p-column>
    <p-column field="size" header="Size (bytes)"></p-column>
    <p-column field="creator" header="Creator"></p-column>
    <p-column field="creationDate" header="Creation Date">
      <ng-template let-col let-doc="rowData" pTemplate="body">
        {{doc[col.field].toLocaleDateString()}}
      </ng-template>
    </p-column>
  </p-dataTable>
</div>

```

每当将文档拖放到回收站时，被放置的文档将从所有可用文档列表中移除，并添加到已删除文档列表中。这发生在`onDrop`回调中：

```ts
drop(event: any) {
  if (this.draggedDoc) {
    // add draggable element to the deleted documents list 
    this.deletedDocs = [...this.deletedDocs, this.draggedDoc];
    // remove draggable element from the available documents list
    this.availableDocs = this.availableDocs.filter(
      (e: Document) => e.id !== this.draggedDoc.id);
    this.draggedDoc = null;
  }
}

```

可用和已删除的文档都通过创建新数组来更新，而不是操作现有数组。这在数据迭代组件中是必要的，以强制 Angular 运行变更检测。操作现有数组不会运行变更检测，UI 将不会更新。

拖动任何带有文档的面板时，回收站区域会变成红色边框。我们通过将`ngClass`设置为`[ngClass]="{'dragged-doc': draggedDoc}"`来实现这种突出显示。当设置了`draggedDoc`对象时，样式类`dragged-doc`就会启用。样式类定义如下：

```ts
.dragged-doc {
  border: solid 2px red;
}

```

# 使用 Galleria 显示图像集合

Galleria 组件可用于显示具有过渡效果的图像集合。

# 让它运行起来

图像集合是以编程方式创建的--它是一个具有以下三个属性的对象数组：

+   `source`：图片的路径

+   `title`：标题部分的标题文本

+   `alt`：标题下方的描述

让我们创建一个`GalleriaComponent`类：

```ts
class GalleriaComponent {
  images: any[];

  ngOnInit() {
    this.images = [];

    this.images.push({
      source: '/assets/data/images/cars/Yeni.png',
      alt: 'This is a first car',
      title: 'Yeni Vollkswagen CC'
    });
    this.images.push({
      source: '/assets/data/images/cars/Golf.png',
      alt: 'This is a second car',
      title: 'Golf'
    });

    ... // more image definitions
  }
}

```

在 HTML 代码中，集合通过输入属性`images`进行引用：

```ts
<p-galleria [images]="images" panelWidth="400" panelHeight="320"
            [autoPlay]="false" [showCaption]="true">
</p-galleria>

```

开发的 UI 如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/8606b121-9daa-4fe5-b66b-095bd94c7649.png)

内容面板的宽度和高度可以通过`panelWidth`和`panelHeight`属性进行自定义。`showCaption`属性可以启用在标题部分显示标题和描述。

底部有一个名为**filmstrip**的小图像区域。通过`showFilmstrip`属性，默认情况下启用 filmstrip 的可见性。您可以通过将属性设置为`false`来禁用它。在 filmstrip 中可视化的帧的宽度和高度分别可以通过`frameWidth`和`frameHeight`属性进行自定义。所有值应以像素为单位提供。

还有`activeIndex`属性，可用于设置显示图像的位置。例如，如果您想在初始页面加载时显示第二张图像，可以设置`activeIndex="1"`。默认值为`0`。

# 自动播放模式和效果

自动播放模式可以打开幻灯片放映。自动播放模式默认情况下是启用的。在示例中，我们通过设置`[autoPlay]="false"`来禁用幻灯片放映。自动播放模式中图像之间的过渡在`4000`毫秒内完成。可以使用`transitionInterval`属性自定义此时间间隔。

在遍历图像时，可以应用过渡效果。`effect`属性可以取`blind`、`bounce`、`clip`、`drop`、`explode`、`fade`（默认值）、`fold`、`highlight`、`puff`、`pulsate`、`scale`、`shake`、`size`、`slide`和`transfer`这些值。`effectDuration`属性也可以用于决定过渡的持续时间。其默认值为`250`毫秒：

```ts
<p-galleria [images]="images" panelWidth="400" panelHeight="320"
            effect="bounce" [effectDuration]="150">
</p-galleria>

```

# 事件

只有一个事件`onImageClicked`，当点击显示的图像时触发：

```ts
<p-galleria [images]="images" panelWidth="400" panelHeight="220"
            [autoPlay]="false" [showCaption]="true"
            (onImageClicked)="onImageClicked($event)">
</p-galleria>

```

调用的回调会得到一个事件对象。除了点击图像的索引和原生点击事件之外，传入的事件对象还保留了集合中的整个图像实例。我们可以在回调中访问源 URL 并在新的浏览器标签中打开图像：

```ts
onImageClicked($event: any) {
  window.open($event.image.source, '_blank');
}

```

带有说明的完整演示应用程序可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter9/galleria`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter9/galleria)。

# 带有 DataTable 的 CRUD 示例实现

PrimeNG 是为企业应用程序创建的。实现**CRUD**（**创建、读取、更新**和**删除**）场景很容易。本节中的示例演示了使用作为域模型对象的员工的这种场景。可以获取、创建、更新和删除员工。所有 CRUD 操作都是通过 Angular 的 HTTP 服务进行的，该服务与模拟后端进行通信。我们将在本节的*使用@ngrx/store 进行状态管理介绍*中改进我们的 CRUD 实现。

使用以下接口定义了域模型对象`Employee`：

```ts
export interface Employee {
  id: string;
  firstName: string;
  lastName: string;
  profession: string;
  department: string;
}

```

模拟后端在此处未显示，因为它超出了本书的范围。

带有说明的完整演示应用程序可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter9/crud-datatable`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter9/crud-datatable)。

`EmployeeService`类具有 CRUD 操作，值得在这里列出。它公开了四种方法，返回值为`Observable`，以便组件类可以调用`subscribe()`来接收传递的数据：

```ts
@Injectable()
export class EmployeeService { 
  private static handleError(error: Response | any) {
    // error handling is done as recommended 
    //in the official Angular documentation
    // https://angular.io/docs/ts/latest/guide/server-
    //communication.html#!#always-handle-errors
    ...
  }

  constructor(private http: Http) { }

  getEmployees(): Observable<Employee[]> {
    return this.http.get('/fake-backend/employees')
      .map(response => response.json() as Employee[])
      .catch(EmployeeService.handleError);
  }

  createEmployee(employee: Employee): Observable<Employee> {
    return this.http.post('/fake-backend/employees', employee)
      .map(response => response.json() as Employee)
      .catch(EmployeeService.handleError);
  }

  updateEmployee(employee: Employee): Observable<any> {
    return this.http.put('/fake-backend/employees', employee)
      .map(response => response.json())
      .catch(EmployeeService.handleError);
  }

  deleteEmployee(id: string): Observable<any> {
    return this.http.delete('/fake-backend/employees/' + id)
      .map(response => response.json())
      .catch(EmployeeService.handleError);
  }
}

```

当从后端获取员工时，员工将显示在 DataTable 中：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/df796d51-9d45-47dc-8557-1337eeec05e8.png)

如您所见，当没有选择员工时，只有添加按钮是启用的。添加和编辑按钮触发显示员工个人数据的对话框。保存按钮根据之前选择的是添加还是编辑按钮，创建新员工或更新现有员工。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/bf3e848d-90ed-47da-9d43-9e6bf91bf104.png)

按钮触发的操作会淡入相应的消息：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/78029f0b-94a1-482c-868b-2bf49041a430.png)

表格是使用`p-dataTable`实现的，如下所示：

```ts
<p-dataTable [value]="employees" selectionMode="single"  
             [(selection)]="selectedEmployee"  
             [paginator]="true" rows="15" 
             [responsive]="true" 
             [alwaysShowPaginator]="false">
  <p-column field="firstName" header="First Name" [sortable]="true">
  </p-column>
  <p-column field="lastName" header="Last Name" [sortable]="true">
  </p-column>
  <p-column field="profession" header="Profession" [sortable]="true">
  </p-column>
  <p-column field="department" header="Department" [sortable]="true">
  </p-column>
  <p-footer>
    <button pButton type="button" label="Add" icon="fa-plus" 
      (click)="add()"> </button>
    <button pButton type="button" label="Edit" icon="fa-pencil" 
      (click)="edit()" [disabled]="!selectedEmployee"></button>
    <button pButton type="button" label="Remove" icon="fa-trash-o" 
    (click)="remove()" [disabled]="!selectedEmployee"></button>
  </p-footer>
</p-dataTable>

```

`p-dataTable`的值绑定到数组属性`employees`。通过点击行选择员工，并保存在`selectedEmployee`属性中。当`selectedEmployee`未设置时，编辑和删除按钮将被禁用。为了简洁起见，我们将跳过对话框的代码。最有趣的部分是组件类。员工是通过`EmployeeService`在`ngOnInit()`生命周期回调中获取的：

```ts
export class DataTableCrudComponent implements OnInit, 
  OnDestroy {
  employees: Employee[];
 selectedEmployee: Employee;
 employeeForDialog: Employee;
 displayDialog: boolean;
 msgs: Message[] = [];

 get$: Subscription;
 add$: Subscription;
 edit$: Subscription;
 delete$: Subscription;

 constructor(private employeeService: EmployeeService) { }

 ngOnInit(): void {
 this.get$ = this.employeeService.getEmployees().subscribe(
      employees => this.employees = employees,
      error => this.showError(error)
    );
  }

 ngOnDestroy() {
 this.get$.unsubscribe();
    this.add$.unsubscribe();
    this.edit$.unsubscribe();
    this.delete$.unsubscribe();
  }

  ...

  private showError(errMsg: string) {
    this.msgs = [];
    this.msgs.push({severity: 'error', 
                    summary: 'Sorry, an error occurred', 
                    detail: errMsg});
  }

  private showSuccess(successMsg: string) {
    this.msgs = [];
    this.msgs.push({severity: 'success', detail: successMsg});
  }
}

```

让我们详细探讨其他 CRUD 方法。`add()`方法构建一个空的员工实例，`edit()`方法克隆所选的员工。两者都在对话框中使用。属性`displayDialog`设置为`true`，强制显示对话框。

该属性在视图中绑定到对话框的可见性，如下所示`[(visible)]="displayDialog"`。

```ts
add() {
  // create an empty employee
  this.employeeForDialog = {
    id: null, firstName: null, lastName: null, profession: null,
    department: null
  }; 
  this.displayDialog = true;
}

edit() {
  // create a clone of the selected employee
  this.employeeForDialog = Object.assign({}, this.selectedEmployee);
  this.displayDialog = true;
}

```

对话框中的保存按钮调用`save()`方法，其中我们通过`id`来检查员工是否存在。只有之前保存过的员工才包含`id`，因为`id`是在后端分配的。现有员工应该被更新，新员工应该被创建：

```ts
save() {
  if (this.employeeForDialog.id) {
    // update
    this.edit$ = 
      this.employeeService.updateEmployee(this.employeeForDialog)
      .finally(() => {
        this.employeeForDialog = null;
        this.displayDialog = false;
      })
      .subscribe(() => {
          this.employees.some((element: Employee, index: number) => {
            if (element.id === this.employeeForDialog.id) {
              this.employees[index] = Object.assign({}, 
              this.employeeForDialog);
              this.employees = [...this.employees];
              this.selectedEmployee = this.employees[index];
              return true;
            }
          });
          this.showSuccess('Employee was successfully updated');
        },
        error => this.showError(error)
      );
  } else {
    // create
    this.add$ = 
      this.employeeService.createEmployee(this.employeeForDialog)
      .finally(() => {
        this.employeeForDialog = null;
        this.selectedEmployee = null;
        this.displayDialog = false;
      })
      .subscribe((employee: Employee) => {
          this.employees = [...this.employees, employee];
          this.showSuccess('Employee was successfully created');
        },
        error => this.showError(error)
      );
  }
}

```

员工将在后端和`employees`数组中更新或创建：

如您所见，创建了`employees`数组的新实例，而不是操作现有的数组。这在数据迭代组件中是必要的，以强制 Angular 运行变更检测。操作现有数组中的元素不会更新数组的引用。结果，变更检测不会运行，UI 也不会更新。

注意，`Observable`提供了一个`finally`方法，我们可以在其中重置属性的值。

作为参数传递给`finally`方法的函数在源可观察序列正常或异常终止后被调用。

`remove()`方法由删除按钮调用：

```ts
remove() {
  this.delete$ = 
  this.employeeService.deleteEmployee(this.selectedEmployee.id)
    .finally(() => {
      this.employeeForDialog = null;
      this.selectedEmployee = null;
    })
    .subscribe(() => {
        this.employees = this.employees.filter(
          (element: Employee) => element.id !== 
          this.selectedEmployee.id);
        this.showSuccess('Employee was successfully removed');
      },
      error => this.showError(error)
    );
}

```

序列逻辑与其他 CRUD 操作类似。

# 推迟机制以优化页面加载

大型应用程序总是需要最佳实践来提高页面加载时间。不建议等到所有页面内容完全加载后再显示登陆页面。PrimeNG 提供了一个 defer 指令，可以推迟内容加载直到组件出现在视口中。当页面滚动时，内容将在变得可见时懒加载。

`pDefer`指令应用于容器元素，内容需要用`ng-template`指令包装如下：

```ts
<div pDefer (onLoad)="loadData()">
  <ng-template>
    deferred content
  </ng-template>
</div>

```

当您使用数据迭代组件（如`p-dataTable`，`p-dataList`，`p-dataGrid`等）时，defer 指令非常有助于延迟加载大型数据集。`onLoad`回调用于在组件通过页面滚动变得可见时按需从数据源查询数据。查询不会在页面加载时启动，因此页面加载速度很快。这里实现了一个具体的例子：

```ts
<div pDefer (onLoad)="loadData()">
  <ng-template>
    <p-dataTable [value]="employees">
      <p-column field="firstName" header="First Name"></p-column>
      <p-column field="lastName" header="Last Name"></p-column>
      <p-column field="profession" header="Profession"></p-column>
      <p-column field="department" header="Department"></p-column>
    </p-dataTable>
  </ng-template>
</div>

```

`loadData()`方法获取员工信息：

```ts
loadData(): void {
  this.employeeService.getEmployees().subscribe(
    employees => this.employees = employees,
    error => this.showError(error)
  );
}

```

# 在长时间运行的 AJAX 调用期间阻止页面片段

BlockUI 组件允许我们阻止页面的任何部分，例如在 AJAX 调用期间。BlockUI 组件在目标元素上添加一个层，并提供阻止用户交互的外观和行为。如果您有一个大型的 DataTable 组件，并且 CRUD 操作需要很长时间，这将非常方便。您几乎可以阻止一切事物--甚至整个页面。在本节中，我们将演示如何处理 BlockUI。

BlockUI 组件阻止一个可阻止的*目标*组件。`target`属性指向这样一个目标组件的模板引用变量。BlockUI 的可见性由布尔属性`blocked`控制。例如，以下 BlockUI 在属性`blocked`设置为`true`时阻止 Panel 组件，并在其他情况下解除阻止：

```ts
<p-blockUI [blocked]="blocked" [target]="pnl">
  // any custom content or empty
</p-blockUI>

<p-panel #pnl header="Panel Header">
  Content of Panel
</p-panel>

```

`target`的默认值是`document`对象。这意味着，如果没有提供`target`，整个页面都会被阻塞。正如你所看到的，可以在`p-blockUI`标签中放置任何自定义内容。自定义内容会显示在半透明层上。

我们将利用上一节中的 CRUD 示例来演示 BlockUI 组件的工作原理。为了简洁起见，只有两个按钮可用--一个是重新加载按钮，用于执行数据获取，另一个是删除按钮。

让我们指定阻塞方式--重新加载按钮应该阻塞整个页面，删除按钮应该只阻塞表格。此外，我们希望显示一个加载指示器和文本 Loading...，如图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/feb94132-b48a-483a-b0bd-32f317c12a80.png)

这些验收标准导致了两个 BlockUI 组件：

```ts
<p-dataTable ... #dtable>
  ...
</p-dataTable>

<p-blockUI [blocked]="blockedTable" [target]="dtable">
  <div class="center">
    <div class="box">
      <div class="content">
        <img src="/assets/data/images/loader.svg"/>
        <h1>Loading...</h1>
      </div>
    </div>
  </div>
</p-blockUI>

<p-blockUI [blocked]="blockedPage">
  <div class="center">
    <div class="box">
      <div class="content">
        <img src="/assets/data/images/loader.svg"/>
        <h1>Loading...</h1>
      </div>
    </div>
  </div>
</p-blockUI>

```

`blockedTable`和`blockedPage`属性在按钮点击时立即设置为`true`。CRUD 操作完成后，这些属性设置为`false`。这种方法在下面的代码块中概述：

```ts
export class DataTableCrudComponent {
  ...
  selectedEmployee: Employee;
  blockedTable: boolean;
  blockedPage: boolean;

  reload() {
    this.blockedPage = true;
    this.employeeService.getEmployees()
      .finally(() => {this.blockedPage = false;})
      .subscribe(...);
  }

  remove() {
    this.blockedTable = true;
    this.employeeService.deleteEmployee(this.selectedEmployee.id)
      .finally(() => {this.blockedTable = false; 
        this.selectedEmployee = null;})
      .subscribe(...);
    }
}

```

被阻塞组件上的半透明层可以按以下方式自定义：

`.ui-blockui.ui-widget-overlay {opacity: 0.5;}`完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter9/blockui`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter9/blockui).

# 进程状态指示器在工作中

ProgressBar 组件指示某个过程、任务或其他内容的状态。它可以处理静态值和动态值。动态值是随时间变化的值。下面的代码片段演示了两个进度条，一个是静态值，一个是动态值：

```ts
<p-growl [value]="msgs"></p-growl>

<h3>Static value</h3>
<p-progressBar [value]="40"></p-progressBar>

<h3>Dynamic value</h3>
<p-progressBar [value]="value"></p-progressBar>

```

动态值每 800 毫秒从 1 到 100 产生，使用`Observable`方法如下：

```ts
export class ProgressBarComponent implements OnInit, OnDestroy {
  msgs: Message[];
  value: number;
  interval$: Subscription;

  ngOnInit() {
    const interval = Observable.interval(800).take(100);
    this.interval$ = interval.subscribe(
      x => this.value = x + 1,
      () => {/** no error handling */ },
      () => this.msgs = [{severity: 'info', summary: 'Success', 
        detail: 'Process completed'}]
    );
  }

  ngOnDestroy() {
    this.interval$.unsubscribe();
  }
}

```

最后，将显示一个带有文本 Process completed 的 growl 消息。快照图片如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/50d4b3f1-76c9-44ec-ad9a-056f384d6574.png)完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter9/progressbar`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter9/progressbar).

# 使用 ColorPicker 选择颜色

ColorPicker 是一个用于从二维方框中选择颜色的图形用户界面输入小部件。该组件使用`ngModel`指令进行双向值绑定。基本上，它支持三种颜色格式，如十六进制、RGB 和 HSB，其中十六进制是默认类型。颜色格式用`format`属性表示，例如，`format="rgb"`。ColorPicker 是一个可编辑的组件，也可以在模型驱动的表单中使用。一个基本的例子如下：

```ts
<p-colorPicker [(ngModel)]="color1"></p-colorPicker>

```

组件必须为默认十六进制值定义`string`类型的颜色属性，而颜色属性应该是对象类型，用于 RGB 和 HSB 格式，如下所示：

```ts
color1: string;
color2: any = {r: 100, g: 120, b: 140};
color3: any = {h: 80, s: 50, b: 40};

```

颜色选择器将显示所选颜色如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/6f08baae-7b66-4b76-9ad1-f9e8e5938237.png)

默认情况下，颜色选择器以覆盖格式显示，但可以使用`inline`属性更改此默认行为，通过启用内联设置，可以启用内联格式。内联格式的颜色选择器组件将如下所示：

```ts
<p-colorPicker [(ngModel)]="color3" inline="true"
 (onChange)="change($event)"></p-colorPicker>

```

此组件还支持带有`event`对象作为参数的`onChange`回调。`event`对象保存浏览器事件和所选颜色值，以通知更改如下：

```ts
change(event){
    this.msgs = [];
    this.msgs.push({severity: 'success', 
 summary: 'The color is changed from ColorPicker',
 detail: 'The selected color is ' + event.value});
}

```

像其他输入组件一样，ColorPicker 支持模型驱动的表单，禁用属性以禁用用户交互，等等。

完整的演示应用程序及说明可在 GitHub 上找到[`github.com/ova2/angular-development-with-primeng/tree/master/chapter9/colorpicker`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter9/colorpicker)。

# 显示带有受保护路由的确认对话框

在 Angular 2+中，您可以使用守卫保护路由。最常用的守卫类型是`CanActivate`和`CanDeactivate`。第一个守卫类型决定是否可以激活路由，第二个守卫类型决定是否可以停用路由。在本节中，我们将讨论`CanDeactivate`。这是一个只有一个方法`canDeactivate`的接口。

```ts
export interface CanDeactivate<T> {
  canDeactivate(component: T, route: ActivatedRouteSnapshot,                 
    state: RouterStateSnapshot):
    Observable<boolean> | Promise<boolean> | boolean;
}

```

此方法可以返回`Observable<boolean>`，`Promise<boolean>`或`boolean`。如果`boolean`的值为`true`，用户可以从路由中导航离开。如果`boolean`的值为`false`，用户将保持在相同的视图上。如果您想在某些情况下阻止路由导航离开，您必须执行三个步骤：

1.  创建一个实现`CanDeactivate`接口的类。该类充当守卫，当从当前视图导航离开时，路由器将对其进行检查。正如你所看到的，该接口期望一个通用组件类。这是当前在`<router-outlet>`标签中呈现的组件。

1.  在使用`@NgModule`注释的模块中将此守卫注册为提供者。

1.  将此守卫添加到路由器配置中。路由器配置具有`canDeactivate`属性，可以在其中多次添加此类守卫。

您可能想查看官方 Angular 文档中的示例

[`angular.io/docs/ts/latest/api/router/index/CanDeactivate-interface.html`](https://angular.io/docs/ts/latest/api/router/index/CanDeactivate-interface.html)。

在本书中，我们想要实现一个典型的用例，即检查用户是否有一些未保存的输入更改。如果当前视图具有未保存的输入值，并且用户试图导航到另一个视图，应该显示一个确认对话框。我们将使用 PrimeNG 的 ConfirmDialog：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/407c81bb-0838-45cf-9f48-359c6c51e854.png)

现在，点击“是”按钮会导航到另一个视图：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/1f151ef4-5da8-4c08-b7e2-bf4f21e3f420.png)

点击“否”按钮会阻止从当前路由导航的过程。让我们创建第一个视图，其中包含一个`input`元素，一个`submit`按钮和`<p-confirmDialog>`组件：

```ts
<h1>This is the first view</h1>

<form novalidate (ngSubmit)="onSubmit(f)" #f="ngForm">
  <label for="username">Username:</label>
  <input id="username" name="username" type="text" 
    pInputText [(ngModel)]="username"/>
  <button type="submit" pButton label="Confirm"></button>
</form>

<p-confirmDialog header="Confirmation" icon="fa fa-question-circle" 
  width="400">
</p-confirmDialog>

```

该模板对应的组件保持表单的`dirty`状态，表示表单正在被编辑：

```ts
export class FirstViewComponent {
  dirty: boolean;
  username: string;

  constructor(private router: Router) { }

  onSubmit(f: FormGroup) {
    this.dirty = f.dirty;
    this.router.navigate(['/chapter9/second-view']);
  }
}

```

我们不会实现任何复杂的算法来检查输入值是否真的已更改。我们只检查表单的`dirty`状态。如果表单没有被编辑，提交时导航应该没问题。无需询问用户有关未保存的更改。现在，我们必须将 PrimeNG 的`ConfirmationService`注入到我们的守卫实现中，这是显示确认对话框所必需的，并在`canDeactivate`方法中像这样使用它：

```ts
this.confirmationService.confirm({
  message: 'You have unsaved changes. 
  Are you sure you want to leave this page?',
  accept: () => {
    // logic to perform a confirmation
  },
  reject: () => {
    // logic to cancel a confirmation
  }
});

```

但是有一个问题。`confirm`方法没有返回所需的`Observable<boolean>`、`Promise<boolean>`或`boolean`。解决方案是通过调用`Observable.create()`创建并返回一个`Observable`对象。`create`方法期望一个带有一个参数`observer: Observer<boolean>`的回调。现在我们需要执行两个步骤：

+   将调用`this.confirmationService.confirm()`放入回调函数体中。

+   通过调用`observer.next(true)`和`observer.next(false)`将`true`或`false`传递给订阅者。订阅者是 PrimeNG 的组件`ConfirmDialog`，需要被告知用户的选择。

下面显示了`UnsavedChangesGuard`的完整实现：

```ts
@Injectable()
export class UnsavedChangesGuard implements 
  CanDeactivate<FirstViewComponent> {

  constructor(private confirmationService: ConfirmationService) { }

  canDeactivate(component: FirstViewComponent) {
    // Allow navigation if the form is unchanged
    if (!component.dirty) { return true; }

    return Observable.create((observer: Observer<boolean>) => {
      this.confirmationService.confirm({
        message: 'You have unsaved changes. 
        Are you sure you want to leave this page?',
        accept: () => {
          observer.next(true);
          observer.complete();
        },
        reject: () => {
          observer.next(false);
          observer.complete();
        }
      });
    });
  }
}

```

正如我们已经说过的，该守卫已在路由配置中注册：

```ts
{path: 'chapter9/first-view', component: FirstViewComponent, 
  canDeactivate: [UnsavedChangesGuard]}

```

如果您更喜欢`Promise`而不是`Observable`，可以返回`Promise`如下：

```ts
return new Promise((resolve, reject) => {
  this.confirmationService.confirm({
    message: "You have unsaved changes. 
    Are you sure you want to leave this page?",
    accept: () => {
      resolve(true);
    },
    reject: () => {
      resolve(false);
    }
  });
});

```

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter9/guarded-routes`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter9/guarded-routes)。

# 使用 Steps 实现自定义向导组件

PrimeNG 有一个名为 Steps 的组件，用于指示工作流程中的步骤。使用方法很简单：

```ts
<p-steps [model]="items" [(activeIndex)]="activeIndex"></p-steps>

```

`model`是`MenuItem`类型的对象集合，我们在第七章中遇到过，*无尽菜单变化*。属性`activeIndex`指向项目集合中活动项目（步骤）的索引。默认值为`0`，表示默认选择第一个项目。我们还可以通过设置`[readonly]="false"`使项目可点击。

请参考 PrimeNG 展示以查看步骤的操作：

[`www.primefaces.org/primeng/#/steps`](https://www.primefaces.org/primeng/#/steps)

基于`<p-steps>`，我们将使用两个自定义组件`<pe-steps>`和`<pe-step>`来实现类似向导的行为。前缀`pe`应该提示"PrimeNG 扩展"。组件`<pe-steps>`作为多个步骤的容器。基本结构：

```ts
<pe-steps [(activeIndex)]="activeIndex" (change)="onChange($event)">
  <pe-step label="First Step">
    // content of the first step
  </pe-step> 
  <pe-step label="Second Step">
    // content of the second step
  </pe-step> 
  <pe-step label="Third Step">
    // content of the third step
  </pe-step>
</pe-steps>

```

我们可以将这个结构理解为向导。在向导步骤之间的导航通过点击面包屑项目（可点击的步骤）、导航按钮或通过编程设置步骤索引（`activeIndex`）来实现。下一张截图显示了向导和导航的样子：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/389d35fa-c440-4ef3-a8f0-31315349667b.png)

在开始实施之前，让我们先指定 API。`<pe-step>`组件具有以下内容：

**属性**：

| **名称** | **类型** | **默认值** | **描述** |
| --- | --- | --- | --- |
| `styleClass` | `string` | `null` | 单个 Step 组件的样式类 |
| `label` | `string` | `null` | 显示此 Step 的标签 |

**样式**：

| **名称** | **元素** |
| --- | --- |
| `pe-step-container` | 单个 Step 组件的容器元素 |

`<pe-steps>`组件具有：

**属性**：

| **名称** | **类型** | **默认值** | **描述** |
| --- | --- | --- | --- |
| `activeIndex` | `number` | `0` | 活动步骤的索引（双向绑定） |
| - `styleClass` | `string` | `null` | 向导容器元素的样式类 |
| - `stepClass` | `string` | `null` | 每个步骤组件的样式类 |

**事件**：

| **名称** | **参数** | **描述** |
| --- | --- | --- |
| `change` | `label`：当前显示步骤的标签 | 切换步骤时调用的回调函数 |

具有这些知识，我们可以实现`StepComponent`和`StepsComponent`。第一个在模板中有`ng-content`，以便放置自定义内容。组件类有两个指定的输入。此外，还有一个`active`属性，指示当前是否显示该步骤：

```ts
@Component({
  selector: 'pe-step',
  styles: ['.pe-step-container {padding: 45px 25px 45px 25px; 
           margin-bottom: 20px;}'],
  template: `
    <div *ngIf="active" [ngClass]="'ui-widget-content ui-corner-all
         pe-step-container'" [class]="styleClass">
      <ng-content></ng-content>
    </div>
  `
})
export class StepComponent {
  @Input() styleClass: string;
  @Input() label: string;
  active: boolean = false;
}

```

第二个组件更复杂。它遍历类型为`StepComponent`的子组件，并在生命周期方法`ngAfterContentInit()`中创建项目。如果子组件的`active`属性与`activeIndex`匹配，则将其设置为`true`。否则，将其设置为`false`。这允许在工作流程中显示一个步骤。完整的清单将超出本书的篇幅。我们只会展示一部分：

```ts
@Component({
  selector: 'pe-steps',
  template: `
    <p-steps [model]="items" [(activeIndex)]="activeIndex"
      [class]="styleClass" [readonly]="false"></p-steps> 
      <ng-content></ng-content>
      <button pButton type="text" *ngIf="activeIndex > 0"
        (click)="previous()" icon="fa-hand-o-left" label="Previous">
      </button>
      <button pButton type="text" *ngIf="activeIndex 
        < items.length - 1"
        (click)="next()" icon="fa-hand-o-right" 
          iconPos="right" label="Next"> 
      </button>
  `
})
export class StepsComponent implements AfterContentInit, OnChanges {
  @Input() activeIndex: number = 0;
  @Input() styleClass: string;
  @Input() stepClass: string;
  @Output() activeIndexChange: EventEmitter<any> = new EventEmitter();
  @Output() change = new EventEmitter();
  items: MenuItem[] = [];
  @ContentChildren(StepComponent) steps: QueryList<StepComponent>;

  ngAfterContentInit() {
    this.steps.toArray().forEach((step: StepComponent, 
      index: number) => 
      {
      ...
      if (index === this.activeIndex) { step.active = true; }

      this.items[index] = {
        label: step.label,
        command: (event: any) => {
          // hide all steps
          this.steps.toArray().forEach((s: StepComponent) => 
            s.active = false);

          // show the step the user has clicked on.
          step.active = true;
          this.activeIndex = index;

          // emit currently selected index (two-way binding)
          this.activeIndexChange.emit(index);
          // emit currently selected label
          this.change.next(step.label);
        }
      };
    });
  }

  ngOnChanges(changes: SimpleChanges) {
    if (!this.steps) { return; }

    for (let prop in changes) {
      if (prop === 'activeIndex') {
        let curIndex = changes[prop].currentValue;
        this.steps.toArray().forEach((step: StepComponent, 
          index: number) => {
          // show / hide the step
          let selected = index === curIndex;
          step.active = selected;
          if (selected) {
            // emit currently selected label
            this.change.next(step.label);
          }
        });
      }
    }
  }

  private next() {
    this.activeIndex++;
    // emit currently selected index (two-way binding)
    this.activeIndexChange.emit(this.activeIndex);
    // show / hide steps and emit selected label
    this.ngOnChanges({
      activeIndex: {
        currentValue: this.activeIndex,
        previousValue: this.activeIndex - 1,
        firstChange: false,
        isFirstChange: () => false
      }
    });
  }

  ...
}

```

完全实现和文档化的组件可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter9/primeng-extensions-wizard`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter9/primeng-extensions-wizard)。

要使实现的向导可分发，我们需要创建`WizardModule`：

```ts
import {NgModule} from '@angular/core';
import {CommonModule} from '@angular/common';
import {StepComponent} from './step.component';
import {StepsComponent} from './steps.component';
import {ButtonModule} from 'primeng/components/button/button';
import {StepsModule} from 'primeng/components/steps/steps';

@NgModule({
  imports: [CommonModule, ButtonModule, StepsModule],
  exports: [StepComponent, StepsComponent],
  declarations: [StepComponent, StepsComponent]
})
export class WizardModule { }

```

`WizardModule`类可以像通常在`@NgModule`内部的`imports`一样在任何 PrimeNG 应用程序中导入。显示图片的具体用法示例如下：

```ts
<pe-steps [(activeIndex)]="activeIndex" (change)="onChange($event)">
  <pe-step label="First Step">
    <label for="firstname">First Name:</label>
    <input id="firstname" name="firstname" type="text" 
      pInputText [(ngModel)]="firstName"/>
    <button pButton label="Go" (click)="next()"></button>
  </pe-step> 
  <pe-step label="Second Step">
    <label for="lastname">Last Name:</label>
    <input id="lastname" name="lastname" type="text" 
      pInputText [(ngModel)]="lastName"/>
    <button pButton label="Go" (click)="next()"></button>
  </pe-step> 
  <pe-step label="Third Step">
    <label for="address">Address:</label>
    <input id="address" name="address" type="text" 
      pInputText [(ngModel)]="address"/>
    <button pButton label="Ok" (click)="ok()"></button>
  </pe-step>
</pe-steps>

<p-growl [value]="msgs"></p-growl>

```

相应的组件实现了`next()`和`ok()`方法，以及事件回调`onChange()`。要前进，只需编写`next() {this.activeIndex++;}`。有关更多详细信息，请参阅 GitHub 项目。

向导组件可以使用`npm run update`发布到`npm`存储库。在 GitHub 项目中没有运行演示应用程序和`npm start`命令。

# 使用@ngrx/store 进行状态管理的介绍

在过去几年中，大型 Angular 应用程序中的状态管理是一个薄弱点。在 AngularJS 1 中，状态管理通常是作为服务、事件和`$rootScope`的混合来完成的。在 Angular 2+中，应用程序状态和数据流更清晰，但在 Angular 核心中仍然没有统一的状态管理。开发人员经常使用*Redux*--JavaScript 应用程序的可预测状态容器（[`redux.js.org`](http://redux.js.org)）。Redux 架构最为人所知的是与*React*库（[`facebook.github.io/react`](https://facebook.github.io/react)）一起使用，但它也可以与 Angular 一起使用。为 Angular 设计的一种流行的类似 Redux 的状态容器是*ngrx/store*（[`github.com/ngrx/store`](https://github.com/ngrx/store)）。

# Redux 原则

Redux 遵循三个基本原则：

+   应用程序的整个状态存储在一个称为*store*的单个不可变状态树中。不允许在 store 之外进行状态管理。一个中心化的不可变存储有很多好处。您可以通过使用`ChangeDetectionStrategy.OnPush`来提高性能，因为使用不可变数据，Angular 只需要检查对象引用来检测更改。此外，撤消/重做功能很容易实现。

+   *Actions*用于将信息从应用程序发送到 store。只有 actions 是 store 的信息来源。Actions 是具有`type`和`payload`属性的普通 JavaScript 对象。`type`属性描述了我们想要的状态变化的类型。`payload`属性是要发送到 store 以更新它的数据。

+   状态变化是通过称为*reducers*的纯函数进行的。纯函数是不会改变对象的函数，而是返回全新的对象。我们可以将 reducers 看作是存储中的处理步骤，允许状态转换。Reducer 在当前状态上操作并返回一个新状态。

总的来说，数据流是双向的。一个组件中的用户输入可能会影响其他组件，反之亦然。Redux 应用程序中的数据流是单向的。视图中的更改触发操作。操作被分派到 store。Reducers 根据操作执行状态更改，通过采用先前的状态和分派的操作返回下一个状态作为新对象。

`Object.assign()` 和 `spread` 运算符可以帮助返回新对象（[`redux.js.org/docs/recipes/UsingObjectSpreadOperator.html`](http://redux.js.org/docs/recipes/UsingObjectSpreadOperator.html)）。

多个组件可以订阅存储以观察随时间的状态变化并将其传播到视图。以下图表记忆了所述的 Redux 原则：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/303e29da-5ae2-4124-8a37-e878191e1794.png)

经典的 Redux 存储提供了两个重要的 API：

+   使用 `store.dispatch(action)` 分发操作

+   使用 `store.subscribe(callback)` 注册更改通知的监听器

如您所见，如果您使用 Redux 存储，您不需要手动在组件之间同步状态。

可预测的状态管理允许使用 co 调试应用程序，称为时间旅行调试器。您需要安装 `store-devtools`（[`github.com/ngrx/store-devtools`](https://github.com/ngrx/store-devtools)）以及适当的 Chrome 扩展。

# 使用 @ngrx/store 的 CRUD 应用程序

作为一个实际的例子，我们将重用“使用 DataTable 实现 CRUD 示例”部分中的相同 CRUD 示例实现。首先添加 Redux-based 应用程序的 `ngrx` 依赖项：

```ts
npm install @ngrx/store @ngrx/core --save

```

首先，我们需要为存储定义一个形状。在实际应用中，最有可能可用的员工和当前选择的员工可能会在多个组件之间共享。因此，存储可以定义如下：

```ts
export interface AppStore {
  employees: Employee[];
  selectedEmployee: Employee;
}

```

接下来，我们需要定义由类型和可选载荷组成的操作。

最佳实践是创建封装相关操作的 *Action Creator Services*：

[`github.com/ngrx/ngrx.github.io/blob/master/store/recipes/actions/action_services.md`](https://github.com/ngrx/ngrx.github.io/blob/master/store/recipes/actions/action_services.md)

我们将创建名为 `CrudActions` 的服务，其中包含四个 CRUD 操作和相关的操作创建者：

```ts
@Injectable()
export class CrudActions {
  static LOAD_EMPLOYEES = 'LOAD_EMPLOYEES';
  static CREATE_EMPLOYEE = 'CREATE_EMPLOYEE';
  static UPDATE_EMPLOYEE = 'UPDATE_EMPLOYEE';
  static DELETE_EMPLOYEE = 'DELETE_EMPLOYEE';

  loadEmployees(employees: Employee[]): Action {
    return {type: CrudActions.LOAD_EMPLOYEES, payload: employees};
  }

  createEmployee(employee: Employee): Action {
    return {type: CrudActions.CREATE_EMPLOYEE, payload: employee};
  }

  updateEmployee(employee: Employee): Action {
    return {type: CrudActions.UPDATE_EMPLOYEE, payload: employee};
  }

  deleteEmployee(id: string): Action {
    return {type: CrudActions.DELETE_EMPLOYEE, payload: id};
  }
}

```

核心部分是 reducer。reducer 函数接受状态和操作，然后使用 `switch` 语句根据操作类型返回新状态。当前状态不会被改变：

```ts
import {ActionReducer, Action} from '@ngrx/store';
import {AppStore} from './app.store';
import {CrudActions} from './crud.actions';
import {Employee} from '../model/employee';

const initialState: AppStore = {employees: [], selectedEmployee: null};

export const crudReducer: ActionReducer<AppStore> =
  (state: AppStore = initialState, action: Action): AppStore => {
 switch (action.type) {
    case CrudActions.LOAD_EMPLOYEES:
      return {
        employees: [...action.payload],
        selectedEmployee: null
  };

    case CrudActions.DELETE_EMPLOYEE:
      return {
        employees: state.employees.filter(
          (element: Employee) => element.id !== action.payload),
          selectedEmployee: null
  };

 case CrudActions.CREATE_EMPLOYEE:
      return {
        employees: [...state.employees, action.payload],
        selectedEmployee: null
  };

 case CrudActions.UPDATE_EMPLOYEE:
      let index = -1;
      // clone employees array with updated employee
  let employees = state.employees.map(
        (employee: Employee, idx: number) => {
        if (employee.id === action.payload.id) {
          index = idx;
          return Object.assign({}, action.payload);
        }
        return employee;
      });

      let selectedEmployee = index >= 0 ? employees[index] : null;
      return {employees, selectedEmployee};

    default:
      return state;
  }
};

```

如您所见，还有一个 `default` 开关语句，它只是在提供的操作不匹配任何预定义操作时返回当前状态。

现在，我们可以使用 `ngrx/store` 模块配置 `AppModule`。通过导入 `StoreModule`，应该调用 `provideStore` 方法并提供我们的 reducer 的名称：

```ts
import {StoreModule} from '@ngrx/store';
import {CrudActions} from './redux/crud.actions';
import {crudReducer} from './redux/crud.reducer';

@NgModule({
  imports: [
    ...
    StoreModule.provideStore({crudReducer})
  ],
  providers: [
    ...
    CrudActions
  ],
  ...
})
export class AppModule { }

```

通常，您也可以提供多个 reducer。这里显示了一个示例：

```ts
let rootReducer = {
  reducerOne: reducerOne,
  reducerTwo: reducerTwo, 
  reducerThree: reducerThree,
  ...
}

StoreModule.provideStore(rootReducer);

```

在内部，`@ngrx/store`使用`combineReducers`方法创建一个*meta-reducer*，该方法使用正确的状态片段调用指定的 reducer。

最后一步是分派操作并选择数据。我们可以将`CrudActions`注入`EmployeeService`并为每个 CRUD 操作创建相应的操作。返回值的类型为`Observable<Action>`：

```ts
constructor(private http: Http, private crudActions: CrudActions) { }

getEmployees(): Observable<Action> {
  return this.http.get('/fake-backend/employees')
    .map(response => response.json() as Employee[])
    .map(employees => this.crudActions.loadEmployees(employees))
    .catch(EmployeeService.handleError);
}

createEmployee(employee: Employee): Observable<Action> {
  return this.http.post('/fake-backend/employees', employee)
    .map(response => response.json() as Employee)
    .map(createdEmployee => 
      this.crudActions.createEmployee(createdEmployee))
    .catch(EmployeeService.handleError);
}

updateEmployee(employee: Employee): Observable<Action> {
  return this.http.put('/fake-backend/employees', employee)
    .map(() => this.crudActions.updateEmployee(employee))
    .catch(EmployeeService.handleError);
}

deleteEmployee(id: string): Observable<Action> {
  return this.http.delete('/fake-backend/employees/' + id)
    .map(() => this.crudActions.deleteEmployee(id))
    .catch(EmployeeService.handleError);
}

```

在组件类中，我们通过调用`store.dispatch(action)`来接收操作并分派它们。操作的分派仅将演示两个 CRUD 操作：加载所有员工和删除一个员工：

```ts
ngOnInit(): void {
  ...

  this.employeeService.getEmployees().subscribe(
    action => this.store.dispatch(action),
    error => this.showError(error)
  );
}

remove() {
  this.employeeService.deleteEmployee(this.selectedEmployee.id)
    .finally(() => {
      this.employeeForDialog = null;
    })
    .subscribe((action) => {
        this.store.dispatch(action);
        this.showSuccess('Employee was successfully removed');
      },
      error => this.showError(error)
    );
}

```

在`@ngrx/store`中选择数据是通过调用`store.select()`来实现的。`select`方法期望选择要在视图中显示的状态片段的 reducer 函数的名称。`select`方法的返回值是`Observable`，它允许订阅存储的数据。下一个代码片段演示了这样的订阅：

```ts
import {Store} from '@ngrx/store';
import {AppStore} from '../redux/app.store';
...

constructor(private store: Store<AppStore>, 
  private employeeService: EmployeeService) { }

ngOnInit(): void {
  this.store.select('crudReducer').subscribe((store: AppStore) => {
    this.employees = store.employees;
    this.selectedEmployee = store.selectedEmployee;
  });
}

```

生命周期方法`ngOnInit`是订阅的好地方。

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter9/redux`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter9/redux).

# 总结

在本章中，您已经学习了更多用于各种用例的 PrimeNG 组件和指令。本章解释了 FileUpload、Draggable、Droppable、Galleria、Defer、BlockUI、ProgressBar 等有趣的功能。您已经看到了使用 DataTable 和模拟后端实现 CRUD 应用程序的实际示例。还演示了使用 ConfirmationDialog 和受保护的路由的最佳实践。阅读完本章后，您将具备必要的知识，能够为接下来的几个 Angular 和 PrimeNG Web 应用程序创建不同的自定义组件。Redux 架构不再是一个陌生的概念。您已经为复杂的 Web 应用程序中有利的状态管理做好了准备。

下一章将介绍使用现代框架进行单元测试和端到端测试。您将学习如何测试和调试 Angular 应用程序。测试驱动开发的技巧也不会缺席。
