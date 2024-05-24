# Xamarin 4.x 跨平台应用开发（二）

> 原文：[`zh.annas-archive.org/md5/183290FB388A7F8EC527693139A6FD11`](https://zh.annas-archive.org/md5/183290FB388A7F8EC527693139A6FD11)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：iOS 的 XamSnap

要开始编写 XamSnap 的 iOS 版本，请打开我们在上一章创建的解决方案。在本章中，我们主要在`XamSnap.iOS`项目中工作。项目模板将自动创建一个名为`ViewController`的控制器；请继续并删除它。我们将在进行中创建我们自己的控制器。

在本章中，我们将涵盖以下内容：

+   iOS 应用的基础知识

+   使用 UINavigationController

+   实现登录界面

+   Segues 和 UITableView

+   添加好友列表

+   添加消息列表

+   编写消息

# 了解 iOS 应用的基础知识

在我们开始开发我们的应用程序之前，让我们回顾一下应用程序的主要设置。苹果使用一个名为`Info.plist`的文件来存储有关任何 iOS 应用的重要信息。这些设置由操作系统本身使用，以及当 iOS 应用程序通过苹果应用商店在设备上安装时。开始开发任何新的 iOS 应用程序，通过填写此文件中的信息。

Xamarin Studio 提供了一个整洁的菜单，用于修改`Info.plist`文件中的值，如下截图所示：

![了解 iOS 应用的基础知识](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00217.jpeg)

最重要的设置如下：

+   **应用名称**：这是 iOS 中应用图标下方的标题。请注意，这与你在 iOS 应用商店中的应用程序官方名称不同。

+   **包标识符**：这是你的应用程序的包标识符或包 ID。这是一个独特的名称，用于识别你的应用程序。约定是使用以你的公司名称开头的反向域名命名风格，如`com.jonathanpeppers.xamsnap`。

+   **版本**：这是你的应用程序的版本号，用户在应用商店中可见，如`1.0.0`。

+   **构建**：这是为开发者保留的版本号（例如 CI 构建等），如`1.0.0.1234`。

+   **设备**：在这里，你可以为你的应用程序选择**iPhone/iPod**、**iPad**或**通用**（所有设备）。

+   **部署目标**：这是你的应用程序运行的最低 iOS 版本。

+   **主界面**：这是你的应用的主故事板文件。

+   **设备方向**：这是你的应用程序能够旋转并支持的不同位置。

+   **状态栏样式**：这些选项可以隐藏应用程序中的顶部状态栏，并全屏运行。

还有其他关于应用图标、启动屏幕等的设置。你也可以在**高级**或**源**标签之间切换，以配置 Xamarin 没有提供友好菜单的其他设置。

为我们的应用程序配置以下设置：

+   **应用名称**：`XamSnap`

+   **包标识符**：`com.yourcompanyname.xamsnap`；确保你为未来应用命名时，它们以`com.yourcompanyname`开头。

+   **设备**：**iPhone/iPod**

+   **部署目标**：**8.0**

+   **支持的设备方向**：只选择**纵向**。

# Xamarin.iOS 构建选项

如果你右键点击你的项目并选择**选项**，你可以找到一些针对 Xamarin iOS 应用程序的附加设置，如下面的截图所示。了解在 Xamarin Studio 中为 iOS 特定项目提供了什么是一个好主意。这里有很多内容，但在大多数情况下，默认设置就足够了。

![Xamarin.iOS 构建选项](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00218.jpeg)

让我们讨论一些最重要的选项，如下：

**iOS 构建**

+   **SDK 版本**：这是用于编译应用程序的 iOS SDK 版本。通常最好使用**默认**版本。

+   **链接器行为**：Xamarin 实现了一个名为**链接**的功能。链接器将移除任何在你的程序集中永远不会调用的代码。这使你的应用程序保持小巧，并允许它们与你的应用程序一起发布核心 Mono 运行的简化版本。除了调试版本外，最好使用**仅链接 SDK 程序集**的选项。我们将在未来的章节中介绍链接。

+   **支持的架构**：这些是处理器的类型。`i386`是模拟器，`ARMv7 + ARM64`是针对现代 iOS 设备编译的选项。你通常应该能够在这里使用默认设置，除非升级较旧的 Xamarin.iOS 应用程序。

+   **HttpClient 实现**：新版本的 Xamarin.iOS 允许你为`System.Net.Http.HttpClient`选择本地 HTTP 栈。Mono 的实现是默认的，但性能不如本地栈。

+   **SSL/TLS 实现**：Xamarin.iOS 也有使用本地 API 进行 SSL 的选项。如果你选择使用 Mono，你的应用程序将只支持 TLS 1.0，因此最好在这里使用本地选项。

+   **使用 LLVM 优化编译器**：勾选此项将编译出体积更小、运行速度更快的代码，但编译时间会更长。**LLVM**代表**低级虚拟机**。

+   **去除本地调试符号**：当这个选项开启时，Xamarin 会从你的应用程序中移除额外的信息，这些信息可以从 Xamarin Studio 中进行调试。

+   **额外的 mtouch 参数**：此字段用于传递给 iOS 的 Xamarin 编译器额外的命令行参数。你可以查看这些参数的完整列表在[`developer.xamarin.com/api`](https://developer.xamarin.com/api)。

+   **针对 iOS 优化 PNG 文件**：苹果使用自定义的 PNG 格式来加速应用程序内 PNG 的加载。你可以关闭此选项来加快构建速度，或者如果你打算自己优化图像。

**iOS 打包签名**

+   **签名标识**：这是用于识别应用程序创建者并将应用程序部署到设备的证书。我们将在后面的章节中详细介绍这一点。

+   **配置文件**：这是一个特定的配置文件，用于将应用程序部署到设备上。它与**签名标识**协同工作，同时声明分发方法和可以安装应用程序的设备。

+   **自定义权利**：这个文件包含了与应用程序权利证明文件一起应用的附加设置，并包含了对应用程序的其他特定声明，比如 iCloud 或推送通知。iOS 应用程序的项目模板为新项目包含了一个默认的`Entitlements.plist`文件。

对于这个应用程序，你可以保留所有这些选项为默认值。在独自开发实际的 iOS 应用程序时，你应该根据应用程序的需求考虑更改这些设置。

# 使用`UINavigationController`。

在 iOS 应用程序中，管理不同控制器间导航的关键类是`UINavigationController`。它是一个父控制器，包含了一个栈中的多个子控制器。用户可以通过在栈顶放置新的控制器来前进，或者使用内置的后退按钮移除控制器并导航回上一个屏幕。

开发者可以使用以下方法操作导航控制器的栈：

+   `SetViewControllers`：这个方法设置一个子控制器数组。它有一个可选值用来动画过渡。

+   `ViewControllers`：这是一个属性，用于获取或设置子控制器数组，但不提供动画选项。

+   `PushViewController`：这个方法将一个新的子控制器放置在栈顶，并可以选择显示动画。

+   `PopViewController`：这个方法会移除栈顶的子控制器，并可以选择是否动画过渡。

+   `PopToViewController`：这个方法移除到指定的子控制器，移除其上的所有控制器。它提供了一个动画过渡的选项。

+   `PopToRootViewController`：这个方法移除除了最底部的控制器之外的所有子控制器。它包括一个显示动画的选项。

+   `TopViewController`：这是一个属性，返回当前位于栈顶的子控制器。

### 提示

需要注意的是，如果在动画过程中尝试修改栈，使用动画选项将会导致崩溃。要解决这个问题，可以选择使用`SetViewControllers`方法并设置整个子控制器列表，或者在组合过渡期间避免使用动画。

让我们通过执行以下步骤，在应用程序中设置导航控制器：

1.  双击`Main.storyboard`文件，在 Xamarin Studio 中打开它。

1.  移除由项目模板创建的控制器。

1.  从右侧的**工具箱**中拖动一个**导航控制器**元素到故事板中。

1.  注意，已经创建了一个默认的**视图控制器**元素以及一个**导航控制器**。

1.  你会看到一个连接两个控制器的**segue**。我们将在本章后面更详细地介绍这个概念。

1.  保存故事板文件。

### 提示

对于 Visual Studio 用户的一个小提示，Xamarin 已经很好地使他们的 Visual Studio 扩展与 Xamarin Studio 完全相同。本章中的所有示例都应如描述的那样在 Xamarin Studio on OS X 或 Windows 上的 Visual Studio 中工作。当然，远程连接的 mac 部署到模拟器或 iOS 设备是一个例外。

如果此时运行应用程序，你将得到一个基本的 iOS 应用，它有一个顶部的状态栏，一个包含默认标题的导航栏的导航控制器，以及一个完全白色的子控制器，如下面的截图所示：

![使用 UINavigationController](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00219.jpeg)

# 实现登录界面

由于我们应用程序的第一个屏幕将是登录屏幕，因此让我们从在故事板文件中设置适当的视图开始。我们将使用 Xamarin Studio 编写 C#代码实现登录屏幕，并使用其 iOS 设计师在故事板文件中创建 iOS 布局。

返回 Xamarin Studio 中的项目，并执行以下步骤：

1.  双击`Main.storyboard`文件，在 iOS 设计师中打开它。

1.  选择你的视图控制器，点击**属性**窗格并选择**小部件**标签页。

1.  在**类**字段中输入`LoginController`。

1.  注意到为你生成了`LoginController`类。如果你愿意，可以创建一个`Controllers`文件夹并将文件移到其中。

以下截图显示了在 Xamarin Studio 中进行更改后控制器设置的样子：

![实现登录界面](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00220.jpeg)

现在让我们通过执行以下步骤来修改控制器的布局：

1.  再次双击`Main.storyboard`文件返回到 iOS 设计师。

1.  点击导航栏并编辑**标题**字段，将其改为`Login`。

1.  将两个文本字段拖到控制器上。适当地为用户名和密码输入定位和调整它们的大小。你可能还想删除默认文本以使字段为空。

1.  对于第二个字段，勾选**安全文本输入**复选框。这将设置控件隐藏密码字段的字符。

1.  你可能还想为`Username`和`Password`填写**占位符**字段。

1.  将一个按钮拖到控制器上。将按钮的**标题**设置为`Login`。

1.  将一个活动指示器拖到控制器上。勾选**动画**和**隐藏**复选框。

1.  接下来，通过填写**名称**字段为每个控件创建出口。分别为这些出口命名为`username`、`password`、`login`和`indicator`。

1.  保存故事板文件，查看`LoginController.designer.cs`。

你会注意到 Xamarin Studio 已经为每个出口生成了属性：

![实现登录界面](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00221.jpeg)

去编译应用程序，确保一切正常。在这一点上，我们还需要添加对前一章创建的`XamSnap.Core`项目的引用。

然后，让我们设置 iOS 应用程序以注册其所有视图模型以及其他将在整个应用程序中使用的服务。我们将使用在第四章，*XamSnap - 一个跨平台应用程序*中创建的`ServiceContainer`类来设置我们应用程序中的依赖关系。打开`AppDelegate.cs`并添加以下方法：

```kt
public override bool FinishedLaunching(
   UIApplication application,
   NSDictionary launchOptions) 
{ 
  //View Models 
  ServiceContainer.Register<LoginViewModel>(() =>
     new LoginViewModel()); 
  ServiceContainer.Register<FriendViewModel>(() =>
     new FriendViewModel()); 
  ServiceContainer.Register<RegisterViewModel>(() =>
     new RegisterViewModel()); 
  ServiceContainer.Register<MessageViewModel>(() =>
     new MessageViewModel()); 

  //Models 
  ServiceContainer.Register<ISettings>(() =>
     new FakeSettings()); 
  ServiceContainer.Register<IWebService>(() =>
     new FakeWebService()); 

  return true; 
} 

```

在后续操作中，我们将用真实的服务替换假服务。现在让我们在`LoginController.cs`中添加登录功能。首先在类顶部将`LoginViewModel`添加到成员变量中，如下所示：

```kt
readonly LoginViewModel loginViewModel =
   ServiceContainer.Resolve<LoginViewModel>(); 

```

这会将`LoginViewModel`的共享实例拉入控制器中的局部变量。这是我们将在整本书中使用的模式，以便将共享视图模型从一个类传递到另一个类。

接下来，重写`ViewDidLoad`以将视图模型的功能与在 outlets 中设置好的视图连接起来，如下所示：

```kt
public override void ViewDidLoad() 
{ 
  base.ViewDidLoad(); 

  login.TouchUpInside += async(sender, e) => 
  { 
    loginViewModel.UserName = username.Text; 
    loginViewModel.Password = password.Text; 

    try 
    { 
      await loginViewModel.Login(); 

      //TODO: navigate to a new screen 
    } 
    catch (Exception exc) 
    { 
      new UIAlertView("Oops!", exc.Message, null, "Ok").Show(); 
    } 
  }; 
} 

```

我们将在本章后面添加代码以导航到一个新屏幕。

接下来，让我们将`IsBusyChanged`事件实际连接起来以执行一个操作，如下所示：

```kt
public override void ViewWillAppear(bool animated) 
{ 
  base.ViewWillAppear(animated); 

  loginViewModel.IsBusyChanged += OnIsBusyChanged; 
} 

public override void ViewWillDisappear(bool animated) 
{ 
  base.ViewWillDisappear(animated); 

  loginViewModel.IsBusyChanged -= OnIsBusyChanged; 
} 

void OnIsBusyChanged(object sender, EventArgs e) 
{ 
  username.Enabled = 
    password.Enabled = 
    login.Enabled =  
    indicator.Hidden = !loginViewModel.IsBusy; 
} 

```

现在，你可能会问为什么我们要以这种方式订阅事件。问题是`LoginViewModel`类将贯穿应用程序的整个生命周期，而`LoginController`类则不会。如果我们只在`ViewDidLoad`中订阅事件，但稍后没有取消订阅，那么我们的应用程序将会有内存泄漏。我们还避免了使用 lambda 表达式作为事件，因为否则将无法取消订阅该事件。

请注意，我们不会遇到按钮上的`TouchUpInside`事件相同的问题，因为它将和控制器一样长时间存在于内存中。这是 C#中事件的一个常见问题，这就是为什么在 iOS 上使用前面的模式是一个好主意。

如果你现在运行应用程序，你应该能够输入用户名和密码，如下面的截图所示。按下**登录**后，你应该看到指示器出现，所有控件被禁用。你的应用程序将正确调用共享代码，并且在我们添加一个真实的网络服务时应该能正确运行。

![实现登录界面](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00222.jpeg)

# 使用 segue 进行导航

Segue 是从一个控制器到另一个控制器的过渡。同样，一个故事板文件是连接在一起的控制器和它们的视图的集合，通过 segue 进行连接。这反过来又允许你同时查看每个控制器的布局和应用程序的一般流程。

有几种类型的 segue，如下所示：

+   **推送**：在导航控制器内使用。它将一个新的控制器推送到导航控制器堆栈的顶部。推送使用导航控制器的标准动画技术，通常是最常用的过渡方式。

+   **关系**：用于为另一个控制器设置子控制器。例如，导航控制器的根控制器，容器视图，或者在 iPad 应用程序中的分割视图控制器。

+   **模态**：使用此方式时，以模态方式呈现的控制器将出现在父控制器的顶部。它将覆盖整个屏幕，直到被关闭。有几种不同类型的过渡动画可供选择。

+   **自定义**：这是一种自定义的过渡，包括一个选项，用于自定义类，该类是`UIStoryboardSegue`的子类。这使你可以细致地控制动画以及下一个控制器的呈现方式。

过渡在执行时也遵循以下模式：

+   目的地控制器及其视图被创建。

+   创建一个`UIStoryboardSegue`的子类的过渡对象。这对于自定义过渡通常很重要。

+   在源控制器上调用`PrepareForSegue`方法。在过渡开始之前，这是一个运行任何自定义代码的好地方。

+   过渡的`Perform`方法被调用，过渡动画开始。这是自定义过渡的大部分代码所在的地方。

在 Xamarin.iOS 设计师中，你有从按钮或表格行自动触发过渡的选择，或者只是给过渡一个标识符。在第二种情况下，你可以通过使用其标识符在源控制器上调用`PerformSegue`方法来自己启动过渡。

现在让我们通过执行以下步骤设置一些`Main.storyboard`文件的方面，来设置一个新的过渡：

1.  双击`Main.storyboard`文件，在 iOS 设计师中打开它。

1.  向故事板中添加一个新的**表格视图控制器**。

1.  选择你的视图控制器，并导航到**属性**窗格和**小部件**标签。

1.  在**类**字段中输入`ConversationsController`。

1.  在**视图控制器**部分向下滚动，并输入一个**标题**为`Conversations`。

1.  通过按住**Ctrl**点击并从`LoginController`拖动蓝线到`ConversationsController`，创建一个过渡。

1.  从出现的弹出菜单中选择**显示**过渡。

1.  通过点击选择此过渡，并为其分配一个标识符`OnLogin`。

1.  保存故事板文件。

你的故事板将与下面截图所示的内容类似：

![使用过渡进行导航](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00223.jpeg)

打开`LoginController.cs`文件，并按照本章早些时候标记为`TODO`的代码行进行修改，如下所示：

```kt
PerformSegue("OnLogin", this); 

```

现在如果你构建并运行应用程序，成功登录后你将导航到新的控制器。过渡将被执行，你将看到导航控制器提供的内置动画。

# 设置 UITableView

接下来，让我们在第二个控制器上设置表格视图。我们在 iOS 上使用了一个强大的类，叫做 `UITableView`。它被用在许多场景中，并且与其他平台上列表视图的概念非常相似。`UITableView` 类由另一个叫做 `UITableViewSource` 的类控制。它有你需要重写的方法，以设置应该存在多少行以及这些行应该如何在屏幕上显示。

### 提示

注意 `UITableViewSource` 是 `UITableViewDelegate` 和 `UITableViewDataSource` 的组合。出于简单考虑，我更喜欢使用 `UITableViewSource`，因为通常需要使用另外两个类。

在我们开始编码之前，让我们回顾一下在 `UITableViewSource` 上最常用的方法，如下：

+   `RowsInSection`：这个方法允许你定义一个部分中的行数。所有表格视图都有多个部分和行。默认情况下，只有一个部分；然而，需要返回一个部分中的行数。

+   `NumberOfSections`：这是表格视图中的部分数。

+   `GetCell`：这个方法必须为每一行返回一个单元格。开发者需要决定单元格的外观；你可以设置表格视图来回收单元格。回收单元格可以在滚动时提供更好的性能。

+   `TitleForHeader`：如果重写这个方法，它是最简单的返回标题字符串的方式。表格视图中的每个部分默认都可以有一个标准的头部视图。

+   `RowSelected`：当用户选择一行时，将调用此方法。

还有其他可以重写的方法，但大多数情况下这些方法就足够了。如果需要开发具有自定义样式的表格视图，你还可以设置自定义的头部和底部。

现在，让我们打开 `ConversationsController.cs` 文件，并在 `ConversationsController` 内部创建一个嵌套类，如下：

```kt
class TableSource : UITableViewSource 
{ 
  const string CellName = "ConversationCell"; 
  readonly MessageViewModel messageViewModel =
     ServiceContainer.Resolve<MessageViewModel>(); 

  public override nint RowsInSection(
     UITableView tableview, nint section) 
  { 
    return messageViewModel.Conversations == null ?
       0 : messageViewModel.Conversations.Length; 
  } 

  public override UITableViewCell GetCell(
     UITableView tableView, NSIndexPath indexPath) 
  { 
    var conversation =
       messageViewModel.Conversations[indexPath.Row]; 
    var cell = tableView.DequeueReusableCell(CellName); 
    if (cell == null) 
    { 
      cell = new UITableViewCell(
         UITableViewCellStyle.Default, CellName); 
      cell.Accessory =
         UITableViewCellAccessory.DisclosureIndicator; 
    } 
    cell.TextLabel.Text = conversation.UserName; 
    return cell; 
  } 
} 

```

我们实现了设置表格视图所需的两个方法：`RowsInSection` 和 `GetCell`。我们返回了视图模型中找到的对话数量，并为每一行设置了我们的单元格。我们还使用了 `UITableViewCellAccessory.DisclosureIndicator`，以便用户可以看到他们可以点击行。

注意我们实现的单元格回收。使用单元格标识符调用 `DequeueReusableCell` 会在第一次返回一个 `null` 单元格。如果为 `null`，你应该使用相同的单元格标识符创建一个新的单元格。后续调用 `DequeueReusableCell` 将返回一个现有的单元格，使你能够复用它。你也可以在故事板文件中定义 `TableView` 单元格，这对于自定义单元格很有用。我们的单元格这里非常简单，所以从代码中定义它更容易。在移动平台上回收单元格对于节省内存和为用户提供流畅的滚动表格非常重要。

接下来，我们需要在 `TableView` 上设置 `TableView` 的数据源。对我们的 `ConversationsController` 类进行以下一些更改：

```kt
readonly MessageViewModel messageViewModel = 
  ServiceContainer.Resolve<MessageViewModel>(); 

public override void ViewDidLoad() 
{ 
  base.ViewDidLoad(); 

  TableView.Source = new TableSource(); 
} 

public async override void ViewWillAppear(bool animated) 
{ 
  base.ViewWillAppear(animated); 

  try 
  { 
    await messageViewModel.GetConversations(); 

    TableView.ReloadData(); 
  } 
  catch(Exception exc) 
  { 
    new UIAlertView("Oops!", exc.Message, null, "Ok").Show(); 
  } 
} 

```

因此，当视图出现时，我们将加载我们的对话列表。在完成该任务后，我们将重新加载表格视图，使其显示我们的对话列表。如果你运行应用程序，你会在登录后看到表格视图中出现一些对话，如下面的截图所示。以后当我们从真正的网络服务加载对话时，一切都会以同样的方式运行。

![设置 UITableView](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00224.jpeg)

# 添加好友列表屏幕

我们 XamSnap 应用程序下一个需要的屏幕是我们的好友列表。当创建新对话时，应用程序将加载好友列表以开始对话。我们将遵循一个非常相似的模式来加载我们的对话列表。

首先，我们将通过以下步骤创建一个`UIBarButtonItem`，它导航到一个名为`FriendsController`的新控制器：

1.  双击`Main.storyboard`文件，在 iOS 设计师中打开它。

1.  向故事板中添加一个新的**表格视图控制器**。

1.  选择你的视图控制器，点击**属性**窗格，确保你选择了**控件**标签页。

1.  在**类**字段中输入`FriendsController`。

1.  滚动到**视图控制器**部分，在**标题**字段中输入`Friends`。

1.  从**工具箱**中拖动一个**导航项**到`ConversationsController`上。

1.  创建一个新的**工具栏按钮**元素，并将其放置在新导航栏的右上角。

1.  在工具栏按钮的**属性**窗格中，将其**标识符**设置为**添加**。这将使用内置的加号按钮，这在 iOS 应用程序中是常用的。

1.  通过按住**Ctrl**键，并将蓝色线条从工具栏按钮拖动到下一个控制器，创建一个从**工具栏按钮**到`FriendsController`的 segue。

1.  从弹出的菜单中选择**显示**segue。

1.  保存故事板文件。

你对故事板的更改应该与以下截图所示类似：

![添加好友列表屏幕](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00225.jpeg)

你应该会看到一个名为`FriendsController`的新类，这是 Xamarin Studio 为你生成的。如果你编译并运行应用程序，你会看到我们创建的新工具栏按钮。点击它将导航到新的控制器。

现在，让我们实现`UITableViewSource`来展示我们的好友列表。首先在`FriendsController`内部创建一个新的嵌套类，如下所示：

```kt
class TableSource : UITableViewSource 
{ 
  const string CellName = "FriendCell"; 
  readonly FriendViewModel friendViewModel =
     ServiceContainer.Resolve<FriendViewModel>(); 

  public override nint RowsInSection(
     UITableView tableview, nint section) 
  { 
    return friendViewModel.Friends == null ?
       0 : friendViewModel.Friends.Length; 
  } 

  public override UITableViewCell GetCell(
     UITableView tableView, NSIndexPath indexPath) 
  { 
    var friend =
       friendViewModel.Friends[indexPath.Row]; 
    var cell = tableView.DequeueReusableCell(CellName); 
    if (cell == null) 
    { 
      cell = new UITableViewCell(
         UITableViewCellStyle.Default, CellName); 
      cell.AccessoryView =
         UIButton.FromType(UIButtonType.ContactAdd); 
      cell.AccessoryView.UserInteractionEnabled = false; 
    } 
    cell.TextLabel.Text = friend.Name; 
    return cell; 
  } 
} 

```

正如之前所做，我们实现了表格单元格的回收利用，并为每个好友的标签设置了文本。我们使用`cell.AccessoryView`来提示用户每个单元格都是可点击的，并开始新的对话。我们在按钮上禁用了用户交互，以便当用户点击按钮时，可以选中行。否则，我们就必须为按钮实现一个点击事件。

接下来，我们将按照对话的方式修改`FriendsController`，如下所示：

```kt
readonly FriendViewModel friendViewModel =
   ServiceContainer.Resolve<FriendViewModel>(); 

public override void ViewDidLoad() 
{ 
  base.ViewDidLoad(); 

  TableView.Source = new TableSource(); 
} 

public async override void ViewWillAppear(bool animated) 
{ 
  base.ViewWillAppear(animated); 

  try 
  { 
    await friendViewModel.GetFriends(); 

    TableView.ReloadData(); 
  } 
  catch(Exception exc) 
  { 
    new UIAlertView("Oops!", exc.Message, null, "Ok").Show(); 
  } 
} 

```

这将和对话列表完全一样：控制器将异步加载朋友列表并刷新表格视图。如果你编译并运行应用程序，你将能够导航到屏幕并查看我们在第四章，*XamSnap - 跨平台应用程序*中创建的示例朋友列表，如下截图所示：

![添加朋友列表屏幕](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00226.jpeg)

# 添加消息列表

现在我们来实现查看对话或消息列表的屏幕。我们将尝试模仿 iOS 内置的短信应用程序的屏幕。为此，我们还将介绍如何创建自定义表格视图单元格的基础知识。

首先，我们需要一个新的`MessagesController`类；执行以下步骤：

1.  双击`Main.storyboard`文件，在 iOS 设计师中打开它。

1.  向故事板中添加一个新的**表格视图控制器**。

1.  选择你的视图控制器，点击**属性**窗格，确保你选择了**小部件**标签。

1.  在**类**字段中输入`MessagesController`。

1.  滚动到**视图控制器**部分，在**标题**字段中输入`Messages`。

1.  通过按住***Ctrl***并将蓝色线条从`ConversationsController`拖到`MessagesController`，创建一个 segue。

1.  从弹出的菜单中选择**显示**segue。在**属性**窗格中输入**标识符** `OnConversation`。

1.  现在在`MessagesController`中的表格视图中创建两个**表格视图单元格**。你可以重复使用默认创建的现有空白单元格。

1.  将每个单元格的**样式**字段更改为**Basic**。

1.  分别为每个单元格将**标识符**设置为`MyCell`和`TheirCell`。

1.  保存故事板文件。

Xamarin Studio 将生成`MessagesController.cs`。和之前一样，你可以将控制器移动到`Controllers`文件夹中。现在打开`MessagesController.cs`，并在嵌套类中实现`UITableViewSource`，如下所示：

```kt
class TableSource : UITableViewSource
{
  const string MyCellName = "MyCell";
  const string TheirCellName = "TheirCell";
  readonly MessageViewModel messageViewModel =
    ServiceContainer.Resolve();
  readonly ISettings settings = ServiceContainer.Resolve();

  public override nint RowsInSection(
    UITableView tableview, nint section)
  {
    return messageViewModel.Messages == null ? 0 :
      messageViewModel.Messages.Length;
  }

  public override UITableViewCell GetCell(
    UITableView tableView, NSIndexPath indexPath)
  {
    var message = messageViewModel.Messages [indexPath.Row];
    bool isMyMessage = message.UserName == settings.User.Name;
    var cell = (BaseMessageCell)tableView.DequeueReusableCell(
      isMyMessage ? MyCellName : TheirCellName);
    cell.TextLabel.Text = message.Text;
    return cell;
  }
}

```

我们添加了一些逻辑，以检查消息是否来自当前用户，以决定适当的表格单元格标识符。由于我们为两个单元格都使用了**Basic**样式，我们可以使用单元格上的`TextLabel`属性来设置`UILabel`的文本。

现在我们对`MessagesController`进行必要的更改，如下所示：

```kt
readonly MessageViewModel messageViewModel = 
  ServiceContainer.Resolve<MessageViewModel>(); 

public override void ViewDidLoad() 
{ 
  base.ViewDidLoad(); 

  TableView.Source = new TableSource(); 
} 

public async override void ViewWillAppear(bool animated) 
{ 
  base.ViewWillAppear(animated); 

  Title = messageViewModel.Conversation.UserName; 
  try 
  { 
    await messageViewModel.GetMessages(); 
    TableView.ReloadData(); 
  } 
  catch (Exception exc) 
  { 
    new UIAlertView("Oops!", exc.Message, null, "Ok").Show(); 
  } 
} 

```

这里的唯一新事物是我们将`Title`属性设置为对话的用户名。

为了完成我们的自定义单元格，我们还需要在 Xcode 中进行以下步骤进行更多更改：

1.  双击`Main.storyboard`文件，在 iOS 设计师中打开它。

1.  通过点击默认文本**Title**，选择一个**标签**。

1.  创造性地为两个标签设置样式。我选择使`MyCell`中的文本为蓝色，`TheirCell`为绿色。我将`TheirCell`中的标签**对齐**设置为右对齐。

1.  保存故事板文件并返回。

接下来，我们需要更新`ConversationsController`以导航到这个新屏幕。让我们修改`ConversationsController.cs`中的`TableSource`类，如下所示：

```kt
readonly ConversationsController controller; 

public TableSource(ConversationsController controller) 
{ 
  this.controller = controller;
}

public override void RowSelected(
  UITableView tableView, NSIndexPath indexPath)
{ 
  var conversation = messageViewModel.Conversations[indexPath.Row]; 
  messageViewModel.Conversation = conversation; 
  controller.PerformSegue("OnConversation", this); 
}

```

当然，你还需要在控制器中的`ViewDidLoad`修改一行小代码：

```kt
TableView.Source = new TableSource(this); 

```

如果你现在运行应用程序，你将能够看到如下截图所示的消息列表：

![添加消息列表](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00227.jpeg)

# 编写消息

为了我们应用程序的最后一块，我们需要实现一些苹果公司 API 不提供的自定义功能。我们需要添加一个带有按钮的文本字段，使其看起来附着在表格视图的底部。其中大部分工作需要编写一些简单的 C#代码并连接事件。

首先，我们在`MessagesController`类中添加一些新的成员变量，如下所示：

```kt
UIToolbar toolbar; 
UITextField message; 
UIBarButtonItem send; 

```

我们将在工具栏中放置文本字段和工具栏按钮，如下面的`ViewDidLoad`中的代码所示：

```kt
public override void ViewDidLoad() 
{ 
  base.ViewDidLoad(); 

  //Text Field 
  message = new UITextField( 
    new CGRect(0, 0, TableView.Frame.Width - 88, 32)) 
  { 
    BorderStyle = UITextBorderStyle.RoundedRect, 
    ReturnKeyType = UIReturnKeyType.Send, 
    ShouldReturn = _ => 
    { 
        Send(); 
        return false; 
    }, 
  }; 

  //Bar button item 
  send = new UIBarButtonItem("Send", UIBarButtonItemStyle.Plain, 
    (sender, e) => Send()); 

  //Toolbar 
  toolbar = new UIToolbar( 
    new CGRect(0, TableView.Frame.Height - 44,  
      TableView.Frame.Width, 44)); 
  toolbar.Items = new[] 
  { 
    new UIBarButtonItem(message), 
    send 
  }; 

  TableView.Source = new TableSource(); 
  TableView.TableFooterView = toolbar; 
} 

```

这项工作大部分是基本的 UI 设置。这不是我们在 Xcode 中能做的事情，因为这是一个非常特定的用例。我们从 C#创建文本字段、工具栏按钮项，并将它们作为`UITableView`的页脚添加。这将使工具栏显示在我们之前定义的任何行下面的表格视图底部。

现在，我们需要按照以下方式修改`ViewWillAppear`：

```kt
public async override void ViewWillAppear(bool animated) 
{ 
  base.ViewWillAppear(animated); 

  Title = messageViewModel.Conversation.Username; 

  messageViewModel.IsBusyChanged += OnIsBusyChanged; 

  try 
  { 
    await messageViewModel.GetMessages(); 
    TableView.ReloadData(); 
    message.BecomeFirstResponder(); 
  } 
  catch (Exception exc) 
  { 
    new UIAlertView("Oops!", exc.Message, null, "Ok").Show(); 
  } 
} 

```

我们需要订阅`IsBusyChanged`以显示和隐藏加载指示器。同时我们调用`BecomeFirstResponder`，这样键盘就会出现并将焦点给予我们的文本字段。

接下来，我们为`ViewWillDisapper`添加一个重写方法，以清理事件，如下所示：

```kt
public override void ViewWillDisappear(bool animated) 
{ 
  base.ViewWillDisappear(animated); 

  messageViewModel.IsBusyChanged -= OnIsBusyChanged; 
} 

```

然后，让我们为`IsBusyChanged`设置方法，如下所示：

```kt
void OnIsBusyChanged (object sender, EventArgs e) 
{ 
  message.Enabled = send.Enabled = !messageViewModel.IsBusy; 
} 

```

`OnIsBusyChanged`用于在加载时禁用我们的一些视图。

最后但并非最不重要的是，我们需要实现一个发送新消息的函数，如下所示：

```kt
async void Send() 
{ 
  //Just hide the keyboard if they didn't type anything 
  if (string.IsNullOrEmpty(message.Text)) 
  { 
    message.ResignFirstResponder(); 
    return; 
  } 

  //Set the text, send the message 
  messageViewModel.Text = message.Text; 
  await messageViewModel.SendMessage(); 

  //Clear the text field & view model 
  message.Text = messageViewModel.Text = string.Empty; 

  //Reload the table 
  TableView.InsertRows(new[]  
  {  
    NSIndexPath.FromRowSection( 
      messageViewModel.Messages.Length - 1, 0)  
  }, UITableViewRowAnimation.Automatic); 
} 

```

这段代码同样直接明了。发送消息后，我们只需清空文本字段并告诉表格视图重新加载新添加的行，如下面的截图所示。使用`async`关键字使这变得简单。

![编写消息](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00228.jpeg)

# 概要

在本章中，我们介绍了苹果和 Xamarin 为开发 iOS 应用程序提供的基本设置。这包括`Info.plist`文件和 Xamarin Studio 中的项目选项。我们涵盖了`UINavigationController`，这是 iOS 应用程序导航的基本构建块，并实现了一个带有用户名和密码字段的登录屏幕。接下来，我们介绍了 iOS 的 segue 和`UITableView`类。我们使用`UITableView`实现了好友列表屏幕，以及消息列表屏幕。最后，我们添加了一个自定义 UI 功能：在消息列表底部的自定义工具栏。

完成本章节后，你将拥有一个部分功能性的 XamSnap 的 iOS 版本。你将对 iOS 平台和工具有一个更深入的理解，并且拥有足够的知识去开发你自己的 iOS 应用程序。请自行实现本章未涵盖的其余屏幕。如果你感到困惑，可以随时回顾本书附带的完整示例应用程序。

在下一章中，我们将实现在 Android 上的这些用户界面。


# 第六章：XamSnap for Android

要开始编写 XamSnap 的 Android 版本，请打开前两章的解决方案。我们将要在 `XamSnap.Droid` 项目中工作，该项目应该已经从 Xamarin 项目模板中设置好了。

在本章中，我们将涵盖：

+   Android 清单文件

+   Android 材料设计

+   为 XamSnap 编写登录界面

+   Android 的 ListView 和 BaseAdapter

+   添加好友列表

+   添加消息列表

# 介绍 Android 清单文件

所有 Android 应用程序都有一个名为 Android Manifest 的 XML 文件，它声明了关于应用程序的基本信息，文件名为 `AndroidManifest.xml`。这非常类似于 iOS 上的 `Info.plist` 文件，但 Xamarin 还提供了 C# 类属性，用于在 Android 清单中放置常见设置。在 **项目选项 | Android 应用程序** 下还有一个很好的 UI 用于编辑清单文件。

最重要的设置，如下截图所示，如下：

+   **应用程序名称**：这是你的应用程序的标题，显示在图标下方。它与在 Google Play 上选择的名称不同。

+   **包名**：这就像 iOS 上的应用程序捆绑标识符。这是一个唯一的名字来标识你的应用程序。约定是使用以你的公司名称开头的反向域名风格；例如，`com.jonathanpeppers.xamsnap`。它必须以小写字母开头并至少包含一个字符。

+   **应用程序图标**：这是你的应用程序在 Android 主屏幕上显示的图标。

+   **版本号**：这是一个数字，表示你的应用程序的版本。提高这个数字表示在 Google Play 上有更新的版本。

+   **版本名称**：这是你应用程序的用户友好版本字符串；例如，**1.0.0**。

+   **最低支持的 Android 版本**：这是你的应用程序支持的最低版本的 Android。

+   **目标 Android 版本**：这是你的应用程序编译时使用的 Android SDK 的版本。使用更高的版本号可以让你访问新的 API；然而，你可能需要进行一些运行时检查，以免在旧设备上调用这些 API。

+   **安装位置**：这定义了你的 Android 应用程序可以安装的不同位置：自动（用户设置）、外部（SD 卡）或内部（设备内部存储）。

![介绍 Android 清单文件](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00229.jpeg)

除了这些设置，还有一组名为**所需权限**的复选框。这些将在用户在 Google Play 安装应用程序之前向用户展示。这是 Android 强制实施安全级别的方式，让用户可以看到应用程序将对设备进行哪些更改的访问权限。

以下是一些常用的清单文件权限：

+   **Camera**：这提供了对设备相机的访问权限

+   **互联网**：这提供了通过互联网进行网络请求的访问权限

+   **ReadContacts**：这提供了读取设备联系人库的访问权限

+   **ReadExternalStorage**：这提供了读取 SD 卡的权限

+   **WriteContacts**：这提供了修改设备联系人库的权限

+   **WriteExternalStorage**：这提供了向 SD 卡写入的权限

除了这些设置之外，很多时候还需要手动更改 Android Manifest。在这种情况下，你可以在 Xamarin Studio 中像编辑标准的 XML 文件一样编辑清单文件。有关有效的 XML 元素和属性完整列表，请访问[`developer.android.com/guide/topics/manifest/manifest-intro.html`](http://developer.android.com/guide/topics/manifest/manifest-intro.html)。

现在，让我们为我们的应用程序填写以下设置：

+   **应用程序名称**：`XamSnap`

+   **包名称**：`com.yourcompanyname.xamsnap`；确保将来命名的应用程序以`com.yourcompanyname`开头

+   **版本号**：从数字`1`开始

+   **版本**：可以是任何字符串，但建议使用类似版本号的字符串

+   **最低 Android 版本**：选择**Android 4.0.3 (API Level 15)**

+   **所需权限**：选择**Internet**；我们稍后会用到它

在这一点上，请注意我们的 Android 项目已经引用了来自便携式类库的共享代码。展开项目的**引用**文件夹，注意对`XamSnap.Core`项目的引用。我们将能够访问在第四章*XamSnap - A Cross-Platform App*中编写的所有共享代码。

前往`Resources`目录，在`values`文件夹中打开`Strings.xml`；这是你整个 Android 应用中应存储所有文本的地方。这是 Android 的一个约定，它将使你非常容易地为应用程序添加多种语言。让我们将我们的字符串更改为以下内容：

```kt
<?xml version="1.0" encoding="utf-8"?> 
<resources> 
    <string name="ApplicationName">XamSnap</string> 
    <string name="ErrorTitle">Oops!</string> 
    <string name="Loading">Loading</string> 
    <string name="Login">Login</string> 
</resources> 

```

我们将在本章后面使用这些值；在需要向用户显示文本的情况下，可以自由添加新的值。

# 设置 Material Design

从 Android 5.0 Lollipop 开始，谷歌发布了一个名为**Material Design**的新主题和颜色调色板，用于 Android 应用程序。对于新应用来说，采用 Material Design 是一个好主意，因为它可以让你轻松设置现代 Android 的外观。有关 Material Design 的更多信息，请查看谷歌的文档：[`developer.android.com/design/material/index.html`](https://developer.android.com/design/material/index.html)。

为了让 Material Design（和其他新的 Android 功能）更容易被采用，谷歌还发布了一个名为**AppCompat**的 Android 库，因此你可以支持在较旧的 Android OS 版本上的这些新功能。Xamarin 在 NuGet 上支持 AppCompat 库的一个版本，以便于 Xamarin.Android 应用程序轻松设置。

要设置 Android 支持库，请按照以下步骤操作：

1.  右键点击**包**并选择**添加包**。

1.  搜索`Xamarin.Android.Support.v7.AppCompat`。

1.  点击**添加包**。

1.  NuGet 将下载库及其依赖项，并在你的 Android 项目中引用它们。

现在让我们实现我们的主应用程序类；从**新建文件**对话框中添加一个新的**Activity**。在这个文件中，我们不会继承`Activity`，但这个模板在文件顶部添加了几个 Android `using`语句，导入可以在代码中使用的 Android API。创建一个新的`Application`类，我们可以在其中注册`ServiceContainer`中的所有内容，如下所示：

```kt
[Application(Theme = "@style/Theme.AppCompat.Light")] 
public class Application : Android.App.Application 
{ 
  public Application(
     IntPtr javaReference, JniHandleOwnership transfer)
     : base(javaReference, transfer) 
  {  
  } 

  public override void OnCreate() 
  { 
    base.OnCreate(); 

```

```kt
    //ViewModels 
    ServiceContainer.Register<LoginViewModel>(
       () => new LoginViewModel()); 
    ServiceContainer.Register<FriendViewModel>(
       () => new FriendViewModel()); 
    ServiceContainer.Register<MessageViewModel>(
       () => new MessageViewModel()); 
    ServiceContainer.Register<RegisterViewModel>(
       () => new RegisterViewModel()); 

    //Models 
    ServiceContainer.Register<ISettings>(
       () => new FakeSettings()); 
    ServiceContainer.Register<IWebService>(
       () => new FakeWebService()); 
  } 
} 

```

我们使用了内置的 Android 主题`Theme.AppCompat.Light`，这是材料设计的默认浅色主题。注意我们必须遵循的奇怪构造函数，这是 Xamarin 中自定义`Application`类的当前要求。你可以将这识别为在这种情况下需要添加的样板代码。

现在让我们为应用程序中的所有活动实现一个简单的基类。在`XamSnap.Droid`项目中创建一个`Activities`文件夹，并添加一个名为`BaseActivity.cs`的新文件，内容如下：

```kt
[Activity] 
public class BaseActivity<TViewModel> : AppCompatActivity
   where TViewModel : BaseViewModel 
{ 
  protected readonly TViewModel viewModel; 
  protected ProgressDialog progress; 

  public BaseActivity() 
  { 
    viewModel = ServiceContainer.Resolve(typeof(TViewModel)) as
       TViewModel; 
  } 
  protected override void OnCreate(Bundle savedInstanceState) 
  { 
    base.OnCreate(savedInstanceState); 

    progress = new ProgressDialog(this); 
    progress.SetCancelable(false);
    progress.SetTitle(Resource.String.Loading);
  } 

  protected override void OnResume() 
  { 
    base.OnResume(); 
    viewModel.IsBusyChanged += OnIsBusyChanged; 
  }

  protected override void OnPause() 
  { 
    base.OnPause(); 
    viewModel.IsBusyChanged -= OnIsBusyChanged; 
  } 

  void OnIsBusyChanged (object sender, EventArgs e) 
  { 
    if (viewModel.IsBusy) 
      progress.Show(); 
    else 
      progress.Hide(); 
  } 
} 

```

我们在这里做了几件事来简化我们其他活动的开发。首先，我们使这个类通用，并定义了一个受保护的变量`viewModel`来存储特定类型的视图模型。请注意，由于平台限制，我们在 iOS 上没有对控制器使用泛型（更多信息请参见 Xamarin 的文档网站：[`developer.xamarin.com/guides/ios/advanced_topics/limitations/`](http://developer.xamarin.com/guides/ios/advanced_topics/limitations/)）。我们还实现了`IsBusyChanged`，并显示了一个简单的`ProgressDialog`，其中包含来自`Strings.xml`文件的`Loading`字符串，以指示网络活动。

让我们为用户显示错误再添加一个方法，如下所示：

```kt
protected void DisplayError(Exception exc) 
{ 
  string error = exc.Message; 
  new AlertDialog.Builder(this)
     .SetTitle(Resource.String.ErrorTitle)
     .SetMessage(error)
     .SetPositiveButton(Android.Resource.String.Ok,
       (IDialogInterfaceOnClickListener)null)
     .Show(); 
} 

```

这个方法将显示一个弹出对话框，指示出现了错误。注意我们也使用了`ErrorTitle`和内置的 Android 资源中的`Ok`字符串。

这将完成我们 Android 应用程序的核心设置。从这里我们可以继续实现我们应用程序中各个屏幕的用户界面。

# 添加登录界面

在创建 Android 视图之前，了解 Android 中可用的不同布局或视图组类型是很重要的。iOS 没有一些这些的等价物，因为 iOS 在其设备上的屏幕尺寸变化较小。由于 Android 具有几乎无限的屏幕尺寸和密度，Android SDK 为视图的自动调整大小和布局提供了大量内置支持。

以下是常见的布局类型：

+   `ViewGroup`：这是包含子视图集合的视图的基础类。通常你不会直接使用这个类。

+   `LinearLayout`：这是一个布局，它将子视图排列成行或列（但不能同时排列）。你还可以为每个子项设置权重，让它们占据可用空间的不同百分比。

+   `RelativeLayout`：这是一个可以更灵活地设置其子项位置的布局。你可以将子视图相对于彼此定位，使它们相互在上方、下方、左侧或右侧。

+   `FrameLayout`：这个布局将它的子视图直接在屏幕上的**z 顺序**一个叠一个。当你有一个需要其他视图覆盖其上并可能停靠在一侧的大子视图时，最好使用这个布局。

+   `ListView`：这会在列表中垂直显示视图，借助确定子视图数量的适配器类。它还支持其子项被选中。

+   `GridView`：这会在网格中以行和列显示视图。它还需要使用适配器类来提供子项的数量。

在我们开始编写登录界面之前，删除从 Android 项目模板创建的`Main.axml`和`MainActivity.cs`文件。接下来，在项目的`Resources`目录下的`layout`文件夹中创建一个名为`Login.axml`的 Android 布局文件。

现在我们可以开始向我们的 Android 布局添加功能，如下所示：

1.  双击新的布局文件以打开 Android 设计器。

1.  将两个**纯文本**视图拖到**文本字段**部分找到的布局中。

1.  在**Id**字段中，分别输入`@+id/username`和`@+id/password`。

1.  对于密码字段，将其**输入类型**属性设置为`textPassword`。

1.  将一个**按钮**拖到布局上，并将其**文本**属性设置为`@string/Login`。

1.  将按钮的**Id**属性设置为`@+id/login`。

当你的布局完成后，它看起来会像下面的截图：

![添加登录界面](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00230.jpeg)

现在在我们之前创建的`Activites`文件夹中创建一个名为`LoginActivity.cs`的新 Android 活动文件。让我们按照以下方式实现登录功能：

```kt
[Activity(Label = "@string/ApplicationName", MainLauncher = true)] 
public class LoginActivity : BaseActivity<LoginViewModel> 
{ 
  EditText username, password; 
  Button login; 

  protected override void OnCreate(Bundle savedInstanceState) 
  { 
    base.OnCreate(savedInstanceState);

    SetContentView(Resource.Layout.Login); 
    username = FindViewById<EditText>(Resource.Id.username); 
    password = FindViewById<EditText>(Resource.Id.password); 
    login = FindViewById<Button>(Resource.Id.login); 
    login.Click += OnLogin; 
  } 

  protected override void OnResume() 
  { 
    base.OnResume(); 
    username.Text =
       password.Text = string.Empty; 
  } 

  async void OnLogin (object sender, EventArgs e) 
  { 
    viewModel.UserName = username.Text; 
    viewModel.Password = password.Text; 
    try 
    { 
      await viewModel.Login(); 
      //TODO: navigate to a new activity 
    } 
    catch (Exception exc) 
    { 
      DisplayError(exc); 
    } 
  } 
} 

```

注意我们设置了`MainLauncher`为`true`，以使此活动成为应用的首个活动。我们还利用了本章早些时候设置的`ApplicationName`值和`BaseActivity`类。我们还重写了`OnResume`以清除两个`EditText`控件，这样如果你返回屏幕，这些值就会被清空。

现在如果你启动应用程序，你将看到我们刚才实现的登录界面，如下面的截图所示：

![添加登录界面](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00231.jpeg)

### 提示

对于 Visual Studio 用户来说，请注意，Xamarin 已经很好地使他们的 Visual Studio 扩展与 Xamarin Studio 完全相同。本章中的所有示例都应在 OS X 上的 Xamarin Studio 或 Windows 上的 Visual Studio 中按所述方式工作。

# 使用 ListView 和 BaseAdapter

现在，让我们在 Android 上实现一个对话列表。`UITableView`和`UITableViewSource`在 Android 上的对应物是`ListView`和`BaseAdapter`。这些 Android 类有并行概念，例如实现抽象方法和滚动时回收单元格。在 Android 中使用了几种不同类型的适配器，如`ArrayAdapter`或`CursorAdaptor`，尽管对于简单列表来说，`BaseAdapter`通常是最合适的选择。

让我们实现我们的对话界面。首先在你的`Activities`文件夹中创建一个新的 Android Activity，命名为`ConversationsActivity.cs`。我们首先只对类定义进行少量修改，如下所示：

```kt
[Activity(Label = "Conversations")] 
public class ConversationsActivity :
   BaseActivity<MessageViewModel> 
{ 
  //Other code here later 
} 

```

执行以下步骤以实现几个 Android 布局：

1.  在`Resources`目录的`layout`文件夹中创建一个新的 Android 布局，命名为`Conversations.axml`。

1.  从**工具箱**中拖动一个**列表视图(ListView)**控件到布局中，并将其**Id**设置为`@+id/conversationsList`。

1.  创建第二个 Android 布局；在`Resources`目录下的`layout`文件夹中命名为`ConversationListItem.axml`。

1.  从**工具箱**中将一个**中等文本(Text Medium)**控件拖到布局中。

1.  将其 ID 设置为`@+id/conversationUsername`。

1.  最后，让我们在**属性(Properties)**框的**布局(Layout)**选项卡中将其**边距(Margin)**设置为`3dp`。

这将设置我们将在对话界面中使用到的所有布局文件。你的`ConversationListItem.axml`布局看起来将类似于以下截图所示：

![使用 ListView 和 BaseAdapter](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00232.jpeg)

现在，我们可以在`ConversationsActivity`内部作为一个嵌套类实现`BaseAdapter`，如下所示：

```kt
class Adapter : BaseAdapter<Conversation> 
{ 
  readonly MessageViewModel messageViewModel =
     ServiceContainer.Resolve<MessageViewModel>(); 
  readonly LayoutInflater inflater; 

  public Adapter(Context context) 
  { 
    inflater = (LayoutInflater)context.GetSystemService(
       Context.LayoutInflaterService); 
  } 

  public override long GetItemId(int position) 
  { 
    //This is an abstract method, just a simple implementation 
    return position; 
  } 

  public override View GetView(
     int position, View convertView, ViewGroup parent) 
  { 
    if (convertView == null) 
    { 
      convertView = inflater.Inflate(
         Resource.Layout.ConversationListItem, null); 
    } 
    var conversation = this [position]; 
    var username = convertView.FindViewById<TextView>(
       Resource.Id.conversationUsername); 
    username.Text = conversation.Username; 
    return convertView; 
  }

  public override int Count 
  { 
    get { return messageViewModel.Conversations == null ? 0
       : messageViewModel.Conversations.Length; } 
  }

  public override Conversation this[int position] 
  { 
    get { return messageViewModel.Conversations [position]; } 
  } 
} 

```

以下是适配器内部正在进行的操作的回顾：

+   我们继承了`BaseAdapter<Conversation>`。

+   我们传递了一个`Context`（我们的活动），这样我们就可以取出`LayoutInflater`。这个类使我们能够加载 XML 布局资源，并将其膨胀成视图对象。

+   我们实现了`GetItemId`。这是一个通常用于标识行的一般方法，但现在我们只是返回位置。

+   我们设置了`GetView`方法，通过仅当`convertView`为空时创建新视图来回收`convertView`变量。我们还取出了布局中的文本视图以设置它们的文本。

+   我们重写了`Count`方法，以返回对话的数量。

+   我们实现了一个索引器，用于根据位置返回一个`Conversation`对象。

总的来说，这应该和我们之前在 iOS 上的操作非常相似。

现在，让我们通过在`ConversationsActivity`的正文添加以下内容来在活动中设置适配器：

```kt
ListView listView; 
Adapter adapter; 

protected override void OnCreate(Bundle bundle) 
{ 
  base.OnCreate(bundle); 

  SetContentView(Resource.Layout.Conversations); 
  listView = FindViewById<ListView>(
     Resource.Id.conversationsList); 
  listView.Adapter = 
     adapter = new Adapter(this); 
} 

protected async override void OnResume() 
{ 
  base.OnResume(); 
  try 
  { 
    await viewModel.GetConversations(); 
    adapter.NotifyDataSetInvalidated(); 
  } 
  catch (Exception exc) 
  { 
    DisplayError(exc); 
  } 
} 

```

这段代码将在活动出现在屏幕上时设置适配器并重新加载我们的对话列表。注意，我们在这里调用了`NotifyDataSetInvalidated`，这样当对话数量更新后，`ListView`可以重新加载其行。

最后但同样重要的是，我们需要修改之前在`LoginActivity`中设置的`OnLogin`方法，以启动我们的新活动，如下所示：

```kt
StartActivity(typeof(ConversationsActivity)); 

```

现在如果我们编译并运行我们的应用程序，登录后我们可以导航到一个对话列表，如下截图所示：

![使用 ListView 和 BaseAdapter](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00233.jpeg)

# 实现好友列表

在我们开始实现好友列表屏幕之前，我们首先需要在应用程序的`ActionBar`中添加一个菜单项。首先在项目的`Resources`文件夹中创建一个名为`menu`的新文件夹。接下来，创建一个名为`ConversationsMenu.axml`的新 Android 布局文件。删除默认创建的布局 XML，并替换为以下内容：

```kt
<?xml version="1.0" encoding="utf-8"?> 
<menu > 
  <item android:id="@+id/addFriendMenu"
     android:text="Add Friend"
     android:showAsAction="ifRoom"/> 
</menu> 

```

我们设置了一个根菜单，其中包含一个菜单项。

以下是我们为 XML 中的项目设置的内容分解：

+   `android:id`：我们稍后在 C#中会使用它，通过`Resource.Id.addFriendMenu`引用菜单项。

+   `android:icon`：这是为菜单项显示的图像资源。我们使用了一个内置的 Android 通用*加号*图标。

+   `android:showAsAction`：如果空间足够，这将使菜单项可见。如果设备的屏幕太窄，将显示一个溢出菜单来代替菜单项。

现在，我们可以在`ConversationsActivity.cs`中进行一些更改，如下所示显示菜单项：

```kt
public override bool OnCreateOptionsMenu(IMenu menu) 
{ 
  MenuInflater.Inflate(Resource.Menu.ConversationsMenu, menu); 
  return base.OnCreateOptionsMenu(menu); 
} 

```

这段代码将使用我们的布局并将其应用到活动中操作栏顶部的菜单。接下来，我们可以添加一些代码，在选中菜单项时运行，如下所示：

```kt
public override bool OnOptionsItemSelected(IMenuItem item) 
{ 
  if (item.ItemId == Resource.Id.addFriendMenu) 
  { 
    //TODO: launch the next activity 
  } 
  return base.OnOptionsItemSelected(item); 
} 

```

现在我们来实现下一个活动。首先复制`Resources`目录中`layout`文件夹中的`Conversations.axml`文件，并将其重命名为`Friends.axml`。我们在这个文件中唯一要做的更改是将 ListView 的 ID 重命名为`@+id/friendsList`。

接下来，执行以下步骤，创建一个可用于`ListView`中列表项的布局：

1.  创建一个名为`FriendListItem.axml`的新 Android 布局。

1.  打开布局，并切换到屏幕底部的**源代码**标签。

1.  将根`LinearLayout` XML 元素更改为`RelativeLayout`元素。

1.  切换回屏幕底部的**设计器**标签。

1.  从**工具箱**中拖动一个**大文本**控件到布局上，并将其**Id**设置为`@+id/friendName`。

1.  从**工具箱**中拖动一个**图像视图**控件到布局上；你可以让它保留默认的**Id**或者将其清空。

1.  将图像视图的图像更改为`@android:drawable/ic_menu_add`。这是我们本章前面使用的同样的加号图标。你可以在**资源**对话框下的**框架资源**标签中选择它。

1.  将控件的两边**宽度和高度**设置为`wrap_content`。这可以在**布局**标签下的**ViewGroup**部分找到。

1.  然后，仅针对图像视图检查**与父级右对齐**的值。

1.  最后，在**属性**框的**布局**标签下，将控件的两边**边距**设置为`3dp`。

使用 Xamarin 设计器可以非常高效，但有些开发者更喜欢更高水平的控制。你可以考虑自己编写 XML 作为替代方案，这相当直接，如下面的代码所示：

```kt
<?xml version="1.0" encoding="utf-8"?> 
<RelativeLayout 

    android:layout_width="fill_parent" 
    android:layout_height="fill_parent"> 
    <TextView 
        android:text="Large Text" 
        android:textAppearance="?android:attr/textAppearanceLarge" 
        android:layout_width="wrap_content" 
        android:layout_height="wrap_content" 
        android:id="@+id/friendName" 
        android:layout_margin="3dp" /> 
    <ImageView 
        android:layout_width="wrap_content" 
        android:layout_height="wrap_content" 
        android:src="img/ic_menu_add" 
        android:layout_margin="3dp" 
        android:layout_alignParentRight="true" /> 
</RelativeLayout> 

```

既然我们已经拥有了新屏幕所需的所有布局，那么在`Activities`文件夹中创建一个名为`FriendsActivity.cs`的 Android 活动吧。让我们按照之前的做法，创建活动的基本定义如下：

```kt
[Activity(Label = "Friends")] 
public class FriendsActivity : BaseActivity<FriendViewModel> 
{ 
  protected override void OnCreate(Bundle savedInstanceState) 
  { 
    base.OnCreate(savedInstanceState); 
  } 
} 

```

现在，让我们实现一个嵌套的`Adapter`类来设置列表视图项，如下所示：

```kt
class Adapter : BaseAdapter<User> 
{ 
  readonly FriendViewModel friendViewModel =
     ServiceContainer.Resolve<FriendViewModel>(); 
  readonly LayoutInflater inflater; 

  public Adapter(Context context) 
  { 
    inflater = (LayoutInflater)context.GetSystemService (
       Context.LayoutInflaterService); 
  } 

  public override long GetItemId(int position) 
  { 
    return position; 
  } 

  public override View GetView(
     int position, View convertView, ViewGroup parent) 
  { 
    if (convertView == null) 
    { 
      convertView = inflater.Inflate(
         Resource.Layout.FriendListItem, null); 
    } 
    var friend = this [position]; 
    var friendname = convertView.FindViewById<TextView>(
       Resource.Id.friendName); 
    friendname.Text = friend.Name; 
    return convertView; 
  }

  public override int Count 
  { 
    get { return friendViewModel.Friends == null ? 0
       : friendViewModel.Friends.Length; } 
  } 

  public override User this[int position] 
  { 
    get { return friendViewModel.Friends[position]; } 
  } 
} 

```

这个适配器与我们之前为对话屏幕实现的适配器实际上没有区别。我们只需要设置好友的名字，并且使用`User`对象而不是`Conversation`对象。

为了完成适配器的设置，我们可以更新`FriendsActivity`类的主体，如下所示：

```kt
ListView listView; 
Adapter adapter; 

protected override void OnCreate(Bundle savedInstanceState) 
{ 
  base.OnCreate(savedInstanceState); 

  SetContentView(Resource.Layout.Friends); 
  listView = FindViewById<ListView>(Resource.Id.friendsList); 
  listView.Adapter =
     adapter = new Adapter(this); 
} 

protected async override void OnResume() 
{ 
  base.OnResume(); 
  try 
  { 
    await viewModel.GetFriends(); 
    adapter.NotifyDataSetInvalidated(); 
  } 
  catch (Exception exc) 
  { 
    DisplayError(exc); 
  } 
} 

```

最后但同样重要的是，我们可以更新`ConversationsActivity`类中的`OnOptionsItemSelected`，如下所示：

```kt
public override bool OnOptionsItemSelected(IMenuItem item) 
{ 
  if (item.ItemId == Resource.Id.addFriendMenu) 
  { 
    StartActivity(typeof(FriendsActivity)); 
  } 
  return base.OnOptionsItemSelected(item); 
} 

```

因此，如果我们编译并运行应用程序，我们可以导航到一个完全实现的好友列表屏幕，如下面的截图所示：

![实现好友列表](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00234.jpeg)

# 撰写消息

下一个屏幕有点复杂；我们将需要创建一个`ListView`，根据行的类型使用多个布局文件。我们还需要执行一些布局技巧，在`ListView`下方放置一个视图，并设置`ListView`自动滚动。

对于下一个屏幕，我们首先在`Resources`目录的`layout`文件夹中创建一个名为`Messages.axml`的新布局，然后执行以下步骤：

1.  在布局中拖动一个新的**ListView**。将其**Id**设置为`@+id/messageList`。

1.  勾选**从底部堆叠**的复选框，并将**文本模式**设置为`alwaysScroll`。这将设置它从底部向上显示项目。

1.  在**LinearLayout**部分的**布局**选项卡中，将**ListView**的**权重**值设置为`1`。

1.  在布局上拖动一个新的**RelativeLayout**。让其**Id**保持默认值，或者移除它。

1.  在**RelativeLayout**内拖动一个新的**按钮**。将其**Id**设置为`@+id/sendButton`。

1.  在**布局**选项卡中勾选**与父容器右对齐**的复选框。

1.  在**RelativeLayout**内，从**文本字段**部分拖动一个新的**纯文本**到按钮左侧。将其**Id**设置为`@+id/messageText`。

1.  在**布局**选项卡中，将**To Left Of**设置为`@+id/sendButton`，并将其**宽度**设置为`match_parent`。

1.  勾选**居中于父容器**以修复垂直居中问题。

完成后，XML 文件如下所示：

```kt
<?xml version="1.0" encoding="utf-8"?> 
<LinearLayout  

    android:orientation="vertical" 
    android:layout_width="match_parent" 
    android:layout_height="match_parent"> 
    <ListView 
        android:minWidth="25px" 
        android:minHeight="25px" 
        android:layout_width="match_parent" 
        android:layout_height="match_parent" 
        android:id="@+id/messageList" 
        android:stackFromBottom="true" 
        android:transcriptMode="alwaysScroll" 
        android:layout_weight="1" /> 
    <RelativeLayout 
        android:minWidth="25px" 
        android:minHeight="25px" 
        android:layout_width="match_parent" 
        android:layout_height="wrap_content"> 
        <EditText 
            android:layout_width="match_parent" 
            android:layout_height="wrap_content" 
            android:id="@+id/messageText" 
            android:layout_toLeftOf="@+id/sendButton" 
            android:layout_centerInParent="true" /> 
        <Button 
            android:text="Send" 
            android:layout_width="wrap_content" 
            android:layout_height="wrap_content" 
            android:id="@+id/sendButton" 
            android:layout_alignParentRight="true" /> 
    </RelativeLayout> 
</LinearLayout> 

```

接下来，执行以下步骤来制作另外两个 Android 布局：

1.  在`Resources`目录的`layout`文件夹中创建一个名为`MyMessageListItem.axml`的新布局。

1.  打开布局并切换到**源代码**选项卡。将根 XML 元素更改为`RelativeLayout`。

1.  切换回**内容**选项卡，并将两个**TextView**控件拖动到布局上。

1.  在**Id**字段中，分别输入`@+id/myMessageText`和`@+id/myMessageDate`。

1.  对于这两个视图，将**边距**设置为`3dp`，将**宽度和高度**设置为`wrap_content`。

1.  对于第一个 TextView，在**样式**选项卡下将其**颜色**设置为`@android:color/holo_blue_bright`。

1.  对于第二个 TextView，在**布局**选项卡下勾选**对齐父级右侧**复选框。

1.  创建一个名为`TheirMessageListItem.axml`的新布局，并重复该过程。为新的布局中的第一个 TextView 选择不同的颜色。

最后，我们需要为屏幕创建一个新的活动。在`Activities`目录中创建一个名为`MessagesActivity.cs`的新 Android 活动。从以下标准代码开始设置活动：

```kt
[Activity(Label = "Messages")] 
public class MessagesActivity : BaseActivity<MessageViewModel> 
{ 
  protected override void OnCreate(Bundle savedInstanceState) 
  { 
    base.OnCreate(savedInstanceState); 
  } 
} 

```

接下来，让我们实现一个比我们之前实现的更复杂的适配器，如下所示：

```kt
class Adapter : BaseAdapter<Message> 
{ 
  readonly MessageViewModel messageViewModel =
     ServiceContainer.Resolve<MessageViewModel>(); 
  readonly ISettings settings =
     ServiceContainer.Resolve<ISettings>(); 
  readonly LayoutInflater inflater; 
  const int MyMessageType = 0, TheirMessageType = 1; 

  public Adapter (Context context) 
  { 
    inflater = (LayoutInflater)context.GetSystemService (
       Context.LayoutInflaterService); 
  } 

  public override long GetItemId(int position) 
  { 
    return position; 
  } 

  public override int Count 
  { 
    get { return messageViewModel.Messages == null ? 0
      : messageViewModel.Messages.Length; } 
  } 

  public override Message this[int position] 
  { 
    get { return messageViewModel.Messages[position]; } 
  } 

  public override int ViewTypeCount 
  { 
    get { return 2; } 
  } 

  public override int GetItemViewType(int position) 
  { 
    var message = this [position]; 
    return message.UserName == settings.User.Name ?
       MyMessageType : TheirMessageType; 
  } 
} 

```

这包括除我们的`GetView`实现之外的所有内容，我们稍后会讨论这一点。这里的第一个变化是一些`MyMessageType`和`TheirMessageType`的常量。然后我们实现了`ViewTypeCount`和`GetItemViewType`。这是 Android 的机制，用于在列表视图中为列表项使用两种不同的布局。我们为用户的消息使用一种类型的布局，而为对话中的另一个用户使用不同的布局。

接下来，我们按照以下方式实现`GetView`：

```kt
public override View GetView(
   int position, View convertView, ViewGroup parent) 
{ 
  var message = this [position]; 
  int type = GetItemViewType(position); 
  if (convertView == null) 
  { 
    if (type == MyMessageType) 
    { 
      convertView = inflater.Inflate(
         Resource.Layout.MyMessageListItem, null); 
    } 
    else 
    { 
      convertView = inflater.Inflate(
         Resource.Layout.TheirMessageListItem, null); 
    } 
  } 
  TextView messageText; 
  if (type == MyMessageType) 
  { 
    messageText = convertView.FindViewById<TextView>(
       Resource.Id.myMessageText); 
  } 
  else 
  { 
    messageText = convertView.FindViewById<TextView>(
       Resource.Id.theirMessageText); 
  } 
  messageText.Text = message.Text; 
  return convertView; 
} 

```

### 提示

需要注意的是，在 Android 中使用唯一 ID 作为每个视图的最佳实践。即使在这种情况下代码看起来有点丑陋，但最好还是这样做，因为当存在具有相同 ID 的视图的多个布局时，`FindViewById`不能按预期工作。

让我们通过以下步骤分解我们的实现过程：

1.  我们首先获取对应于行位置的`message`对象。

1.  接下来，我们获取决定是当前用户的消息还是对话中另一个用户的视图类型。

1.  如果`convertView`为`null`，我们会根据类型充气适当的布局。

1.  接下来，我们从`convertView`中取出两个文本视图，`messageText`和`dateText`。我们必须使用类型值以确保使用正确的资源 ID。

1.  我们使用`message`对象在两个文本视图中设置适当的文本。

1.  我们返回`convertView`。

现在，让我们通过设置适配器的其余部分来完成`MessagesActivity`。首先，让我们实现一些成员变量和`OnCreate`方法，如下所示：

```kt
ListView listView; 
EditText messageText; 
Button sendButton; 
Adapter adapter; 

protected override void OnCreate(Bundle savedInstanceState) 
{ 
  base.OnCreate(savedInstanceState); 

  Title = viewModel.Conversation.UserName; 
  SetContentView(Resource.Layout.Messages); 
  listView = FindViewById<ListView>(Resource.Id.messageList); 
  messageText = FindViewById<EditText>(Resource.Id.messageText); 
  sendButton = FindViewById<Button>(Resource.Id.sendButton); 

  listView.Adapter =
     adapter = new Adapter(this); 

  sendButton.Click += async (sender, e) => 
  { 
    viewModel.Text = messageText.Text; 
    try 
    { 
      await viewModel.SendMessage(); 
      messageText.Text = string.Empty; 
      adapter.NotifyDataSetInvalidated(); 
    } 
    catch (Exception exc) 
    { 
      DisplayError(exc); 
    } 
  }; 
} 

```

到目前为止，与本章中的先前活动相比，这个活动相当标准。我们还必须在`OnCreate`中连接`sendButton`的点击事件，以便发送消息并刷新列表。我们还使用了一个技巧，通过将列表视图的选择设置为最后一个项目来滚动到列表末尾。

接下来，我们需要实现`OnResume`来加载消息，使适配器无效，然后滚动列表视图到底部，如下所示：

```kt
protected async override void OnResume() 
{ 
  base.OnResume(); 
  try 
  { 
    await viewModel.GetMessages(); 
    adapter.NotifyDataSetInvalidated(); 
    listView.SetSelection(adapter.Count); 
  } 
  catch (Exception exc) 
  { 
    DisplayError(exc); 
  } 
} 

```

最后但同样重要的是，我们需要修改`ConversationsActivity.cs`文件，使得在点击列表视图中的行时能够向前导航：

```kt
protected override void OnCreate(Bundle savedInstanceState) 
{ 
  base.OnCreate(savedInstanceState); 

  //Leave code here unmodified 

  listView.ItemClick += (sender, e) => 
  { 
    viewModel.Conversation = viewModel.Conversations[e.Position]; 
    StartActivity(typeof(MessagesActivity)); 
  }; 
} 

```

因此，最后，如果你编译并运行该应用，你将能够导航到消息界面并向列表中添加新消息，如下面的截图所示：

![编写消息](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00235.jpeg)

# 总结

在本章中，我们首先回顾了 Android Manifest 文件中的基本设置。接下来，我们实现了一个自定义的`Application`类来设置我们的`ServiceContainer`。然后，我们介绍了不同类型的 Android 布局，并使用原生的 Android 视图实现了一个登录界面。之后，我们通过使用 Android 布局并覆盖一些内置方法，在 Android 操作栏中设置了一个菜单。我们实现了好友列表界面，并学习了`ListView`和适配器的基础知识。最后，我们实现了消息界面，并使用了列表视图适配器和布局中更高级的功能。

完成本章后，你将拥有一个部分功能性的 XamSnap 的 Android 版本。你将对 Android SDK 和工具有了更深入的理解。你应该有信心使用 Xamarin 开发自己的 Android 应用程序。尝试自己实现本章未涵盖的剩余界面。如果你遇到困难，随时可以查看本书附带的完整示例应用程序。在下一章中，我们将介绍如何部署到移动设备上，以及为什么在真实设备上测试你的应用程序非常重要。


# 第七章：在设备上部署和测试

部署到设备既重要又有些麻烦，尤其是第一次尝试时。某些问题只会在移动设备上发生，无法在 iOS 仿真器或 Android 仿真器中复现。您还可以测试只有在真实设备上才能实现的功能，如 GPS、摄像头、内存限制或蜂窝网络连接。在为 Xamarin 开发时，也存在一些常见的陷阱，只有在物理设备上测试时才会显现。

在本章中，我们将涵盖以下内容：

+   iOS 配置

+   安卓设备调试设置

+   链接器

+   提前编译（AOT）

+   使用 Xamarin 常见的内存陷阱

在开始本章之前，需要注意的是，要部署到 iOS 设备，需要一个有效的 iTunes 账户或 iOS 开发者计划会员资格。可以随时回到第一章，*Xamarin 设置*，了解该过程。

# iOS 配置

苹果对将应用程序部署到 iOS 设备有一个严格的过程。尽管对于开发者来说这个过程可能相当复杂和痛苦，但苹果可以通过阻止普通用户侧载可能恶意应用程序来提供一定级别的安全性。

在我们将应用程序部署到 iOS 设备之前，我们将在**iOS 开发中心**设置一些事情。我们将从为您的账户创建一个应用 ID 或捆绑 ID 开始。这是任何 iOS 应用程序的主要标识符。

开始时请访问 [`developer.apple.com/account`](http://developer.apple.com/account) 并执行以下步骤：

1.  使用您的开发者账户登录。

1.  在右侧导航栏中点击**证书、ID 和配置文件**。

1.  点击**应用 IDs**。

1.  点击加号按钮添加新的 iOS 应用 ID。

1.  在**名称**字段中，输入一些有意义的文字，例如`YourCompanyNameWildcard`。

1.  选择**通配符应用 ID**单选按钮。

1.  在**捆绑 ID**字段中，为您的公司选择一个反向域名格式的名称，例如`com.yourcompanyname.*`。

1.  点击**继续**。

1.  检查最终设置并点击**提交**。

保持此网页打开，因为我们在整个章节中都会使用它。

我们刚刚为您的账户注册了一个通配符捆绑 ID；将此作为您希望用此账户标识的所有未来应用程序的前缀。稍后，当您准备将应用程序部署到苹果应用商店时，您将创建一个**显式应用 ID**，如`com.yourcompanyname.yourapp`。这允许您将特定应用程序部署到商店，而通配符 ID 最好用于将应用程序部署到测试设备。

接下来我们需要找到你计划调试应用程序的每个设备的唯一标识符。苹果要求每个设备都在你的账户下注册，并且每个开发者每种设备类型最多可注册 110 个设备（110 个 iPhone、iPad、iPod、Apple TV 或 Apple Watch）。绕过这一要求的唯一方式是注册 iOS 开发者企业计划，该计划除了标准的 99 美元开发者费用外，还需支付 299 美元的年费。

开始启动 Xcode 并执行以下步骤：

1.  在顶部菜单中点击**窗口** | **设备**。

1.  使用 USB 线连接你的目标设备。

1.  在左侧导航栏中，你应该看到你的设备名称；选择它。

1.  注意你的设备的**标识符**值。将其复制到剪贴板。

以下截图显示了在 Xcode 中选择你的设备后的屏幕样子：

![iOS 配置](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00236.jpeg)

返回到[`developer.apple.com/account`](http://developer.apple.com/account)（希望本章早些时候它还保持打开状态），并执行以下步骤：

1.  点击左侧导航栏中的**设备 | 全部**。

1.  点击页面右上角的加号按钮。

1.  为你的设备输入一个有意义的名称，并将剪贴板中的**标识符**粘贴到**UDID**字段中。

1.  点击**继续**。

1.  检查你输入的信息并点击**注册**。

在以后，当你的账户完全设置好后，你只需在 Xcode 中点击**用于开发**按钮，就可以跳过这第二个步骤。

以下截图显示了你的设备列表在完成时的样子：

![iOS 配置](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00237.jpeg)

接下来，我们需要生成一个证书，以代表你的账户作为开发者。在 Xcode 5 之前，你必须使用 Mac 上的**钥匙串**应用程序创建一个证书签名请求。Xcode 的新版本将这一流程集成到 Xcode 中，使得操作更加简便。

打开 Xcode 并执行以下步骤：

1.  在顶部菜单中导航至**Xcode** | **偏好设置**。

1.  选择**账户**标签页。

1.  点击左下角的加号按钮，然后点击**添加 Apple ID**。

1.  输入你的开发者账户的电子邮件和密码。

1.  创建账户后，点击右下角的**查看详情**。

1.  点击左下角的**下载全部**按钮。

1.  如果这是一个新账户，Xcode 会显示一个警告，提示还没有证书存在。勾选每个框并点击**请求**以生成证书。

Xcode 现在将自动为你的账户创建一个开发者证书，并将其安装到你的 Mac 钥匙串中。

以下截图显示了设置你的账户后屏幕的样子：

![iOS 配置](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00238.jpeg)

接下来，我们需要创建一个**配置文件**。这是允许应用程序安装在 iOS 设备上的最终文件。配置文件包含一个 App ID、一个设备 ID 列表，最后还有开发者的证书。你还需要在 Mac 的钥匙串中拥有开发者证书的私钥才能使用配置文件。

以下是几种配置文件类型：

+   **开发**：这用于调试或发布版本；当你的应用程序处于开发阶段时，你会积极使用这种类型的配置文件。

+   **Ad Hoc**：这主要用于发布版本；这种证书非常适合进行 beta 测试或分发给一组小用户。使用这种方法，你可以通过企业开发者账户向无限数量的用户分发。

+   **App Store**：这用于提交到 App Store 的发布版本。你不能使用此证书将应用程序部署到你的设备；它只能用于商店提交。

让我们回到[`developer.apple.com/apple`](http://developer.apple.com/apple)，通过执行以下步骤创建一个新的配置文件：

1.  点击左侧导航栏中的**配置文件 | 全部**。

1.  点击页面右上角的加号按钮。

1.  选择**iOS 应用开发**并点击**继续**。

1.  选择本章前面创建的通配符 App ID 并点击**继续**。

1.  选择我们在本章前面创建的证书并点击**继续**。

1.  选择你想要部署到的设备并点击**继续**。

1.  输入一个合适的**配置文件名称**，如`YourCompanyDev`。

1.  点击**继续**，你的配置文件将被创建。

下面的截图展示了你创建后最终会得到的新配置文件。不必担心下载文件；我们将使用 Xcode 导入最终的配置文件。

![iOS 配置](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00239.jpeg)

要导入配置文件，请回到 Xcode 并执行以下步骤：

1.  导航到对话框顶部菜单中的**Xcode** | **偏好设置**。

1.  选择**账户**标签。

1.  选择你的账户并点击**查看详情**。

1.  点击左下角的**下载全部**按钮。

1.  几秒钟后，你的配置文件将出现。

Xcode 应该会自动包含你在 Apple 开发者网站上创建的所有配置文件。Xcode 还会自行创建一些配置文件。

在最新版本的 Xamarin Studio 中，你可以查看这些配置文件，但无法同步它们。导航到 **Xamarin Studio** | **偏好设置** | **开发者账户**，从 Xamarin Studio 中查看配置文件。你也可以在 Xamarin 的文档网站上查看关于 iOS 配置的文档，网址为[`developer.xamarin.com/guides/ios/getting_started/device_provisioning/`](http://developer.xamarin.com/guides/ios/getting_started/device_provisioning/)。

# 安卓设备设置

与在 iOS 设备上部署应用程序的麻烦相比，Android 就轻松多了。要将应用程序部署到设备上，你只需在设备上设置几个选项。这是由于与 iOS 相比，Android 的开放性。大多数用户的 Android 设备调试功能是关闭的，但任何希望尝试编写 Android 应用程序的用户都可以轻松地开启它。

首先打开**设置**应用。你可能需要通过查看设备上的所有应用程序来找到它，如下所示：

1.  向下滚动并点击标有**开发者选项**的部分。

1.  在顶部的操作栏中，你可能需要将一个开关切换到**开启**位置。这个操作在每个设备上都有所不同。

1.  向下滚动并勾选**USB 调试**。

1.  将会出现一个警告确认提示；点击**确定**。

### 提示

请注意，一些较新的 Android 设备使得普通用户开启 USB 调试变得更加困难。你需要点击**开发者选项**七次来开启这个选项。

下面的截图展示了在过程中你的设备的样子：

![Android 设备设置](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00240.jpeg)

启用这个选项后，你只需通过 USB 连接你的设备，并在 Xamarin Studio 中调试一个 Android 应用程序。你会在**选择设备**对话框中看到你的设备列表。请注意，如果你使用的是 Windows 系统，或者你的设备是非标准的，你可能需要访问设备制造商的网站来安装驱动程序。大多数三星和 Nexus 设备会自动安装它们的驱动程序。在 Android 4.3 及更高版本中，在开始 USB 调试会话之前，设备上还会出现一个确认对话框。

下面的截图展示了在**选择设备**对话框中三星 Galaxy 设备的样子。Xamarin Studio 将显示型号号码，这并不总是一个你可能认识的名字。你可以在你的设备的设置中查看这个型号号码。

![Android 设备设置](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00241.jpeg)

# 了解链接器

为了让 Xamarin 应用程序在移动设备上保持小型和轻量级，Xamarin 为编译器创建了一个名为**链接器**的功能。其主要目的是从核心 Mono 程序集（如`System.dll`）和特定平台的程序集（`Mono.Android.dll`和`Xamarin.iOS.dll`）中移除未使用的代码；然而，如果设置得当，它也可以为你自己的程序集提供同样的好处。如果不运行链接器，整个 Mono 框架可能大约有 30 兆字节。这就是为什么在设备构建中默认启用链接，这样你可以保持应用程序的小巧。

链接器使用静态分析来处理程序集中的各种代码路径。如果它确定一个方法或类从未被使用，它会从该程序集中移除未使用的代码。这个过程可能会很耗时，因此默认情况下，在模拟器中运行的构建会跳过这一步。

Xamarin 应用程序有以下三个主要的链接器设置：

+   **不链接**：在这种情况下，链接器编译步骤将被跳过。这对于在模拟器中运行的构建或如果你需要诊断链接器的潜在问题最为合适。

+   **仅链接 SDK 程序集**：在这种情况下，链接器只会在核心 Mono 程序集上运行，如`System.dll`、`System.Core.dll`和`System.Xml.dll`。

+   **链接所有程序集**：在这种情况下，链接器将对应用程序中的所有程序集运行，包括你正在使用的任何类库或第三方程序集。

这些设置可以在任何 Xamarin.iOS 或 Xamarin.Android 应用程序的项目选项中找到。这些设置通常不会出现在类库中，因为它们通常与将要部署的 iOS 或 Android 应用程序相关联。

链接器还可能在运行时引起潜在问题，因为有时它的分析会错误地确定一段代码未被使用。如果你在`System.Reflection`命名空间中使用特性而不是直接访问方法或属性，这可能会发生。这就是为什么在物理设备上测试你的应用程序很重要，因为设备构建启用了链接。

为了说明这个问题，让我们看一下以下代码示例：

```kt
//Just a simple class for holding info 
public class Person 
{ 
  public int Id { get; set; } 
  public string Name { get; set; } 
} 

//Then somewhere later in your code 
var person = new Person { Id = 1, Name = "Chuck Norris" }; 
var propInfo = person.GetType().GetProperty("Name"); 
string value = propInfo.GetValue(person) as string; 
Console.WriteLine("Name: " + value); 

```

运行前面的代码，在**不链接**或**仅链接 SDK 程序集**的选项下将正常工作。然而，如果你在**链接所有程序集**的选项下尝试运行此代码，你会遇到类似以下的异常：

```kt
Unhandled Exception: 
System.ArgumentException: Get Method not found for 'Name'
   at System.Reflection.MonoProperty.GetValue (System.Object obj,
   BindingFlags invokeAttr, System.Reflection.Binder binder,
   System.Object[] index, System.Globalization.CultureInfo culture)
   at System.Reflection.PropertyInfo.GetValue (System.Object obj) 

```

由于从未直接从代码中使用`Name`属性的 getter，链接器将其从程序集中剥离。这导致反射代码在运行时失败。

尽管你的代码可能会出现潜在问题，但**链接所有程序集**的选项仍然非常有用。有些优化只能在此模式下执行，Xamarin 可以将你的应用程序缩减到尽可能小的尺寸。如果你的应用程序需要性能或极小的下载尺寸，请尝试这个选项。然而，应进行彻底测试，以确保链接程序集不会引起任何问题。

为了解决代码中的问题，Xamarin 提供了一套完整的解决方案，以防止代码中的特定部分被剥离。

以下是一些选项：

+   使用`[Preserve]`标记类成员；这将强制链接器包含带属性的方法、字段或属性。

+   使用`[Preserve(AllMembers=true)]`标记整个类；这将保留类中的所有代码。

+   使用`[assembly: Preserve]`标记整个程序集；这是一个程序集级别的属性，将保留其中的所有代码。

+   通过修改项目选项中的**附加 mtouch 参数**来跳过整个程序集；使用`--linkskip=System`来跳过整个程序集。这可以用于那些你没有源代码的程序集。

+   通过 XML 文件自定义链接，当你需要跳过没有源代码的具体类或方法的链接时，这是最佳选择。在**附加 mtouch 参数**中使用 `--xml=YourFile.xml`。

以下是一个演示自定义链接的示例 XML 文件：

```kt
<linker> 
  <assembly fullname="mscorlib"> 
    <type fullname="System.Environment"> 
      <field name="mono_corlib_version" /> 
      <method name="get_StackTrace" />  
    </type> 
  </assembly> 
  <assembly fullname="My.Assembly.Name"> 
    <type fullname="MyTypeA" preserve="fields" /> 
      <method name=".ctor" /> 
    </type> 
    <type fullname="MyTypeB" />                          
      <method signature="System.Void MyFunc(System.Int32 x)" /> 
      <field signature="System.String _myField" /> 
    </type> 
  </assembly> 
</linker> 

```

自定义链接是选项中最复杂的，通常是最后的选择。幸运的是，大多数 Xamarin 应用程序不需要解决许多链接问题。

# 了解 AOT 编译

Windows 上的 Mono 和 .NET 运行时基于**即时编译**（**JIT**）器。C# 和其他 .NET 语言被编译成**微软中间语言**（**MSIL**）。在运行时，MSIL 会即时编译成本地代码（正好在需要时），以在任何类型的架构上运行你的应用程序。Xamarin.Android 遵循这一确切模式。然而，由于苹果对动态生成代码的限制，iOS 上不允许使用**即时编译（JIT）**器。

为了绕过这一限制，Xamarin 开发了一个名为**提前编译**（**AOT**）的新选项，你的 C# 代码被编译成特定于平台的本地机器代码。除了使 .NET 在 iOS 上成为可能之外，AOT 还具有其他好处，例如启动时间更短，性能可能更好。

AOT 也有一些与 C# 泛型相关的限制。为了提前编译程序集，编译器需要对代码进行一些静态分析，以确定类型信息。泛型在这种情况下会带来一些问题。

AOT 不支持一些在 C# 中完全有效的情况。首先是泛型接口，如下所示：

```kt
interface MyInterface<T>  
{ 
  T GetMyValue(); 
} 

```

编译器无法提前确定可能实现此接口的类，特别是涉及多个程序集时。第二个限制与第一个相关：你不能覆盖包含泛型参数或返回值的虚拟方法。

以下是一个简单的例子：

```kt
class MyClass<T> 
{ 
  public virtual T GetMyValue()  
  { 
    //Some code here 
  } 
} 

class MySubClass : MyClass<int> 
{ 
  public override int GetMyValue() 
  { 
    //Some code here 
  } 
} 

```

再次强调，编译器的静态分析无法在编译时确定哪些类可能会覆盖这个方法。

另一个限制是，你不能在泛型类中使用 `DllImport`，如下面的代码所示：

```kt
class MyGeneric<T> 
{ 
  [DllImport("MyImport")] 
  public static void MyImport(); 
} 

```

如果你不太熟悉这个语言特性，`DllImport` 是一种从 C# 调用本地 C/C++ 方法的方式。在泛型类中使用它们是不支持的。

这些限制是为什么在设备上进行测试很重要的另一个原因，因为上述代码在其他可以运行 C# 代码的平台上是没问题的，但在 Xamarin.iOS 上不行。

# 避免常见的内存陷阱

移动设备上的内存绝对不是无限的资源。因此，你的应用程序中的内存使用可能比桌面应用程序更重要。有时，你可能会发现需要使用内存分析器或改进代码以更有效地使用内存。

以下是最常见的内存陷阱：

+   **垃圾回收器**（**GC**）无法快速回收大对象以跟上应用程序的步伐

+   你的代码无意中导致了内存泄漏

+   一个 C#对象被垃圾回收，但后来被本地代码尝试使用

让我们看看第一个问题，即 GC 无法跟上。假设我们有一个 Xamarin.iOS 应用程序，其中有一个用于在 Twitter 上分享图像的按钮，如下所示：

```kt
twitterShare.TouchUpInside += (sender, e) => 
{ 
  var image = UImage.FromFile("YourLargeImage.png"); 
  //Share to Twitter 
}; 

```

现在假设图像是用户相册中的 10MB 图像。如果用户点击按钮并迅速取消 Twitter 帖子，应用程序可能会出现内存不足的情况。iOS 通常会强制关闭使用过多内存的应用程序，你不会希望用户在使用你的应用时遇到这种情况。

最佳解决方案是在使用完图像后调用其`Dispose`方法，如下所示：

```kt
var image = UImage.FromFile("YourLargeImage.png"); 
//Share to Twitter 
image.Dispose(); 

```

更好的方法将是利用 C#的`using`语句，如下所示：

```kt
using(var image = UImage.FromFile("YourLargeImage.png")) 
{ 
  //Share to Twitter 
} 

```

C#的`using`语句会自动在`try-finally`块中调用`Dispose`，因此即使抛出异常，对象也将被释放。我建议尽可能对任何`IDisposable`类使用`using`语句。对于小对象如`NSString`来说，这并不总是必要的，但对于更大、更重的`UIKit`对象来说，这总是一个好主意。

### 提示

在 Android 上，与`Bitmap`类也可能发生类似情况。虽然略有不同，但最好是在此类上调用`Dispose`方法，这与你在 iOS 上对`UIImage`的处理是一样的。

内存泄漏是下一个潜在问题。C#作为一种管理的、垃圾回收的语言，防止了很多内存泄漏，但并非全部。C#中最常见的泄漏是由事件引起的。

假设我们有一个带有事件的静态类，如下所示：

```kt
static class MyStatic 
{ 
  public static event EventHandler MyEvent; 
} 

```

现在，假设我们需要从 iOS 控制器中订阅事件，如下所示：

```kt
public override void ViewDidLoad() 
{ 
  base.ViewDidLoad(); 

  MyStatic.MyEvent += (sender, e) => 
  { 
    //Do something 
  }; 
} 

```

这里的问题是，静态类将持有对控制器的引用，直到事件被取消订阅。这是许多开发者可能会忽略的情况。为了在 iOS 上解决这个问题，我会在`ViewWillAppear`中订阅事件，并在`ViewWillDisappear`中取消订阅。在 Android 上，使用`OnStart`和`OnStop`，或者`OnPause`和`OnResume`。

你会正确实现此事件，如下所示：

```kt
public override void ViewWillAppear() 
{ 
  base.ViewWillAppear(); 
  MyStatic.MyEvent += OnMyEvent; 
} 

public override void ViewWillDisappear() 
{ 
  base.ViewWillDisappear (); 
  MyStatic.MyEvent -= OnMyEvent; 
} 

```

然而，事件并不是内存泄漏的必然原因。例如，在`ViewDidLoad`方法中订阅按钮的`TouchUpInside`事件是没问题的。由于按钮与控制器在内存中的生命周期相同，一切都可以被垃圾回收，而不会造成问题。

对于最后一个问题，垃圾回收器有时可能会移除一个 C#对象；后来，一个 Objective-C 对象尝试访问它。

下面是一个添加按钮到`UITableViewCell`的例子：

```kt
public override UITableViewCell GetCell(
   UITableView tableView, NSIndexPath indexPath) 
{ 
  var cell = tableView.DequeueReusableCell("MyCell"); 
  //Remaining cell setup here 

  var button = UIButton.FromType(UIButtonType.InfoDark); 
  button.TouchUpInside += (sender, e) => 
  { 
    //Do something 
  }; 
  cell.AccessoryView = button; 
  return cell; 
} 

```

我们将内置的信息按钮作为单元格的附件视图添加。这里的问题是，按钮将被垃圾回收，但其 Objective-C 对应物仍将在屏幕上显示时被使用。如果过了一段时间后点击按钮，你可能会遇到类似下面的崩溃情况：

```kt
mono-rt: Stacktrace:
mono-rt:   at <unknown>
mono-rt:   at (wrapper managed-to-native) MonoTouch.UIKit.UIApplication.UIApplicationMain
    (int,string[],intptr,intptr) 
mono-rt:   at MonoTouch.UIKit.UIApplication.Main (string[],string,string) 
... Continued ...
=================================================================
Got a SIGSEGV while executing native code. This usually indicates
a fatal error in the mono runtime or one of the native libraries 
used by your application.
================================================================

```

这不是最描述性的错误消息，但一般来说，你知道原生 Objective-C 代码中出了问题。要解决这个问题，请创建一个`UITableViewCell`的自定义子类，并为按钮创建一个专用的成员变量，如下所示：

```kt
public class MyCell : UITableViewCell 
{ 
  UIButton button;

  public MyCell() 
  { 
    button = UIButton.FromType(UIButtonType.InfoDark); 
    button.TouchUpInside += (sender, e) =>  
    { 
      //Do something 
    }; 
    AccessoryView = button; 
  } 
} 

```

现在，你的`GetCell`实现看起来可能如下所示：

```kt
public override UITableViewCell GetCell(
   UITableView tableView, NSIndexPath indexPath) 
{ 
  var cell = tableView.DequeueReusableCell("MyCell") as MyCell; 
  //Remaining cell setup here 
  return cell; 
} 

```

由于按钮不是一个局部变量，它不会比需要的时候更早地被垃圾回收。这样可以避免崩溃，并且在某些方面，这段代码看起来更整洁。在 Android 上，C#与 Java 之间的交互也可能出现类似情况；然而，由于两者都是垃圾回收语言，这种情况不太可能发生。

# 概括

在本章中，我们开始学习设置 iOS 供应配置文件的过程，以便部署到 iOS 设备。接下来，我们查看了将应用程序部署到 Android 设备所需的设备设置。我们发现了 Xamarin 链接器，以及它如何使应用程序变得更小、性能更好。我们讨论了解决由你的代码和链接器引起问题的各种设置，并解释了 iOS 上的 AOT 编译及其出现的限制。最后，我们涵盖了 Xamarin 应用程序可能遇到的常见内存陷阱。

在移动设备上测试 Xamarin 应用程序有多种原因。由于 Xamarin 必须绕过的平台限制，一些错误只能在设备上显示。你的电脑强大得多，因此在使用模拟器与物理设备上的性能表现会有所不同。在下一章中，我们将使用 Windows Azure 创建一个真实的网络服务来驱动我们的 XamChat 应用程序。我们将使用一个名为 Azure Mobile Services 的功能，并在 iOS 和 Android 上实现推送通知。
