# Java9 编程蓝图（四）

> 原文：[`zh.annas-archive.org/md5/EFCA429E6A8AD54477E9BBC3A0DA41BA`](https://zh.annas-archive.org/md5/EFCA429E6A8AD54477E9BBC3A0DA41BA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：使用 PhotoBeans 进行照片管理

到目前为止，我们已经编写了库。我们编写了命令行实用程序。我们还使用 JavaFX 编写了 GUI。在本章中，我们将尝试完全不同的东西。我们将构建一个照片管理系统，当然，它需要是一个图形应用程序，但我们将采取不同的方法。我们将使用现有的应用程序框架。该框架是 NetBeans **Rich Client Platform**（**RCP**），这是一个成熟、稳定和强大的框架，不仅支持我们使用的 NetBeans IDE，还支持从石油和天然气到航空航天等各行各业的无数应用程序。

在本章中，我们将涵盖以下主题：

+   如何启动 NetBeans RCP 项目

+   如何将 JavaFX 与 NetBeans RCP 集成

+   RCP 应用程序的基本原理，如节点、操作、查找、服务和顶级组件

那么，话不多说，让我们开始吧。

# 入门

也许您的问题清单中排在前面或附近的问题是，**我为什么要使用 NetBeans RCP？**在我们深入了解应用程序的细节之前，让我们回答这个非常公平的问题，并尝试理解为什么我们要以这种方式构建它。

当您开始研究 NetBeans 平台时，您会注意到的第一件事是模块化的强烈概念。由于 Java 9 的 Java 模块系统是 Java 的一个突出特性，这可能看起来像一个细节，但 NetBeans 在应用程序级别向我们公开了这个概念，使插件变得非常简单，并允许我们以逐步更新应用程序。

RCP 还提供了一个强大、经过充分测试的框架，用于处理窗口、菜单、操作、节点、服务等。如果我们要像在前几章中使用**纯**JavaFX 一样从头开始构建这个应用程序，我们将不得不手动定义屏幕上的区域，然后手动处理窗口放置。使用 RCP，我们已经定义了丰富的窗口规范，可以轻松使用。它提供了诸如最大化/最小化窗口、滑动、分离和停靠窗口等功能。

RCP 还提供了**节点**的强大概念，将特定领域的数据封装在用户界面概念中，通常在应用程序的左侧树视图中看到，以及可以与这些节点（或菜单项）关联的操作，以对它们代表的数据进行操作。再次强调，所有这些都可以在 JavaFX（或 Swing）中完成，但您需要自己编写所有这些功能。实际上，有许多开源框架提供了这样的功能，例如 Canoo 的 Dolphin Platform（[`www.dolphin-platform.io`](http://www.dolphin-platform.io/)），但没有一个像 NetBeans RCP 那样经过多年的生产硬化和测试，因此我们将保持关注在这里。

# 启动项目

您如何创建 NetBeans RCP 项目将对项目的其余部分的处理方式产生非常基本的影响。默认情况下，NetBeans 使用 Ant 作为所有 RCP 应用程序的构建系统。几乎所有来自 NetBeans 项目的在线文档和 NetBeans 传道者的博客条目也经常反映了这种偏好。我们一直在使用 Maven 进行其他项目，这里也不会改变。幸运的是，NetBeans 确实允许我们使用 Maven 创建 RCP 项目，这就是我们要做的。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/ba9bc9dd-b737-4aa3-a707-a312c86746f0.png)

在新项目窗口中，我们选择 Maven，然后选择 NetBeans Application。在下一个屏幕上，我们像往常一样配置项目，指定项目名称、photobeans、项目位置、包等。

当我们点击“下一步”时，将会出现“新项目向导”的“模块选项”步骤。在这一步中，我们配置 RCP 应用程序的一些基本方面。具体来说，我们需要指定我们将使用的 NetBeans API 版本，以及是否要将 OSGi 捆绑包作为依赖项，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/431c03b2-1ada-42a4-b11a-f9dc98c1bad4.png)

在撰写本文时，最新的平台版本是 RELEASE82。到 Java 9 发布时，可以合理地期望 NetBeans 9.0，因此 RELEASE90 将可用。我们希望使用最新版本，但请注意，根据 NetBeans 项目的发布计划，它很可能 *不* 是 9.0。对于“允许将 OSGi 捆绑包作为依赖项”选项，我们可以安全地接受默认值，尽管更改它不会给我们带来任何问题，而且如果需要，我们可以很容易地稍后更改该值。

创建项目后，我们应该在项目窗口中看到三个新条目：`PhotoBeans-parent`、`PhotoBeans-app` 和 `PhotoBeans-branding`。`-parent` 项目没有真正的可交付成果。与其他章节的 `master` 项目一样，它仅用于组织相关模块、协调依赖关系等。

# 为您的应用程序进行品牌定制

`-branding` 模块是我们可以定义应用程序品牌细节的地方，正如你可能已经猜到的那样。您可以通过右键单击品牌模块并在内容菜单底部附近选择 `品牌...` 来访问这些品牌属性。这样做后，您将看到一个类似于这样的屏幕：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/02d5bdd7-9ad3-49b3-9c52-c3ce3f628ef1.png)

在上述选项卡中，您可以设置或更改应用程序的名称，并指定应用程序图标。

在“启动画面”选项卡中，您可以配置最重要的是在应用程序加载时显示在启动画面上的图像。您还可以启用或禁用进度条，并设置进度条和启动消息的颜色、字体大小和位置：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/685b88d8-5aea-485d-a7a8-9b61469cee2b.png)

目前对我们感兴趣的唯一其他选项卡是“窗口系统”选项卡。在这个选项卡中，我们可以配置一些功能，比如窗口拖放、窗口滑动、关闭等等：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/55bc7aca-986d-41de-9ac5-2c7a101ee28b.png)

很可能，默认值对我们的目的是可以接受的。但是，在您自己的 NetBeans RCP 应用程序中，此屏幕可能更加重要。

我们主要关注 `-app` 模块。这个模块将定义应用程序的所有依赖关系，并且将是其入口点。不过，与我们在之前章节中看到的 JavaFX 应用程序不同，我们不需要定义 `public static void main` 方法，因为 NetBeans 会为我们处理。实际上，`-app` 模块根本没有任何 Java 类，但是应用程序可以直接运行，尽管它并没有做太多事情。我们现在来修复这个问题。

# NetBeans 模块

NetBeans 平台的一个优点是其模块化。如果您以前曾使用过 NetBeans IDE（比如在阅读本书之前），那么在使用插件时就已经看到了这种模块化的作用：每个 NetBeans 插件由一个或多个模块组成。实际上，NetBeans 本身由许多模块组成。这就是 RCP 应用程序设计的工作方式。它促进了解耦，并使扩展和升级应用程序变得更加简单。

通常接受的模式是，将 API 类放在一个模块中，将实现放在另一个模块中。这样可以使其他实现者重用 API 类，可以通过隐藏私有类来帮助强制低耦合等等。然而，为了简化我们学习平台的过程，我们将创建一个模块，该模块将提供所有核心功能。为此，我们右键单击父项目下的“模块”节点，然后选择“创建新模块...”：如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/51979733-3823-4037-a5ff-4fdf71d46acf.png)

一旦选择，您将看到新项目窗口。在这里，您需要选择 Maven 类别和 NetBeans 模块项目类型，如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/6813f74b-a46d-4b75-a214-f617bf0e6825.png)

点击“下一步”将进入“名称和位置”步骤，这是本书中已经多次见过的步骤。在这个窗格上，我们将模块命名为`main`，将包设置为`com.steeplesoft.photobeans.main`，并接受其他字段的默认值。在下一个窗格“模块选项”中，我们将确保 NetBeans 版本与之前选择的版本相同，并点击“完成”。

# TopComponent - 选项卡和窗口的类

现在我们有一个大部分为空的模块。NetBeans 为我们创建了一些工件，但我们不需要关心这些，因为构建将为我们管理这些。不过，我们需要做的是创建我们的第一个 GUI 元素，这将是 NetBeans 称为 TopComponent 的东西。从 NetBeans Javadoc 中，可以在[`bits.netbeans.org/8.2/javadoc/`](http://bits.netbeans.org/8.2/javadoc/)找到这个定义：

可嵌入的可视组件，用于在 NetBeans 中显示。这是显示的基本单位--窗口不应该直接创建，而应该使用这个类。顶部组件可能对应于单个窗口，但也可能是窗口中的选项卡（例如）。它可以被停靠或未停靠，有选定的节点，提供操作等。

正如我们将看到的，这个类是 NetBeans RCP 应用程序的主要组件。它将保存和控制各种相关的用户界面元素。换句话说，它位于用户界面的组件层次结构的顶部。要创建 TopComponent，我们可以通过在项目资源管理器树中右键单击我们现在空的包，并选择新建 | 窗口来使用 NetBeans 向导。如果“窗口”不是一个选项，选择其他 | 模块开发 | 窗口。

现在您应该看到以下基本设置窗口：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/23214245-cb24-48c2-825b-887194834139.png)

在前面的窗口中有许多选项。我们正在创建的是一个将显示照片列表的窗口，因此一些合理的设置是选择以下内容：

+   应用程序启动时打开

+   不允许关闭

+   不允许最大化

这些选项似乎非常直接了当，但“窗口位置”是什么？使用 NetBeans RCP 而不是从头开始编写的另一个好处是，平台提供了许多预定义的概念和设施，因此我们不需要担心它们。其中一个关注点是窗口定位和放置。NetBeans 用户界面规范（可以在 NetBeans 网站上找到，网址为[`ui.netbeans.org/docs/ui/ws/ws_spec-netbeans_ide.html`](https://ui.netbeans.org/docs/ui/ws/ws_spec-netbeans_ide.html)）定义了以下区域：

+   **资源管理器：** 这用于提供对用户对象的访问的所有窗口，通常是树浏览器

+   **输出：** 这是默认用于输出窗口和 VCS 输出窗口

+   **调试器：** 这用于所有调试器窗口和其他需要水平布局的支持窗口

+   **调色板：** 这用于组件调色板窗口

+   **检查器：** 这用于组件检查器窗口

+   **属性：** 这用于属性窗口

+   **文档：** 这用于所有文档窗口

文档还提供了这个有用的插图：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/0909beeb-225d-4bf0-a7c2-a9d42b9c1232.png)

规范页面有大量的额外信息，但现在这些信息足够让您开始了。我们希望我们的照片列表在应用程序窗口的左侧，所以我们选择窗口位置为编辑器。点击“下一步”，我们配置组件的名称和图标。严格来说，我们不需要为 TopComponent 指定图标，所以我们只需输入`PhotoList`作为类名前缀，并点击“完成”：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/d05b3b56-34c1-447e-8e11-678bc22f827f.png)

当您在这里单击“完成”时，NetBeans 会为您创建一些文件，尽管只有一个文件会显示在项目资源管理器树中，即`PhotoListTopComponent.java`。还有一个名为`PhotoListTopComponent.form`的文件，您需要了解一下，尽管您永远不会直接编辑它。NetBeans 为构建用户界面提供了一个非常好的所见即所得（WYSIWYG）编辑器。用户界面定义存储在`.form`文件中，这只是一个 XML 文件。当您进行更改时，NetBeans 会为您修改这个文件，并在一个名为`initComponents()`的方法中生成相应的 Java 代码。您还会注意到，NetBeans 不允许您修改这个方法。当然，您可以使用另一个编辑器来这样做，但是如果您以这种方式进行更改，那么如果您在 GUI 编辑器中进行更改，那么您所做的任何更改都将丢失，所以最好还是让这个方法保持不变。`TopComponent`的其余部分是什么样子的呢？

```java
    @ConvertAsProperties( 
      dtd = "-//com.steeplesoft.photobeans.main//PhotoList//EN", 
      autostore = false 
    ) 
    @TopComponent.Description( 
      preferredID = "PhotoListTopComponent", 
      //iconBase="SET/PATH/TO/ICON/HERE", 
      persistenceType = TopComponent.PERSISTENCE_ALWAYS 
    ) 
    @TopComponent.Registration(mode = "editor",
     openAtStartup = true) 
    @ActionID(category = "Window", id =  
      "com.steeplesoft.photobeans.main.PhotoListTopComponent") 
    @ActionReference(path = "Menu/Window" /*, position = 333 */) 
    @TopComponent.OpenActionRegistration( 
      displayName = "#CTL_PhotoListAction", 
      preferredID = "PhotoListTopComponent" 
    ) 
    @Messages({ 
      "CTL_PhotoListAction=PhotoList", 
      "CTL_PhotoListTopComponent=PhotoList Window", 
      "HINT_PhotoListTopComponent=This is a PhotoList window" 
    }) 
    public final class PhotoListTopComponent 
     extends TopComponent { 

```

这是很多注释，但也是 NetBeans 平台为您做了多少事情的一个很好的提醒。在构建过程中，这些注释被处理以创建元数据，平台将在运行时使用这些元数据来配置和连接您的应用程序。

一些亮点如下：

```java
    @TopComponent.Registration(mode = "editor",
      openAtStartup = true) 

```

这样注册了我们的`TopComponent`，并反映了我们放置它的选择和何时打开它的选择。

我们还有一些国际化和本地化工作正在进行，如下所示：

```java
    @ActionID(category = "Window", id =  
      "com.steeplesoft.photobeans.main.PhotoListTopComponent") 
    @ActionReference(path = "Menu/Window" /*, position = 333 */) 
    @TopComponent.OpenActionRegistration( 
      displayName = "#CTL_PhotoListAction", 
      preferredID = "PhotoListTopComponent" 
    ) 
    @Messages({ 
      "CTL_PhotoListAction=PhotoList", 
      "CTL_PhotoListTopComponent=PhotoList Window", 
      "HINT_PhotoListTopComponent=This is a PhotoList window" 
    }) 

```

不要过多涉及细节并冒险混淆事情，前三个注释注册了一个开放的操作，并在我们的应用程序的“窗口”菜单中公开了一个项目。最后一个注释`@Messages`用于定义本地化键和字符串。当这个类被编译时，同一个包中会创建一个名为`Bundle`的类，该类使用指定的键来返回本地化字符串。例如，对于`CTL_PhotoListAction`，我们得到以下内容：

```java
    static String CTL_PhotoListAction() { 
      return org.openide.util.NbBundle.getMessage(Bundle.class,  
        "CTL_PhotoListAction"); 
    } 

```

上述代码查找了标准 Java 的`.properties`文件中的本地化消息的键。这些键值对与 NetBeans 向我们生成的`Bundle.properties`文件中找到的任何条目合并。

我们的`TopComponent`的以下构造函数也很有趣：

```java
    public PhotoListTopComponent() { 
      initComponents(); 
      setName(Bundle.CTL_PhotoListTopComponent()); 
      setToolTipText(Bundle.HINT_PhotoListTopComponent()); 
      putClientProperty(TopComponent.PROP_CLOSING_DISABLED,  
       Boolean.TRUE); 
      putClientProperty(TopComponent.PROP_MAXIMIZATION_DISABLED,  
       Boolean.TRUE); 
    } 

```

在上述构造函数中，我们可以看到组件的名称和工具提示是如何设置的，以及我们的与窗口相关的选项是如何设置的。

如果我们现在运行我们的应用程序，我们不会看到任何变化。因此，我们需要在应用程序中添加对`main`模块的依赖。我们可以通过右键单击应用程序模块的“Dependencies”节点来实现这一点，如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/1aa28e23-b962-4fad-8f55-67e404fea645.png)

现在您应该看到“添加依赖项”窗口。选择“打开项目”选项卡，然后选择`main`，如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/914375f3-13e0-441f-aa45-afb38ecada31.png)

一旦我们添加了依赖项，我们需要先构建`main`模块，然后构建`app`，然后我们就可以准备运行 PhotoBeans 了：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/22f3de03-4365-44a0-b88d-271ea1359073.png)

注意上一个屏幕中窗口标题中的奇怪日期？那是 NetBeans 平台的构建日期，在我们的应用程序中看起来不太好看，所以让我们来修复一下。我们有两个选择。第一个是使用我们之前看过的品牌用户界面。另一个是直接编辑文件。为了保持事情的有趣，并帮助理解磁盘上的位置，我们将使用第二种方法。

在品牌模块中，在其他来源|nbm-branding 下，您应该找到`modules/org-netbeans-core-windows.jar/org/netbeans/core/windows/ view/ui/Bundle.properties`文件。在这个文件中，您应该看到这些行：

```java
    CTL_MainWindow_Title=PhotoBeans {0} 
    CTL_MainWindow_Title_No_Project=PhotoBeans {0} 

```

我们所需要做的就是删除`{0}`部分，重新构建这个模块和应用程序，我们的标题栏就会变得更漂亮。虽然看起来更好了，但是我们的 TopComponent 呢？为了解决这个问题，我们需要学习一些新的概念。

# 节点，NetBeans 演示对象

您已经听过 Node 这个术语。我已经多次使用它来描述点击的内容和位置。正式地说，一个 Node 代表对象（bean）层次结构中的一个元素。它提供了在资源管理器视图和 bean 之间进行通信所需的所有方法。在我们的应用程序的资源管理器部分，我们希望向用户表示照片列表。我们将每张照片以及拍摄日期和月份表示为一个 Node。为了显示这些节点，我们将使用一个名为`BeanTreeView`的 NetBeans 类，它将以树形式显示这个节点层次结构。还有一些概念需要学习，但让我们先从现有的开始。

我们将首先定义我们的节点，它们将作为我们应用程序业务领域模型和 NetBeans API 之间的一种包装或桥梁。当然，我们还没有定义这样的模型，所以现在需要解决这个问题。我们的基本数据项是一张照片，是存储在磁盘上的图像文件。在应用程序中，我们将以嵌套树结构显示这些照片，按年份和月份进行分组。如果展开一个年份节点，您将看到一个月份节点列表，如果展开一个月份节点，您将看到一个照片节点列表。这是一个非常基本、有些天真的数据模型，但它足够有效地演示了这些概念，同时也足够简单，不会使概念变得模糊。

与所有层次结构一样，我们需要一个根节点，所以我们将从那里开始：

```java
    public class RootNode extends AbstractNode 

```

所有节点的基类在技术上是 Node，但扩展该类会给我们带来更多的负担，因此我们使用 NetBeans 提供的`AbstractNode`，它为我们实现了大量节点的基本行为，并提供了合理的默认值。

接下来，我们定义一些构造函数，如下所示：

```java
    public RootNode() { 
      this(new InstanceContent()); 
    } 

    protected RootNode(InstanceContent ic) { 
      super(Children.create(new YearChildFactory(), true), 
       new AbstractLookup(ic)); 
      setDisplayName(Bundle.LBL_RootNode()); 
      setShortDescription(Bundle.HINT_RootNode()); 

      instanceContent = ic; 
    } 

```

请注意，我们有两个构造函数，一个是`public`，一个是`protected`。之所以这样做是因为我们想要创建和捕获`InstanceContent`的实例，这样我们作为这个类 Lookup 的创建者就可以控制 Lookup 中实际包含的内容。由于我们需要将 Lookup 传递给我们类的父构造函数，所以我们采用了这种两步实例化对象的方法。

# Lookup，NetBeans 的基础

什么是 Lookup？它是一个**通用注册表，允许客户端找到服务的实例（给定接口的实现）**。换句话说，它是一个机制，通过它我们可以发布各种工件，系统的其他部分可以通过一个键（可以是`Class`或`Lookup.Template`，这里我们不讨论）查找这些工件，模块之间没有耦合。

这通常用于查找服务接口的实现。您还记得我之前提到过吗？通常我们会看到 API 在一个模块中定义，而实现在另一个模块中。这就是它特别方便的地方。假设您正在开发一个从在线服务中检索照片的 API（这将是该应用程序的一个很棒的功能！）。您计划为一个服务提供实现，比如 Google 照片，但希望让第三方开发人员为 Flickr 提供实现。如果您将所需的 API 接口、类等放在一个模块中，将 Google 照片的实现放在另一个模块中，第三方开发人员可以仅依赖于您的 API 模块，避免依赖于您的实现模块。Flickr 模块将声明照片服务 API 的实现，我们可以通过查找请求加载 Flickr 和我们自己的 Google 照片实现。简而言之，该系统允许在一个非常干净、简单的 API 中解耦 API 定义、实现和实例获取。

这是 Lookup，但是`InstanceContent`是什么？Lookup API 只公开了获取项目的方法。没有机制可以向 Lookup 添加项目，这是有道理的，因为 Lookup 实例是由未知的第三方使用的，我们不希望他们随机更改我们的 Lookup 的内容。然而，我们可能确实希望更改这些内容，我们可以通过`InstanceContent`来实现，它公开了我们需要添加或删除项目的方法。我们将在应用程序的后续部分看到这个概念的演示。

# 编写我们自己的节点

前面的部分涵盖了这两个类，但是`YearChildFactory`是什么？类`RootNode`为系统定义了将成为我们树的根节点。但是，如果节点有子节点，它负责加载和构建这些子节点，这是通过这个`ChildFactory`类完成的。我们的实例看起来是这样的：

```java
    public class YearChildFactory extends ChildFactory<String> { 
      private final PhotoManager photoManager; 
      private static final Logger LOGGER =  
        Logger.getLogger(YearChildFactory.class.getName()); 
      public YearChildFactory() { 
        this.photoManager =  
          Lookup.getDefault().lookup(PhotoManager.class); 
        if (photoManager == null) { 
          LOGGER.log(Level.SEVERE,  
          "Cannot get PhotoManager object"); 
          LifecycleManager.getDefault().exit(); 
        } 
      } 

      @Override 
      protected boolean createKeys(List<String> list) { 
        list.addAll(photoManager.getYears()); 
        return true; 
      } 

      @Override 
      protected Node createNodeForKey(String key) { 
        return new YearNode(Integer.parseInt(key)); 
      } 
    } 

```

我们正在创建一个`ChildFactory`接口，它将返回操作字符串的节点。如果您有一个更复杂的数据模型，例如使用 POJOs 的模型，您可以将该类指定为参数化类型。

在我们的构造函数中，我们看到了通过 Lookup 查找服务实现的示例，就是这样：

```java
    this.photoManager=Lookup.getDefault().lookup(
      PhotoManager.class); 

```

我们稍后将讨论定义服务，但是现在，您需要理解的是，我们正在向全局 Lookup（与我们之前创建的 Lookup 不同，它不与特定类绑定）请求`PhotoManager`接口的一个实例。或许有些天真，我们假设只有一个这个接口的实例，但由于我们没有导出这个接口，我们对这个假设感到放心。不过，我们确实检查确保至少有一个实例，如果没有，就退出应用程序。

接下来的两个方法是工厂用来创建子节点的方法。第一个方法`createKeys(List<String> list)`是系统调用的，用于生成子节点的键列表。在我们的实现中，我们要求`PhotoManager`接口提供年份列表（正如我们将看到的，这是对数据库的一个简单查询，用于获取系统中我们拥有照片的年份列表）。然后平台获取这些键，并逐个传递给`createNodeForKey(String key)`来创建实际的节点。在这里，我们创建一个`YearNode`的实例来表示这一年。

`YearNode`，就像`RootNode`一样，扩展了`AbstractNode`。

```java
    public class YearNode extends AbstractNode { 
      public YearNode(int year) { 
        super(Children.create(new MonthNodeFactory(year), true),  
         Lookups.singleton(year)); 
        setName("" + year); 
        setDisplayName("" + year); 
      } 
    } 

```

前面的内容显然是一个更简单的节点，但基本原理是一样的——我们创建`ChildFactory`来创建我们的子节点，我们创建一个 Lookup，在这种情况下，它保存了一个值，即节点表示的年份。

`MonthNodeFactory`看起来几乎和`YearNodeFactory`一样，唯一的区别是它为给定年份加载月份，所以我们不会在这里显示源代码。它还为列表中的每个月创建`MonthNode`实例。像`YearNode`一样，`MonthNode`非常简单，您可以在以下代码片段中看到：

```java
    public class MonthNode extends AbstractNode { 
      public MonthNode(int year, int month) { 
        super(Children.create( 
          new PhotoNodeFactory(year, month), true),  
           Lookups.singleton(month)); 
          String display = month + " - " +  
           Month.values()[month-1].getDisplayName( 
             TextStyle.FULL, Locale.getDefault()); 
          setName(display); 
          setDisplayName(display); 
      } 
    } 

```

我们做了更多的工作来给节点一个有意义的名称和显示名称，但基本上是一样的。还要注意，我们有另一个`ChildFactory`，它将生成我们需要的`PhotoNodes`作为子节点。工厂本身没有什么新鲜的内容，但`PhotoNode`有，所以让我们来看看它：

```java
    public class PhotoNode extends AbstractNode { 
      public PhotoNode(String photo) { 
        this(photo, new InstanceContent()); 
    } 

    private PhotoNode(String photo, InstanceContent ic) { 
      super(Children.LEAF, new AbstractLookup(ic)); 
      final String name = new File(photo).getName(); 
      setName(name); 
      setDisplayName(name); 

      ic.add((OpenCookie) () -> { 
        TopComponent tc = findTopComponent(photo); 
        if (tc == null) { 
          tc = new PhotoViewerTopComponent(photo); 
          tc.open(); 
        } 
        tc.requestActive(); 
      }); 
    } 

```

在这里，我们再次看到了双构造函数方法，不过，在这种情况下，我们确实使用了`InstanceContent`。请注意，`super()`的第一个参数是`Children.LEAF`，表示这个节点没有任何子节点。我们还传递了现在熟悉的`new AbstractLookup(ic)`。

设置名称和显示名称后，我们向`InstanceContent`对象添加了一个 lambda。没有 lambda 版本的代码如下：

```java
    ic.add(new OpenCookie() { 
      @Override 
      public void open() { 
      } 
    }); 

```

`OpenCookie`是什么？它是标记接口`Node.Cookie`的子接口，cookie 是**一种设计模式，用于向现有数据对象和节点添加行为，或将实现与主对象分禅**。使用这个 cookie，我们可以很好地抽象出可以打开的信号以及如何打开它。

在这种情况下，当系统尝试打开节点表示的照片时，它将调用我们定义的`OpenCookie.open()`，该方法将尝试找到照片的打开实例。无论它找到现有的还是需要创建新的，它都会指示系统使其活动（或者给予焦点）。

请注意，打开的照片由另一个 TopComponent 表示。为了找到它，我们有这个方法：

```java
    private TopComponent findTopComponent(String photo) { 
      Set<TopComponent> openTopComponents =  
        WindowManager.getDefault().getRegistry().getOpened(); 
      for (TopComponent tc : openTopComponents) { 
        if (photo.equals(tc.getLookup().lookup(String.class))) { 
          return tc; 
        } 
      } 
      return null; 
    } 

```

我们要求`WindowManager`的查找器获取所有打开的 TopComponents，然后遍历每一个，将`String photo`（即图像的完整路径）与 TopComponent 的查找中存储的任何`String`进行比较。如果有匹配项，我们就返回该 TopComponent。这种按`String`查找有点天真，可能会在更复杂的应用程序中导致意外的匹配。在本应用程序中，我们可能足够安全，但在您自己的应用程序中，您需要确保匹配标准足够严格和唯一，以避免错误的匹配。

# 执行操作

我们稍后会看一下`PhotoViewerTopComponent`，但在继续之前，我们需要看一些其他项目。

`PhotoNode`覆盖了另外两个方法，如下所示：

```java
    @Override 
    public Action[] getActions(boolean context) { 
      return new Action[]{SystemAction.get(OpenAction.class)}; 
    } 

    @Override 
    public Action getPreferredAction() { 
      return SystemAction.get(OpenAction.class); 
    } 

```

毫不奇怪，`getActions()`方法返回了一个用于该节点的操作数组。操作是一个抽象（来自 Swing，而不是 NetBeans），它允许我们向菜单添加项目，并为用户与系统交互提供一种方式。主菜单或上下文菜单中的每个条目都由操作支持。在我们的情况下，我们将 NetBeans 定义的`OpenAction`与我们的节点关联起来，当点击时，它将在节点的查找中查找`OpenCookie`实例并调用`OpenCookie.open()`，这是我们之前定义的。

我们还覆盖了`getPreferredAction()`，这让我们定义了当节点被双击时的行为。这两种方法的结合使用户可以右键单击一个节点并选择“打开”，或者双击一个节点，最终结果是打开该节点的 TopComponent。

# 服务 - 暴露解耦功能

在查看我们的`TopComponent`的定义之前，让我们先看看`PhotoManager`，并了解一下它的服务。`PhotoManager`接口本身非常简单：

```java
    public interface PhotoManager extends Lookup.Provider { 
      void scanSourceDirs(); 
      List<String> getYears(); 
      List<String> getMonths(int year); 
      List<String> getPhotos(int year, int month); 
    } 

```

在上述代码中，除了`extends Lookup.Provider`部分外，没有什么值得注意的。通过在这里添加这个，我们可以强制实现来实现该接口上的唯一方法，因为我们以后会需要它。有趣的部分来自实现，如下所示：

```java
    @ServiceProvider(service = PhotoManager.class) 
    public class PhotoManagerImpl implements PhotoManager { 

```

这就是向平台注册服务所需的全部内容。注解指定了所需的元数据，构建会处理其余部分。让我们来看看实现的其余部分：

```java
    public PhotoManagerImpl() throws ClassNotFoundException { 
      setupDatabase(); 

      Preferences prefs =  
        NbPreferences.forModule(PhotoManager.class); 
      setSourceDirs(prefs.get("sourceDirs", "")); 
      prefs.addPreferenceChangeListener(evt -> { 
        if (evt.getKey().equals("sourceDirs")) { 
          setSourceDirs(evt.getNewValue()); 
          scanSourceDirs(); 
        } 
      }); 

      instanceContent = new InstanceContent(); 
      lookup = new AbstractLookup(instanceContent); 
      scanSourceDirs(); 
    } 

```

在这个简单的实现中，我们将使用 SQLite 来存储我们找到的照片的信息。该服务将提供代码来扫描配置的源目录，存储找到的照片信息，并公开检索那些在特定性上变化的信息的方法。

首先，我们需要确保数据库在应用程序首次运行时已经正确设置。我们可以包含一个预构建的数据库，但在用户的机器上创建它可以增加一些弹性，以应对数据库意外删除的情况。

```java
    private void setupDatabase() { 
      try { 
       connection = DriverManager.getConnection(JDBC_URL); 
       if (!doesTableExist()) { 
         createTable(); 
       } 
      } catch (SQLException ex) { 
        Exceptions.printStackTrace(ex); 
      } 
    } 

    private boolean doesTableExist() { 
      try (Statement stmt = connection.createStatement()) { 
        ResultSet rs = stmt.executeQuery("select 1 from images"); 
        rs.close(); 
        return true; 
      } catch (SQLException e) { 
        return false; 
      } 
    } 

    private void createTable() { 
      try (Statement stmt = connection.createStatement()) { 
        stmt.execute( 
          "CREATE TABLE images (imageSource VARCHAR2(4096), " 
          + " year int, month int, image VARCHAR2(4096));"); 
          stmt.execute( 
            "CREATE UNIQUE INDEX uniq_img ON images(image);"); 
      } catch (SQLException e) { 
        Exceptions.printStackTrace(e); 
      } 
    } 

```

接下来，我们要求引用`PhotoManager`模块的 NetBeans 首选项。我们将在本章后面更详细地探讨管理首选项，但现在我们只说我们将要向系统请求`sourceDirs`首选项，然后将其用于配置我们的扫描代码。

我们还创建了`PreferenceChangeListener`来捕获用户更改首选项的情况。在这个监听器中，我们验证我们关心的首选项`sourceDirs`是否已更改，如果是，我们将新值存储在我们的`PhotoManager`实例中，并启动目录扫描。

最后，我们创建`InstanceContent`，创建并存储一个 Lookup，并开始扫描目录，以确保应用程序与磁盘上的照片状态保持最新。

`getYears()`、`getMonths()`和`getPhotos()`方法基本相同，当然，它们的工作数据类型不同，所以我们让`getYears()`来解释这三个方法：

```java
    @Override 
    public List<String> getYears() { 
      List<String> years = new ArrayList<>(); 
      try (Statement yearStmt = connection.createStatement(); 
      ResultSet rs = yearStmt.executeQuery( 
        "SELECT DISTINCT year FROM images ORDER BY year")) { 
          while (rs.next()) { 
            years.add(rs.getString(1)); 
          } 
        } catch (SQLException ex) { 
          Exceptions.printStackTrace(ex); 
        } 
      return years; 
    } 

```

如果您熟悉 JDBC，这应该不足为奇。我们使用 Java 7 的`try-with-resources`语法来声明和实例化我们的`Statement`和`ResultSet`对象。对于不熟悉这种结构的人来说，它允许我们声明某些类型的资源，并且一旦`try`的范围终止，系统会自动关闭它们，因此我们不必担心关闭它们。但需要注意的主要限制是，该类必须实现`AutoCloseable`；`Closeable`不起作用。其他两个`get*`方法在逻辑上是类似的，因此这里不再显示。

这里的最后一个重要功能是源目录的扫描，由`scanSourceDirs()`方法协调，如下所示：

```java
    private final ExecutorService executorService =  
      Executors.newFixedThreadPool(5); 
    public final void scanSourceDirs() { 
      RequestProcessor.getDefault().execute(() -> { 
        List<Future<List<Photo>>> futures = new ArrayList<>(); 
        sourceDirs.stream() 
         .map(d -> new SourceDirScanner(d)) 
         .forEach(sds ->  
          futures.add((Future<List<Photo>>)  
          executorService.submit(sds))); 
        futures.forEach(f -> { 
          try { 
            final List<Photo> list = f.get(); 
            processPhotos(list); 
          } catch (InterruptedException|ExecutionException ex) { 
            Exceptions.printStackTrace(ex); 
          } 
        }); 
        instanceContent.add(new ReloadCookie()); 
      }); 
    } 

```

为了加快这个过程，我们为每个配置的源目录创建一个 Future，然后将它们传递给我们的`ExecutorService`。我们将其配置为池中最多有五个线程，这在很大程度上是任意的。更复杂的方法可能会使其可配置，或者自动调整，但对于我们的目的来说，这应该足够了。

一旦 Futures 被创建，我们遍历列表，请求每个结果。如果源目录的数量超过了我们线程池的大小，多余的 Futures 将等待直到有一个线程可用，此时`ExecutorService`将选择一个线程来运行。一旦它们都完成了，对`.get()`的调用将不再阻塞，应用程序可以继续。请注意，我们没有阻塞用户界面来让这个方法工作，因为我们将这个方法的大部分作为 lambda 传递给`RequestProcessor.getDefault().execute()`，以请求在用户界面线程之外运行。

当照片列表构建并返回后，我们用这个方法处理这些照片：

```java
    private void processPhotos(List<Photo> photos) { 
      photos.stream() 
       .filter(p -> !isImageRecorded(p)) 
       .forEach(p -> insertImage(p)); 
    } 

```

`isImageRecorded()` 方法检查图像路径是否已经在数据库中，如果是，则返回 true。我们根据这个测试的结果对流进行`filter()`操作，所以`forEach()`只对之前未知的图像进行操作，然后通过`insertImage()`将它们插入到数据库中。这两种方法看起来是这样的：

```java
    private boolean isImageRecorded(Photo photo) { 
      boolean there = false; 
      try (PreparedStatement imageExistStatement =  
        connection.prepareStatement( 
          "SELECT 1 FROM images WHERE image = ?")) { 
            imageExistStatement.setString(1, photo.getImage()); 
            final ResultSet rs = imageExistStatement.executeQuery(); 
            there = rs.next(); 
            close(rs); 
          } catch (SQLException ex) { 
            Exceptions.printStackTrace(ex); 
          } 
      return there; 
    } 

    private void insertImage(Photo photo) { 
      try (PreparedStatement insertStatement =  
       connection.prepareStatement( 
         "INSERT INTO images (imageSource, year, month, image)
          VALUES (?, ?, ?, ?);")) { 
            insertStatement.setString(1, photo.getSourceDir()); 
            insertStatement.setInt(2, photo.getYear()); 
            insertStatement.setInt(3, photo.getMonth()); 
            insertStatement.setString(4, photo.getImage()); 
            insertStatement.executeUpdate(); 
       } catch (SQLException ex) { 
         Exceptions.printStackTrace(ex); 
       } 
    } 

```

我们使用`PreparedStatement`，因为通常通过连接创建 SQL 语句是不明智的，这往往会导致 SQL 注入攻击，所以我们无法在第一个方法中完全使用`try-with-resources`，需要手动关闭`ResultSet`。

# PhotoViewerTopComponent

现在我们可以找到图像，但我们仍然不能告诉系统去哪里找。在转向处理 NetBeans 平台的偏好设置之前，我们还有一个 TopComponent 要看一看--`PhotoViewerTopComponent`。

如果你回想一下我们在 NetBeans 窗口系统提供的区域的讨论，当我们查看一张图片时，我们希望图片加载到`Editor`区域。为此，我们指示 NetBeans 通过右键单击所需的包，并选择 New | Window 来创建一个 TopComponent：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/ae06490b-677c-4e4c-957f-8f075658b0b8.png)

在下一个窗格中，我们为新的 TopComponent 指定一个类名前缀--如下截图所示的`PhotoViewer`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/b5e21806-8be6-417b-b315-27f30b73c35a.png)

NetBeans 现在将创建文件`PhotoViewerTopComponent.java`和`PhotoViewerTopComponent.form`，就像之前讨论的那样。不过，对于这个 TopComponent，我们需要做一些改变。当我们打开`Window`时，我们需要指定一个要加载的图片，因此我们需要提供一个带有图片路径的构造函数。然而，TopComponents 必须有一个无参数的构造函数，所以我们保留它，但让它调用我们的新构造函数并传入空的图片路径。

```java
    public PhotoViewerTopComponent() { 
      this(""); 
    } 

    public PhotoViewerTopComponent(String photo) { 
      initComponents(); 
      this.photo = photo; 
      File file = new File(photo); 
      setName(file.getName()); 
      setToolTipText(photo); 
      associateLookup(Lookups.singleton(photo)); 
      setLayout(new BorderLayout()); 
      init(); 
    } 

```

虽然这可能看起来很多，但这里的步骤很简单：我们将照片路径保存在一个实例变量中，然后从中创建一个`File`实例，以便更容易地获取文件名，将照片路径添加到 TopComponent 的 Lookup 中（这是我们如何找到给定照片的 TopComponent），更改布局，然后初始化窗口。

# 将 JavaFX 与 NetBeans RCP 集成

`init()`方法很有趣，因为我们将做一些略有不同的事情；我们将使用 JavaFX 来查看图片。我们在其他 TopComponent 中也可以使用 Swing，但这给了我们一个很好的机会，可以演示如何集成 JavaFX 和 Swing，以及 JavaFX 和 NetBeans 平台。

```java
    private JFXPanel fxPanel; 
    private void init() { 
      fxPanel = new JFXPanel(); 
      add(fxPanel, BorderLayout.CENTER); 
      Platform.setImplicitExit(false); 
      Platform.runLater(this::createScene); 
    } 

```

`JFXPanel`是一个 Swing 组件，用于将 JavaFX 嵌入 Swing 中。我们的窗口布局是`BorderLayout`，所以我们将`JFXPanel`添加到`CENTER`区域，并让它扩展以填充`Window`。JavaFX 组件的任何复杂布局将由我们`JFXPanel`内的另一个容器处理。不过，我们的用户界面相当简单。与我们之前的 JavaFX 系统一样，我们通过 FXML 定义用户界面如下：

```java
    <BorderPane fx:id="borderPane" prefHeight="480.0"  
      prefWidth="600.0"  

      fx:controller= 
        "com.steeplesoft.photobeans.main.PhotoViewerController"> 
      <center> 
        <ScrollPane fx:id="scrollPane"> 
          <content> 
            <Group> 
              <children> 
                <ImageView fx:id="imageView"  
                  preserveRatio="true" /> 
              </children> 
            </Group> 
          </content> 
        </ScrollPane> 
      </center> 
    </BorderPane> 

```

由于 FXML 需要一个根元素，我们指定了一个`BorderLayout`，正如讨论的那样，这给了我们在`JFXPanel`中的`BorderLayout`。这可能听起来很奇怪，但这就是嵌入 JavaFX 的工作方式。还要注意的是，我们仍然指定了一个控制器。在该控制器中，我们的`initialize()`方法如下：

```java
    @FXML 
    private BorderPane borderPane; 
    @FXML 
    private ScrollPane scrollPane; 
    public void initialize(URL location,
     ResourceBundle resources) { 
       imageView.fitWidthProperty() 
        .bind(borderPane.widthProperty()); 
       imageView.fitHeightProperty() 
        .bind(borderPane.heightProperty()); 
    } 

```

在这种最后的方法中，我们所做的就是将宽度和高度属性绑定到边界窗格的属性上。我们还在 FXML 中将`preserveRatio`设置为`True`，这样图片就不会被扭曲。当我们旋转图片时，这将很重要。

我们还没有看到旋转的代码，所以现在让我们来看一下。我们将首先添加一个按钮，如下所示：

```java
    <top> 
      <ButtonBar prefHeight="40.0" prefWidth="200.0"  
         BorderPane.alignment="CENTER"> 
         <buttons> 
           <SplitMenuButton mnemonicParsing="false" 
             text="Rotate"> 
              <items> 
                <MenuItem onAction="#rotateLeft"  
                  text="Left 90°" /> 
                <MenuItem onAction="#rotateRight"  
                  text="Right 90°" /> 
              </items> 
            </SplitMenuButton> 
         </buttons> 
      </ButtonBar> 
    </top> 

```

在`BorderPane`的`top`部分，我们添加了`ButtonBar`，然后添加了一个单独的`SplitMenuButton`。这给了我们一个像右侧的按钮。在非焦点状态下，它看起来像一个普通按钮。当用户点击箭头时，菜单会呈现给用户，提供了在列出的方向中旋转图片的能力：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/b50c9cc1-2b53-4144-b3dd-e2065ed1c24f.png)

我们已经将这些 MenuItems 绑定到了 FXML 定义中控制器中的适当方法：

```java
    @FXML 
    public void rotateLeft(ActionEvent event) { 
      imageView.setRotate(imageView.getRotate() - 90); 
    } 
    @FXML 
    public void rotateRight(ActionEvent event) { 
      imageView.setRotate(imageView.getRotate() + 90); 
    } 

```

使用 JavaFX `ImageView`提供的 API，我们设置了图片的旋转。

我们可以找到图片，查看它们，并旋转它们，但我们仍然不能告诉系统在哪里查找这些图片。是时候解决这个问题了。

# NetBeans 首选项和选项面板

管理首选项的关键在于`NbPreferences`和选项面板。`NbPreferences`是存储和加载首选项的手段，选项面板是向用户提供用于编辑这些首选项的用户界面的手段。我们将首先看看如何添加选项面板，这将自然地引向`NbPreferences`的讨论。接下来是 NetBeans 选项窗口：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/303583cd-79b6-4894-b79b-82822cd57d77.png)

在前面的窗口中，我们可以看到两种类型的选项面板--主选项和次要选项。主选项面板由顶部的图标表示：常规、编辑器、字体和颜色等。次要选项面板是一个选项卡，就像我们在中间部分看到的：Diff、Files、Output 和 Terminal。在添加选项面板时，您必须选择主选项或次要选项。我们想要添加一个新的主要面板，因为它将在视觉上将我们的首选项与其他面板分开，并且让我们有机会创建两种类型的面板。

# 添加一个主要面板

要创建一个主选项面板，请右键单击所需的包或项目节点，然后单击“新建|选项面板”。如果选项面板不可见，请选择“新建|其他|模块开发|选项面板”。接下来，选择“创建主选项面板”：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/cd62cb4c-24c6-4353-b665-7c86e6bd862f.png)

我们必须指定一个标签，这是我们将在图标下看到的文本。我们还必须选择一个图标。系统将允许您选择除 32x32 图像之外的其他内容，但如果它不是正确的大小，它在用户界面中看起来会很奇怪；因此，请谨慎选择。系统还要求您输入关键字，如果用户对选项窗口应用了过滤器，将使用这些关键字。最后，选择“允许次要面板”。主要面板没有任何真正的内容，只用于显示次要面板，我们将很快创建。

当您点击“下一步”时，将要求您输入类前缀和包：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/58423d52-bfb4-46b1-a482-499a076a6a7b.png)

当您点击“完成”时，NetBeans 将创建这个单一文件，`package-info.java`：

```java
    @OptionsPanelController.ContainerRegistration(id = "PhotoBeans", 
      categoryName = "#OptionsCategory_Name_PhotoBeans",  
      iconBase = "com/steeplesoft/photobeans/main/options/
       camera-icon-32x32.png",  
       keywords = "#OptionsCategory_Keywords_PhotoBeans",  
       keywordsCategory = "PhotoBeans") 
    @NbBundle.Messages(value = { 
      "OptionsCategory_Name_PhotoBeans=PhotoBeans",  
      "OptionsCategory_Keywords_PhotoBeans=photo"}) 
    package com.steeplesoft.photobeans.main.options; 

    import org.netbeans.spi.options.OptionsPanelController; 
    import org.openide.util.NbBundle; 

```

# 添加一个次要面板

定义了主要面板后，我们准备创建次要面板，这将完成我们的工作。我们再次右键单击包，并选择“新建|选项面板”，这次选择“创建次要面板”：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/497a878f-fe1c-4d38-9094-71b6db76400f.png)

由于我们已经定义了自己的主要面板，我们可以将其选择为我们的父级，并且像之前一样设置标题和关键字。点击“下一步”，选择和/或验证类前缀和包，然后点击“完成”。这将创建三个文件--`SourceDirectoriesOptionPanelController.java`、`SourceDirectoriesPanel.java`和`SourceDirectoriesPanel.form`，NetBeans 将为您呈现面板的 GUI 编辑器。

我们想要向我们的面板添加四个元素--一个标签、一个列表视图和两个按钮。我们通过从右侧的工具栏拖动它们，并将它们排列在下一个表单中来添加它们：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/14b4277f-1eec-44c7-99a2-9873ee3f58aa.png)

为了使与这些用户界面元素的工作更有意义，我们需要设置变量名。我们还需要设置用户界面的文本，以便每个元素对用户来说都是有意义的。我们可以通过右键单击每个元素来做到这一点，如此屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/e7a16fc5-c806-43c4-956e-c0101b9a51f4.png)

在前面的屏幕上，我们可以看到三个感兴趣的项目--编辑文本、更改变量名称...和事件|操作|actionPeformed [buttonAddActionPerformed]。对于我们的按钮，我们需要使用所有三个，因此我们将文本设置为`Add`（或`Remove`），将变量名称更改为`buttonAdd`/`buttonRemove`，并选择`actionPerformed`。回到我们的 Java 源代码中，我们看到为我们创建的一个方法，我们需要填写它：

```java
    private void buttonAddActionPerformed(ActionEvent evt) {                                               
      String lastDir = NbPreferences 
       .forModule(PhotoManager.class).get("lastDir", null); 
      JFileChooser chooser = new JFileChooser(); 
      if (lastDir != null) { 
        chooser.setCurrentDirectory( 
          new java.io.File(lastDir)); 
      } 
      chooser.setDialogTitle("Add Source Directory"); 
      chooser.setFileSelectionMode(
        JFileChooser.DIRECTORIES_ONLY); 
      chooser.setAcceptAllFileFilterUsed(false); 
      if (chooser.showOpenDialog(null) ==  
        JFileChooser.APPROVE_OPTION) { 
          try { 
            String dir = chooser.getSelectedFile() 
            .getCanonicalPath(); 
            ensureModel().addElement(dir); 
            NbPreferences.forModule(PhotoManager.class) 
            .put("lastDir", dir); 
          } catch (IOException ex) { 
              Exceptions.printStackTrace(ex); 
            } 
        } else { 
            System.out.println("No Selection "); 
          } 
    } 

```

我们这里有很多事情要做：

1.  我们首先检索`lastDir`偏好值。如果设置了，我们将使用它作为选择要添加的目录的起点。通常，至少根据我的经验，感兴趣的目录在文件系统中通常相互靠近，因此我们使用这个偏好值来节省用户的点击次数。

1.  接下来，我们创建`JFileChooser`，这是一个 Swing 类，允许我们选择目录。

1.  如果`lastDir`不为空，我们将其传递给`setCurrentDirectory()`。

1.  我们将对话框的标题设置为有意义的内容。

1.  我们指定对话框只能让我们选择目录。

1.  最后，我们禁用“选择所有文件过滤器”选项。

1.  我们调用`chooser.showOpenDialog()`来向用户呈现对话框，并等待其关闭。

1.  如果对话框的返回代码是`APPROVE_OPTION`，我们需要将所选目录添加到我们的模型中。

1.  我们获取所选文件的规范路径。

1.  我们调用`ensureModel()`，稍后我们将看到，以获取我们`ListView`的模型，然后将这个新路径添加到其中。

1.  最后，我们将所选路径存储为`lastDir`在我们的偏好中，以设置起始目录，如前所述。

1.  删除按钮的操作要简单得多，如下所示：

```java
        private void buttonRemoveActionPerformed(ActionEvent evt) {                                              
          List<Integer> indexes = IntStream.of( 
            sourceList.getSelectedIndices()) 
            .boxed().collect(Collectors.toList()); 
          Collections.sort(indexes); 
          Collections.reverse(indexes); 
          indexes.forEach(i -> ensureModel().remove(i)); 
        } 

```

当我们从模型中删除项目时，我们按项目索引进行删除。但是，当我们删除一个项目时，之后的索引号会发生变化。因此，我们在这里所做的是创建一个选定索引的列表，对其进行排序以确保它处于正确的顺序（这可能在这里有些过度，但这是一个相对廉价的操作，并且使下一个操作更安全），然后我们反转列表的顺序。现在，我们的索引按降序排列，我们可以遍历列表，从我们的模型中删除每个索引。

我们现在已经多次使用了`ensureModel()`，让我们看看它是什么样子的：

```java
    private DefaultListModel<String> ensureModel() { 
      if (model == null) { 
        model = new DefaultListModel<>(); 
        sourceList.setModel(model); 
      } 
      return model; 
    } 

```

重要的是，我们将模型视为`DefaultListModel`而不是`ListView`期望的`ListModel`类型，因为后者不公开任何用于改变模型内容的方法，而前者则公开。通过处理`DefaultListModel`，我们可以根据需要添加和删除项目，就像我们在这里所做的那样。

# 加载和保存偏好

在这个类中还有两个我们需要看一下的方法，它们加载和存储面板中表示的选项。我们将从`load()`开始，如下所示：

```java
    protected void load() { 
      String dirs = NbPreferences 
       .forModule(PhotoManager.class).get("sourceDirs", ""); 
      if (dirs != null && !dirs.isEmpty()) { 
        ensureModel(); 
        model.clear(); 
        Set<String> set = new HashSet<>( 
          Arrays.asList(dirs.split(";"))); 
        set.forEach(i -> model.addElement(i)); 
      } 
    } 

```

`NbPreferences`不支持存储字符串列表，因此，正如我们将在下面看到的，我们将源目录列表存储为分号分隔的字符串列表。在这里，我们加载`sourceDirs`的值，如果不为空，我们在分号上拆分，并将每个条目添加到我们的`DefaultListModel`中。

保存源目录也相当简单：

```java
    protected void store() { 
      Set<String> dirs = new HashSet<>(); 
      ensureModel(); 
      for (int i = 0; i < model.getSize(); i++) { 
        final String dir = model.getElementAt(i); 
        if (dir != null && !dir.isEmpty()) { 
          dirs.add(dir); 
        } 
      } 
      if (!dirs.isEmpty()) { 
        NbPreferences.forModule(PhotoManager.class) 
        .put("sourceDirs", String.join(";", dirs)); 
      } else { 
        NbPreferences.forModule(PhotoManager.class) 
          .remove("sourceDirs"); 
      } 
    } 

```

我们遍历`ListModel`，将每个目录添加到本地`HashSet`实例中，这有助于我们删除任何重复的目录。如果`Set`不为空，我们使用`String.join()`创建我们的分隔列表，并将其`put()`到我们的偏好存储中。如果为空，我们将偏好条目从存储中删除，以清除可能早期持久化的任何旧数据。

# 对偏好更改做出反应

现在我们可以持久化更改，我们需要使应用程序对更改做出反应。幸运的是，NetBeans RCP 提供了一种巧妙的、解耦的处理方式。我们不需要在这里从我们的代码中显式调用一个方法。我们可以在系统中感兴趣的变化点附加一个监听器。我们已经在`PhotoManagerImpl`中看到了这段代码：

```java
    prefs.addPreferenceChangeListener(evt -> { 
      if (evt.getKey().equals("sourceDirs")) { 
        setSourceDirs(evt.getNewValue()); 
        scanSourceDirs(); 
      } 
    }); 

```

当我们保存`PhotoManager`模块的任何偏好设置时，将调用此监听器。我们只需检查确保它是我们感兴趣的键，并相应地采取行动，正如我们所见，这涉及重新启动源目录扫描过程。

一旦加载了新数据，我们如何使用户界面反映这种变化？我们需要手动更新用户界面吗？再次感谢 RCP，答案是否定的。我们已经在`scanSourceDirs()`的末尾看到了前半部分，即：

```java
    instanceContent.add(new ReloadCookie()); 

```

NetBeans 有许多 cookie 类来指示应该执行某些操作。虽然我们不共享类层次结构（由于不幸的依赖于节点 API），但我们希望通过共享相同的命名方式来窃取一点熟悉感。那么`ReloadCookie`是什么样子呢？它并不复杂；它是这样给出的：

```java
    public class ReloadCookie { 
    } 

```

在我们的情况下，我们只有一个空类。我们不打算在其他地方使用它，所以我们不需要在类中编码任何功能。我们将只是将其用作指示器，就像我们在 `RootNode` 的构造函数中看到的那样，如下所示：

```java
    reloadResult = photoManager.getLookup().lookup( 
      new Lookup.Template(ReloadCookie.class)); 
    reloadResult.addLookupListener(event -> setChildren( 
      Children.create(new YearChildFactory(), true))); 

```

`Lookup.Template` 用于定义系统可以过滤我们的 `Lookup` 请求的模式。使用我们的模板，我们创建一个 `Lookup.Result` 对象 `reloadResult`，并通过一个 lambda 为它添加一个监听器。这个 lambda 使用 `Children.create()` 和我们之前看过的 `YearChildFactory` 创建了一组新的子节点，并将它们传递给 `setChildren()` 来更新用户界面。

这似乎是相当多的代码，只是为了在首选项更改时更新用户界面，但解耦肯定是值得的。想象一个更复杂的应用程序或一个依赖模块树。使用这种监听器方法，我们无需向外部世界公开方法，甚至类，从而使我们的内部代码可以在不破坏客户端代码的情况下进行修改。简而言之，这是解耦代码的主要原因之一。

# 总结

再一次，我们来到了另一个应用程序的尽头。你学会了如何引导基于 Maven 的 NetBeans 富客户端平台应用程序。你了解了 RCP 模块，以及如何将这些模块包含在我们的应用程序构建中。你还学会了 NetBeans RCP Node API 的基础知识，如何创建我们自己的节点，以及如何嵌套子节点。我们解释了如何使用 NetBeans Preferences API，包括创建用于编辑首选项的新选项面板，如何加载和存储它们，以及如何对首选项的更改做出反应。

关于 NetBeans RCP 的最后一句话——虽然我们在这里构建了一个体面的应用程序，但我们并没有完全挖掘 RCP 的潜力。我尝试覆盖平台的足够部分来让你开始，但如果你要继续使用这个平台，你几乎肯定需要学到更多。虽然官方文档很有帮助，但全面覆盖的首选来源是 Jason Wexbridge 和 Walter Nyland 的 *NetBeans Platform for Beginners*（[`leanpub.com/nbp4beginners`](https://leanpub.com/nbp4beginners)）。这是一本很棒的书，我强烈推荐它。

在下一章中，我们将开始涉足客户端/服务器编程，并实现我们自己的记事应用程序。它可能不像市场上已经存在的竞争对手那样健壮和功能齐全，但我们将朝着那个方向取得良好进展，并希望在这个过程中学到很多东西。


# 第九章：使用 Monumentum 做笔记

对于我们的第八个项目，我们将再次做一些新的事情--我们将构建一个 Web 应用程序。而我们所有其他的项目都是命令行、GUI 或两者的组合，这个项目将是一个单一模块，包括一个 REST API 和一个 JavaScript 前端，所有这些都是根据当前的微服务趋势构建的。

要构建这个应用程序，你将学习以下主题：

+   构建微服务应用程序的一些 Java 选项

+   Payara Micro 和`microprofile.io`

+   用于 RESTful Web 服务的 Java API

+   文档数据存储和 MongoDB

+   OAuth 身份验证（针对 Google，具体来说）

+   **JSON Web Tokens** (**JWT**)

正如你所看到的，从许多方面来看，这将是一个与我们到目前为止所看到的项目类型大不相同的项目。

# 入门

我们大多数人可能都使用过一些记事应用程序，比如 EverNote、OneNote 或 Google Keep。它们是一种非常方便的方式来记录笔记和想法，并且可以在几乎所有环境中使用--桌面、移动和网络。在本章中，我们将构建一个相当基本的这些行业巨头的克隆版本，以便练习一些概念。我们将称这个应用程序为 Monumentum，这是拉丁语，意思是提醒或纪念，这种类型的应用程序的一个合适的名字。

在我们深入讨论这些之前，让我们花点时间列出我们应用程序的需求：

+   能够创建笔记

+   能够列出笔记

+   能够编辑笔记

+   能够删除笔记

+   笔记正文必须能够存储/显示富文本

+   能够创建用户账户

+   必须能够使用 OAuth2 凭据登录到现有系统的应用程序

我们的非功能性需求相当温和：

+   必须有一个 RESTful API

+   必须有一个 HTML 5/JavaScript 前端

+   必须有一个灵活的、可扩展的数据存储

+   必须能够轻松部署在资源受限的系统上

当然，这个非功能性需求列表的选择部分是因为它们反映了现实世界的需求，但它们也为我们提供了一个很好的机会来讨论我想在本章中涵盖的一些技术。简而言之，我们将创建一个提供基于 REST 的 API 和 JavaScript 客户端的 Web 应用程序。它将由一个文档数据存储支持，并使用 JVM 可用的许多微服务库/框架之一构建。

那么这个堆栈是什么样的？在我们选择特定选择之前，让我们快速调查一下我们的选择。让我们从微服务框架开始。

# JVM 上的微服务框架

虽然我不愿意花太多时间来解释微服务是什么，因为大多数人对这个话题都很熟悉，但我认为至少应该简要描述一下，以防你不熟悉这个概念。话虽如此，这里有一个来自 SmartBear 的简洁的微服务定义，SmartBear 是一家软件质量工具提供商，也许最为人所知的是他们对 Swagger API 及相关库的管理：

基本上，微服务架构是一种开发软件应用程序的方法，它作为一套独立部署的、小型的、模块化的服务，每个服务运行一个独特的进程，并通过一个定义良好的、轻量级的机制进行通信，以实现业务目标。

换句话说，与将几个相关系统捆绑在一个 Web 应用程序中并部署到大型应用服务器（如 GlassFish/Payara 服务器、Wildfly、WebLogic 服务器或 WebSphere）的较老、更成熟的方法不同，这些系统中的每一个都将在自己的 JVM 进程中单独运行。这种方法的好处包括更容易的、分步的升级，通过进程隔离增加稳定性，更小的资源需求，更大的机器利用率等等。这个概念本身并不一定是新的，但它在近年来显然变得越来越受欢迎，并且以快速的速度不断增长。

那么在 JVM 上我们有哪些选择呢？我们有几个选择，包括但不限于以下内容：

+   Eclipse Vert.x：这是官方的*用于在 JVM 上构建反应式应用程序的工具包*。它提供了一个事件驱动的应用程序框架，非常适合编写微服务。Vert.x 可以在多种语言中使用，包括 Java、Javascript、Kotlin、Ceylon、Scala、Groovy 和 Ruby。更多信息可以在[`vertx.io/`](http://vertx.io/)找到。

+   Spring Boot：这是一个构建独立 Spring 应用程序的库。Spring Boot 应用程序可以完全访问整个 Spring 生态系统，并可以使用单个 fat/uber JAR 运行。Spring Boot 位于[`projects.spring.io/spring-boot/`](https://projects.spring.io/spring-boot/)。

+   Java EE MicroProfile：这是一个由社区和供应商主导的努力，旨在为 Java EE 创建一个新的配置文件，专门针对微服务。在撰写本文时，该配置文件包括**用于 RESTful Web 服务的 Java API**（**JAX-RS**），CDI 和 JSON-P，并得到了包括 Tomitribe、Payara、Red Hat、Hazelcast、IBM 和 Fujitsu 在内的多家公司以及伦敦 Java 社区和 SouJava 等用户组的赞助。MicroProfile 的主页是[`microprofile.io/`](http://microprofile.io/)。

+   Lagom：这是一个相当新的框架，是 Lightbend 公司（Scala 背后的公司）推出的反应式微服务框架。它被描述为一种有主见的微服务框架，并使用了 Lightbend 更著名的两个库--Akka 和 Play。Lagom 应用程序可以用 Java 或 Scala 编写。更多细节可以在[`www.lightbend.com/platform/development/lagom-framework`](https://www.lightbend.com/platform/development/lagom-framework)找到。

+   Dropwizard：这是一个用于开发运维友好、高性能、RESTful Web 服务的 Java 框架。它提供了 Jetty 用于 HTTP，Jersey 用于 REST 服务，以及 Jackson 用于 JSON。它还支持其他库，如 Guava、Hibernate Validator、Freemarker 等。您可以在[`www.dropwizard.io/`](http://www.dropwizard.io/)找到 Dropwizard。

还有一些其他选择，但很明显，作为 JVM 开发人员，我们有很多选择，这几乎总是好事。由于我们只能使用一个，我选择使用 MicroProfile。具体来说，我们将基于 Payara Micro 构建我们的应用程序，Payara Micro 是基于 GlassFish 源代码（加上 Payara 的错误修复、增强等）的实现。

通过选择 MicroProfile 和 Payara Micro，我们隐含地选择了 JAX-RS 作为我们 REST 服务的基础。当然，我们可以自由选择使用任何我们想要的东西，但偏离框架提供的内容会降低框架本身的价值。

这留下了我们选择数据存储的余地。我们已经看到的一个选择是关系数据库。这是一个经过验证的选择，支持行业的广泛范围。然而，它们并非没有局限性和问题。虽然数据库本身在分类和功能方面可能很复杂，但与关系数据库最流行的替代方案也许是 NoSQL 数据库。虽然这些数据库已经存在了半个世纪，但在过去的十年左右，随着**Web 2.0**的出现，这个想法才开始获得重要的市场份额。

虽然**NoSQL**这个术语非常广泛，但这类数据库的大多数示例往往是键值、文档或图形数据存储，每种都提供独特的性能和行为特征。对每种 NoSQL 数据库及其各种实现的全面介绍超出了本书的范围，因此为了节约时间和空间，我们将直接选择 MongoDB。它的可扩展性和灵活性，特别是在文档模式方面，与我们的目标用例非常契合。

最后，在客户端，我们再次有许多选项。最受欢迎的是来自 Facebook 的 ReactJS 和来自 Google 的 Angular。还有各种其他框架，包括较旧的选项，如 Knockout 和 Backbone，以及较新的选项，如 Vue.js。我们将使用后者。它不仅是一个非常强大和灵活的选项，而且在开始时也提供了最少的摩擦。由于本书侧重于 Java，我认为选择一个在满足我们需求的同时需要最少设置的选项是明智的。

# 创建应用程序

使用 Payara Micro，我们创建一个像平常一样的 Java web 应用程序。在 NetBeans 中，我们将选择文件|新项目|Maven|Web 应用程序，然后点击下一步。对于项目名称，输入`monumentum`，选择适当的项目位置，并根据需要修复 Group ID 和 Package：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/17938130-2c4c-4617-af05-4a1cf8b13303.png)

接下来的窗口将要求我们选择服务器，我们可以留空，以及 Java EE 版本，我们要将其设置为 Java EE 7 Web：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/edfd2e3b-4443-4803-be5b-3f71e61ec1d5.png)

过了一会儿，我们应该已经创建好并准备好去。由于我们创建了一个 Java EE 7 web 应用程序，NetBeans 已经将 Java EE API 依赖项添加到了项目中。在我们开始编码之前，让我们将 Payara Micro 添加到构建中，以准备好这部分。为了做到这一点，我们需要向构建中添加一个插件。它看起来会像这样（尽管我们只在这里展示了重点）：

```java
    <plugin>
      <groupId>org.codehaus.mojo</groupId>
      <artifactId>exec-maven-plugin</artifactId>
      <version>1.5.0</version>
      <dependencies>
        <dependency>
          <groupId>fish.payara.extras</groupId>
          <artifactId>payara-microprofile</artifactId>
          <version>1.0</version>
        </dependency>
      </dependencies>

```

这设置了 Maven exec 插件，用于执行外部应用程序或者，就像我们在这里做的一样，执行 Java 应用程序：

```java
    <executions>
      <execution>
        <id>payara-uber-jar</id>
        <phase>package</phase>
        <goals>
          <goal>java</goal>
        </goals>

```

在这里，我们将该插件的执行与 Maven 的打包阶段相关联。这意味着当我们运行 Maven 构建项目时，插件的 java 目标将在 Maven 开始打包项目时运行，从而允许我们精确地修改 JAR 中打包的内容：

```java
    <configuration>
      <mainClass>
        fish.payara.micro.PayaraMicro
      </mainClass>
      <arguments>
        <argument>--deploy</argument>
        <argument>
          ${basedir}/target/${warfile.name}.war
        </argument>
        <argument>--outputUberJar</argument>
        <argument>
          ${basedir}/target/${project.artifactId}.jar
        </argument>
      </arguments>
    </configuration>

```

这最后一部分配置了插件。它将运行`PayaraMicro`类，传递`--deploy <path> --outputUberJar ...`命令。实际上，我们正在告诉 Payara Micro 如何运行我们的应用程序，但是，而不是立即执行包，我们希望它创建一个超级 JAR，以便稍后运行应用程序。

通常，当您构建项目时，您会得到一个仅包含直接包含在项目中的类和资源的 jar 文件。任何外部依赖项都留作执行环境必须提供的内容。使用超级 JAR，我们的项目的 jar 中还包括所有依赖项，然后以这样的方式配置，以便执行环境可以根据需要找到它们。

设置的问题是，如果保持不变，当我们构建时，我们将得到一个超级 JAR，但我们将没有任何简单的方法从 NetBeans 运行应用程序。为了解决这个问题，我们需要稍微不同的插件配置。具体来说，它需要这些行：

```java
    <argument>--deploy</argument> 
    <argument> 
      ${basedir}/target/${project.artifactId}-${project.version} 
    </argument> 

```

这些替换了之前的`deploy`和`outputUberJar`选项。为了加快我们的构建速度，我们也不希望在我们要求之前创建超级 JAR，因此我们可以将这两个插件配置分成两个单独的配置文件，如下所示：

```java
    <profiles> 
      <profile> 
        <id>exploded-war</id> 
        <!-- ... --> 
      </profile> 
      <profile> 
        <id>uber</id> 
        <!-- ... --> 
      </profile> 
    </profiles> 

```

当我们准备构建部署工件时，我们在执行 Maven 时激活超级配置文件，然后我们将获得可执行的 jar：

```java
$ mvn -Puber install 

```

`exploded-war`配置文件是我们将从 IDE 中使用的配置文件，它运行 Payara Micro，并将其指向我们构建目录中的解压缩 war。为了指示 NetBeans 使用它，我们需要修改一些操作配置。为此，在 NetBeans 中右键单击项目，然后从上下文菜单的底部选择属性。在操作下，找到运行项目并选择它，然后在激活配置下输入`exploded-war`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/1b56d41f-a354-4913-98f5-a0290cfbafef.png)

如果我们现在运行应用程序，NetBeans 会抱怨因为我们还没有选择服务器。虽然这是一个 Web 应用程序，通常需要服务器，但我们使用的是 Payara Micro，所以不需要定义应用服务器。幸运的是，NetBeans 会让我们告诉它，就像下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/03421687-eacb-4b7a-a7cb-9664844f1d26.png)

选择忽略，我不想使用 IDE 管理部署，然后点击确定，然后观察输出窗口。你应该会看到大量的文本滚动过，几秒钟后，你应该会看到类似这样的文本：

```java
Apr 05, 2017 1:18:59 AM fish.payara.micro.PayaraMicro bootStrap 
INFO: Payara MicroProfile  4.1.1.164-SNAPSHOT (build ${build.number}) ready in 9496 (ms) 

```

一旦你看到这个，我们就准备测试我们的应用程序，就像现在这样。在你的浏览器中，打开`http://localhost:8080/monumentum-1.0-SNAPSHOT/index.html`，你应该会在页面上看到一个大而令人兴奋的*Hello World!*消息。如果你看到了这个，那么你已经成功地启动了一个 Payara Micro 项目。花点时间来祝贺自己，然后我们将使应用程序做一些有用的事情。

# 创建 REST 服务

这基本上是一个 Java EE 应用程序，尽管它打包和部署的方式有点不同，但你可能学到的关于编写 Java EE 应用程序的一切可能仍然适用。当然，你可能从未编写过这样的应用程序，所以我们将逐步介绍步骤。

在 Java EE 中，使用 JAX-RS 编写 REST 应用程序，我们的起点是`Application`。`Application`是一种与部署无关的方式，用于向运行时声明根级资源。运行时如何找到`Application`，当然取决于运行时本身。对于像我们这样的 MicroProfile 应用程序，我们将在 Servlet 3.0 环境中运行，因此我们无需做任何特殊的事情，因为 Servlet 3.0 支持无描述符的部署选项。运行时将扫描一个带有`@ApplicationPath`注解的`Application`类型的类，并使用它来配置 JAX-RS 应用程序，如下所示：

```java
    @ApplicationPath("/api") 
      public class Monumentum extends javax.ws.rs.core.Application { 
      @Override 
      public Set<Class<?>> getClasses() { 
        Set<Class<?>> s = new HashSet<>(); 
        return s; 
      } 
    } 

```

使用`@ApplicationPath`注解，我们指定了应用程序的 REST 端点的根 URL，当然，这是相对于 Web 应用程序的根上下文本身的。`Application`有三种我们可以重写的方法，但我们只对这里列出的一个感兴趣：`getClasses()`。我们很快会提供有关这个方法的更多细节，但是现在请记住，这是我们将向 JAX-RS 描述我们顶级资源的方式。

Monumentum 将有一个非常简单的 API，主要端点是与笔记交互。为了创建该端点，我们创建一个简单的 Java 类，并使用适当的 JAX-RS 注解标记它：

```java
    @Path("/notes") 
    @RequestScoped 
    @Produces(MediaType.APPLICATION_JSON)  
    public class NoteResource { 
    } 

```

通过这个类，我们描述了一个将位于`/api/notes`的端点，并将生成 JSON 结果。JAX-RS 支持例如 XML，但大多数 REST 开发人员习惯于 JSON，并且期望除此之外别无他物，因此我们无需支持除 JSON 之外的任何其他内容。当然，你的应用程序的需求可能会有所不同，所以你可以根据需要调整支持的媒体类型列表。

虽然这将编译并运行，JAX-RS 将尝试处理对我们端点的请求，但我们实际上还没有定义它。为了做到这一点，我们需要向我们的端点添加一些方法，这些方法将定义端点的输入和输出，以及我们将使用的 HTTP 动词/方法。让我们从笔记集合端点开始：

```java
    @GET 
    public Response getAll() { 
      List<Note> notes = new ArrayList<>(); 
      return Response.ok( 
        new GenericEntity<List<Note>>(notes) {}).build(); 
    } 

```

现在我们有一个端点，它在`/api/notes`处回答`GET`请求，并返回一个`Note`实例的`List`。在 REST 开发人员中，关于这类方法的正确返回有一些争论。有些人更喜欢返回客户端将看到的实际类型，例如我们的情况下的`List<Note>`，因为这样可以清楚地告诉开发人员阅读源代码或从中生成的文档。其他人更喜欢，就像我们在这里做的那样，返回一个 JAX-RS `Response`对象，因为这样可以更好地控制响应，包括 HTTP 头、状态码等。我倾向于更喜欢这种第二种方法，就像我们在这里做的那样。当然，你可以自由选择使用任何一种方法。

这里最后需要注意的一件事是我们构建响应体的方式：

```java
    new GenericEntity<List<Note>>(notes) {} 

```

通常，在运行时，由于类型擦除，List 的参数化类型会丢失。像这样使用`GenericEntity`允许我们捕获参数化类型，从而允许运行时对数据进行编组。使用这种方法可以避免编写自己的`MessageBodyWriter`。少写代码几乎总是一件好事。

如果我们现在运行我们的应用程序，我们将得到以下响应，尽管它非常无聊：

```java
$ curl http://localhost:8080/monumentum-1.0-SNAPSHOT/api/notes/
[] 

```

这既令人满意，也不令人满意，但它确实表明我们正在正确的轨道上。显然，我们希望该端点返回数据，但我们没有办法添加一个笔记，所以现在让我们来修复这个问题。

通过 REST 创建一个新的实体是通过将一个新的实体 POST 到它的集合中来实现的。该方法看起来像这样：

```java
    @POST 
    public Response createNote(Note note) { 
      Document doc = note.toDocument(); 
      collection.insertOne(doc); 
      final String id = doc.get("_id",  
        ObjectId.class).toHexString(); 

      return Response.created(uriInfo.getRequestUriBuilder() 
        .path(id).build()) 
      .build(); 
    } 

```

`@POST`注解表示使用 HTTP POST 动词。该方法接受一个`Note`实例，并返回一个`Response`，就像我们在前面的代码中看到的那样。请注意，我们不直接处理 JSON。通过在方法签名中指定`Note`，我们可以利用 JAX-RS 的一个很棒的特性--POJO 映射。我们已经在以前的代码中看到了`GenericEntity`的一点提示。JAX-RS 将尝试解组--也就是将序列化的形式转换为模型对象--JSON 请求体。如果客户端以正确的格式发送 JSON 对象，我们就会得到一个可用的`Note`实例。如果客户端发送了一个构建不当的对象，它会得到一个响应。这个特性使我们只需处理我们的领域对象，而不用担心 JSON 的编码和解码，这可以节省大量的时间和精力。

# 添加 MongoDB

在方法的主体中，我们第一次看到了与 MongoDB 的集成。为了使其编译通过，我们需要添加对 MongoDB Java Driver 的依赖：

```java
    <dependency> 
      <groupId>org.mongodb</groupId> 
      <artifactId>mongodb-driver</artifactId> 
      <version>3.4.2</version> 
    </dependency> 

```

MongoDB 处理文档，所以我们需要将我们的领域模型转换为`Document`，我们通过模型类上的一个方法来实现这一点。我们还没有看`Note`类的细节，所以现在让我们来看一下：

```java
    public class Note { 
      private String id; 
      private String userId; 
      private String title; 
      private String body; 
      private LocalDateTime created = LocalDateTime.now(); 
      private LocalDateTime modified = null; 

      // Getters, setters and some constructors not shown 

      public Note(final Document doc) { 
        final LocalDateTimeAdapter adapter =  
          new LocalDateTimeAdapter(); 
        userId = doc.getString("user_id"); 
        id = doc.get("_id", ObjectId.class).toHexString(); 
        title = doc.getString("title"); 
        body = doc.getString("body"); 
        created = adapter.unmarshal(doc.getString("created")); 
        modified = adapter.unmarshal(doc.getString("modified")); 
      } 

      public Document toDocument() { 
        final LocalDateTimeAdapter adapter =  
           new LocalDateTimeAdapter(); 
        Document doc = new Document(); 
        if (id != null) { 
           doc.append("_id", new ObjectId(getId())); 
        } 
        doc.append("user_id", getUserId()) 
         .append("title", getTitle()) 
         .append("body", getBody()) 
         .append("created",  
           adapter.marshal(getCreated() != null 
           ? getCreated() : LocalDateTime.now())) 
         .append("modified",  
           adapter.marshal(getModified())); 
         return doc; 
      } 
    } 

```

这基本上只是一个普通的 POJO。我们添加了一个构造函数和一个实例方法来处理与 MongoDB 的`Document`类型的转换。

这里有几件事情需要注意。第一点是 MongoDB `Document`的 ID 是如何处理的。存储在 MongoDB 数据库中的每个文档都会被分配一个`_id`。在 Java API 中，这个`_id`被表示为`ObjectId`。我们不希望在我们的领域模型中暴露这个细节，所以我们将它转换为`String`，然后再转换回来。

我们还需要对我们的日期字段进行一些特殊处理。我们选择将`created`和`modified`属性表示为`LocalDateTime`实例，因为新的日期/时间 API 优于旧的`java.util.Date`。不幸的是，MongoDB Java Driver 目前还不支持 Java 8，所以我们需要自己处理转换。我们将这些日期存储为字符串，并根据需要进行转换。这个转换是通过`LocalDateTimeAdapter`类处理的：

```java
    public class LocalDateTimeAdapter  
      extends XmlAdapter<String, LocalDateTime> { 
      private static final Pattern JS_DATE = Pattern.compile 
        ("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d+Z"); 
      private static final DateTimeFormatter DEFAULT_FORMAT =  
        DateTimeFormatter.ISO_LOCAL_DATE_TIME; 
      private static final DateTimeFormatter JS_FORMAT =  
        DateTimeFormatter.ofPattern 
        ("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"); 

      @Override 
      public LocalDateTime unmarshal(String date) { 
        if (date == null) { 
          return null; 
        } 
        return LocalDateTime.parse(date,  
          (JS_DATE.matcher(date).matches()) 
          ? JS_FORMAT : DEFAULT_FORMAT); 
      } 

      @Override 
      public String marshal(LocalDateTime date) { 
        return date != null ? DEFAULT_FORMAT.format(date) : null; 
      } 
    } 

```

这可能比您预期的要复杂一些，这是因为它做的事情比我们到目前为止讨论的要多。我们现在正在研究的用法，即来自我们的模型类，不是这个类的主要目的，但我们稍后会讨论到这一点。除此之外，这个类的行为非常简单--接受一个`String`，确定它表示的是两种支持的格式中的哪一种，并将其转换为`LocalDateTime`。它也可以反过来。

这个类的主要目的是供 JAX-RS 使用。当我们通过网络传递`Note`实例时，`LocalDateTime`也需要被解组，我们可以通过`XmlAdapter`告诉 JAX-RS 如何做到这一点。

定义了这个类之后，我们需要告诉 JAX-RS 关于它。我们可以用几种不同的方式来做到这一点。我们可以在我们的模型中的每个属性上使用注释，就像这样：

```java
    @XmlJavaTypeAdapter(value = LocalDateTimeAdapter.class) 
    private LocalDateTime created = LocalDateTime.now(); 

```

虽然这样可以工作，但作为这类事情而言，这是一个相当大的注释，并且您必须将其放在每个`LocalDateTime`属性上。如果您有几个具有此类型字段的模型，您将不得不触及每个属性。幸运的是，有一种方法可以将类型与适配器关联一次。我们可以在一个特殊的 Java 文件`package-info.java`中做到这一点。大多数人从未听说过这个文件，甚至更少的人使用它，但它只是一个用于包级别文档和注释的地方。我们感兴趣的是后一种用法。在我们的模型类的包中，创建`package-info.java`并将其放入其中：

```java
    @XmlJavaTypeAdapters({ 
      @XmlJavaTypeAdapter(type = LocalDateTime.class,  
        value = LocalDateTimeAdapter.class) 
    }) 
    package com.steeplesoft.monumentum.model; 

```

我们在前面的代码中看到了与之前相同的注释，但它包裹在`@XmlJavaTypeAdapters`中。JVM 只允许在元素上注释给定类型，因此这个包装器允许我们绕过这个限制。我们还需要在`@XmlJavaTypeAdapter`注释上指定类型参数，因为它不再在目标属性上。有了这个设置，每个`LocalDateTime`属性都将被正确处理，而无需任何额外的工作。

这是一个相当复杂的设置，但我们还不太准备好。我们已经在 REST 端设置好了一切。现在我们需要将 MongoDB 类放在适当的位置。要连接到 MongoDB 实例，我们从`MongoClient`开始。然后，我们从`MongoClient`获取对`MongoDatabase`的引用，然后获取`MongoCollection`：

```java
    private MongoCollection<Document> collection; 
    private MongoClient mongoClient; 
    private MongoDatabase database; 

    @PostConstruct 
    public void postConstruct() { 
      String host = System.getProperty("mongo.host", "localhost"); 
      String port = System.getProperty("mongo.port", "27017"); 
      mongoClient = new MongoClient(host, Integer.parseInt(port)); 
      database = mongoClient.getDatabase("monumentum"); 
      collection = database.getCollection("note"); 
    } 

```

`@PostConstruct`方法在构造函数运行后在 bean 上运行。在这个方法中，我们初始化我们各种 MongoDB 类并将它们存储在实例变量中。有了这些准备好的类，我们可以重新访问，例如`getAll()`：

```java
    @GET 
    public Response getAll() { 
      List<Note> notes = new ArrayList<>(); 
      try (MongoCursor<Document> cursor = collection.find() 
      .iterator()) { 
        while (cursor.hasNext()) { 
          notes.add(new Note(cursor.next())); 
        } 
      } 

      return Response.ok( 
        new GenericEntity<List<Note>>(notes) {}) 
      .build(); 
    } 

```

现在我们可以查询数据库中的笔记，并且通过前面代码中`createNote()`的实现，我们可以创建以下笔记：

```java
$ curl -v -H "Content-Type: application/json" -X POST -d '{"title":"Command line note", "body":"A note from the command line"}' http://localhost:8080/monumentum-1.0-SNAPSHOT/api/notes/ 
*   Trying ::1... 
* TCP_NODELAY set 
* Connected to localhost (::1) port 8080 (#0) 
> POST /monumentum-1.0-SNAPSHOT/api/notes/ HTTP/1.1 
... 
< HTTP/1.1 201 Created 
... 
$ curl http://localhost:8080/monumentum-1.0-SNAPSHOT/api/notes/ | jq . 
[ 
  { 
    "id": "58e5d0d79ccd032344f66c37", 
    "userId": null, 
    "title": "Command line note", 
    "body": "A note from the command line", 
    "created": "2017-04-06T00:23:34.87", 
    "modified": null 
  } 
] 

```

为了使这在您的机器上运行，您需要一个正在运行的 MongoDB 实例。您可以在 MongoDB 网站上下载适合您操作系统的安装程序，并找到安装说明（[`docs.mongodb.com/manual/installation/`](https://docs.mongodb.com/manual/installation/)）。

在我们继续处理其他资源方法之前，让我们最后再看一下我们的 MongoDB API 实例。虽然像我们这样实例化实例是有效的，但它也给资源本身带来了相当多的工作。理想情况下，我们应该能够将这些问题移到其他地方并注入这些实例。希望这对你来说听起来很熟悉，因为这正是**依赖注入**（**DI**）或**控制反转**（**IoC**）框架被创建来解决的类型问题。

# 使用 CDI 进行依赖注入

Java EE 提供了诸如 CDI 之类的框架。有了 CDI，我们可以使用编译时类型安全将任何容器控制的对象注入到另一个对象中。然而，问题在于所涉及的对象需要由容器控制，而我们的 MongoDB API 对象不是。幸运的是，CDI 提供了一种方法，容器可以通过生产者方法创建这些实例。这会是什么样子呢？让我们从注入点开始，因为这是最简单的部分：

```java
    @Inject 
    @Collection("notes") 
    private MongoCollection<Document> collection; 

```

当 CDI 容器看到`@Inject`时，它会检查注解所在的元素来确定类型。然后它将尝试查找一个实例来满足注入请求。如果有多个实例，注入通常会失败。尽管如此，我们已经使用了一个限定符注解来帮助 CDI 确定要注入什么。该注解定义如下：

```java
    @Qualifier  
    @Retention(RetentionPolicy.RUNTIME)  
    @Target({ElementType.METHOD, ElementType.FIELD,  
      ElementType.PARAMETER, ElementType.TYPE})   
    public @interface Collection { 
      @Nonbinding String value() default "unknown";   
    } 

```

通过这个注解，我们可以向容器传递提示，帮助它选择一个实例进行注入。正如我们已经提到的，`MongoCollection`不是容器管理的，所以我们需要修复它，我们通过以下生产者方法来实现：

```java
    @RequestScoped 
    public class Producers { 
      @Produces 
      @Collection 
      public MongoCollection<Document>  
        getCollection(InjectionPoint injectionPoint) { 
          Collection mc = injectionPoint.getAnnotated() 
          .getAnnotation(Collection.class); 
        return getDatabase().getCollection(mc.value()); 
      } 
    } 

```

`@Produces`方法告诉 CDI，这个方法将产生容器需要的实例。CDI 从方法签名确定可注入实例的类型。我们还在方法上放置了限定符注解，作为运行时的额外提示，因为它试图解析我们的注入请求。

在方法本身中，我们将`InjectionPoint`添加到方法签名中。当 CDI 调用这个方法时，它将提供这个类的一个实例，我们可以从中获取有关每个特定注入点的信息，因为它们被处理。从`InjectionPoint`中，我们可以获取`Collection`实例，从中可以获取我们感兴趣的 MongoDB 集合的名称。现在我们准备获取我们之前看到的`MongoCollection`实例。`MongoClient`和`MongoDatabase`的实例化在类内部处理，与我们之前的用法没有显著变化。

CDI 有一个小的设置步骤。为了避免 CDI 容器进行潜在昂贵的类路径扫描，我们需要告诉系统我们希望打开 CDI，所以要说。为此，我们需要一个`beans.xml`文件，它可以是充满 CDI 配置元素的，也可以是完全空的，这就是我们要做的。对于 Java EE Web 应用程序，`beans.xml`需要在`WEB-INF`目录中，所以我们在`src/main/webapp/WEB-INF`中创建文件。

确保文件真的是空的。如果有空行，Weld，Payara 的 CDI 实现，将尝试解析文件，给你一个 XML 解析错误。

# 完成笔记资源

在我们可以从`Note`资源中继续之前，我们需要完成一些操作，即读取、更新和删除。读取单个笔记非常简单：

```java
    @GET 
    @Path("{id}") 
    public Response getNote(@PathParam("id") String id) { 
      Document doc = collection.find(buildQueryById(id)).first(); 
      if (doc == null) { 
        return Response.status(Response.Status.NOT_FOUND).build(); 
      } else { 
        return Response.ok(new Note(doc)).build(); 
      } 
    } 

```

我们已经指定了 HTTP 动词`GET`，但是在这个方法上我们有一个额外的注解`@Path`。使用这个注解，我们告诉 JAX-RS 这个端点有额外的路径段，请求需要匹配。在这种情况下，我们指定了一个额外的段，但我们用花括号括起来。没有这些括号，匹配将是一个字面匹配，也就是说，“这个 URL 末尾有字符串'id'吗？”但是，有了括号，我们告诉 JAX-RS 我们想要匹配额外的段，但它的内容可以是任何东西，我们想要捕获这个值，并给它一个名字`id`。在我们的方法签名中，我们指示 JAX-RS 通过`@PathParam`注解注入这个值，让我们可以在方法中访问用户指定的`Note` ID。

要从 MongoDB 中检索笔记，我们将第一次真正看到如何查询 MongoDB：

```java
    Document doc = collection.find(buildQueryById(id)).first(); 

```

简而言之，将`BasicDBObject`传递给`collection`上的`find()`方法，它返回一个`FindIterable<?>`对象，我们调用`first()`来获取应该返回的唯一元素（当然，假设有一个）。这里有趣的部分隐藏在`buildQueryById()`中：

```java
    private BasicDBObject buildQueryById(String id) { 
      BasicDBObject query =  
        new BasicDBObject("_id", new ObjectId(id)); 
      return query; 
    } 

```

我们使用`BasicDBObject`定义查询过滤器，我们用键和值初始化它。在这种情况下，我们想要按文档中的`_id`字段进行过滤，所以我们将其用作键，但请注意，我们传递的是`ObjectId`作为值，而不仅仅是`String`。如果我们想要按更多字段进行过滤，我们将在`BasicDBObject`变量中追加更多的键/值对，我们稍后会看到。

一旦我们查询了集合并获得了用户请求的文档，我们就使用`Note`上的辅助方法将其从`Document`转换为`Note`，并以状态码 200 或`OK`返回它。

在数据库中更新文档有点复杂，但并不过分复杂，就像你在这里看到的一样：

```java
    @PUT 
    @Path("{id}") 
    public Response updateNote(Note note) { 
      note.setModified(LocalDateTime.now()); 
      UpdateResult result =  
        collection.updateOne(buildQueryById(note.getId()), 
        new Document("$set", note.toDocument())); 
      if (result.getModifiedCount() == 0) { 
        return Response.status(Response.Status.NOT_FOUND).build(); 
      } else { 
        return Response.ok().build(); 
      } 
    } 

```

要注意的第一件事是 HTTP 方法--`PUT`。关于更新使用什么动词存在一些争论。一些人，比如 Dropbox 和 Facebook，说`POST`，而另一些人，比如 Google（取决于你查看的 API），说`PUT`。我认为选择在很大程度上取决于你。只要在你的选择上保持一致即可。我们将完全用客户端传递的内容替换服务器上的实体，因此该操作是幂等的。通过选择`PUT`，我们可以向客户端传达这一事实，使 API 对客户端更加自我描述。

在方法内部，我们首先设置修改日期以反映操作。接下来，我们调用`Collection.updateOne()`来修改文档。语法有点奇怪，但这里发生了什么--我们正在查询集合以获取我们想要修改的笔记，然后告诉 MongoDB 用我们提供的新文档替换加载的文档。最后，我们查询`UpdateResult`来查看有多少文档被更新。如果没有，那么请求的文档不存在，所以我们返回`NOT_FOUND`（`404`）。如果不为零，我们返回`OK`（`200`）。

最后，我们的删除方法如下：

```java
    @DELETE 
    @Path("{id}") 
    public Response deleteNote(@PathParam("id") String id) { 
      collection.deleteOne(buildQueryById(id)); 
      return Response.ok().build(); 
    } 

```

我们告诉 MongoDB 使用我们之前看到的相同查询过滤器来过滤集合，然后删除一个文档，这应该是它找到的所有内容，当然，鉴于我们的过滤器，但`deleteOne()`是一个明智的保障措施。我们可以像在`updateNote()`中做的那样进行检查，看看是否实际上删除了某些东西，但这没有多大意义--无论文档在请求开始时是否存在，最终都不在那里，这是我们的目标，所以从返回错误响应中获得的收益很少。

现在我们可以创建、读取、更新和删除笔记，但是你们中的敏锐者可能已经注意到，任何人都可以阅读系统中的每一条笔记。对于多用户系统来说，这不是一件好事，所以让我们来解决这个问题。

# 添加身份验证

身份验证系统很容易变得非常复杂。从自制系统，包括自定义用户管理屏幕，到复杂的单点登录解决方案，我们有很多选择。其中一个更受欢迎的选择是 OAuth2，有许多选项。对于 Monumentum，我们将使用 Google 进行登录。为此，我们需要在 Google 的开发者控制台中创建一个应用程序，该控制台位于[`console.developers.google.com`](https://console.developers.google.com)。

一旦您登录，点击页面顶部的项目下拉菜单，然后点击“创建项目”，这样应该会给您呈现这个屏幕：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/d2cb8092-38cc-4ddf-97d0-6059c3263aee.png)

提供项目名称，为下面两个问题做出选择，然后点击“创建”。项目创建后，您应该会被重定向到库页面。点击左侧的凭据链接，然后点击“创建凭据”并选择 OAuth 客户端 ID。如果需要，按照指示填写 OAuth 同意屏幕。选择 Web 应用程序作为应用程序类型，输入名称，并按照此屏幕截图中显示的授权重定向 URI。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/4b495119-fe81-4aed-b107-67c2fe04c1f4.png)

在将其移至生产环境之前，我们需要在此屏幕上添加生产 URI，但是这个配置在开发中也可以正常工作。当您点击保存时，您将看到您的新客户端 ID 和客户端密钥。记下这些：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/3222b4c9-b2b7-46f1-889d-f360a56bf828.png)

有了这些数据（请注意，这些不是我的实际 ID 和密钥，所以您需要生成自己的），我们就可以开始处理我们的身份验证资源了。我们将首先定义资源如下：

```java
    @Path("auth") 
    public class AuthenticationResource { 

```

我们需要在我们的“应用程序”中注册这个，如下所示：

```java
    @ApplicationPath("/api") 
    public class Monumentum extends javax.ws.rs.core.Application { 
      @Override 
      public Set<Class<?>> getClasses() { 
        Set<Class<?>> s = new HashSet<>(); 
        s.add(NoteResource.class); 
        s.add(AuthenticationResource.class); 
        return s; 
      } 
    } 

```

与 Google OAuth 提供程序一起工作，我们需要声明一些实例变量并实例化一些 Google API 类：

```java
    private final String clientId; 
    private final String clientSecret; 
    private final GoogleAuthorizationCodeFlow flow; 
    private final HttpTransport HTTP_TRANSPORT =  
      new NetHttpTransport(); 
    private static final String USER_INFO_URL =  
      "https://www.googleapis.com/oauth2/v1/userinfo"; 
    private static final List<String> SCOPES = Arrays.asList( 
      "https://www.googleapis.com/auth/userinfo.profile", 
      "https://www.googleapis.com/auth/userinfo.email"); 

```

变量`clientId`和`clientSecret`将保存 Google 刚刚给我们的值。另外两个类对我们即将进行的流程是必需的，`SCOPES`保存了我们想要从 Google 获取的权限，即访问用户的个人资料和电子邮件。类构造函数完成了这些项目的设置：

```java
    public AuthenticationResource() { 
      clientId = System.getProperty("client_id"); 
      clientSecret = System.getProperty("client_secret"); 
      flow = new GoogleAuthorizationCodeFlow.Builder(HTTP_TRANSPORT, 
        new JacksonFactory(), clientId, clientSecret, 
        SCOPES).build(); 
    } 

```

认证流程的第一部分是创建一个认证 URL，就像这样：

```java
    @Context 
    private UriInfo uriInfo; 
    @GET 
    @Path("url") 
    public String getAuthorizationUrl() { 
      return flow.newAuthorizationUrl() 
      .setRedirectUri(getCallbackUri()).build(); 
    } 
    private String getCallbackUri()  
      throws UriBuilderException, IllegalArgumentException { 
      return uriInfo.getBaseUriBuilder().path("auth") 
        .path("callback").build() 
        .toASCIIString(); 
    } 

```

使用 JAX-RS 类`UriInfo`，我们创建一个指向我们应用程序中另一个端点`/api/auth/callback`的`URI`。然后将其传递给`GoogleAuthorizationCodeFlow`以完成构建我们的登录 URL。当用户点击链接时，浏览器将被重定向到 Google 的登录对话框。成功认证后，用户将被重定向到我们的回调 URL，由此方法处理：

```java
    @GET 
    @Path("callback") 
    public Response handleCallback(@QueryParam("code")  
    @NotNull String code) throws IOException { 
      User user = getUserInfoJson(code); 
      saveUserInformation(user); 
      final String jwt = createToken(user.getEmail()); 
      return Response.seeOther( 
        uriInfo.getBaseUriBuilder() 
        .path("../loginsuccess.html") 
        .queryParam("Bearer", jwt) 
        .build()) 
      .build(); 
    } 

```

当 Google 重定向到我们的`callback`端点时，它将提供一个代码，我们可以使用它来完成认证。我们在`getUserInfoJson()`方法中这样做：

```java
    private User getUserInfoJson(final String authCode)  
    throws IOException { 
      try { 
        final GoogleTokenResponse response =  
          flow.newTokenRequest(authCode) 
          .setRedirectUri(getCallbackUri()) 
          .execute(); 
        final Credential credential =  
          flow.createAndStoreCredential(response, null); 
        final HttpRequest request =  
          HTTP_TRANSPORT.createRequestFactory(credential) 
          .buildGetRequest(new GenericUrl(USER_INFO_URL)); 
        request.getHeaders().setContentType("application/json"); 
        final JSONObject identity =  
          new JSONObject(request.execute().parseAsString()); 
        return new User( 
          identity.getString("id"), 
          identity.getString("email"), 
          identity.getString("name"), 
          identity.getString("picture")); 
      } catch (JSONException ex) { 
        Logger.getLogger(AuthenticationResource.class.getName()) 
        .log(Level.SEVERE, null, ex); 
        return null; 
      } 
    } 

```

使用我们刚从 Google 获取的认证代码，我们向 Google 发送另一个请求，这次是为了获取用户信息。当请求返回时，我们获取响应主体中的 JSON 对象并用它构建一个`User`对象，然后将其返回。

回到我们的 REST 端点方法，如果需要，我们调用此方法将用户保存到数据库中：

```java
    private void saveUserInformation(User user) { 
      Document doc = collection.find( 
        new BasicDBObject("email", user.getEmail())).first(); 
      if (doc == null) { 
        collection.insertOne(user.toDocument()); 
      } 
    } 

```

一旦我们从 Google 获取了用户的信息，我们就不再需要代码，因为我们不需要与任何其他 Google 资源进行交互，所以我们不会将其持久化。

最后，我们想要向客户端返回一些东西 --某种令牌 --用于证明客户端的身份。为此，我们将使用一种称为 JSON Web Token（JWT）的技术。JWT 是*用于创建断言某些声明的访问令牌的基于 JSON 的开放标准（RFC 7519）*。我们将使用用户的电子邮件地址创建一个 JWT。我们将使用服务器专用的密钥对其进行签名，因此我们可以安全地将其传递给客户端，客户端将在每个请求中将其传递回来。由于它必须使用服务器密钥进行加密/签名，不可信任的客户端将无法成功地更改或伪造令牌。

要创建 JWT，我们需要将库添加到我们的项目中，如下所示：

```java
    <dependency> 
      <groupId>io.jsonwebtoken</groupId> 
      <artifactId>jjwt</artifactId> 
      <version>0.7.0</version> 
    </dependency> 

```

然后我们可以编写这个方法：

```java
    @Inject 
    private KeyGenerator keyGenerator; 
    private String createToken(String login) { 
      String jwtToken = Jwts.builder() 
      .setSubject(login) 
      .setIssuer(uriInfo.getAbsolutePath().toString()) 
      .setIssuedAt(new Date()) 
      .setExpiration(Date.from( 
        LocalDateTime.now().plusHours(12L) 
      .atZone(ZoneId.systemDefault()).toInstant())) 
      .signWith(SignatureAlgorithm.HS512,  
        keyGenerator.getKey()) 
      .compact(); 
      return jwtToken; 
    } 

```

令牌的主题是电子邮件地址，我们的 API 基地址是发行者，到期日期和时间是未来 12 小时，令牌由我们使用新类`KeyGenerator`生成的密钥签名。当我们调用`compact()`时，将生成一个 URL 安全的字符串，我们将其返回给调用者。我们可以使用[`jwt.io`](http://jwt.io/)上的 JWT 调试器查看令牌的内部情况：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/74641548-f509-4617-883a-de28f8c7dcfc.png)

显然，令牌中的声明是可读的，所以不要在其中存储任何敏感信息。使其安全的是在签署令牌时使用秘钥，理论上使其不可能在不被检测到的情况下更改其内容。

用于给我们提供签名密钥的`KeyGenerator`类如下所示：

```java
    @Singleton 
    public class KeyGenerator { 
      private Key key; 

      public Key getKey() { 
        if (key == null) { 
          String keyString = System.getProperty("signing.key",  
            "replace for production"); 
          key = new SecretKeySpec(keyString.getBytes(), 0,  
            keyString.getBytes().length, "DES"); 
        } 

        return key; 
      } 
    } 

```

该类使用`@Singleton`进行注释，因此容器保证该 bean 在系统中只存在一个实例。`getKey()`方法将使用系统属性`signing.key`作为密钥，允许用户在启动系统时指定唯一的秘钥。当然，完全随机的密钥更安全，但这会增加一些复杂性，如果我们尝试将该系统水平扩展。我们需要所有实例使用相同的签名密钥，以便无论客户端被定向到哪个服务器，JWT 都可以被验证。在这种情况下，数据网格解决方案，如 Hazelcast，将是这些情况下的合适工具。就目前而言，这对我们的需求已经足够了。

我们的身份验证资源现在已经完成，但我们的系统实际上还没有被保护。为了做到这一点，我们需要告诉 JAX-RS 如何对请求进行身份验证，我们将使用一个新的注解和`ContainerRequestFilter`来实现这一点。

如果我们安装一个没有额外信息的请求过滤器，它将应用于每个资源，包括我们的身份验证资源。这意味着我们必须进行身份验证才能进行身份验证。显然这是没有意义的，所以我们需要一种方法来区分请求，以便只有对某些资源的请求才应用这个过滤器，这意味着一个新的注解：

```java
    @NameBinding 
    @Retention(RetentionPolicy.RUNTIME) 
    @Target({ElementType.TYPE, ElementType.METHOD}) 
    public @interface Secure { 
    } 

```

我们已经定义了一个语义上有意义的注解。`@NameBinding`注解告诉 JAX-RS 只将注解应用于特定的资源，这些资源是按名称绑定的（与在运行时动态绑定相对）。有了定义的注解，我们需要定义另一方面的东西，即请求过滤器：

```java
    @Provider 
    @Secure 
    @Priority(Priorities.AUTHENTICATION) 
    public class SecureFilter implements ContainerRequestFilter { 
      @Inject 
      private KeyGenerator keyGenerator; 

      @Override 
      public void filter(ContainerRequestContext requestContext)  
       throws IOException { 
        try { 
          String authorizationHeader = requestContext 
          .getHeaderString(HttpHeaders.AUTHORIZATION); 
          String token = authorizationHeader 
          .substring("Bearer".length()).trim(); 
          Jwts.parser() 
          .setSigningKey(keyGenerator.getKey()) 
          .parseClaimsJws(token); 
        } catch (Exception e) { 
          requestContext.abortWith(Response.status 
          (Response.Status.UNAUTHORIZED).build()); 
        } 
      } 
    } 

```

我们首先定义一个实现`ContainerRequestFilter`接口的类。我们必须用`@Provider`对其进行注释，以便 JAX-RS 能够识别和加载该类。我们应用`@Secure`注解来将过滤器与注解关联起来。我们将在一会儿将其应用于资源。最后，我们应用`@Priority`注解来指示系统该过滤器应该在请求周期中较早地应用。

在过滤器内部，我们注入了之前看过的相同的`KeyGenerator`。由于这是一个单例，我们可以确保在这里使用的密钥和身份验证方法中使用的密钥是相同的。接口上唯一的方法是`filter()`，在这个方法中，我们从请求中获取 Authorization 头，提取 Bearer 令牌（即 JWT），并使用 JWT API 对其进行验证。如果我们可以解码和验证令牌，那么我们就知道用户已经成功对系统进行了身份验证。为了告诉系统这个新的过滤器，我们需要修改我们的 JAX-RS`Application`如下：

```java
    @ApplicationPath("/api") 
    public class Monumentum extends javax.ws.rs.core.Application { 
      @Override 
      public Set<Class<?>> getClasses() { 
        Set<Class<?>> s = new HashSet<>(); 
        s.add(NoteResource.class); 
        s.add(AuthenticationResource.class); 
        s.add(SecureFilter.class); 
        return s; 
      } 
    } 

```

系统现在知道了过滤器，但在它执行任何操作之前，我们需要将其应用到我们想要保护的资源上。我们通过在适当的资源上应用`@Secure`注解来实现这一点。它可以应用在类级别，这意味着类中的每个端点都将被保护，或者在资源方法级别应用，这意味着只有那些特定的端点将被保护。在我们的情况下，我们希望每个`Note`端点都受到保护，所以在类上放置以下注解：

```java
    @Path("/notes") 
    @RequestScoped 
    @Produces(MediaType.APPLICATION_JSON) 
    @Secure 
    public class NoteResource { 

```

只需再做几个步骤，我们的应用程序就会得到保护。我们需要对`NoteResource`进行一些修改，以便它知道谁已登录，并且便笺与经过身份验证的用户相关联。我们将首先注入`User`：

```java
    @Inject 
    private User user; 

```

显然这不是一个容器管理的类，所以我们需要编写另一个`Producer`方法。在那里有一点工作要做，所以我们将其封装在自己的类中：

```java
    @RequestScoped 
    public class UserProducer { 
      @Inject 
      private KeyGenerator keyGenerator; 
      @Inject 
      HttpServletRequest req; 
      @Inject 
      @Collection("users") 
      private MongoCollection<Document> users; 

```

我们将其定义为一个请求范围的 CDI bean，并注入我们的`KeyGenerator`、`HttpServletRequest`和我们的用户集合。实际的工作是在`Producer`方法中完成的：

```java
    @Produces 
    public User getUser() { 
      String authHeader = req.getHeader(HttpHeaders.AUTHORIZATION); 
      if (authHeader != null && authHeader.contains("Bearer")) { 
        String token = authHeader 
        .substring("Bearer".length()).trim(); 
        Jws<Claims> parseClaimsJws = Jwts.parser() 
        .setSigningKey(keyGenerator.getKey()) 
        .parseClaimsJws(token); 
        return getUser(parseClaimsJws.getBody().getSubject()); 
      } else { 
        return null; 
      }  
    } 

```

使用 Servlet 请求，我们检索`AUTHORIZATION`头。如果存在并包含`Bearer`字符串，我们可以处理令牌。如果条件不成立，我们返回 null。要处理令牌，我们从头中提取令牌值，然后让`Jwts`为我们解析声明，返回一个`Jws<Claims>`类型的对象。我们在`getUser()`方法中构建用户如下：

```java
    private User getUser(String email) { 
      Document doc = users.find( 
        new BasicDBObject("email", email)).first(); 
      if (doc != null) { 
        return new User(doc); 
      } else { 
        return null; 
      } 
    } 

```

通过解析声明，我们可以提取主题并用它来查询我们的`Users`集合，如果找到则返回`User`，如果找不到则返回`null`。

回到我们的`NoteResource`，我们需要修改我们的资源方法以使其“用户感知”：

```java
    public Response getAll() { 
      List<Note> notes = new ArrayList<>(); 
      try (MongoCursor<Document> cursor =  
        collection.find(new BasicDBObject("user_id",  
        user.getId())).iterator()) { 
      // ... 
      @POST 
      public Response createNote(Note note) { 
        Document doc = note.toDocument(); 
        doc.append("user_id", user.getId()); 
        // ... 
      @PUT 
      @Path("{id}") 
      public Response updateNote(Note note) { 
        note.setModified(LocalDateTime.now()); 
        note.setUser(user.getId()); 
        // ... 
      private BasicDBObject buildQueryById(String id) { 
        BasicDBObject query =  
        new BasicDBObject("_id", new ObjectId(id)) 
         .append("user_id", user.getId()); 
        return query; 
    } 

```

我们现在有一个完整和安全的 REST API。除了像 curl 这样的命令行工具，我们没有任何好的方法来使用它，所以让我们构建一个用户界面。

# 构建用户界面

对于用户界面，我们有许多选择。在本书中，我们已经看过 JavaFX 和 NetBeans RCP。虽然它们是很好的选择，但对于这个应用程序，我们将做一些不同的事情，构建一个基于 Web 的界面。即使在这里，我们也有很多选择：JSF、Spring MVC、Google Web Toolkit、Vaadin 等等。在现实世界的应用程序中，虽然我们可能有一个 Java 后端，但我们可能有一个 JavaScript 前端，所以我们将在这里这样做，这也是你的选择可能变得非常令人眼花缭乱的地方。

在撰写本书时，市场上最大的两个竞争者是 Facebook 的 React 和 Google 的 Angular。还有一些较小的竞争者，如 React API 兼容的 Preact、VueJS、Backbone、Ember 等等。你的选择将对应用程序产生重大影响，从架构到更加平凡的事情，比如构建项目本身，或者你可以让架构驱动框架，如果有对特定架构的迫切需求。与往常一样，你的特定环境会有所不同，应该比书本或在线阅读的内容更多地驱动决策。

由于这是一本 Java 书，我希望避免过多地涉及 JavaScript 构建系统和替代**JavaScript VM**语言、转译等细节，因此我选择使用 Vue，因为它是一个快速、现代且流行的框架，满足我们的需求，但仍然允许我们构建一个简单的系统，而不需要复杂的构建配置。如果你有其他框架的经验或偏好，使用你选择的框架构建一个类似的系统应该是相当简单的。

请注意，我*不是*一个 JavaScript 开发者。本章中我们将构建的应用程序不应被视为最佳实践的示例。它只是一个尝试构建一个可用的，尽管简单的 JavaScript 前端，以演示一个完整的堆栈应用程序。请查阅 Vue 或您选择的框架的文档，了解如何使用该工具构建成语言应用程序的详细信息。

让我们从索引页面开始。在 NetBeans 的项目资源管理器窗口中，展开其他资源节点，在 webapp 节点上右键单击，选择新建|空文件，将其命名为`index.html`。在文件中，我们目前所需的最低限度是以下内容：

```java
    <!DOCTYPE html> 
      <html> 
        <head> 
          <title>Monumentum</title> 
          <meta charset="UTF-8"> 
          <link rel="stylesheet" href="monumentum.css"> 
          <script src="img/vue"></script> 
        </head> 
        <body> 
          <div id="app"> 
            {{ message }} 
          </div> 
          <script type="text/javascript" src="img/index.js"></script> 
        </body> 
      </html> 

```

目前这将显示一个空白页面，但它确实导入了 Vue 的源代码，以及我们需要创建的客户端应用程序`index.js`的 JavaScript 代码：

```java
    var vm = new Vue({ 
      el: '#app', 
      data: { 
        message : 'Hello, World!' 
      } 
    }); 

```

如果我们部署这些更改（提示：如果应用程序已经在运行，只需按下*F11*告诉 NetBeans 进行构建；这不会使任何 Java 更改生效，但它会将这些静态资源复制到输出目录），并在浏览器中刷新页面，我们现在应该在页面上看到*Hello, World!*。

大致上，正在发生的是我们正在创建一个新的`Vue`对象，将其锚定到具有`app` ID 的(`el`)元素。我们还为这个组件(`data`)定义了一些状态，其中包括单个属性`message`。在页面上，我们可以使用 Mustache 语法访问组件的状态，就像我们在索引页面中看到的那样--`{{ message }}`。让我们扩展一下我们的组件：

```java
    var vm = new Vue({ 
      el: '#app', 
      store, 
      computed: { 
        isLoggedIn() { 
          return this.$store.state.loggedIn; 
        } 
      }, 
      created: function () { 
        NotesActions.fetchNotes(); 
      } 
    }); 

```

我们在这里添加了三个项目：

+   我们引入了一个名为`store`的全局数据存储

+   我们添加了一个名为`isLoggedIn`的新属性，它的值来自一个方法调用

+   我们添加了一个生命周期方法`created`，它将在页面上创建组件时从服务器加载`Note`

我们的数据存储是基于 Vuex 的，它是一个用于`Vue.js`应用程序的状态管理模式和库。它作为应用程序中所有组件的集中存储，通过规则确保状态只能以可预测的方式进行变化。([`vuex.vuejs.org`](https://vuex.vuejs.org/))。要将其添加到我们的应用程序中，我们需要在我们的页面中添加以下代码行：

```java
    <script src="img/vuex"></script>

```

然后我们向我们的组件添加了一个名为`store`的字段，您可以在前面的代码中看到。到目前为止，大部分工作都是在`NotesActions`对象中进行的：

```java
    var NotesActions = { 
      buildAuthHeader: function () { 
        return new Headers({ 
          'Content-Type': 'application/json', 
          'Authorization': 'Bearer ' +    
          NotesActions.getCookie('Bearer') 
        }); 
      }, 
      fetchNotes: function () { 
        fetch('api/notes', { 
          headers: this.buildAuthHeader() 
        }) 
        .then(function (response) { 
          store.state.loggedIn = response.status === 200; 
          if (response.ok) { 
            return response.json(); 
          } 
        }) 
        .then(function (notes) { 
          store.commit('setNotes', notes); 
        }); 
      } 
    } 

```

页面加载时，应用程序将立即向后端发送一个请求以获取笔记，如果有的话，将在`Authorization`标头中发送令牌。当响应返回时，我们会更新存储中`isLoggedIn`属性的状态，并且如果请求成功，我们会更新页面上的`Notes`列表。请注意，我们正在使用`fetch()`。这是用于在浏览器中发送 XHR 或 Ajax 请求的新的实验性 API。截至撰写本书时，它在除 Internet Explorer 之外的所有主要浏览器中都受支持，因此如果您无法控制客户端的浏览器，请小心在生产应用程序中使用它。

我们已经看到存储器使用了几次，所以让我们来看一下它：

```java
    const store = new Vuex.Store({ 
      state: { 
        notes: [], 
        loggedIn: false, 
        currentIndex: -1, 
        currentNote: NotesActions.newNote() 
      } 
    }; 

```

存储器的类型是`Vuex.Store`，我们在其`state`属性中指定了各种状态字段。正确处理，任何绑定到这些状态字段之一的 Vue 组件都会自动更新。您无需手动跟踪和管理状态，反映应用程序状态的变化。Vue 和 Vuex 会为您处理。大部分情况下。有一些情况，比如数组突变（或替换），需要一些特殊处理。Vuex 提供了**mutations**来帮助处理这些情况。例如，`NotesAction.fetchNotes()`，在成功请求时，我们将进行此调用：

```java
     store.commit('setNotes', notes); 

```

前面的代码告诉存储器`commit`一个名为`setNotes`的 mutation，并将`notes`作为有效载荷。我们像这样定义 mutations：

```java
    mutations: { 
      setNotes(state, notes) { 
        state.notes = []; 
        if (notes) { 
          notes.forEach(i => { 
            state.notes.push({ 
              id: i.id, 
              title: i.title, 
              body: i.body, 
              created: new Date(i.created), 
              modified: new Date(i.modified) 
            }); 
        }); 
      } 
    } 

```

我们传递给此 mutation 的是一个 JSON 数组（希望我们在这里没有显示类型检查），因此我们首先清除当前的笔记列表，然后遍历该数组，创建和存储新对象，并在此过程中重新格式化一些数据。严格使用此 mutation 来替换笔记集，我们可以保证用户界面与应用程序状态的变化保持同步，而且是免费的。

那么这些笔记是如何显示的呢？为了做到这一点，我们定义了一个新的 Vue 组件并将其添加到页面中，如下所示：

```java
    <div id="app"> 
      <note-list v-bind:notes="notes" v-if="isLoggedIn"></note-list> 
    </div> 

```

在这里，我们引用了一个名为`note-list`的新组件。我们将模板变量`notes`绑定到同名的应用程序变量，并指定只有在用户登录时才显示该组件。实际的组件定义发生在 JavaScript 中。回到`index.js`，我们有这样的代码：

```java
    Vue.component('note-list', { 
      template: '#note-list-template', 
      store, 
      computed: { 
        notes() { 
          return this.$store.state.notes; 
        }, 
        isLoggedIn() { 
          return this.$store.state.loggedIn; 
        } 
      }, 
      methods: { 
        loadNote: function (index) { 
          this.$store.commit('noteClicked', index); 
        }, 
        deleteNote: function (index) { 
          if (confirm 
            ("Are you sure want to delete this note?")) { 
              NotesActions.deleteNote(index); 
            } 
        } 
      } 
    }); 

```

该组件名为`note-list`；其模板位于具有`note-list-template`ID 的元素中；它具有两个计算值：`notes`和`isLoggedIn`；并且提供了两种方法。在典型的 Vue 应用程序中，我们将有许多文件，最终使用类似 Grunt 或 Gulp 的工具编译在一起，其中一个文件将是我们组件的模板。由于我们试图尽可能简化，避免 JS 构建过程，我们在页面上声明了所有内容。在`index.html`中，我们可以找到我们组件的模板：

```java
    <script type="text/x-template" id="note-list-template"> 
      <div class="note-list"> 
        <h2>Notes:</h2> 
        <ul> 
          <div class="note-list"  
            v-for="(note,index) in notes" :key="note.id"> 
          <span : 
             v-on:click="loadNote(index,note);"> 
          {{ note.title }} 
          </span> 
            <a v-on:click="deleteNote(index, note);"> 
              <img src="img/x-225x225.png" height="20"  
                 width="20" alt="delete"> 
            </a> 
          </div> 
        </ul> 
        <hr> 
      </div>  
    </script> 

```

使用带有`text/x-template`类型的`script`标签，我们可以将模板添加到 DOM 中，而不会在页面上呈现。在此模板中，有趣的部分是带有`note-list`类的`div`标签。我们在其上有`v-`属性，这意味着 Vue 模板处理器将使用此`div`作为显示数组中每个`note`的模板进行迭代。

每个笔记将使用`span`标签进行渲染。使用模板标记`:title`，我们能够使用我们的应用程序状态为标题标签创建一个值（我们不能说因为字符串插值在 Vue 2.0 中已被弃用）。`span`标签的唯一子元素是`{{ note.title }}`表达式，它将`note`列表的标题呈现为字符串。当用户在页面上点击笔记标题时，我们希望对此做出反应，因此我们通过`v-on:click`将`onClick`处理程序绑定到 DOM 元素。这里引用的函数是我们在组件定义的`methods`块中定义的`loadNote()`函数。

`loadNote()`函数调用了一个我们还没有看过的 mutation：

```java
    noteClicked(state, index) { 
      state.currentIndex = index; 
      state.currentNote = state.notes[index]; 
      bus.$emit('note-clicked', state.currentNote); 
    } 

```

这个 mutation 修改状态以反映用户点击的笔记，然后触发（或发出）一个名为`note-clicked`的事件。事件系统实际上非常简单。它是这样设置的：

```java
    var bus = new Vue(); 

```

就是这样。这只是一个基本的、全局范围的 Vue 组件。我们通过调用`bus.$emit()`方法来触发事件，并通过调用`bus.$on()`方法来注册事件监听器。我们将在 note 表单中看到这是什么样子的。

我们将像我们对`note-list`组件做的那样，将 note 表单组件添加到页面中：

```java
    <div id="app"> 
      <note-list v-bind:notes="notes" v-if="isLoggedIn"></note-list> 
      <note-form v-if="isLoggedIn"></note-form> 
    </div> 

```

而且，组件如下所示在`index.js`中定义：

```java
    Vue.component('note-form', { 
      template: '#note-form-template', 
      store, 
      data: function () { 
        return { 
          note: NotesActions.newNote() 
        }; 
      }, 
      mounted: function () { 
        var self = this; 
        bus.$on('add-clicked', function () { 
          self.$store.currentNote = NotesActions.newNote(); 
          self.clearForm(); 
        }); 
        bus.$on('note-clicked', function (note) { 
          self.updateForm(note); 
        }); 
        CKEDITOR.replace('notebody'); 
      } 
    }); 

```

模板也在`index.html`中，如下所示：

```java
    <script type="text/x-template" id="note-form-template"> 
      <div class="note-form"> 
        <h2>{{ note.title }}</h2> 
        <form> 
          <input id="noteid" type="hidden"  
            v-model="note.id"></input> 
          <input id="notedate" type="hidden"  
            v-model="note.created"></input> 
          <input id="notetitle" type="text" size="50"  
            v-model="note.title"></input> 
          <br/> 
          <textarea id="notebody"  
            style="width: 100%; height: 100%"  
            v-model="note.body"></textarea> 
          <br> 
          <button type="button" v-on:click="save">Save</button> 
        </form> 
      </div> 
    </script> 

```

这基本上是普通的 HTML 表单。有趣的部分是 v-model 将表单元素与组件的属性绑定在一起。在表单上进行的更改会自动反映在组件中，而在组件中进行的更改（例如，通过事件处理程序）会自动反映在 UI 中。我们还通过现在熟悉的`v-on:click`属性附加了一个`onClick`处理程序。

你注意到我们在组件定义中提到了`CKEDITOR`吗？我们将使用富文本编辑器`CKEditor`来提供更好的体验。我们可以去`CKEditor`并下载分发包，但我们有更好的方法--WebJars。WebJars 项目将流行的客户端 Web 库打包为 JAR 文件。这使得向项目添加支持的库非常简单：

```java
    <dependency> 
      <groupId>org.webjars</groupId> 
      <artifactId>ckeditor</artifactId> 
      <version>4.6.2</version> 
    </dependency> 

```

当我们打包应用程序时，这个二进制 jar 文件将被添加到 Web 存档中。但是，如果它仍然被存档，我们如何访问资源呢？根据您正在构建的应用程序类型，有许多选项。我们将利用 Servlet 3 的静态资源处理（打包在 Web 应用程序的`lib`目录中的`META-INF/resources`下的任何内容都会自动暴露）。在`index.html`中，我们使用这一简单的行将`CKEditor`添加到页面中：

```java
    <script type="text/javascript"
      src="img/ckeditor.js"></script>

```

`CKEditor`现在可以使用了。

前端的最后一个重要部分是让用户能够登录。为此，我们将创建另一个组件，如下所示：

```java
    <div id="app"> 
      <navbar></navbar> 
      <note-list v-bind:notes="notes" v-if="isLoggedIn"></note-list> 
      <note-form v-if="isLoggedIn"></note-form> 
    </div> 

```

然后，我们将添加以下组件定义：

```java
    Vue.component('navbar', { 
      template: '#navbar-template', 
      store, 
      data: function () { 
        return { 
          authUrl: "#" 
        }; 
      }, 
      methods: { 
        getAuthUrl: function () { 
          var self = this; 
          fetch('api/auth/url') 
          .then(function (response) { 
            return response.text(); 
          }) 
          .then(function (url) { 
            self.authUrl = url; 
          }); 
        } 
      }, 
      mounted: function () { 
        this.getAuthUrl(); 
      } 
    }); 

```

最后，我们将添加以下模板：

```java
    <script type="text/x-template" id="navbar-template"> 
      <div id="nav" style="grid-column: 1/span 2; grid-row: 1 / 1;"> 
        <a v-on:click="add" style="padding-right: 10px;"> 
          <img src="img/plus-225x225.png" height="20"  
            width="20" alt="add"> 
        </a> 
        <a v-on:click="logout" v-if="isLoggedIn">Logout</a> 
        <a v-if="!isLoggedIn" :href="authUrl"  
         style="text-decoration: none">Login</a> 
      </div> 
    </script> 

```

当这个组件被**挂载**（或附加到 DOM 中的元素）时，我们调用`getAuthUrl()`函数，该函数向服务器发送一个 Ajax 请求以获取我们的 Google 登录 URL。一旦获取到，登录锚点标签将更新以引用该 URL。

在我们这里没有明确涵盖的 JavaScript 文件中还有一些细节，但感兴趣的人可以查看存储库中的源代码，并阅读剩下的细节。我们已经为我们的笔记应用程序拥有了一个工作的 JavaScript 前端，支持列出、创建、更新和删除笔记，以及支持多个用户。这不是一个漂亮的应用程序，但它可以工作。对于一个 Java 程序员来说，还不错！

# 总结

现在我们回到了熟悉的调子 - 我们的应用程序已经**完成**。在这一章中我们涵盖了什么？我们使用 JAX-RS 创建了一个 REST API，不需要直接操作 JSON。我们学习了如何将请求过滤器应用到 JAX-RS 端点上，以限制只有经过身份验证的用户才能访问，我们使用 Google 的 OAuth2 工作流对他们的 Google 帐户进行了身份验证。我们使用 Payara Micro 打包了应用程序，这是开发微服务的一个很好的选择，并且我们使用了 MongoDB Java API 将 MongoDB 集成到我们的应用程序中。最后，我们使用 Vue.js 构建了一个非常基本的 JavaScript 客户端来访问我们的应用程序。

在这个应用程序中有很多新的概念和技术相互作用，这使得它在技术上非常有趣，但仍然有更多可以做的事情。应用程序可以使用大量的样式，支持嵌入式图像和视频也会很好，移动客户端也是如此。这个应用程序有很多改进和增强的空间，但感兴趣的人有一个坚实的基础可以开始。虽然对我们来说，现在是时候转向下一章和一个新的项目了，在那里我们将进入云计算的世界，使用函数作为服务。
