# 精通 Windows8 C++ 应用开发（二）

> 原文：[`zh.annas-archive.org/md5/B768CC5DACB0E0A295995599D27B3552`](https://zh.annas-archive.org/md5/B768CC5DACB0E0A295995599D27B3552)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：使用 XAML 构建 UI

用户界面和用户体验在 Windows 8 Store 应用程序中扮演着重要的角色。为 Store 应用程序创建了一种新的设计，现在称为现代设计风格（以前称为 Metro），其中关键词包括“快速流畅”、“内容优先”和“触摸为中心”。应用程序 UI 占据整个屏幕（除了在快照视图中），这使得 UI 变得更加重要。在本章（和下一章）中，我们将讨论为 Store 应用程序构建 UI 的方式，更多地是在技术层面上而不是在实际设计上。微软在线提供了大量设计 UI 的资源。

# XAML

C++ Store 应用程序通常使用**可扩展应用程序标记语言**（**XAML**）作为创建用户界面的主要语言。当首次提到 XAML 时，首先想到的问题是为什么？C++或任何其他现有的编程语言有什么问题吗？

XAML 是一种基于 XML 的语言，描述了“什么”，而不是“如何”；它是声明性的和中立的。从技术上讲，完整的应用程序可以在没有任何 XAML 的情况下编写；没有 XAML 可以做的事情是 C++做不到的。以下是 XAML 有意义的一些原因（或者至少可能有意义的一点）：

+   与 XAML 相比，C++非常冗长。XAML 通常比等效的 C++代码更短。

+   由于 XAML 是中立的，面向设计的工具可以读取和操作它。微软专门提供了 Expression Blend 工具用于此目的。

+   XAML 的声明性使得构建用户界面更容易（大多数情况下，用户习惯后），因为这些界面具有类似 XML 的树状结构。

XAML 本身与用户界面本身无关。XAML 是一种创建对象（通常是对象树）并设置其属性的方法。这适用于任何“XAML 友好”的类型，这意味着它应该具有以下特点：

+   默认的公共构造函数

+   可设置的公共属性

第二点不是严格要求，但是没有属性，对象就相当无聊。

### 注意

XAML 最初是为**Windows Presentation Foundation**（**WPF**）创建的，这是.NET 中的主要丰富客户端技术。现在它被其他技术所利用，主要是在.NET 空间中，比如 Silverlight 和**Windows Workflow Foundation**（**WF**）。

WinRT 中当前实现的 XAML 级别大致相当于 Silverlight 3 XAML。特别是，它不像 WPF 的 XAML 那样强大。

## XAML 基础知识

XAML 有一些规则。一旦我们理解了这些规则，就可以阅读和编写任何 XAML。最基本的 XAML 规则如下：

+   XML 元素意味着对象创建

+   XML 属性意味着设置属性（或事件处理程序）

有了这两条规则，下面的标记意味着创建一个`Button`对象，并将其`Content`属性设置为字符串`Click me`：

```cpp
<Button Content="Click me!" />
```

等效的 C++代码如下：

```cpp
auto b = ref new Button;
b->Content = "Click me";
```

创建新的空白应用程序项目时，会创建一个`MainPage.xaml`文件以及头文件和实现文件。以下是该 XAML 文件的外观：

```cpp
<Page
  x:Class="BasicXaml.MainPage"
  xmlns="http://schemas.microsoft.com/winfx/
  2006/xaml/presentation"

  xmlns:mc="http://schemas.openxmlformats.org/
  markup-compatibility/2006"
  mc:Ignorable="d">

  <Grid Background="{StaticResource  
    ApplicationPageBackgroundThemeBrush}">
  </Grid>
</Page>
```

详细了解这些行是值得的。在这个例子中，项目名称是`BasicXaml`。根元素是`Page`，并设置了一个`x:Class`属性，指示从`Page`继承的类，这里命名为`BasicXaml::MainPage`。请注意，类名是包括命名空间的完整名称，其中分隔符必须是句点（而不是 C++的作用域解析运算符`::`）。`x:Class`只能放在根元素上。

跟在根元素后面的是一堆 XML 命名空间声明。这些为页面整个 XAML 中使用的元素提供了上下文。默认的 XML 命名空间（没有名称）告诉 XAML 解析器，诸如`Page`、`Button`和`Grid`这样的类型可以直接写成它们自己，不需要任何特殊前缀。这是最常见的情况，因为页面中的大部分 XAML 都是用户界面元素。

下一个 XML 命名空间前缀是`x`，它指向 XAML 解析器的特殊指令。我们刚刚看到`x:Class`的作用。我们将在本章的后面遇到其他类似的属性。

接下来是一个名为`local`的前缀，它指向在`BasicXaml`命名空间中声明的类型。这允许在 XAML 中创建我们自己的对象；这些类型的前缀必须是`local`，以便 XAML 解析器知道在哪里查找这样的类型（当然，我们可以将其更改为任何我们喜欢的东西）。例如，假设我们创建了一个名为`MyControl`的用户控件派生类型。要在 XAML 中创建一个`MyControl`实例，我们可以使用以下标记：

```cpp
<local:MyControl />
```

`d`前缀用于与设计相关的属性，主要与 Expression Blend 一起使用。`mc:ignorable`属性说明`d`前缀应该被 XAML 解析器忽略（因为它与 Blend 与 XAML 的工作方式有关）。

`Grid`元素托管在`Page`内，"托管"将在下文中变得清晰。其`Background`属性设置为`{StaticResource ApplicationPageBackgroundThemeBrush}`。这是一个标记扩展，在本章的后面部分讨论。

### 注意

XAML 无法直接调用方法；它只能设置属性。这是可以理解的，因为 XAML 需要保持声明性的特性；它并不是作为 C++或任何其他编程语言的替代品。

## 类型转换器

XML 处理字符串。然而，很明显许多属性不是字符串。许多属性仍然可以指定为字符串，并且由于 XAML 解析器使用的类型转换器，仍然可以正确工作。以下是`Rectangle`元素的一个例子：

```cpp
<Rectangle Fill="Red" />
```

可以推测，`Fill`属性不是字符串类型。实际上，它是一个`Brush`。这里的`Red`实际上意味着`ref new SolidColorBrush(Colors::Red)`。XAML 解析器知道如何将字符串（例如`Red`和许多其他字符串）转换为`Brush`类型（在这种情况下是更具体的`SolidColorBrush`）。

类型转换器只是 XAML 的一个方面，使其比等效的 C++代码更简洁。

## 复杂属性

正如我们所见，设置属性是通过 XML 属性完成的。那么，对于无法表示为字符串并且没有类型转换器的复杂属性呢？在这种情况下，使用扩展语法（属性元素语法）来设置属性。这里有一个例子：

```cpp
<Rectangle Fill="Red">
  <Rectangle.RenderTransform>
    <RotateTransform Angle="45" />
  </Rectangle.RenderTransform>
</Rectangle>
```

设置`RenderTransform`属性不能使用简单的字符串；它必须是从`Transform`类派生的对象（在这种情况下是`RotateTransform`）。

### 注意

各种示例属性（`Fill`，`RenderTransform`等）的确切含义将在第四章中讨论，*布局、元素和控件*。

前面的标记等同于以下 C++代码：

```cpp
auto r = ref new Rectangle;
r->Fill = ref new SolidColorBrush(Colors::Red);
auto rotate = ref new RotateTransform();
rotate->Angle = 45;
r->RenderTransform = rotate; 
```

## 依赖属性和附加属性

各种元素和控件上的大多数属性都不是正常的，它们不是简单的私有字段的包装器。依赖属性的重要性将在第五章中讨论，*数据绑定*。现在，重要的是要意识到在 XAML 中，依赖属性和常规属性之间没有区别；语法是相同的。实际上，仅仅通过在 XAML 中使用某个属性，无法判断某个属性是依赖属性还是普通属性。

### 注意

依赖属性提供以下功能（详细解释在第六章中提供，*组件、模板和自定义元素*）：

+   当属性值改变时进行更改通知

+   某些属性的视觉继承（主要是与字体相关的属性）

+   可能影响最终值的多个提供者（一个获胜）

+   内存保护（值在改变时不分配）

某些 WinRT 功能，如数据绑定、样式和动画，依赖于该支持。

另一种依赖属性是附加属性。再次，详细讨论将推迟到第五章*数据绑定*，但基本上附加属性是上下文相关的——它由一个类型定义（具有将在第六章*组件、模板和自定义控件*中讨论的注册机制），但可以被任何继承自`DependencyObject`的类型使用（因为所有元素和控件都这样做）。由于这种属性不是由其使用的对象定义的，因此它在 XAML 中具有特殊的语法。以下是一个包含两个元素的`Canvas`面板的示例：

```cpp
<Canvas>
  <Rectangle Fill="Red" Canvas.Left="120" Canvas.Top="40"
    Width="100" Height="50"/>
  <Ellipse Fill="Blue" Canvas.Left="30" Canvas.Top="90" 
    Width="80" Height="80" />
</Canvas>
```

`Canvas.Left`和`Canvas.Top`是附加属性。它们由`Canvas`类定义，但附加到`Rectangle`和`Ellipse`元素上。附加属性只在某些情况下有意义。在这种情况下，它们指示画布内元素的确切位置。画布在布局阶段查找这些属性（在下一章中详细讨论）。这意味着，如果这些相同的元素放置在，比如一个`Grid`中，这些属性将没有效果，因为没有感兴趣的实体在这些属性中（但是没有伤害）。附加属性可以被视为动态属性，可以在对象上设置或不设置。

这是生成的 UI：

![依赖属性和附加属性](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_03_04.jpg)

在代码中设置附加属性有点冗长。以下是在名为`_myrect`的元素上设置`Canvas.Left`和`Canvas.Top`属性的等效 C++代码：

```cpp
Canvas::SetLeft(_myrect, 120);
Canvas::SetTop(_myrect, 40);
```

前面的调用将变得明显的原因将在我们学习如何在第六章*组件、模板和自定义元素*中创建附加属性时讨论。

## 内容属性

`Page`对象和`Grid`对象之间的关系并不明显。`Grid`似乎在`Page`内部。但是这如何转换为代码呢？`Page`/`Grid`标记可以总结如下（忽略详细标记）：

```cpp
<Page>
    <Grid Background="...">
    </Grid>
</Page>
```

这实际上是以下标记的快捷方式：

```cpp
<Page>
   <Page.Content>
      <Grid Background="...">
      </Grid>
   </Page.Content>
</Page>
```

这意味着`Grid`对象被设置为`Page`对象的`Content`属性；现在关系清晰了。XAML 解析器将某些属性（每个类型层次结构最多一个）视为默认或内容属性。它不一定要被命名为`Content`，但在`Page`的情况下是这样。这个属性在控件的元数据中使用`Windows::UI::Xaml::Markup::ContentAttribute`类属性来指定。在 Visual Studio 对象浏览器中查看`Page`类，没有这样的属性。但`Page`继承自`UserControl`；导航到`UserControl`，我们可以看到设置了该属性：

![内容属性](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_03_01.jpg)

### 注意

属性是一种以声明方式扩展类型元数据的方法。它们可以通过在应用该属性的项目之前的方括号中插入 C++/CX 中的属性类型名称来插入（可以是类、接口、方法、属性和其他代码元素）。属性类必须从`Platform::Metadata::Attribute`派生，才能被编译器视为这样的属性。

WinRT 类型中一些常见的`ContentProperty`属性如下：

+   `ContentControl`的`Content`（以及所有派生类型）

+   `UserControl`的`Content`

+   `Panel`的`Children`（所有布局容器的基类）

+   `ItemsControl`的`Items`（集合型控件的基类）

+   `GradientBrush`的`GradientStops`（`LinearGradientBrush`的基类）

## 集合属性

一些属性是集合（例如`IVector<T>`或`IMap<K,V>`类型）。这些属性可以填充对象，XAML 解析器将调用`IVector<T>::Append`或`IMap<K,V>::Insert`方法。这是`LinearGradientBrush`的一个示例：

```cpp
<Rectangle>
    <Rectangle.Fill>
        <LinearGradientBrush EndPoint="1,0">
            <GradientStop Offset="0" Color="Red" />
            <GradientStop Offset=".5" Color="Yellow" />
            <GradientStop Offset="1" Color="Blue" />
        </LinearGradientBrush>
    </Rectangle.Fill>
</Rectangle>
```

这里有两条规则。第一条是`LinearGradientBrush`的`ContentProperty`（`GradientStops`），不需要指定。它是`GradientStopCollection`类型，实现了`IVector<GradientStop>`，因此有资格进行自动追加。这相当于以下代码：

```cpp
auto r = ref new Rectangle;
auto brush = ref new LinearGradientBrush;
brush->EndPoint = Point(1.0, 0);
auto stop = ref new GradientStop;
stop->Offset = 0; stop->Color = Colors::Red;
brush->GradientStops->Append(stop);
stop = ref new GradientStop;
stop->Offset = 0.5; stop->Color = Colors::Yellow;
brush->GradientStops->Append(stop);
stop = ref new GradientStop;
stop->Offset = 1; stop->Color = Colors::Blue;
brush->GradientStops->Append(stop);
r->Fill = brush;
```

这可能是 XAML 语法优势在 C++上的第一个明显迹象。以下是矩形的全部荣耀：

![集合属性](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_03_02.jpg)

对于`IMap<K,V>`，必须在每个项目上设置名为`x:Key`的属性，以指示发送到`IMap<K,V>::Insert`方法的键。在本章后面，我们将讨论资源时，将看到这样一个地图的例子。

## 标记扩展

**标记扩展**是对 XAML 解析器的特殊指令，提供了表达超出对象创建或设置某些属性的方式。这些指令仍然是声明性的，但它们的代码等效通常涉及调用方法，在 XAML 中直接不可能。

标记扩展放置在花括号内作为属性值。它们可以包含参数和属性，我们将在后面的章节中看到。在空白页面中默认使用的唯一标记扩展是`{StaticResource}`，将在本章后面讨论。

### 注意

WPF 和 Silverlight 5 允许开发人员通过从`MarkupExtension`派生类来创建自定义标记扩展。当前 WinRT 实现中不支持此功能。

一种简单的标记扩展的例子是`{x:Null}`。每当需要指定值`nullptr`时，在 XAML 中使用它，因为没有更好的方法来使用字符串。以下示例在`Rectangle`元素中创建了一个空白：

```cpp
<Rectangle Stroke="Red" StrokeThickness="10" Fill="{x:Null}" />
```

## 命名元素

通过 XAML 创建的对象可以使用`x:Name` XAML 属性进行命名。以下是一个例子：

```cpp
<Rectangle x:Name="r1">
…
</Rectangle>
```

最终结果是一个私有成员变量（字段），由 XAML 编译器在`MainPage.g.h`中创建（如果在`MainPage.xaml`上工作）：

```cpp
private: ::Windows::UI::Xaml::Shapes::Rectangle^ r1;
```

引用本身必须在`MainPage::InitializeComponent`的实现中设置，使用以下代码：

```cpp
// Get the Rectangle named 'r1'
r1 = safe_cast<::Windows::UI::Xaml::Shapes::Rectangle^>(
    static_cast<Windows::UI::Xaml::IFrameworkElement^>(
    this)->FindName(L"r1"));
```

提到的文件和方法在* XAML 编译和执行*部分进一步讨论。无论它是如何工作的，`r1`现在是对该特定矩形的引用。

## 连接事件到处理程序

事件可以通过与设置属性相同的语法连接到处理程序，但在这种情况下，属性的值必须是代码后台类中具有正确委托签名的方法。

如果在输入事件名称后两次按下* Tab*，Visual Studio 会自动添加一个方法。Visual Studio 使用的默认名称包括元素的名称（`x:Name`）（如果有）或其类型（如果没有），后跟下划线和事件名称，如果检测到重复，则后跟下划线和索引。默认名称通常不理想；一个更好的方法，仍然让 Visual Studio 创建正确的原型，是按照我们想要的方式编写处理程序名称，然后右键单击处理程序名称并选择**导航到事件处理程序**。这将创建处理程序（如果不存在）并切换到方法实现。

以下是 XAML 事件连接的示例：

```cpp
<Button Content="Change" Click="OnChange" />
```

处理程序如下（假设 XAML 在`MainPage.xaml`中）：

```cpp
void MainPage::OnChange(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
}
```

### 提示

Visual Studio 还在类名前面写入命名空间名称（在前面的代码示例中删除了）；这可以安全地删除，因为文件顶部存在正确命名空间的使用命名空间语句。此外，使用`Platform::Object`而不仅仅是`Object`（以及类似于`RoutedEventArgs`）不够可读；命名空间前缀可以被移除，因为它们默认在文件顶部设置。

所有事件（按照惯例）使用类似的委托。第一个参数始终是事件的发送者（在本例中是`Button`），第二个参数是有关事件的额外信息。`RoutedEventArgs`是事件的最小类型，称为路由事件。路由事件的详细讨论将在下一章中进行。

## XAML 规则摘要

这是所有 XAML 规则的摘要：

+   XAML 元素意味着创建一个实例。

+   XAML 属性设置属性或事件处理程序。对于属性，根据属性的类型，可能会执行类型转换器。

+   使用`Type.Property`元素语法设置复杂属性。

+   使用`Type.Property`语法设置附加属性，其中`Type`是附加属性的声明类型。

+   `ContentPropertyAttribute`设置一个不需要指定的`Content`属性。

+   作为集合的属性会自动调用`Append`或`Insert`的 XAML 解析器。

+   标记扩展允许特殊（预定义）指令。

## 介绍 Blend for Visual Studio 2012 工具

Visual Studio 2012 安装了 Blend for Visual Studio 2012 工具。UI 设计师通常使用此工具来创建或操作基于 XAML 的应用程序的用户界面。

### 注意

Blend for Visual Studio 2012 的初始版本仅支持 Windows 8 商店应用程序和 Windows Phone 8 项目。对于 Visual Studio 2012 的更新 2 中添加了对 WPF 4.5 和 Silverlight 的支持。

Blend 可以与 Visual Studio 2012 一起使用，因为两者都能理解相同的文件类型（例如解决方案`.sln`文件）。在这两种工具之间来回切换并不罕见，每个工具都发挥其优势。这是 Blend 打开`CH03.sln`解决方案文件的屏幕截图（该解决方案包含本章节所有示例）：

![介绍 Blend for Visual Studio 2012 工具](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_03_10.jpg)

上述屏幕截图显示了一个特定的 XAML 文件打开，其中选择了一个按钮。Blend 由几个窗口组成，其中一些与其 Visual Studio 对应部分相似，即**项目**和**属性**。一些新窗口包括：

+   **资源**：包含 WinRT 中可用的元素和控件（以及其他一些有用的快捷方式）

+   **对象**和**时间轴**：包括可视树中的所有对象以及动画

+   **资源**：包含应用程序中的所有资源（参见下一节）

Blend 的设计界面允许操作元素和控件，这在 Visual Studio 中也是可能的。Blend 的布局和一些特殊的编辑功能使得 UI/图形设计师更容易使用，因为它模仿了其他流行的应用程序，如 Adobe Photoshop 和 Illustrator。

使用设计师进行的任何更改都会立即反映在更改的 XAML 中。切换回 Visual Studio 并接受重新加载选项会同步文件；当然，这两种方式都可以做到。

完全可以在 Blend 内部工作。按下*F5*以通常方式构建和启动应用程序。但是，Blend 不是 Visual Studio，不支持断点和其他调试任务。

Blend 是一个非常复杂的工具，远远超出了本书的范围。然而，通过实验可以走得更远。

## XAML 编译和执行

作为正常编译过程的一部分运行的 XAML 编译器，将 XAML 作为内部资源放置在 EXE 或 DLL 中。在 XAML 根元素类型（例如`MainPage`）的构造函数中，调用`InitializeComponent`。该方法使用静态辅助方法`Application::LoadComponent`来加载 XAML 并解析它，创建对象，设置属性等。这是编译器为`InitializeComponent`创建的实现（在`MainPage.g.hpp`中，进行了一些代码清理）：

```cpp
void MainPage::InitializeComponent() {
  if (_contentLoaded)
  return;

  _contentLoaded = true;

  // Call LoadComponent on ms-appx:///MainPage.xaml
  Application::LoadComponent(this, 
    ref new ::Windows::Foundation::Uri(
    L"ms-appx:///MainPage.xaml"),    
  ComponentResourceLocation::Application);
}
```

## 将 XAML、H 和 CPP 文件连接到构建过程

从开发人员的角度来看，使用 XAML 文件还需要另外两个文件，即 H 和 CPP。让我们更详细地检查一下它们。这是默认的 `MainPage.xaml.h`（已删除注释和命名空间）：

```cpp
#include "MainPage.g.h"

namespace BasicXaml {
  public ref class MainPage sealed {
    public:
    MainPage();

    protected:
    virtual void OnNavigatedTo(NavigationEventArgs^ e)
    override;
  };
}
```

代码显示了一个构造函数和一个名为 `OnNavigatedTo` 的虚方法重写（对于本讨论不重要）。似乎缺少的一件事是在前一节中提到的 `InitializeComponent` 方法声明。还有之前提到的从 `Page` 继承也缺失了。原来 XAML 编译器生成了另一个名为 `MainPage.g.h`（`g` 代表生成）的头文件，基于 XAML 本身（这可以通过顶部的 `#include` 声明来证明）。这个文件包含以下内容（可以通过选择 **项目** | **显示所有文件**，或等效的工具栏按钮，或右键单击 `#include` 并选择 **打开文档…** 来轻松打开）：

```cpp
namespace BasicXaml {
  partial ref class MainPage : public Page, 
  public IComponentConnector {
    public:
    void InitializeComponent();
    virtual void Connect(int connectionId, Object^ target);

    private:
    bool _contentLoaded;

  };
}
```

在这里我们找到了缺失的部分。在这里我们找到了 `InitializeComponent`，以及从 `Page` 派生。一个类怎么会有多个头文件？一个名为部分类的新 C++/CX 功能允许这样做。`MainPage` 类被标记为 `partial`，意味着它有更多的部分。最后一个部分不应该被标记为 `partial`，并且应该包含至少一个头文件，以便形成一个链，最终包括所有部分头文件；所有这些头文件必须是同一个编译单元（一个 CPP 文件）的一部分。`MainPage.g.h` 文件是在任何编译发生之前生成的；它是在编辑 XAML 文件时动态生成的。这很重要，因为命名元素是在那个文件中声明的，提供实例智能感知。

在编译过程中，`MainPage.cpp` 最终被编译，生成一个对象文件 `MainPage.obj`。它仍然有一些未解决的函数，比如 `InitializeComponent`。此时，`MainPage.obj`（以及其他 XAML 对象文件，如果存在）被用来生成元数据（`.winmd`）文件。

为了完成构建过程，编译器生成了 `MainPage.g.hpp`，实际上是一个实现文件，根据从元数据文件中提取的信息创建的（`InitializeComponent` 实现是在这个文件中生成的）。这个生成的文件只包含在一个名为 `XamlTypeInfo.g.cpp` 的文件中，这个文件也是根据元数据文件自动生成的（它的工作与数据绑定有关，如 第五章 中讨论的 *数据绑定*），但这已经足够让 `MainPage.g.hpp` 最终被编译，允许链接正确进行。

整个过程可以用以下图表总结：

![将 XAML、H 和 CPP 文件连接到构建过程](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_03_03.jpg)

# 资源

术语“资源”有很多含义。在经典的 Win32 编程中，资源指的是应用程序使用的只读数据块。典型的 Win32 资源包括字符串、位图、菜单、工具栏和对话框，但也可以创建自定义资源，使 Win32 将其视为未知的二进制数据块。

WinRT 定义了二进制、字符串和逻辑资源。以下部分讨论二进制和逻辑资源（字符串资源对于本节的本地化场景很有用，不在本节讨论范围内）。

## 二进制资源

二进制资源是指作为应用程序包的一部分提供的数据块。这些通常包括图像、字体和应用程序正常运行所需的任何其他静态数据。

可以通过在解决方案资源管理器中右键单击项目，然后选择 **添加现有项** 来将二进制资源添加到项目中。然后，选择必须位于项目目录或子目录中的文件。

### 注意

与 C#或 VB 项目相反，从位置添加现有项目不会将文件复制到项目的目录中。对于熟悉 C#/VB 项目的人来说，这种不一致性有点恼人，希望在将来的 Visual Studio 版本或服务包中能得到调和。

典型的商店应用程序项目已经在`Assets`项目文件夹中存储了一些二进制资源，即应用程序使用的图像：

![二进制资源](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_03_05.jpg)

使用文件夹是按类型或用途组织资源的好方法。右键单击项目节点并选择**添加新过滤器**会创建一个逻辑文件夹，可以将项目拖放到其中。

### 注意

与 C#/VB 项目相反，项目文件夹不会在文件系统中创建。建议实际上在文件系统中创建这些文件夹以便更好地组织。

添加的二进制资源作为应用程序包的一部分打包，并在可执行文件夹或子文件夹中可用，保持其相对位置。右键单击此类资源并选择**属性**会出现以下对话框：

![二进制资源](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_03_06.jpg)

**内容**属性必须设置为**是**才能实际可用（默认值）。**项目类型**通常会被 Visual Studio 自动识别。如果没有，我们可以始终将其设置为**文本**并在代码中进行任何操作。

### 提示

不要将**项目类型**设置为**资源**。这在 WinRT 中不受支持，会导致编译错误（此设置实际上是为 WPF/Silverlight 准备的）。

根据需要，可以在 XAML 或代码中访问二进制资源。以下是一个示例，使用存储在应用程序的`Assets`文件夹下`Images`文件夹中的子文件夹中名为`apple.png`的图像的`Image`元素：

```cpp
<Image Source="/Assets/Images/apple.png" />
```

注意相对 URI。前面的标记之所以有效是因为使用了类型转换器或`Image::Source`属性（类型为`ImageSource`）。该路径实际上是以下等效 URI 的快捷方式：

```cpp
<Image Source="ms-appx:///Assets/Images/apple.png" />
```

其他属性可能需要稍有不同的语法，但都是通过`ms-appx`方案生成，表示应用程序包的根。

应用程序引用的另一个组件中存储的二进制资源可以使用以下语法访问：

```cpp
<Image Source="/ResourceLibrary/jellyfish.jpg" />
```

标记假定应用程序引用了名为`ResourceLibrary.Dll`的组件 DLL，并且其根文件夹中存在名为`jellyfish.jpg`的二进制资源。

## 逻辑资源

二进制资源对于商店应用程序并不新鲜或独特。它们几乎永远存在。另一方面，逻辑资源是一个较新的添加。首先由 WPF 创建和使用，然后是各个版本的 Silverlight，它们也在 WinRT 中使用。那么，它们是什么？

逻辑资源几乎可以是任何东西。这些是对象，而不是二进制数据块。它们存储在`ResourceDictionary`对象中，并可以通过使用`StaticResource`标记扩展在 XAML 中轻松访问。

以下是使用相同画笔的两个元素的示例：

```cpp
<Ellipse Grid.Row="0" Grid.Column="1">
    <Ellipse.Fill>
        <LinearGradientBrush EndPoint="0,1">
            <GradientStop Offset="0" Color="Green" />
            <GradientStop Offset=".5" Color="Orange" />
            <GradientStop Offset="1" Color="DarkRed" />
        </LinearGradientBrush>
    </Ellipse.Fill>
</Ellipse>
<Rectangle Grid.Row="1" Grid.Column="1" StrokeThickness="20">
    <Rectangle.Stroke>
        <LinearGradientBrush EndPoint="0,1">
            <GradientStop Offset="0" Color="Green" />
            <GradientStop Offset=".5" Color="Orange" />
            <GradientStop Offset="1" Color="DarkRed" />
        </LinearGradientBrush>
    </Rectangle.Stroke>
</Rectangle>
```

问题应该是不言自明的。我们两次使用了同一画笔。这有两个原因不好：

+   如果我们想要更改画笔，我们需要做两次（因为重复）。如果该画笔被两个以上的元素使用，这自然会更严重。

+   尽管只需要一个共享对象，但创建了两个不同的对象。

`LinearGradientBrush`可以转换为逻辑资源（或简单资源），并被任何需要它的元素引用。为此，画笔必须放置在`ResourceDictionary`对象中。幸运的是，每个元素都有一个`Resources`属性（类型为`ResourceDictionary`）可以使用。这通常在根 XAML 元素（通常是`Page`）上完成，或者（我们马上会看到的）在应用程序的 XAML（`App.Xaml`）中完成：

```cpp
<Page.Resources>
    <LinearGradientBrush x:Key="brush1" EndPoint="0,1">
        <GradientStop Offset="0" Color="Green" />
        <GradientStop Offset=".5" Color="Orange" />
        <GradientStop Offset="1" Color="DarkRed" />
    </LinearGradientBrush>
</Page.Resources>
```

任何逻辑资源必须有一个键，因为它在字典中。该键由`x:Key`XAML 指令指定。一旦放置，资源可以通过以下方式使用`StaticResource`标记扩展从`Page`中的任何元素中访问：

```cpp
<Ellipse Fill="{StaticResource brush1}" />
<Rectangle Stroke="{StaticResource brush1}" StrokeThickness="40" />
```

`StaticResource`标记扩展从当前元素开始搜索具有指定键的资源。如果找不到，则在其父元素（例如 Grid）的资源上继续搜索。如果找到，则选择资源（在第一次请求时创建），并且`StaticResource`完成。如果找不到，则搜索父级的父级，依此类推。如果在顶级元素（通常是`Page`，但可以是`UserControl`或其他内容）中找不到资源，则在应用程序资源（`App.xaml`）中继续搜索。如果找不到，则抛出异常。搜索过程可以通过以下图表总结：

![逻辑资源](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_03_07.jpg)

### 注意

为什么标记扩展被称为`StaticResource`？是否有`DynamicResource`？`DynamicResource`仅存在于 WPF 中，它允许资源动态替换，并且所有绑定到它的对象都能注意到这种变化。这在 WinRT 中目前不受支持。

没有与`StaticResource`等效的单个调用，尽管如果需要，创建一个并不困难。可以在任何所需的级别上使用`FrameworkElement::Resources`属性进行查询，使用`Parent`属性导航到父元素。 `Application::Resources`属性具有特殊意义，因为在其中定义的任何资源都可以被整个应用程序中的任何页面或元素引用。这通常用于设置一致外观和感觉的各种默认值。

### 注意

将实际元素存储为资源可能很诱人（例如按钮）。应该避免这样做，因为资源在其使用容器中是单例；这意味着在同一页面中多次引用该按钮将导致在第二次引用时抛出异常，因为元素只能在可视树中出现一次。

资源实际上是用于可共享的对象，例如画笔、动画、样式和模板。

可以通过使用`ResourceDictionary::Insert`方法（在相关的`ResourceDictionary`上）动态添加资源，并通过调用`ResourceDictionary::Remove`来删除资源。这只对后续的{StaticResource}调用产生影响；已绑定的资源不受影响。

### 注意

资源也可以使用`StaticResource`标记扩展。为了使其工作，任何`StaticResource`必须引用在 XAML 中先前定义的资源；这是由于 XAML 解析器的工作方式。它无法找到尚未遇到的资源。

### 管理逻辑资源

逻辑资源可以是各种类型，例如画笔、几何图形、样式、模板等。将所有这些资源放在一个文件中，例如`App.xaml`，会阻碍可维护性。更好的方法是将不同类型的资源（或基于其他标准）从它们自己的文件中分离出来。但是，它们必须以某种方式从一个共同的文件（如`App.xaml`）中引用，以便它们被识别。

`ResourceDictionary`可以使用其`MergedDictionaries`属性（一个集合）合并其他资源字典。这意味着`ResourceDictionary`可以引用尽可能多的资源字典，并且可以拥有自己的资源。 `Source`属性必须指向`ResourceDictionary`的位置。由 Visual Studio 创建的默认`App.xaml`包含以下内容（已删除注释）：

```cpp
<Application.Resources>
    <ResourceDictionary>
        <ResourceDictionary.MergedDictionaries>
            <ResourceDictionary
              Source="Common/StandardStyles.xaml"/>
        </ResourceDictionary.MergedDictionaries>
    </ResourceDictionary>
</Application.Resources>
```

确实，在`Common`文件夹中我们找到了一个名为`StandardStyles.xaml`的文件，其中包含一堆逻辑资源，其根元素为`ResourceDictionary`。当调用`StaticResource`时，要考虑到这个文件，它必须被另一个`ResourceDictionary`引用，可以是从`Page`或应用程序引用（应用程序更常见）。`ResourceDictionary::MergedDictionaries`属性包含其他`ResourceDictionary`对象，其`Source`属性必须指向要包含的所需 XAML 文件（该 XAML 文件必须以`ResourceDictionary`作为其根元素）。

我们可以使用 Visual Studio 的**添加新项**菜单选项并选择**资源字典**来创建自己的`ResourceDictionary` XAML：

![管理逻辑资源](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_03_08.jpg)

### 重复的键

在同一个`ResourceDictionary`实例中，两个对象不能具有相同的键。`StaticResource`会获取它在指定键中找到的第一个资源，即使该键已经存在于`ResourceDictionary`中。那么合并字典呢？

合并不同的资源字典可能会导致问题——来自不同合并字典的两个或更多具有相同键的资源。这不是错误，也不会引发异常。相反，所选对象是来自最后一个添加的资源字典（具有该键的资源）。此外，如果当前资源字典中的资源与其合并字典中的任何资源具有相同的键，它总是胜出。以下是一个例子：

```cpp
<ResourceDictionary>
  <SolidColorBrush Color="Blue" x:Key="brush1" />
  <ResourceDictionary.MergedDictionaries>
    <ResourceDictionary Source="Resources/Brushes2.xaml" />
    <ResourceDictionary Source="Resources/Brushes1.xaml" />
  </ResourceDictionary.MergedDictionaries>
</ResourceDictionary>     
```

根据这个标记，名为`brush1`的资源是蓝色的`SolidColorBrush`，因为它出现在`ResourceDictionary`本身中。这会覆盖合并字典中命名为`brush1`的任何资源。如果这个蓝色的画笔不存在，`brush1`将首先在`Brushes1.xaml`中查找，因为这是合并字典集合中的最后一个条目。

### 注意

包含`ResourceDictionary`作为其根的 XAML 可以使用静态`XamlReader::Load`方法从字符串动态加载，然后根据需要添加为合并字典。

# 样式

用户界面的一致性是一个重要特征；一致性有许多方面，其中之一是控件的一致外观和感觉。例如，所有按钮应该大致相同——类似的颜色、字体、大小等。样式提供了一种方便的方式，将一组属性分组到一个单一对象下，然后有选择地（或自动地，我们稍后会看到）将其应用到元素上。

样式总是被定义为资源（通常在应用程序级别，但也可以在`Page`或`UserControl`级别）。一旦定义，它们可以通过设置`FrameworkElement::Style`属性应用到元素上。

以下是作为`Page`的`Resources`部分的一部分定义的样式：

```cpp
<Page.Resources>
    <Style TargetType="Button" x:Key="style1">
        <Setter Property="FontSize" Value="40" />
        <Setter Property="Background">
            <Setter.Value>
                <LinearGradientBrush >
                    <GradientStop Offset="0" Color="Yellow" />
                    <GradientStop Offset="1" Color="Orange" />
                </LinearGradientBrush>
            </Setter.Value>
        </Setter>
        <Setter Property="Foreground" Value="DarkBlue" />
    </Style>
</Page.Resources>
```

该样式有一个键（`style1`），并且必须有`TargetType`。这是样式可以应用到的类型（以及任何派生类型）。XAML 解析器具有将`TargetType`转换为`TypeName`对象的类型转换器。

`Style`中的主要成分是其`Setters`集合（也是其`ContentProperty`）。该集合接受`Setter`对象，需要`Property`和`Value`。属性必须是依赖属性（通常不是问题，因为大多数元素属性都是依赖属性）；这些依赖属性由于幕后使用的类型转换器而作为简单字符串提供。

上面的标记设置了`FontSize`、`Background`（由于`LinearGradientBrush`的复杂属性语法）和`Foreground`属性，都是为`Button`控件设置的。

一旦定义，样式可以通过在 XAML 中使用通常的`StaticResource`标记扩展来应用到元素，通过设置`FrameworkElement::Style`属性，如下例所示：

```cpp
<Button Content="Styled button" Style="{StaticResource style1}" />
```

### 注意

熟悉 WPF 的读者可能会想知道是否可以省略`TargetType`属性，以便覆盖更大的控件范围。在当前版本的 WinRT 中不支持这样做。

在不兼容的元素类型上设置样式（例如在此示例中的`CheckBox`控件）会导致在页面加载时抛出异常。如果`CheckBox`也应该能够使用相同的样式，则可以将`TargetType`更改为`ButtonBase`（涵盖所有按钮类型）。

### 注意

为不同的元素使用不同的样式，即使基本类型似乎覆盖了几个控件。很可能以后某些属性可能需要针对特定类型进行微调，这样更改样式就会变得困难。为不同的具体类型构建不同的样式。您还可以使用样式继承（如后面所述）来缩短一些标记。

如果具有应用样式的元素将属性设置为与`Style`中的属性不同的值会发生什么？本地值获胜。这意味着以下按钮的字体大小为`30`而不是`40`：

```cpp
<Button Content="Styled button" FontSize="30" 
        Style="{StaticResource style1}" />
```

## 隐式（自动）样式

前一节展示了如何创建具有名称（`x:Key`）的样式以及如何将其应用于元素。然而，有时我们希望样式自动应用于特定类型的所有元素，以使应用程序具有一致的外观。例如，我们可能希望所有按钮都具有特定的字体大小或背景，而无需为每个按钮设置`Style`属性。这样可以更轻松地创建新按钮，因为开发人员/设计人员不必知道应用哪种样式（如果有的话，将自动使用范围内的隐式样式）。

要创建自动应用的`Style`，必须删除`x:Key`属性：

```cpp
 <Style TargetType="Button">
 …
 </Style>
```

键仍然存在，因为`Style`属性仍然是`ResourceDictionary`的一部分（实现了`IMap<Object, Object>`），但会自动设置为指定`TargetType`的`TypeName`对象。

一旦`Style`属性被定义，并且在`ResourceDictionary`的`Style`属性范围内有任何`Button`元素（在本例中），那么该样式将自动应用。元素仍然可以通过设置本地值来覆盖任何属性。

### 注意

自动样式仅应用于确切类型，而不适用于派生类型。这意味着`ButtonBase`的自动样式是无用的，因为它是一个抽象类。

元素可能希望恢复其默认样式，并且不希望自动应用隐式样式。这可以通过将`FrameworkElement::Style`设置为`nullptr`（在 XAML 中为`x:Null`）来实现。

## 样式继承

样式支持继承的概念，与面向对象中的相同概念有些类似。这是使用`BasedOn`属性完成的，该属性必须指向要继承的另一个样式。派生样式的`TargetType`必须与基本样式中的相同。

继承样式可以为新属性添加`Setter`对象，或者可以为基本样式设置的属性提供不同的值。以下是按钮的基本样式示例：

```cpp
<Style TargetType="Button" x:Key="buttonBaseStyle">
    <Setter Property="FontSize" Value="70" />
    <Setter Property="Margin" Value="4" />
    <Setter Property="Padding" Value="40,10" />
    <Setter Property="HorizontalAlignment" Value="Stretch" />
</Style>
```

以下标记创建了三种继承样式：

```cpp
<Style TargetType="Button" x:Key="numericStyle" 
       BasedOn="{StaticResource buttonBaseStyle}">
    <Setter Property="Background" Value="Blue" />
    <Setter Property="Foreground" Value="White" />
</Style>
<Style TargetType="Button" x:Key="operatorStyle" 
       BasedOn="{StaticResource buttonBaseStyle}">
    <Setter Property="Background" Value="Orange" />
    <Setter Property="Foreground" Value="Black" />
</Style>
<Style TargetType="Button" x:Key="specialStyle" 
       BasedOn="{StaticResource buttonBaseStyle}">
    <Setter Property="Background" Value="Red" />
    <Setter Property="Foreground" Value="White" />
</Style>
```

这些样式是一个简单的整数计算器应用程序的一部分。运行时，计算器如下所示：

![Style inheritance](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_03_09.jpg)

计算器的大部分元素都是按钮。以下是数字按钮的标记：

```cpp
<Button Style="{StaticResource numericStyle}" Grid.Row="1" 
        Content="7" Click="OnNumericClick" />
<Button Style="{StaticResource numericStyle}" Grid.Row="1" 
        Grid.Column="1" Content="8" Click="OnNumericClick"/>
<Button Style="{StaticResource numericStyle}" Grid.Row="1" 
        Grid.Column="2"  Content="9" Click="OnNumericClick"/>
```

运算符按钮只是使用了不同的样式：

```cpp
<Button Style="{StaticResource operatorStyle}" Grid.Row="3" 
      Grid.Column="3" Content="-" Click="OnOperatorClick"/>
<Button Style="{StaticResource operatorStyle}" Grid.Row="4" 
      Grid.Column="3" Content="+" Grid.ColumnSpan="2" 
      Click="OnOperatorClick"/>
```

`=`按钮使用与运算符相同的样式，但通过设置本地值来更改其背景：

```cpp
<Button Style="{StaticResource operatorStyle}" Grid.Row="4" 
    Grid.Column="1" Grid.ColumnSpan="2" Content="=" 
 Background="Green" Click="OnCalculate"/>
```

完整项目名为`StyledCalculator`，可以在本章可下载源代码的一部分中找到。

样式继承可能看起来非常有用，但应谨慎使用。它遭受与面向对象继承相同的问题，在深层继承层次结构中，上层样式的更改可能会影响很多样式，有点不可预测，导致维护噩梦。因此，一个好的经验法则是最多有两个继承级别。超过这个数量可能会导致事情失控。

## 存储应用程序样式

由 Visual Studio 创建的商店应用项目在`Common`文件夹中有一个名为`StandardStyles.xaml`的默认样式文件。该文件包括所有常见元素和控件的样式，设置了一个推荐的共同外观和感觉作为起点。当然，可以根据需要更改这些样式或从中继承。

### 注意

WinRT 样式在概念上类似于 Web 开发中使用的 CSS，用于为 HTML 页面提供样式。层叠部分暗示了 CSS 的多层性质，就像 WinRT 样式的多层性质一样（应用程序、页面、面板、特定元素等）。

# 总结

本章主要讨论了 XAML，这是用于构建 Windows 商店应用用户界面的声明性语言。XAML 需要一些时间来适应，但它的声明性特性和标记扩展很难用 C++（或其他语言）的过程性代码来匹配。面向设计师的工具，如 Expression Blend 甚至 Visual Studio 设计师，使得相对容易地操纵 XAML 而不实际编写 XAML，但正如已经意识到的其他基于 XAML 的技术的开发人员和设计师所知，有时需要手动编写 XAML，这使得它成为一项重要的技能。

在下一章中，我们将继续大量使用 XAML，同时涵盖在 Windows 8 商店应用中使用的元素、控件和布局。


# 第四章：布局、元素和控件

上一章讨论了 XAML，这是一种中立的语言，用于创建对象并设置它们的属性。但是 XAML 只是一个工具，内容才是最重要的。构建有效的用户界面至少涉及选择最佳的元素和控件，以实现可用性和所需的用户体验。

在本章中，我们将介绍 WinRT 布局系统，并讨论构成大多数用户界面的主要元素和控件。

# 介绍布局

布局是元素放置和它们的大小和位置在用户交互或内容更改时发生变化的过程。在 Win32/MFC 世界中，布局通常非常简单和有限。控件是使用距离窗口左上角的距离放置的，并且它们的大小是明确指定的。这种模型的灵活性非常有限；如果控件的内容发生变化（例如变得更大），控件无法自动补偿。其他类似的变化对 UI 布局没有影响。

另一方面，WinRT 提供了一个基于一组布局面板的更灵活的模型，这些面板提供了不同的布局元素的方式。通过以各种方式组合这些面板，可以创建复杂和自适应的布局。

布局是一个两步过程。首先，布局容器询问每个子元素它们所需的大小。在第二步中，它使用适用的任何逻辑（对于该面板类型）来确定每个子元素的位置和大小，并将每个子元素放置在该矩形区域中。

每个元素向其父元素指示其大小要求。以下图总结了与这些要求相关的最重要的属性：

![Introducing layout](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_04_01.jpg)

以下是这些重要属性的快速概述：

+   `Width`/`Height` – 所讨论的元素的宽度和高度。通常不设置（在 XAML 中未设置值为默认值—`"Auto"`—更多内容稍后会介绍），这意味着元素希望尽可能大。但是，如果需要，这些可以设置。元素的实际（渲染）宽度和高度可以使用`FrameworkElement::ActualWidth`和`ActualHeight`只读属性获得。

+   `MinWidth`/`MaxWidth`/`MinHeight`/`MaxHeight` – 元素大小的最小值和最大值（图中未显示）。默认值为最小值为`0`，最大值为无穷大。

+   `Margin` – 元素周围的“呼吸空间”。这是`Thickness`类型，有四个字段（`Left`、`Top`、`Right`和`Bottom`），用于确定元素周围的空间量。它可以在 XAML 中使用四个值（左、上、右、下）、两个值（第一个是左和右，第二个是上和下）或一个单一数字（四个方向上的相同距离）来指定。

+   `Padding` – 与`Margin`相同的概念，但确定元素的外边缘与其内容（如果有）之间的空间。这也被定义为`Thickness`，并由`Control`基类和一些其他特殊元素（如`Border`和`TextBlock`）定义。

+   `HorizontalAlignment`/`VerticalAlignment` – 指定元素相对于其父元素对齐的方式（如果有额外的空间）。可能的值是`Left`、`Center`、`Right`和`Stretch`（对于`HorizontalAlignment`），以及`Top`、`Center`、`Bottom`和`Stretch`（对于`VerticalAlignment`）。

+   `HorizontalContentAlignment`/`VerticalContentAlignment`（图中未显示）– 与`Horizontal`/`VerticalAlignment`相同的概念，但用于元素的`Content`（如果有）。

+   `FlowDirection` – 可用于将布局方向从默认值（`LeftToRight`）切换到`RightToLeft`，适用于从右到左的语言，如希伯来语或阿拉伯语。这实际上将每个“左”变为“右”，反之亦然。

在布局面板收集每个子元素所需的大小（通过对每个元素调用`UIElement::Measure`）之后，它进入布局的第二阶段——排列。在这个阶段，面板根据元素的期望大小（`UIElement::DesiredSize`只读属性）和适合该面板的任何算法来计算其子元素的最终位置和大小，并通过调用`UIElement::Arrange`通知每个元素所得到的矩形。这个过程可以递归进行，因为一个元素本身可以是一个布局面板，依此类推。结果被称为可视树。

### 注意

感兴趣的读者可能想知道如何在代码中为`Width`（例如）指定`"Auto"`XAML 值，因为这是一个`double`值。这是通过包括`<limits>`，然后使用表达式`std::numeric_limits<double>::quiet_NaN()`来完成的。类似地，要指定无限值，请使用`std::numeric_limits<double>::infinity()`。

# 布局面板

所有布局面板都必须派生自`Windows::UI::Xaml::Controls::Panel`类，它本身派生自`FrameworkElement`。主要的附加`Panel`是`Children`属性（也是它的`ContentProperty`，用于更容易的 XAML 编写），它是实现`IVector<UIElement>`接口的元素集合。通过使用`Children`属性，可以动态地向`Panel`添加或删除元素。WinRT 提供了一堆特定的面板，每个面板都有自己的布局逻辑，提供了创建布局的灵活性。在接下来的章节中，我们将看一些内置的布局面板。

### 注意

所有面板类，以及稍后描述的元素和控件，都假定存在于`Windows::UI::Xaml::Controls`命名空间中，除非另有说明。

## StackPanel

`StackPanel`是最简单的布局面板之一。它根据`Orientation`属性（`Vertical`是默认值）在*堆栈*中水平或垂直地布置其子元素。

当用于垂直布局时，每个元素都会得到它想要的高度和所有可用的宽度，反之亦然。这是`StackPanel`与一些元素的示例：

```cpp
<StackPanel Orientation="Horizontal" >
    <TextBlock Text="Name:" FontSize="30" Margin="0,0,10,0"/>
    <TextBox Width="130" FontSize="30"/>
</StackPanel>
```

这是运行时的样子（在输入一些文本后）：

![StackPanel](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_04_02.jpg)

`StackPanel`对于小型布局任务很有用，作为其他更复杂的布局面板的一部分。

## Grid

`Grid`可能是最有用的布局面板，因为它很灵活。它创建了一个类似表格的单元格布局。元素可以占据单个或多个单元格，单元格大小是可定制的。我们已经使用`Grid`来创建了上一章中的计算器布局。这里是另一个`Grid`示例（包装在`Border`元素中），一个登录页面的标记：

```cpp
<Border HorizontalAlignment="Center" VerticalAlignment="Center"
    BorderThickness="1" BorderBrush="Blue" Padding="10">
    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto" />
            <RowDefinition Height="Auto" />
            <RowDefinition Height="Auto" />
            <RowDefinition Height="Auto" />
        </Grid.RowDefinitions>
        <Grid.ColumnDefinitions>
            <ColumnDefinition />
            <ColumnDefinition />
        </Grid.ColumnDefinitions>
        <TextBlock Text="Enter credentials:" Grid.ColumnSpan="2"
            TextAlignment="Center" FontSize="40" Margin="20"/>
        <TextBlock Text="Username:" TextAlignment="Right"
            Margin="10" Grid.Row="1" FontSize="40"
            VerticalAlignment="Bottom"/>
        <TextBox HorizontalAlignment="Left" Width="250"
            Grid.Row="1" Grid.Column="1" Margin="10" 
            FontSize="30" />
        <TextBlock Text="Password:" TextAlignment="Right"
            Margin="10" Grid.Row="2" FontSize="40"
            VerticalAlignment="Bottom" />
        <PasswordBox HorizontalAlignment="Left" Width="250"
            Grid.Row="2" Grid.Column="1" Margin="10" 
            FontSize="30" />
        <Button Content="Login" HorizontalAlignment="Stretch"
            Grid.Row="3" FontSize="30" Margin="10,30,10,10"
            Background="Green" />
        <Button Content="Cancel" HorizontalAlignment="Center" 
            Grid.Row="3" Grid.Column="1" FontSize="30" 
            Margin="10,30,10,10" Background="Red" />
    </Grid>
</Border>
```

这是运行时的样子：

![Grid](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_04_03.jpg)

行数和列数不是通过简单的属性来指定的。而是使用`RowDefinition`对象（对于行）和`ColumnDefinition`对象（对于列）来指定。原因在于可以根据行和/或列的大小和行为来指定。

`RowDefinition`有一个`Height`属性，而`ColumnDefintion`有一个`Width`属性。两者都是`GridLength`类型。有三种设置`GridLength`的选项：

+   特定长度

+   基于星号的（相对）因子（这是默认值，因子等于 1）

+   自动长度

将`Height`（`RowDefintion`）或`Width`（`ColumnDefinition`）设置为特定数字会使该行/列具有特定的大小。在代码中，它相当于`ref new GridLength(len)`。

在 XAML 中将`Height`或`Width`设置为`"Auto"`会使行/列的高度/宽度根据放置在该行/列中的最高/最宽元素的需要而定。在代码中，它相当于静态属性`GridLength::Auto`。

最后一个选项（默认情况下）是在 XAML 中将`Height`/`Width`设置为`n*`，其中*n*是一个数字（如果省略则为`1`）。这将与具有“星号”长度的其他行/列建立关系。例如，这是`Grid`的三行：

```cpp
<RowDefinition Height="2*" />
<RowDefinition />
<RowDefinition Height="3*" />
```

这意味着第一行的高度是第二行的两倍（`Height="*"`）。最后一行比第二行高三倍，比第一行高一倍半。即使`Grid`由于布局更改而动态调整大小，这些关系也会保持不变。

### 注意

“星号”因子的值不必是整数；它也可以是浮点数值。重要的是比例，而不是实际数字。

使用附加的`Grid.Row`和`Grid.Column`属性将元素放置在特定的网格单元格中（两者默认为零，意味着第一行和第一列）。

元素默认情况下占用一个单元格。可以通过使用`Grid.RowSpan`和`Grid.ColumnSpan`属性来更改这一点（在先前的 XAML 中为第一个`TextBlock`设置了这个属性）。

### 提示

可以使用大数字指定`ColumnSpan`或`RowSpan`以确保元素将占据给定方向上的所有单元格。`Grid`将自动使用实际的行/列计数。

## 画布

`Canvas`模拟了经典的 Win32/MFC 布局——精确定位。如果需要精确坐标，例如图形、动画、图形游戏和其他复杂绘图的情况下，这种布局很有用。`Canvas`是最快的布局面板，因为它几乎没有布局（实际上几乎没有）。

以下是`Canvas`托管一些形状的示例：

```cpp
<Canvas x:Name="_canvas" >
    <Ellipse Stroke="White" StrokeThickness="2" Fill="Red" 
        Width="100" Height="100" Canvas.Left="50"/>
    <Rectangle Stroke="White" StrokeThickness="2" Fill="Green" 
        Canvas.Left="100" Canvas.Top="120" Width="120" 
        Height="120"/>
    <Polygon Points="0,0 150,60 50,-70" Canvas.Left="250" 
        Canvas.Top="200" Fill="Blue" Stroke="White" 
        StrokeThickness="2" />
</Canvas>
```

输出如下所示：

![Canvas](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_04_04.jpg)

使用`Canvas.Left`和`Canvas.Top`附加属性设置放置坐标（两者默认为零，意味着`Canvas`的左上角）。`Canvas`定义的唯一其他附加属性是`ZIndex`。这指定了在`Canvas`内部渲染元素的相对顺序，其中大值将元素放置在顶部。默认情况下，XAML 中后定义的元素在 Z 顺序中更高。

作为更复杂的示例，假设我们想要允许用户使用鼠标或手指在`Canvas`上拖动形状。首先，我们将为指针按下、释放和移动添加事件处理程序：

```cpp
<Canvas x:Name="_canvas" PointerPressed="OnPointerPressed" PointerReleased="OnPointerReleased" PointerMoved="OnPointerMoved">
```

### 注意

“指针”的概念取代了可能熟悉的来自 Win32/MFC/WPF/Silverlight 的“鼠标”事件名称；指针是通用的，代表任何指针设备，无论是鼠标、触控笔还是手指。

与指针相关的事件使用冒泡策略，这意味着对元素（例如使用的形状）的任何按压都会首先引发该形状上的`PointerPressed`事件，如果未处理（在这种情况下），则会冒泡到其父级（`Canvas`）上，那里会得到处理。

`PointerPressed`事件可以这样处理：

```cpp
void MainPage::OnPointerPressed(Platform::Object^ sender,
   PointerRoutedEventArgs^ e) {
  _element = (FrameworkElement^)e->OriginalSource;
  if(_element == _canvas) return;
  _lastPoint = e->GetCurrentPoint(_canvas)->Position;
  _lastPoint.X -= (float)Canvas::GetLeft(_element);
  _lastPoint.Y -= (float)Canvas::GetTop(_element);
  _canvas->CapturePointer(e->Pointer);
  e->Handled = true;
  _isMoving = true;
}
```

由于此事件在`Canvas`上触发，即使原始元素是`Canvas`的子元素，我们如何才能到达该子元素？发送者参数是实际发送事件的对象——在这种情况下是`Canvas`。子元素由`PointerRoutedEventArgs::OriginalSource`属性指示（从`RoutedEventArgs`继承）。首先，检查是否按下指针实际上在`Canvas`本身上。如果是，该方法立即返回。

### 注意

在前面的`Canvas`中，这是不可能发生的。原因是`Canvas`的默认`Background`（或者任何其他`Panel`）是`nullptr`，因此无法在其上注册事件——它们会传播到其父级。如果需要`Canvas`本身上的事件，`Background`必须是一些非`nullptr`的`Brush`；如果父级的背景`Brush`需要显示，使用`ref new SolidColorBrush(Colors::Transparent)`就足够了。

接下来，通过两个步骤提取按压的位置，首先使用`PointerRoutedEventArgs::GetCurrentPointer()`（这是一个`PointerPoint`对象），然后使用`PointerPoint::Position`属性（类型为`Windows::Foundation::Point`）。然后调整该点，使其成为按压点到元素左上角位置的偏移量，这有助于使后续移动准确。

捕获指针（`UIElement::CapturePointer`）确保`Canvas`继续接收指针相关事件，无论指针在何处。将`PointerRoutedEventArgs::Handled`设置为`true`可以防止进一步的冒泡（因为这里没有必要），并且设置一个标志，指示从现在开始应该发生移动，直到释放指针（另一个私有成员变量）。

### 注意

指针捕获与其他 UI 技术（Win32/MFC/WPF/Silverlight）中存在的鼠标捕获概念类似。

当指针移动时，相关元素也需要移动，只要指针尚未释放：

```cpp
void MainPage::OnPointerMoved(Platform::Object^ sender,
   PointerRoutedEventArgs^ e) {
  if(_isMoving) {
    auto pos = e->GetCurrentPoint(_canvas)->Position;
    Canvas::SetLeft(_element, pos.X - _lastPoint.X);
    Canvas::SetTop(_element, pos.Y - _lastPoint.Y);
    e->Handled = true;
  }
}
```

这里的主要思想是通过设置附加的`Canvas`属性`Canvas.Left`和`Canvas.Top`（使用静态的`Canvas::SetLeft`和`Canvas::SetTop`方法）来移动元素。

当指针最终释放时，我们只需要进行一些清理工作：

```cpp
void MainPage::OnPointerReleased(Platform::Object^ sender,
   PointerRoutedEventArgs^ e) {
  _isMoving = false;
  _canvas->ReleasePointerCapture(e->Pointer);
  e->Handled = true;
}
```

完整的代码在一个名为`CanvasDemo`的项目中，是本章可下载代码的一部分。

### 注意

指针相关的方法可能看起来比需要的更复杂，但实际上并非如此。由于触摸输入通常是多点触控，如果两根手指同时按在两个不同的元素上并尝试移动它们会发生什么？可能会触发多个`PointerPressed`事件，因此需要一种方法来区分一个手指和另一个手指。先前的代码是在假设一次只使用一个手指的情况下实现的。

### 动态向面板添加子元素

`Panel::Children`属性可以通过编程方式进行操作（适用于任何`Panel`类型）。例如，使用`Canvas`作为绘图表面，我们可以使用先前的指针事件来添加连接到彼此的`Line`元素以创建绘图。当指针移动（在按下后），可以使用以下代码添加`Line`对象：

```cpp
void MainPage::OnPointerMoved(Object^ sender, 
   PointerRoutedEventArgs^ e) {
  if(_isDrawing) {
    auto pt = e->GetCurrentPoint(_canvas);
    auto line = ref new Line();
    line->X1 = _lastPoint->Position.X;
    line->Y1 = _lastPoint->Position.Y;
    line->X2 = pt->Position.X;
    line->Y2 = pt->Position.Y;
    line->StrokeThickness = 2;
    line->Stroke = _paintBrush;
    _canvas->Children->Append(line);
    _lastPoint = pt;
  }
}
```

构造了一个`Line`对象，设置了适当的属性，最后将其添加到`Canvas`的`Children`集合中。如果没有这最后一步，那么`Line`对象将不会附加到任何东西上，并且当其引用超出范围时，它将被销毁。`_paintBrush`是由托管页面维护的`Brush`字段（未显示）。

完整的源代码在一个名为`SimpleDraw`的项目中，是本章可下载代码的一部分。以下是使用此应用程序完成的示例绘图：

![动态向面板添加子元素](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_04_05.jpg)

## VariableSizedWrapGrid

`StackPanel`、`Grid`和`Canvas`都非常直观；它们与 WPF 或 Silverlight 中的对应物几乎没有什么不同。WinRT 有一些更有趣的面板，从`VariableSizedWrapGrid`开始。

顾名思义，它本质上是一个网格，其中的项目按行或列排列（取决于`Orientation`属性）。当空间不足时，或者如果一行/列中的项目数量达到了`MaximumRowsOrColumns`属性设置的限制，布局将继续到下一行/列。

最后一个关于`VariableSizedWrapGrid`的技巧是，它有两个附加属性，`RowSpan`和`ColumnSpan`，可以改变一个项目的大小，使其占据多个单元格。以下是一个带有一堆`Rectangle`元素的`VariableSizedWrapGrid`示例：

```cpp
<Grid Background=
    "{StaticResource ApplicationPageBackgroundThemeBrush}">
    <Grid.Resources>
        <Style TargetType="Rectangle">
            <Setter Property="Stroke" Value="White" />
            <Setter Property="StrokeThickness" Value="2" />
            <Setter Property="Margin" Value="8" />
            <Setter Property="Width" Value="100" />
            <Setter Property="Height" Value="100" />
            <Setter Property="Fill" Value="Red" />
        </Style>
    </Grid.Resources>
    <VariableSizedWrapGrid x:Name="_grid"     
        Orientation="Horizontal" 
        MaximumRowsOrColumns="6">
        <Rectangle />
        <Rectangle Fill="Yellow" />
        <Rectangle Fill="Purple"/>
        <Rectangle />
        <Rectangle Fill="Blue" VariableSizedWrapGrid.RowSpan="2" 
           Height="200"/>
        <Rectangle />
        <Rectangle Fill="Brown"/>
        <Rectangle VariableSizedWrapGrid.ColumnSpan="2" 
           Width="200" Fill="Aqua"/>
        <Rectangle Fill="LightBlue"/>
        <Rectangle Fill="Green"/>
        <Rectangle VariableSizedWrapGrid.ColumnSpan="2"
           VariableSizedWrapGrid.RowSpan="2" Width="150" 
           Height="150" Fill="BlueViolet"/>
        <Rectangle Fill="AntiqueWhite"/>
        <Rectangle Fill="Azure"/>
        <Rectangle />
        <Rectangle Fill="BlanchedAlmond"/>
        <Rectangle Fill="Orange"/>
        <Rectangle Fill="Crimson"/>
        <Rectangle Fill="DarkGoldenrod"/>
    </VariableSizedWrapGrid>
</Grid>
```

这是结果：

![VariableSizedWrapGrid](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_04_06.jpg)

## 面板虚拟化

所有先前讨论的面板在添加时都会创建它们的子元素。对于大多数情况，这是可以接受的。但是，如果项目数量非常多（数百个或更多），面板的性能可能会下降，因为需要创建和管理许多元素，占用内存并在创建时浪费 CPU 周期，或在布局更改时发生。虚拟化面板不会一次性创建它所持有的项目的所有元素；相反，它只会创建当前可见的实际元素。如果用户滚动以查看更多数据，则会根据需要创建元素。滚出视图的元素可能会被销毁。这种方案节省了内存和 CPU 时间（在创建时）。

`VirtualizingPanel`类是 WinRT 中所有虚拟化面板实现的抽象基类。`VirtualizingPanel`的进一步细化是`OrientedVirtualizingPanel`，表示具有固有方向的面板。WinRT 提供了三种虚拟化面板，我们将在稍后看到。

所有虚拟化面板都有一个更有趣的特点，它们只能用于自定义基于`ItemsControl`（通常使用数据绑定）的控件面板；它们不能像正常面板一样使用——在其中放置项目（在 XAML 或以编程方式）。`ItemsControl`及其派生类的完整讨论将在本章的后面部分进行；现在我们将快速查看现有虚拟化面板的工作方式；当讨论`ItemsControl`时，我们将在稍后看到使用示例。

### 虚拟化面板

最容易理解的虚拟化面板是`VirtualizingStackPanel`。它的行为就像常规的`StackPanel`，但它会虚拟化当前不可见的元素。

`WrapGrid`类似于`VariableSizedWrapGrid`，但没有“可变”部分（它没有可以更改单个元素大小的附加属性）。它在`GridView`中用作默认面板（`GridView`是从`ItemsControl`派生的许多类型之一）。它可以通过属性进行自定义，例如`Orientation`，`ItemHeight`，`ItemWidth`和`MaximumRowsOrColumns`，这些属性大多是不言自明的。

`CarouselControl`类似于`VirtualizingStackPanel`，还具有在达到最后一个项目时滚动到第一个项目的功能。它被用作`ComboBox`的默认面板，并且实际上不能被其他控件使用，因此通常没有什么用处。

# 与元素和控件一起工作

“元素”和“控件”之间的区别在实践中并不那么重要，但了解这种区别是有用的。

**元素**从`FrameworkElement`（直接或间接）派生，但不是从`Control`派生。它们具有一些外观并提供一些可通过更改属性进行自定义的功能。例如，`Ellipse`是一个元素。没有办法改变`Ellipse`的基本外观（并且能够将`Ellipse`变成矩形是不合逻辑的）。但是可以使用诸如`Stroke`，`StrokeThickness`，`Fill`和`Stretch`等属性以某种方式进行自定义。

另一方面，**控件**从`Control`类（直接或间接）派生。`Control`添加了一堆属性，其中最重要的是`Template`属性。这允许完全更改控件的外观而不影响其行为。此外，所有这些都可以仅使用 XAML 实现，无需代码或任何类派生。我们将在第六章中讨论控件模板，*组件，模板和自定义元素*。

以下类图显示了 WinRT 中一些基本的与元素相关的类：

![与元素和控件一起工作](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_04_07.jpg)

在接下来的几节中，我们将讨论各种元素和控件的组（基于派生和使用类别），研究它们的主要特点和用法。在每个组中，我们将查看一些更有用或独特的控件。这些部分并不完整（也不打算如此）；更多信息可以在官方 MSDN 文档和示例中找到。

## 内容控件

内容控件派生自`ContentControl`类（它本身派生自`Control`）。`ContentControl`添加了两个重要属性：`Content`（也是其`ContentProperty`属性，使其在 XAML 中易于设置）和`ContentTemplate`。`ContentControl`的一个简单示例是`Button`：

```cpp
<Button Content="Login" FontSize="30" />
```

这个`Content`属性可能看起来像一个字符串，但实际上它的类型是`Platform::Object^`，意味着它可以是任何东西。

### 注意

`Platform::Object`指定“任何内容”似乎有些奇怪；毕竟，WinRT 是基于 COM 的，所以肯定有一个接口在后面。实际上，`Platform::Object`就是`IInspectable`接口指针的投影替代品。

从`ContentControl`派生的类型使用以下规则呈现其`Content`：

+   如果它是一个字符串，将呈现`TextBlock`，其`Text`设置为字符串值。

+   如果它是从`UIElement`派生的，它将按原样呈现。

+   否则（`Content`不是从`UIElement`派生的，也不是字符串），如果`ContentTemplate`是`nullptr`，那么内容将呈现为一个`TextBlock`，其`Text`设置为`Content`的字符串表示。否则，提供的`DataTemplate`用于呈现。

前述规则适用于任何从`ContentControl`派生的类型。在前面的按钮的情况下，使用第一条规则，因为`Button`的`Content`是字符串**Login**。以下是使用第二条规则的示例：

```cpp
<Button>
    <StackPanel Orientation="Horizontal">
        <Image Source="assets/upload.png" Stretch="None" />
        <TextBlock Text="Upload" FontSize="35"
            VerticalAlignment="Center" Margin="10,0,0,0" />
    </StackPanel>
</Button>
```

生成的按钮如下所示：

![内容控件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_04_08.jpg)

生成的控件仍然是一个按钮，但其`Content`设置为从`UIElement`派生的类型（在本例中是`StackPanel`）。

第三条规则是最有趣的。假设我们有一个简单的数据对象实现如下：

```cpp
namespace ContentControlsDemo {
  public ref class Book sealed {
  public:
    property Platform::String^ BookName;
    property Platform::String^ AuthorName;
    property double Price;
  };
}
```

有了这个实现，让我们在 XAML 中创建一个`Book`实例作为资源：

```cpp
<Page.Resources>
    <local:Book x:Key="book1" BookName="Windows Internals"
       AuthorName="Mark Russinovich" Price="50.0" />
</Page.Resources>
```

### 注意

为了使其编译不出错，必须在`MainPage.xaml.h`中添加`#include "book.h"`。这样做的原因将在下一章中变得清晰。

现在，我们可以将从`ContentControl`（如`Button`）派生的类型的`Content`设置为该`Book`对象：

```cpp
<Button Content="{StaticResource book1}" FontSize="30"/>
```

运行应用程序显示以下结果：

![内容控件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_04_09.jpg)

结果只是类的完全限定类型名称（包括命名空间）；这并不总是这样，这取决于所讨论的控件的默认控件模板。无论如何，显然这通常不是我们想要的。要为对象获取自定义呈现，需要一个`DataTemplate`，并将其插入到`ContentTemplate`属性中。

以下是一个为在问题中的`Button`中使用的`DataTemplate`的示例：

```cpp
<Button Margin="12" Content="{StaticResource book1}" >
    <Button.ContentTemplate>
        <DataTemplate>
            <Grid>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto" />
                    <RowDefinition Height="Auto" />
                </Grid.RowDefinitions>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition />
                    <ColumnDefinition Width="15" />
                    <ColumnDefinition Width="Auto" />
                </Grid.ColumnDefinitions>
                <TextBlock FontSize="35" Foreground="Yellow"
                    Text="{Binding BookName}" />
                <TextBlock Grid.Row="1" FontSize="25"
                    Foreground="Orange" 
                    Text="{Binding AuthorName}" />
                <TextBlock FontSize="40" Grid.Column="2"
                    Grid.RowSpan="2" TextAlignment="Center"
                    VerticalAlignment="Center">
                <Span FontSize="25">Just</Span><LineBreak />
                <Span FontSize="40">$</Span>
                <Run Text="{Binding Price}" FontSize="40" />
                </TextBlock>
            </Grid>
        </DataTemplate>
    </Button.ContentTemplate>
</Button>
```

这里有几点需要注意：

+   `DataTemplate`可以包含一个单一元素（通常是一个`Panel`—在本例中是`Grid`），并且可以构建任何所需的 UI。

+   使用实际内容的属性是通过数据绑定表达式完成的，使用`{Binding}`标记扩展和属性名称。有关数据绑定的完整处理在下一章中找到。

+   要使属性与数据对象（在本例中是`Book`）一起工作，必须像这样用`Bindable`属性装饰类（`Book`）：

```cpp
[Windows::UI::Xaml::Data::Bindable]
public ref class Book sealed {
```

结果如下所示：

![内容控件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_04_10.jpg)

数据模板是可视化数据对象的强大工具；我们以后会遇到更多。现在，重要的是要意识到每个从`ContentControl`派生的类型都具有这种自定义能力。

在接下来的几节中，我们将讨论一些常见的`ContentControl`派生类型。

### 按钮

正如我们已经看到的，经典的`Button`控件是一个`ContentControl`，这意味着它可以拥有任何内容，但仍然像一个按钮一样工作。`Button`的大部分功能都是从它的抽象基类`ButtonBase`派生出来的。`ButtonBase`声明了无处不在的`Click`事件，以及一些其他有用的属性：

+   `ClickMode` - 指示什么构成“点击”：`Release`，`Press`或`Hover`。自然地，这主要适用于鼠标。

+   `Command` - 指示在按钮被点击时要调用哪个命令（如果有的话）（命令将在下一章中讨论）。

+   `CommandParameter` - 与调用的命令一起发送的可选参数。

Button 派生自`ButtonBase`，在成员方面没有任何添加，除了具体化，而不是抽象化。

另一个`ButtonBase`的派生类是`HyperlinkButton`。它默认呈现为一个网页超链接，并添加了一个`NavigationUri`属性，导致自动导航到指定的 URI；`Click`事件通常不会被处理。

`RepeatButton`（在`Windows::UI::Xaml::Controls::Primitives`命名空间中）是另一个`ButtonBase`的派生类。只要按钮被按下，它就会引发`Click`事件；可以使用`Delay`（第一个`Click`事件）和`Interval`（`Click`事件引发的时间间隔）属性来指定`Click`事件的速率。

### 注意

`RepeatButton`本身不太有用；它主要作为其他更复杂的控件的构建块。这可以通过将控件放置在`Primitives`子命名空间中来暗示。例如，`RepeatButton`组成了`ScrollBar`的几个部分（它本身在`Primitives`命名空间中）。

另外两个有用的按钮控件是`CheckBox`和`RadioButton`。两者都派生自一个共同的基类`ToggleButton`。`ToggleButton`定义了`IsChecked`属性，它可以有三个值（`true`，`false`或`nullptr`）。后者表示一个不确定的状态，由`CheckBox`支持（但不由`RadioButton`支持）。`ToggleButton`还声明了`IsThreeState`属性，以指示是否应允许第三种状态。最后，它定义了三个事件，`Checked`，`Unchecked`和`Indeterminate`。

`CheckBox`除了变得具体之外，对`ToggleButton`没有任何添加。`RadioButton`只添加了一个属性`GroupName`（一个字符串）。这允许对`RadioButton`控件进行分组，以用作排他性组。默认情况下，同一直接父级下的所有`RadioButton`控件都成为一组（该组中只能有一个`IsChecked`属性设置为`true`）。如果指定了`GroupName`，则所有具有相同`GroupName`的`RadioButtons`被视为一组。

这是一个简单的示例，使用了`CheckBox`和`RadioButton`控件：

```cpp
<StackPanel>
    <TextBlock Text="What kind of tea would you like?"
       FontSize="25" Margin="4,12"/>
    <RadioButton Content="Earl Grey" IsChecked="True" Margin="4" 
       FontSize="20" />
    <RadioButton Content="Mint" Margin="4" FontSize="20"/>
    <RadioButton Content="Chinese Green" Margin="4" 
       FontSize="20"/>
    <RadioButton Content="Japanese Green" Margin="4" 
       FontSize="20"/>

    <TextBlock Text="Select tea supplements:" FontSize="25" 
       Margin="4,20,4,4" />
    <CheckBox Content="Sugar" Margin="4" FontSize="20" />
    <CheckBox Content="Milk" Margin="4" FontSize="20" />
    <CheckBox Content="Lemon" Margin="4" FontSize="20" />
</StackPanel>
```

在进行一些选择后，得到的显示如下：

![Buttons](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_04_11.jpg)

### ScrollViewer

`ScrollViewer`是一个内容控件，它承载一个子元素（就像任何其他`ContentControl`的`Content`属性一样），并使用一对`ScrollBar`控件来支持滚动。最重要的属性是`VerticalScrollBarVisibility`和`HorizontalScrollBarVisibility`，它们指示滚动的方式和滚动条的呈现方式。有四个选项（`ScrollBarVisibility`枚举）：

+   `Visible` - 滚动条始终可见。如果内容不需要滚动，滚动条将被禁用。

+   `Auto` - 如果需要，滚动条会出现，如果不需要，它会消失。

+   `Hidden` - 滚动条不显示，但仍然可以使用键盘、触摸或编程方式进行滚动。

+   `Disabled` - 滚动条被隐藏，无法滚动。`ScrollViewer`不会给内容提供比它在该维度上拥有的更多的空间。

`VerticalScrollBarVisibility`的默认值为`Visible`，`HorizontalScrollBarVisibility`的默认值为`Disabled`。

`ScrollViewer`的另一个有用功能是它能够通过缩放/捏触手势来允许`Content`进行放大或缩小。这是通过`ZoomMode`属性（`Enabled`或`Disabled`）来控制的。

`HorizontalScrollBarVisibility`、`VerticalScrollBarVisibility`和`ZoomMode`属性也作为附加属性公开，因此它们与内部使用`ScrollViewer`的其他控件相关，例如`ListBox`或`GridView`。以下是一个简单的示例，它改变了`ListBox`中水平滚动条的呈现方式：

```cpp
<ListBox ScrollViewer.HorizontalScrollBarVisibility="Hidden">
```

### 其他需要注意的内容控件

以下是 WinRT 中一些其他`ContentControl`派生类型的简要描述。

#### AppBar

`AppBar`是一个用于应用栏的`ContentControl`，通常出现在底部（有时在顶部），如果用户从底部（或顶部）滑动或右键单击鼠标。它通常托管一个水平的`StackPanel`，其中包含各种选项的按钮。以下是一个来自天气应用程序的示例，该应用程序可在任何 Windows 8 安装中使用：

![AppBar](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_04_12.jpg)

#### Frame

`Frame`是用于在派生自`Page`的控件之间进行导航的`ContentControl`。使用`Navigate`方法与`Page`类型“导航”到该页面，通过创建一个实例并调用一些虚拟方法：在旧页面上调用`OnNavigatedFrom`（如果有的话），在新页面上调用`OnNavigatedTo`。默认情况下，应用程序向导在`App::OnLaunched`方法（`Lanuched`事件的事件处理程序）中创建一个`Frame`对象，然后快速导航到`MainPage`，代码如下：

```cpp
rootFrame->Navigate(TypeName(MainPage::typeid), args->Arguments)
```

`Navigate`的第二个参数是一个可选的上下文参数，在`OnNavigatedTo`重写中可用（在`NavigationEventArgs::Parameter`中）。

`Frame`对象维护着一个页面的后退堆栈，可以使用`GoBack`和`GoForward`等方法进行导航。`CanGoBack`和`CanGoForward`只读属性可以帮助维护用于导航目的的按钮的状态。

导航到先前访问的页面可以创建这些页面的新实例或重用实例。`CacheSize`属性可以设置在导航期间在内存中保留的最大缓存页面数。要为特定的`Page`实例启用任何类型的缓存，必须将其`Page::NavigationCacheMode`属性设置为`Enabled`或`Required`（`Disabled`是默认值）。`Enabled`与缓存一起工作，而`Required`始终在内存中保持页面状态（`Required`设置不计入`Frame::CacheSize`值）。

#### SelectorItem

`SelectorItem`是可在`ItemsControl`控件中选择的项目的抽象基类（有关`ItemsControl`的描述，请参见下一节）。它只添加了一个属性：`IsSelected`。派生类型是其各自基于集合的控件中项目的容器：`ListBoxItem`（在`ListBox`中）、`GridViewItem`（在`GridView`中）、`ListViewItem`（在`ListView`中）等。

## 基于集合的控件

以下各节讨论了持有多个数据项的控件。这些都派生自提供所有派生类型的基本结构的`ItemsControl`类。

`Items`只读属性是托管在此`ItemsControl`中的对象的集合（类型为`ItemCollection`，也是其`ContentProperty`）。对象可以使用`Append`和`Insert`方法添加，使用`Remove`和`RemoveAt`方法移除（任何类型的对象都可以成为`ItemsControl`的一部分）。尽管这听起来很吸引人，但这不是与`ItemsControl`或其派生类型一起工作的典型方式；通常会将对象集合设置为`ItemsSource`属性（通常使用数据绑定表达式），并且自动使用`Items`属性在幕后填充控件。我们将在第五章*数据绑定*中看到这一点。

`ItemsPanel`属性允许更改特定`ItemsControl`中托管项目的默认`Panel`。例如，`ListView`使用垂直`VirtualizingStackPanel`作为其默认`Panel`。这可以通过`ListView`元素内的以下 XAML 片段更改为`WrapGrid`：

```cpp
<ListView.ItemsPanel>
    <ItemsPanelTemplate>
        <WrapGrid Orientation="Horizontal"/>
    </ItemsPanelTemplate>
</ListView.ItemsPanel>
```

`ItemTemplate`属性可以设置为`DataTemplate`，以显示集合中的对象。`ItemTemplate`具有与`ContentControl::ContentTemplate`相同的目的和规则，但适用于`ItemsControl`中的每个对象。我们将在下一章中看到`ItemTemplate`的用法示例。

`DisplayMemberPath`是一个`String`属性，如果`ItemTemplate`为`nullptr`，则可以用来显示此`ItemsControl`中对象的某个属性（或子属性）。例如，假设我们使用以下`Book`类（之前定义）：

```cpp
[Bindable]
public ref class Book sealed {
public:
  property Platform::String^ BookName;
  property Platform::String^ AuthorName;
  property double Price;
  };
```

创建这样的`Book`对象数组，并将其放置在`ItemsControl::ItemsSource`属性中（或通过`Items->Append`方法手动添加它们），默认情况下会显示`Book`类型名称（假设没有设置`ItemTemplate`）。将`DisplayMemberPath`设置为`"BookName"`将在`ItemsControl`中显示每个对象的`BookName`。

`ItemContainerStyle`属性可用于在此`ItemsControl`的特定容器项上放置`Style`。例如，设置`ItemContainerStyle`属性的`ListView`会影响`ListViewItem`控件，每个控件都包含所讨论的数据对象（根据内容的通常规则）。

我们将在下一章中看到`ItemsControl`的更多属性。以下部分简要讨论了一些从`ItemsControl`派生的常见类型。从技术上讲，只有一个这样的类：`Selector`，添加了`SelectedItem`（实际数据对象）和`SelectedIndex`（整数索引）属性的选择概念。`SelectedValue`属性根据`SelectedValuePath`属性指示所选项目的“值”。例如，如果控件保存`Book`对象，如前所示，并且`SelectedValuePath`为`"BookName"`，那么`SelectedValue`将保存`SelectedItem`的实际书名（`SelectedItem`保存整个`Book`对象）。

`Selector`还定义了一个事件`SelectionChanged`，当选定的项目发生变化时触发。

### ListBox 和 ComboBox

`ListBox`和`ComboBox`是经典 Windows 控件的 WinRT 版本。`ListBox`显示对象的集合（默认情况下是垂直的），如果需要，会有滚动条。`ListBox`还添加了多个选定项目的概念，具有`SelectedItems`属性和`SelectionMode`属性（`Single`，`Multiple`——每次单击/触摸都会选择/取消选择项目，以及`Extended`——按下*Shift*会选择多个连续对象，按下*Ctrl*会选择非相邻的组）。

`ComboBox`只显示一个从下拉列表中选择的项目。在商店应用中不鼓励使用这两个控件，因为它们的触摸行为不如应该的好，而且它们没有有趣的视觉过渡，使它们有点乏味；尽管如此，它们有时仍然可能有用，特别是`ComboBox`，它没有类似的替代品。

### ListView 和 GridView

`ListView`和`GridView`都派生自`ListViewBase`（派生自`Selector`），它们是托管多个项目的首选控件。`ListView`和`GridView`对`ListViewBase`没有任何添加——它们只是具有不同的`ItemsPanel`属性默认值和一些其他调整。

这两者都经过深思熟虑地设计，以适应触摸输入、过渡动画等；它们是显示对象集合的工作马。事实上，Visual Studio 有一些项目模板，用于构建示例`ListView`和`GridView`控件，以帮助开发人员入门：

![ListView 和 GridView](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_04_13.jpg)

### FlipView

`FlipView`控件对`Selector`没有任何添加，但具有一种独特的外观，一次只显示一个（选定的）项目（类似于`ComboBox`），但允许通过向左或向右滑动或单击两侧的箭头来“翻转”项目。经典示例是翻转图像对象：

![FlipView](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_04_14.jpg)

## 基于文本的元素

文本是任何用户界面的重要部分。自然地，WinRT 提供了几个具有文本作为其主要视觉外观的元素和控件。通常涉及与字体相关的属性。这些包括：

+   `FontSize` - 文本的大小（`double`值）。

+   `FontFamily` - 字体系列名称（如"Arial"或"Verdana"）。这可以包括备用字体系列（用逗号分隔），以防该特定字体不可用。

+   `FontStretch` - 指示字体的拉伸特性，如`Condensed`，`Normal`（默认值），`ExtraCondensed`，`Expanded`等。

+   `FontWeight` - 指示字体重量，如`Bold`，`ExtraBold`，`Medium`，`Thin`等（都取自`FontWeights`类的静态属性）。

+   `FontStyle` - `Normal`，`Oblique`或`Italic`之一。

所有与字体相关的属性都有一个显着的属性，它们为存在为元素的子元素（直接或间接）设置了一个“默认”字体。这意味着在`Page`对象上设置与字体相关的属性实际上为页面中的所有元素设置了默认字体（除了两个例外：由控件模板显式设置的字体属性和特定元素设置的本地字体属性；两者都会覆盖默认字体设置）。

大多数文本元素共有的另一个属性是`Foreground`。这设置绘制实际文本的`Brush`。有几种`Brush`类型，`SolidColorBrush`是最简单的，但还有其他类型，如`LinearGradientBrush`和`TileBrush`。

大多数与文本相关的元素共有的其他文本相关属性包括`TextAlignment`（`Left`，`Right`，`Center`，`Justify`），`TextTrimming`（`None`和`WordEllipsis`），和`TextWrapping`（`NoWrap`和`Wrap`），都相当容易理解。

### 使用自定义字体

可以在 WinRT 中使用自定义字体。这涉及将字体文件添加到项目中（带有`.TTF`扩展名），并确保在 Visual Studio 中其**Content**属性设置为**Yes**：

![使用自定义字体](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_04_16.jpg)

现在所需的就是使用`FontFamily`属性和特殊值，包括字体 URI（文件名和任何逻辑文件夹），一个井号（#）和字体名称本身，当在 Windows 中双击字体文件时可见。以下是使用标准字体和自定义字体的两行示例：

```cpp
<StackPanel>
    <TextBlock Text="This text is in a built in font"
        FontFamily="Arial" FontSize="30" Margin="20"/>
    <TextBlock Text="This text is in old Star Trek style" 
       FontFamily="Finalold.ttf#Final Frontier Old Style" 
       FontSize="30" Margin="20" />
</StackPanel>
```

结果如下所示：

![使用自定义字体](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_04_15.jpg)

以下部分讨论了一些常见的与文本相关的元素和控件。

### TextBlock

`TextBlock`可能是最有用的与文本相关的元素。它显示用户无法交互更改的文本（只能进行编程更改）。这对于显示静态文本非常有用，用户不应该编辑它。

### 注意

尽管文本无法在`TextBlock`中编辑，但用户仍然可以选择它（甚至可以通过按下*Ctrl* + *C*进行复制），如果`IsTextSelectionEnabled`为`true`。如果是这样，还可以使用其他属性，即`SelectedText`，`SelectionStart`和`SelectionEnd`（后者返回`TextPointer`对象）。

使用`TextBlock`最直接的方法是设置`Text`属性（一个`String`）和必要时的与字体相关的属性。作为`Text`的替代，`TextBlock`支持一组称为 inlines 的对象（通过`Inlines`属性，这也是它的`ContentProperty`用于 XAML 目的），允许构建一个更复杂的`TextBlock`，但仍然只使用一个元素（`TextBlock`）。

内联包括（都派生自`Inline`）`Span`，`Run`，`LineBreak`和`InlineUIContainer`（都在`Windows::UI::Xaml::Documents`命名空间中）。`Span`是具有相同属性的更多内联的容器。`Run`具有`Text`属性并添加`FlowDirection`。`LineBreak`就是那样。`InlineUIContainter`不能在`TextBlock`中使用，只能在`RichTextBlock`中使用（稍后讨论）。

这是一个`TextBlock`的例子：

```cpp
<TextBlock>
    <Run FontSize="30" Foreground="Red" Text="This is a run" />
    <LineBreak />
    <Span Foreground="Yellow" FontSize="20">
        <Run Text="This text is in yellow" />
        <LineBreak />
        <Run Text="And so is this" />
    </Span>
</TextBlock>
```

结果如下所示：

![TextBlock](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_04_17.jpg)

### 注意

如果`Text`属性与内联一起使用，`Text`优先，内联不会显示。

### TextBox

`TextBox`是经典的文本输入控件，并提供了所有预期的控件功能。常见属性包括（除了字体属性和其他在本节开头讨论的属性）：

+   `Text` - 用户实际显示或编辑的文本。

+   `MaxLength` - 用户输入的最大字符长度（在通过编程方式操作`TextBox`中的`Text`时不使用此设置）。

+   `SelectedText`，`SelectedLength`，`SelectionStart`，`SelectionEnd` - 选择相关的属性（不言自明）。

+   `IsReadOnly` - 指示文本是否实际可编辑（默认为`false`）。

+   `AcceptsReturn` - 如果为`true`，表示多行`TextBox`（默认为`false`）。

+   `InputScope` - 指示在不使用物理键盘的触摸设备上应该弹出什么样的虚拟键盘。这可以帮助输入文本。值（来自`InputScopeNameValue`枚举）包括：`Url`，`Number`，`EmailSmtpAddress`（电子邮件地址）等。这是`Number`的`InputScope`的键盘截图：![TextBox](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_04_22.jpg)

这是`InputScope`为`Url`的键盘的例子：

![TextBox](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_04_23.jpg)

这是`EmailSmtpAddress`的`InputScope`的一个例子：

![TextBox](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_04_24.jpg)

`TextBox`定义了几个事件，其中`TextChanged`是最有用的。

### PasswordBox

`PasswordBox`用于输入密码（毫不意外）。文本显示为单个重复字符，可以使用`PasswordChar`属性更改（默认为`'*'`，显示为圆圈）。`Password`属性是实际密码，通常在代码中读取。

`PasswordBox`的一个很好的功能是一个“显示”按钮，当按下按钮时可以显示实际密码，有助于确保输入的密码是预期的；通过将`IsPasswordRevealButtonEnabled`设置为`false`可以关闭此功能。

### RichTextBlock 和 RichEditBox

`TextBlock`和`TextBox`的“丰富”版本提供了更丰富的格式化功能。例如，可以将字体相关属性设置为控件内的任何文本。

对于`RichTextBlock`，控件的实际内容在块对象的集合中（`Blocks`属性），只有一个派生类型 - `Paragraph`。`Paragraph`有自己的格式化属性，并且可以承载`Inline`对象（类似于`TextBlock`）；`RichTextBlock`支持`InlineUIContainer`内联，可以嵌入元素（例如图像，或其他任何内容）作为文本的一部分。

`RichEditBox`允许更丰富的编辑功能，可以嵌入*丰富*内容，例如超链接。`Document`属性（类型为`ITextDocument`）提供了`RichEditBox`背后的对象模型的入口。此对象模型支持以文本和富文本（RTF）格式保存和加载文档，多次撤消/重做功能等其他功能。

## 图像

图像可以使用`Image`元素显示。`Source`属性指示应显示什么。最简单的可能性是将图像添加到项目作为内容：

```cpp
<Image Source="penguins.jpg" />
```

`Source`属性是`ImageSource`类型；此标记仅起作用是因为存在类型转换器，可以将相对 URI 转换为从`ImageSource`派生的类型。

最简单的派生类型是`BitmapImage`（实际上是从`BitmapSource`派生的，而`BitmapSource`又是从`ImageSource`派生的）。`BitmapImage`可以从 URI（使用`UriSource`属性）初始化，这正是在前面的 XAML 中使用的类型转换器所发生的。

更有趣的类型是`WriteableBitmap`（也是从`BitmapSource`派生的），它公开了动态更改位图位的能力。

要创建`WriteableBitmap`，我们需要指定其像素尺寸，如下面的代码所示：

```cpp
_bitmap = ref new WriteableBitmap(600, 600);
```

`_bitmap`是一个`WriteableBitmap`引用。接下来，我们将其设置为`Image`元素的`Source`属性：

```cpp
_image->Source = _bitmap;
```

要访问实际的位，我们需要使用 WRL 的本机接口。首先，两个`includes`和一个 using 语句：

```cpp
#include <robuffer.h>
#include <wrl.h>

using namespace Microsoft::WRL;
```

`robuffer.h`定义了`IBufferByteAccess`接口，与`WriteableBitmap::PixelBuffer`属性一起使用，如下所示：

```cpp
ComPtr<IUnknown> buffer((IUnknown*)_bitmap->PixelBuffer);
ComPtr<IBufferByteAccess> byteBuffer;
buffer.As(&byteBuffer);
byte* bits;
byteBuffer->Buffer(&bits);
```

最后，可以使用这些位。以下是一个简单的示例，用随机颜色绘制位图中的第一行：

```cpp
RGBQUAD* bits2 = (RGBQUAD*)bits;
RGBQUAD color = { 
   ::rand() & 0xff, ::rand() & 0xff, ::rand() & 0xff 
};
for(int x = 0; x < 600; x++)
  bits2[x] = color;
_bitmap->Invalidate();
```

调用`WriteableBitmap::Invalidate`是必要的，确保位图被重绘，从而连接的`Image`元素得到更新。

### Stretch 属性

`Image::Stretch`属性设置`ImageSource`根据`Image`元素的大小进行拉伸的方式。以下是`Stretch`属性如何影响显示的图像：

![Stretch 属性](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_04_18.jpg)

使用`Stretch=None`，图像以其原始大小显示。在所示的图像中，企鹅被裁剪，因为图像太大而无法适应。`Uniform`和`UniformToFill`保留了纵横比（原始图像宽度除以高度），而`Fill`只是简单地拉伸图像以填充`Image`的可用空间。如果可用空间的纵横比与原始图像不同，`UniformToFill`可能会切掉内容。

### 注意

不要混淆`Image`和`ImageSource`。`Image`是一个元素，因此可以放置在可视树的某个位置。`ImageSource`是实际数据，`Image`元素只是以某种方式显示图像数据。原始图像数据（`ImageSource`）保持不变。

## 语义缩放控件

`SemanticZoom`控件值得单独一节，因为它非常独特。它将两个视图合并到一个控件中，一个作为“缩小”视图，另一个作为“放大”视图。`SemanticZoom`背后的理念是两个相关的视图——一个更一般（缩小），另一个更具体（放大）。经典示例是开始屏幕。进行捏/缩放触摸手势（或按住*Ctrl*并滚动鼠标滚轮）在两个视图之间切换。以下是放大的视图：

![语义缩放控件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_04_20.jpg)

这是缩小的视图：

![语义缩放控件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_04_19.jpg)

`ZoomedInView`和`ZoomedOutView`属性保存视图——通常是`ListView`或`GridView`，但在技术上可以是任何实现`ISemanticZoomInformation`接口的东西。

`SemanticZoom`是处理易于访问和直观的主/细节场景的有效方式。

# 总结

构建一个有效且引人入胜的用户界面本身就是一门艺术，超出了本书的范围。与 Windows Store 应用相关的现代设计指南相对较新，但可以在网上、微软网站和其他地方找到大量信息。

本章的目标是向 C++开发人员介绍 UI 景观，使其成为一个更舒适的区域。即使最终 C++开发人员将更关注应用程序逻辑、基础设施和其他低级活动，了解用户体验和用户界面的景观仍然是有用的。

在下一章中，我们将通过数据绑定将用户界面和数据联系起来，以创建健壮且可扩展的应用程序，至少在涉及用户界面和数据方面是这样。


# 第五章：数据绑定

在前两章中，我们看了 XAML 以及如何使用布局面板构建和布局用户界面元素。然而，用户界面只是第一步。必须在 UI 上设置一些数据来构成应用程序。

有几种方法可以将数据传递给控件。最简单、直接的方法可能是我们迄今为止一直在使用的方法；获取对控件的引用并在需要时更改相关属性。如果我们需要将一些文本放置在`TextBox`中，我们只需在需要时更改其`Text`属性。

这当然有效，当使用 Win32 API 进行 UI 目的时，确实没有其他方法。但这充其量是繁琐的，最糟糕的是会导致难以管理的维护头痛。不仅需要处理数据，还需要检查并可能动态更改元素状态，例如启用/禁用和选中/未选中。在 WinRT 中，大部分这些工作都是通过数据绑定来处理的。

# 理解数据绑定

数据绑定基本上很简单——某个对象（源）中的一个属性发生变化，另一个对象（目标）中的另一个属性以某种有意义的方式反映这种变化。结合数据模板，数据绑定提供了一种引人注目且强大的可视化和与数据交互的方式。

### 注意

熟悉 WPF 或 Silverlight 的人会发现 WinRT 数据绑定非常熟悉。在 WinRT 中有一些更改，主要是省略，使数据绑定比在 WPF/Silverlight 中稍微不那么强大。但是，它仍然比手动传输和同步数据要好得多。

WinRT 中的数据绑定导致了一种以无缝方式处理数据和 UI 的众所周知的模式之一，称为**Model-View-ViewModel**（**MVVM**），我们将在本章末尾简要讨论。

## 数据绑定概念

我们将首先检查与数据绑定相关的一些基本术语，添加 WinRT 特定内容：

+   **源**：要监视其属性以进行更改的对象。

+   **源路径**：要监视的源对象上的属性。

+   目标：当源发生变化时，其属性发生变化的对象。在 WinRT 中，目标属性必须是一个依赖属性（我们稍后会看到）。

+   **绑定模式**：指示绑定的方向。

可能的值（均来自`Windows::UI::Xaml::Data::BindingMode`枚举）如下：

+   `OneWay`：源更改更新目标

+   `TwoWay`：源和目标相互更新

+   `OneTime`：源仅更新一次目标

数据绑定通常（大部分时间）在 XAML 中指定，提供了一种声明性和便捷的连接数据的方式。这直接减少了管理元素状态和控件与数据对象之间交换数据的编写代码量。

# 元素到元素的绑定

我们将首先检查的绑定场景是如何在不编写任何代码的情况下连接元素在一起的方式——通过在所需属性之间执行数据绑定。考虑以下两个元素：

```cpp
<TextBlock Text="This is a sizing text"                   
    TextAlignment="Center" VerticalAlignment="Center"/>
<Slider x:Name="_slider" Grid.Row="1" Minimum="10" Maximum="100"
    Value="30"/>
```

假设我们希望根据`Slider`的当前`Value`来更改`TextBlock`的`FontSize`。我们该如何做呢？

显而易见的方法是使用事件。我们可以对`Slider`的`ValueChanged`事件做出反应，并修改`TextBlock`的`FontSize`属性值，使其等于`Slider`的`Value`。

这当然有效，但有一些缺点：

+   需要编写 C++代码才能使其工作。这很遗憾，因为这里并没有使用真正的数据，这只是 UI 行为。也许设计师可以负责这一点，如果他/她只能使用 XAML 而不是代码。

+   这样的逻辑可能会在将来发生变化，造成维护上的困扰——请记住，典型的用户界面将包含许多这样的交互——C++开发人员实际上并不想关心每一个这样的小细节。

数据绑定提供了一个优雅的解决方案。这是使这个想法工作所需的`TextBlock`的`FontSize`设置，而不需要任何 C++代码：

```cpp
FontSize="{Binding Path=Value, ElementName=_slider}"
```

数据绑定表达式必须在目标属性上使用`{Binding}`标记扩展。`Path`属性指示要查找的源属性（在这种情况下是`Slider::Value`），如果源对象是当前页面上的元素，则`ElementName`是要使用的属性（在这种情况下，`Slider`被命名为`_slider`）。

运行结果如下：

![元素到元素绑定](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_05_01.jpg)

拖动滑块会自动更改文本大小；这就是数据绑定的强大之处。

### 注意

如果`Binding`的`Path`属性的值是第一个参数，则可以省略。这意味着前一个绑定表达式等同于以下内容：

```cpp
FontSize="{Binding Value, ElementName=_slider}".
```

这更方便，大多数情况下会使用。

同样的表达式可以通过代码实现，例如：

```cpp
auto binding = ref new Binding;
binding->Path = ref new PropertyPath("Value");
binding->ElementName = "_slider";
BindingOperations::SetBinding(_tb, TextBlock::FontSizeProperty,
binding);
```

代码假设`_tb`是相关`TextBlock`的名称。这显然更冗长，实际上只在特定情况下使用（我们将在第六章中进行检查，*组件、模板和自定义元素*）。

让我们再添加另一个元素，一个`TextBox`，其`Text`应该反映`TextBlock`的当前字体大小。我们也将使用数据绑定：

```cpp
<TextBox Grid.Row="2" Text="{Binding Value, ElementName=_slider}" 
    FontSize="20" TextAlignment="Center"/>
```

这样可以工作。但是，如果我们更改`TextBox`的实际文本为不同的数字，字体大小不会改变。为什么？

原因是绑定默认是单向的。要指定双向绑定，我们需要更改绑定的`Mode`属性：

```cpp
Text="{Binding Value, ElementName=_slider, Mode=TwoWay}"
```

现在，更改`TextBox`并将焦点移动到另一个控件（例如通过键盘上的*Tab*键或触摸其他元素），会更改`TextBlock`的`FontSize`值。

# 对象到元素绑定

尽管元素到元素的绑定有时很有用，但经典的数据绑定场景涉及一个源，即常规的非 UI 对象，以及一个目标，即 UI 元素。绑定表达式本身类似于元素到元素绑定的情况；但自然地，不能使用`ElementName`属性。

第一步是创建一个可以支持数据绑定的对象。这必须是一个带有`Bindable`属性的 WinRT 类。绑定本身是在属性上的（一如既往）。以下是一个简单的`Person`类声明：

```cpp
[Windows::UI::Xaml::Data::BindableAttribute]
public ref class Person sealed {
  public:
  property Platform::String^ FirstName;
  property Platform::String^ LastName;
  property int BirthYear;
};
```

前面的代码使用了自动实现的属性，现在足够了。

我们可以在 XAML 中创建这样的对象作为资源，然后使用`Binding::Source`属性来连接绑定本身。首先，两个`Person`对象被创建为资源：

```cpp
<Page.Resources>
  <local:Person FirstName="Albert" LastName="Einstein" 
    BirthYear="1879" x:Key="p1" />
  <local:Person FirstName="Issac" LastName="Newton" 
    BirthYear="1642" x:Key="p2" />
</Page.Resources>
```

接下来，我们可以将这些对象绑定到元素，如下所示（都在`StackPanel`内）：

```cpp
<TextBlock Text="{Binding FirstName, Source={StaticResource p1}}"
  FontSize="30" />
<TextBlock Text="{Binding LastName, Source={StaticResource p1}}"
  FontSize="30" />
<TextBlock FontSize="30" >
  <Span>Born: </Span>
  <Run Text="{Binding BirthYear, Source={StaticResource p1}}" />
</TextBlock>
```

`Source`属性指的是被绑定的对象；在这种情况下是一个`Person`实例。以下是结果 UI：

![对象到元素绑定](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_05_02.jpg)

请注意，`Source`在每个绑定表达式中都有指定。如果没有它，绑定将会失败，因为没有源对象可以绑定。

由于所有三个元素的源都是相同的，因此可以一次性指定源，并允许所有相关元素自动绑定到它，而无需显式指定源，这将是有益的。幸运的是，使用`FrameworkElement::DataContext`属性是可能的。规则很简单，如果在绑定表达式中没有显式指定源，将在可视树中从目标元素开始搜索`DataContext`，直到找到一个或者到达可视树的根（通常是`Page`或`UserControl`）。如果找到`DataContext`，它将成为绑定的源。以下是一个示例，它将`DataContext`设置为父`StackPanel`上的一个用于其子元素（无论是直接的还是不直接的）的示例：

```cpp
<StackPanel Margin="4" DataContext="{StaticResource p2}">
    <TextBlock Text="{Binding FirstName}" />
    <TextBlock Text="{Binding LastName}" />
    <TextBlock>
        <Span>Born: </Span>
        <Run Text="{Binding BirthYear}" />
    </TextBlock>
</StackPanel>
```

这是结果（经过一些字体大小调整）：

![对象到元素绑定](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_05_03.jpg)

绑定表达式工作正常，因为隐式源是`Person`对象，其键是`p2`。如果没有`DataContext`，所有这些绑定都会悄悄失败。

### 注意

注意数据绑定表达式如何通过`DataContext`简化。它们表达的意思是，“我不在乎源是什么，只要在范围内有一个名为`<填写属性名称>`的`DataContext`属性。”

`DataContext`的概念是强大的，事实上，很少使用`Source`属性。

当然，在 XAML 中将`Source`或`DataContext`设置为预定义资源也是罕见的。通常通过代码获取相关数据源，如本地数据库或 Web 服务，来设置`DataContext`。但无论`DataContext`在何处或如何设置，它都能正常工作。

# 绑定失败

绑定是松散类型的——属性被指定为字符串，并且可能拼写错误。例如，在前面的示例中写`FirstNam`而不是`FirstName`不会引发任何异常；绑定会悄悄失败。如果程序在调试器下运行，则可以在**Visual Studio 输出**窗口（菜单中的**查看** | **输出**）中找到发生错误的唯一指示。

```cpp
Error: BindingExpression path error: 'FirstNam' property not found on 'ElementObjectBinding.Person'. BindingExpression: Path='FirstNam' DataItem='ElementObjectBinding.Person'; target element is 'Windows.UI.Xaml.Controls.TextBlock' (Name='null'); target property is 'Text' (type 'String')
```

这段文字准确定位了确切的问题，指定了要绑定的属性名称，源对象类型以及有关目标的详细信息。这应该有助于修复拼写错误。

为什么没有抛出异常？原因是数据绑定可能在某个时间点失败，这没关系，因为此时尚未满足此绑定的条件；例如，可能有一些信息是从数据库或 Web 服务中检索的。当数据最终可用时，这些绑定突然开始正常工作。

这意味着无法真正调试数据绑定表达式。一个很好的功能是能够在 XAML 绑定表达式中设置断点。目前不支持这一功能，尽管在图形上可以在绑定上设置断点，但它根本不会触发。这个功能在 Silverlight 5 中可用；希望它会在未来的 WinRT 版本中得到支持。

### 提示

调试数据绑定的一种方法是使用值转换器，稍后在本章中讨论。

# 更改通知

数据绑定支持三种绑定模式：单向，双向和一次性。直到现在，绑定发生在页面首次加载时，并在此后保持不变。如果在绑定已经就位后改变`Person`对象上的属性值会发生什么？

在添加一个简单的按钮后，`Click`事件处理程序执行以下操作：

```cpp
auto person = (Person^)this->Resources->Lookup("p1");
person->BirthYear++;
```

由于`Person`实例被定义为资源（不常见，但可能），它通过使用指定的键（`p1`）从页面的`Resources`属性中提取。然后递增`BirthYear`属性。

运行应用程序时没有视觉变化。在`Click`处理程序中设置断点确认它实际上被调用了，并且`BirthYear`已更改，但绑定似乎没有效果。

这是因为`BirthYear`属性当前的实现方式：

```cpp
property int BirthYear;
```

这是一个使用私有字段在后台实现的琐碎实现。问题在于当属性改变时，没有人知道；具体来说，绑定系统不知道发生了什么。

要改变这一点，数据对象应该实现`Windows::UI::Xaml::Data::INotifyPropertyChanged`接口。绑定系统会查询此接口，如果找到，就会注册`PropertyChanged`事件（该接口的唯一成员）。以下是`Person`类的修订声明，重点是`BirthYear`属性：

```cpp
[Bindable]
public ref class Person sealed : INotifyPropertyChanged {
public:
  property int BirthYear { 
    int get() { return _birthYear; }
    void set(int year);
  }

  virtual event PropertyChangedEventHandler^ PropertyChanged;

private:
  int _birthYear;
//...
};
```

getter 是内联实现的，setter 在 CPP 文件中实现如下：

```cpp
void Person::BirthYear::set(int year) {
  _birthYear = year;
  PropertyChanged(this, 
  ref new PropertyChangedEventArgs("BirthYear"));
}
```

`PropertyChanged` 事件被触发，接受一个 `PropertyChangedEventArgs` 对象，该对象接受了更改的属性名称。现在，运行应用程序并点击按钮会显示一个增加的出生年份，如预期的那样。

这实际上意味着每个属性都应该以类似的方式实现；在 setter 中声明一个私有字段并在其中引发 `PropertyChanged` 事件。这是 `FirstName` 属性的修订实现（这次是内联实现）：

```cpp
property String^ FirstName {
  String^ get() { return _firstName; }
  void set(String^ name) {
    _firstName = name;
    PropertyChanged(this, 
    ref new PropertyChangedEventArgs("FirstName"));
  }
}
```

`_firstName` 是类内部定义的私有 `String^` 字段。

# 绑定到集合

之前的例子使用了绑定到单个对象的属性。正如我们在前一章中看到的，从 `ItemsControl` 派生的一堆控件可以呈现多个数据项的信息。这些控件应该绑定到数据项的集合，比如 `Person` 对象的集合。

用于绑定目的的属性是 `ItemsSource`。这应该设置为一个集合，通常是 `IVector<T>`。这是一些 `Person` 对象绑定到 `ListView` 的例子（为方便初始化，`Person` 添加了一个构造函数）：

```cpp
auto people = ref new Vector<Person^>;
people->Append(ref new Person(L"Bart", L"Simpson", 1990));
people->Append(ref new Person(L"Lisa", L"Simpson", 1987));
people->Append(ref new Person(L"Homer", L"Simpson", 1960));
people->Append(ref new Person(L"Marge", L"Simpson", 1965));
people->Append(ref new Person(L"Maggie", L"Simpson", 2000));
```

要设置绑定，我们可以使用显式赋值给 `ListView::ItemsSource` 属性：

```cpp
_theList->ItemsSource = people;
```

一个（优雅且首选的）替代方法是将 `ItemsSource` 绑定到与 `DataContext` 相关的内容。例如，`ListView` 的标记可以从这里开始：

```cpp
<ListView ItemsSource="{Binding}" >
```

这意味着 `ItemsSource` 绑定到 `DataContext` 是什么（在这种情况下应该是一个集合）。缺少属性路径意味着对象本身。使用这个标记，绑定是通过以下简单的代码完成的：

```cpp
DataContext = people;
```

要查看实际的 `Person` 对象，`ItemsControl` 提供了 `ItemTemplate` 属性，它是一个 `DataTemplate` 对象，定义了如何显示 `Person` 对象。默认情况下（没有 `DataTemplate`），会显示类型名称或对象的另一个字符串表示（如果有的话）。这很少有用。一个简单的替代方法是使用 `DisplayMemberPath` 属性来显示数据对象上的特定属性（例如 `Person` 对象的 `FirstName`）。一个更强大的方法是使用 `DataTemplate`，为每个通过数据绑定连接到实际对象的可自定义用户界面提供。这是我们 `ListView` 的一个例子：

```cpp
<ListView ItemsSource="{Binding}">
  <ListView.ItemTemplate>
    <DataTemplate>
      <Border BorderThickness="0,1" Padding="4"
        BorderBrush="Red">
          <Grid>
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto" />
              <RowDefinition Height="Auto" />
            </Grid.RowDefinitions>
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="200"/>
              <ColumnDefinition Width="80" />
            </Grid.ColumnDefinitions>
            <TextBlock Text="{Binding FirstName}"
            FontSize="20" />
            <TextBlock FontSize="16" Foreground="Yellow" 
            Grid.Row="1" Text="{Binding LastName}" />
            <TextBlock Grid.Column="1" Grid.RowSpan="2">
            <Span FontSize="15">Born</Span>
            <LineBreak />
            <Run FontSize="30" Foreground="Green" 
            Text="{Binding BirthYear}" />
          </TextBlock>
        </Grid>
      </Border> 
    </DataTemplate>
  </ListView.ItemTemplate>
</ListView>
```

`DataTemplate` 中的绑定表达式可以访问数据对象本身的相关属性。这是生成的 `ListView`：

![绑定到集合](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_05_04.jpg)

# 自定义数据视图

数据模板提供了一种强大的方式来可视化和与数据交互，部分是因为数据绑定的强大功能。然而，有时需要更多的自定义。例如，在 `Book` 对象的列表中，当前打折的每本书都应该以不同的颜色显示，或者有一些特殊的动画等等。

以下部分描述了一些自定义数据模板的方法。

## 值转换器

值转换器是实现 `Windows::UI::Xaml::Data::IValueConverter` 接口的类型。该接口提供了一种将一个值转换为另一个值的方式，这两个值可以是不同类型的。假设我们想要显示一组书籍，但是打折的书应该有略微不同的外观。使用普通的数据模板，这很困难，除非有特定的 `Book` 属性对可视化有影响（比如颜色或画笔）；这是不太可能的，因为数据对象应该关心数据，而不是如何显示数据。

这是 `Book` 类的定义（为简化示例，未实现更改通知）：

```cpp
[Windows::UI::Xaml::Data::BindableAttribute]
public ref class Book sealed {
public:
  property Platform::String^ BookName;
  property double Price;
  property Platform::String^ Author;
  property bool IsOnSale;

internal:
  Book(Platform::String^ bookName, Platform::String^ author,
    double price, bool onSale) {
    BookName = bookName;
    Author = author;
    Price = price;
    IsOnSale = onSale;
  }
};
```

值转换器提供了一个优雅的解决方案，使对象（在这个例子中是 `Book`）与其呈现方式解耦。这是一个基本的 `Book` 数据模板：

```cpp
<ListView.ItemTemplate>
  <DataTemplate>
    <Border BorderThickness="1" BorderBrush="Blue" Margin="2"
    Padding="4">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="400" />
          <ColumnDefinition Width="50" />
        </Grid.ColumnDefinitions>
        <TextBlock VerticalAlignment="Center" 
          FontSize="20">
          <Run Text="{Binding BookName}" />
          <Span> by </Span>
          <Run Text="{Binding Author}" />
        </TextBlock>
        <TextBlock Grid.Column="1" FontSize="25">
          <Span>$</Span>
          <Run Text="{Binding Price}" />
        </TextBlock>
      </Grid>
    </Border>
  </DataTemplate>
</ListView.ItemTemplate>
```

这是书籍的显示方式：

![值转换器](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_05_05.jpg)

假设我们想要为打折的书籍使用绿色背景。我们不想在`Book`类中添加`Background`属性。相反，将使用值转换器将`IsOnSale`属性（布尔值）转换为适用于`Background`属性的`Brush`对象。

首先，我们的值转换器的声明如下：

```cpp
public ref class OnSaleToBrushConverter sealed : IValueConverter {
public:
  virtual Object^ Convert(Object^ value, TypeName targetType,
  Object^ parameter, String^ language);
  virtual Object^ ConvertBack(Object^ value, TypeName
  targetType, Object^ parameter, String^ language);

  OnSaleToBrushConverter();

private:
  Brush^ _normalBrush;
  Brush^ _onSaleBrush;
};
```

有两种方法来实现：

+   `Convert`：从源到目标绑定时使用（通常的方式）

+   `ConvertBack`：仅适用于双向绑定

在我们的情况下，我们使用的是单向绑定，所以`ConvertBack`可以简单地返回`nullptr`或抛出异常。这是实现：

```cpp
OnSaleToBrushConverter::OnSaleToBrushConverter() {
  _normalBrush = ref new SolidColorBrush(Colors::Transparent);
  _onSaleBrush = ref new SolidColorBrush(Colors::Green);
}

Object^ OnSaleToBrushConverter::Convert(Object^ value, TypeName targetType, Object^ parameter, String^ culture) {
  return (bool)value ? _onSaleBrush : _normalBrush;
}

Object^ OnSaleToBrushConverter::ConvertBack(Object^ value, TypeName targetType, Object^ parameter, String^ culture) {
  throw ref new NotImplementedException();
}
```

在构造函数中创建了两个画笔；一个用于普通书籍（透明），另一个用于打折书籍（绿色）。调用`Convert`方法时，`value`参数是所讨论书籍的`IsOnSale`属性。这将很快变得清楚。该方法只是查看布尔值并返回适当的画笔。这种转换是从布尔值到`Brush`。

下一步将是实际创建转换器的实例。这通常是在 XAML 中完成的，将转换器作为资源：

```cpp
<Page.Resources>
    <local:OnSaleToBrushConverter x:Key="sale2brush" />
</Page.Resources>
```

现在，为了最终连接，使用适当的属性绑定到`IsOnSale`并为操作提供一个转换器。在我们的情况下，`Border`（`DataTemplate`的一部分）非常合适：

```cpp
<Border BorderThickness="1" BorderBrush="Blue" Margin="2"
    Padding="4" Background="{Binding IsOnSale, 
    Converter={StaticResource sale2brush}}">
```

没有转换器，绑定将会失败，因为没有办法自动将布尔值转换为`Brush`。转换器已经传递了`IsOnSale`的值，并且应该返回适合目标属性的内容以使转换成功。

### 注意

可以使用不带`Path`（在此示例中不带`IsOnSale`）的`Binding`表达式。结果是整个对象（`Book`）作为转换器的值参数传递。这有助于基于多个属性做出决策。

这是结果：

![值转换器](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_05_06.jpg)

让我们在打折的书旁边添加一个小图片。我们可以添加一张图片，但只有当书打折时才显示。我们可以使用（有点经典的）转换器，从布尔值转换为`Visibility`枚举，反之亦然：

```cpp
Object^ BooleanToVisibilityConverter::Convert(Object^ value, TypeName targetType, Object^ parameter, String^ culture) {
  return (bool)value ? Visibility::Visible :
    Visibility::Collapsed;
}

Object^ BooleanToVisibilityConverter::ConvertBack(Object^ value, TypeName targetType, Object^ parameter, String^ culture) {
  return (Visibility)value == Visibility::Visible;
}
```

有了这个，我们可以像通常一样在资源中创建一个实例：

```cpp
<local:BooleanToVisibilityConverter x:Key="bool2vis" />
```

然后，我们可以在需要时向第三列添加一张图片：

```cpp
<Image Source="Assets/sun.png" VerticalAlignment="Center" 
  HorizontalAlignment="Center" Height="24" Grid.Column="2"
  Visibility="{Binding IsOnSale, Converter={StaticResource
  bool2vis}}" />
```

这是结果：

![值转换器](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_05_07.jpg)

值转换器非常强大，因为它们可以利用代码实现视觉变化。

### Convert 和 ConvertBack 的其他参数

`Convert`和`ConvertBack`接受更多参数，不仅仅是值。以下是完整列表：

+   `value`：`value`参数（第一个）对于`Convert`/`ConvertBack`方法非常重要。还有其他三个参数。

+   `targetType`：这表示应返回的预期对象类型。这可用于检查转换器是否正确使用（在我们的示例中，`OnSaleToBrushConverter`的`Convert`方法的`targetType`将是`Brush`类型）。此参数的另一个可能用途是在更复杂的值转换器的情况下，可能需要处理多个返回类型并且可能需要了解当前请求。

+   `parameter`：这是一个自由参数，可以通过`Binding`表达式的`ConverterParameter`属性传递。这对于根据绑定表达式自定义值转换器很有用。

+   `culture`：这接收`Binding`表达式的`ConverterLanguage`属性的内容。这可用于根据语言返回不同的值，这实际上只是可以传递给转换器的另一个字符串。

## 数据模板选择器

在更极端的情况下，从`DataTemplate`所需的更改可能对值转换器没有用。如果不同的对象（在同一集合中）需要非常不同的模板，数据模板选择器可能是一个更好的选择。

数据模板选择器是一个从`Windows::UI::Xaml::Controls::DataTemplateSelector`派生的类（尽管命名空间不同，但它不是一个控件），并重写了以下定义的`SelectTemplateCore`方法：

```cpp
protected:
virtual DataTemplate^ SelectTemplateCore(Object^ item, 
  DependencyObject^ container);
```

该方法需要返回与`item`参数对应的`DataTemplate`。在前面的示例中，每个项目都是`Book`；代码将查看一些`Book`属性，并得出应该使用哪个`DataTemplate`。这也可以基于`container`参数，在这种情况下，它是实际托管这些对象的控件（在我们的示例中是`ListView`）。

接下来，在 XAML 中创建此类的一个实例（类似于值转换器），并将该实例设置为`ItemsControl::ItemTemplateSelector`属性。如果设置了这个属性，`ItemTemplate`不能同时设置，因为它会与模板选择器使用的逻辑冲突。

# 命令

将用户界面的一部分连接到某些逻辑的传统方法是通过事件。典型的例子是按钮——当点击时，会执行一些操作，希望实现用户打算的某个目标。尽管 WinRT 完全支持这种模型（就像其他 UI 框架一样），但它也有缺点：

+   事件处理程序是“代码后台”的一部分，其中声明了 UI，通常是`Page`或`UserControl`。这使得从可能希望调用相同逻辑的其他对象中调用它变得困难。

+   前面提到的按钮可能会消失并被不同的控件替换。这将需要潜在地更改事件挂钩代码。如果我们希望多个控件调用相同的功能怎么办？

+   在某些状态下可能不允许执行操作——按钮（或其他任何东西）需要在正确的时间被禁用或启用。这给开发人员增加了管理开销——需要跟踪状态并为调用相同功能的所有 UI 元素更改它。

+   事件处理程序只是一个方法——没有简单的方法来捕获它并将其保存在某个地方，例如用于撤销/重做的目的。

+   在没有使用实际用户界面的情况下测试应用程序逻辑是困难的，因为逻辑和 UI 是交织在一起的。

这些以及其他更微妙的问题使得处理事件处理程序不太理想，特别是涉及应用程序逻辑时。如果某些事件只是为了增强可用性或仅为了服务 UI，通常不会引起关注。

解决此 UI 逻辑耦合的典型方法是命令的概念。这遵循了著名的“命令设计模式”，将应用程序逻辑抽象为不同的对象。作为一个对象，命令可以从多个位置调用，保存在列表中（例如，用于撤销目的），等等。它甚至可以指示在某些时间是否允许，从而使其他实体免于处理可能绑定到该命令的控件的实际启用或禁用。

WinRT 使用`Windows::UI::Xaml::Input::ICommand`接口定义了基本的命令支持。`ICommand`有两个方法和一个事件：

+   **`Execute`方法**：执行所讨论的命令。它接受一个参数，可以是任何可以用作命令参数的东西。

+   **`CanExecute`方法**：此方法指示此命令在此时是否可用。WinRT 将此作为启用或禁用命令源的提示。

+   **`CanExecuteChanged`事件**：这由命令引发，让 WinRT 知道它应该再次调用`CanExecute`，因为命令的可用性可能已经改变。

各种控件都有一个`Command`属性（类型为`ICommand`），可以设置（通常使用数据绑定）指向由`ICommand`实现的对象的对象（和一个`CommandParameter`，允许将一些信息传递给命令）。经典的例子是经典的`Button`。当按钮被点击时，将调用挂接命令的`Execute`方法。这意味着不需要设置`Click`处理程序。

WinRT 没有为`ICommand`提供任何实现。开发人员需要创建适当的实现。下面是一个简单的用于增加一个人出生年份的命令的实现：

```cpp
public ref class IncreaseAgeCommand sealed : ICommand {
public:
  virtual void Execute(Platform::Object^ parameter);
  virtual bool CanExecute(Platform::Object^ parameter);
  virtual event EventHandler<Object^>^ CanExecuteChanged;

};
```

实现如下：

```cpp
void IncreaseAgeCommand::Execute(Object^ parameter)  {
  auto person = (Person^)parameter;
  person->BirthYear++;
}

bool IncreaseAgeCommand::CanExecute(Object^ parameter) {
  return true;
}
```

为了使其工作，我们可以创建一个命令源，比如一个按钮，并填写命令的细节如下：

```cpp
<Button Content="Inrease Birth Year With Command" 
  CommandParameter="{StaticResource p1}">
  <Button.Command>
    <local:IncreaseAgeCommand />
  </Button.Command>
</Button>
```

在`Command`属性中创建一个命令是不寻常的，通常的方式是绑定到 ViewModel 上的适当属性，我们将在下一节中看到。

# MVVM 简介

命令只是处理非平凡应用程序中用户界面更一般模式的一个方面。为此，有许多 UI 设计模式可用，如**模型视图控制器**（**MVC**）、**模型视图呈现器**（**MVP**）和**模型-视图-视图模型**（**MVVM**）。所有这些都有共同之处：将实际 UI（视图）与应用程序逻辑（控制器、呈现器和视图模型）以及底层数据（模型）分离。

WPF 和 Silverlight 推广的 MVVM 模式利用数据绑定和命令的力量，通过使用中介（视图模型）在 UI（视图）和数据（模型）之间创建解耦。

## MVVM 组成部分

MVVM 有三个参与者。模型代表数据或业务逻辑。这可能包括可以用标准 C++编写的类型，而不考虑 WinRT。它通常是中立的；也就是说，它不知道它将如何被使用。

视图是实际的 UI。它应该显示模型的相关部分并提供所需的交互功能。视图不应直接了解模型，这就是数据绑定的作用。所有绑定都访问一个属性，而不明确知道另一端是什么类型的对象。这种魔术在运行时通过将视图的`DataContext`设置为提供数据的对象来满足；这就是 ViewModel。

ViewModel 是将所需数据分发给视图（基于模型）的粘合剂。ViewModel 就是这样——视图的模型。它有几个责任：

+   在视图中公开允许绑定的属性。这可能只是通过访问模型上的属性（如果它是用 WinRT 编写的），但如果模型以另一种方式公开数据（比如使用方法）或需要翻译的类型，比如需要返回为`IVector<T>`的`std::vector<T>`，可能会更复杂。

+   公开命令（`ICommand`）以供视图中的元素调用。

+   维护视图的相关状态。

模型、视图和视图模型之间的整个关系可以用以下图表来总结：

![MVVM 组成部分](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ms-win8-cpp-appdev/img/5022_05_08.jpg)

## 构建 MVVM 框架

在这一点上应该很清楚，基于 MVVM 的应用程序有很多共同的元素，比如变更通知和命令。创建一个可在许多应用程序中简单利用的可重用框架将是有益的。虽然有几个很好的框架（大多是免费的），它们都是基于.NET 的，这意味着它们不能在 C++应用程序中使用，因为它们没有作为 WinRT 组件公开，即使它们这样做了，C++应用程序也必须付出.NET CLR 的代价。自己构建这样的框架并不太困难，而且会增强我们的理解。

我们要解决的第一件事是希望对象能够实现`INotifyPropertyChanged`接口，以便它们在任何属性更改时都能引发`PropertyChanged`事件。我们可以用以下 WinRT 类来实现这一点：

```cpp
public ref class ObservableObject : 
  DependencyObject, INotifyPropertyChanged {
  public:
    virtual event PropertyChangedEventHandler^ PropertyChanged;
  protected:
    virtual void OnPropertyChanged(Platform::String^ name);
  };
```

实现如下：

```cpp
void ObservableObject::OnPropertyChanged(String^ name) {
  PropertyChanged(this, ref new PropertyChangedEventArgs(name));
}
```

从`DependencyObject`继承可能看起来是多余的，但实际上这是必要的，以规避当前 WinRT 支持中的一个不足之处——任何常规类都必须是密封的，使其作为基类毫无用处。任何从`DependencyObject`继承的类都可以保持未密封状态——这正是我们想要的。

`ObservableObject`类似乎非常简单，也许不值得作为一个单独的类。但我们可以为其添加任何派生类都可以受益的常见功能。例如，我们可以支持`ICustomPropertyProvider`接口——该接口允许对象支持动态属性，这些属性在类型中并非静态部分（感兴趣的读者可以在 MSDN 文档中找到更多信息）。

具体类型可以使用类似以下代码的`ObservableObject`：

```cpp
public ref class Book : ObservableObject {
public:
  property Platform::String^ BookName {
    Platform::String^ get() { return _bookName; }
  void set(Platform::String^ name) {
    _bookName = name;
    OnPropertyChanged("BookName");
  }
}

property bool IsOnLoan {
  bool get() { return _isOnLoan; }
  void set(bool isLoaned) {
    _isOnLoan = isLoaned;
    OnPropertyChanged("IsOnLoan");
  }
}

private:
  Platform::String^ _bookName;
  bool _isOnLoan;
//...
};
```

接下来要处理的是命令。正如我们所见，我们可以通过实现`ICommand`来创建一个命令，有时这是必要的。另一种方法是创建一个更通用的类，该类使用委托来调用我们想要响应`Execute`和`CanExecute`方法的任何代码。以下是这样一个命令的示例：

```cpp
public delegate void ExecuteCommandDelegate(Platform::Object^
  parameter);
public delegate bool CanExecuteCommandDelegate(Platform::Object^
  parameter);

public ref class DelegateCommand sealed : ICommand {
public:
  DelegateCommand(ExecuteCommandDelegate^ executeHandler,
    CanExecuteCommandDelegate^ canExecuteHandler)
  : _executeHandler(executeHandler),
    _canExecuteHandler(canExecuteHandler) { }

  virtual bool CanExecute(Platform::Object^ parameter) {
    if (_canExecuteHandler != nullptr)
    return _canExecuteHandler(parameter);

    return true;
  }

  virtual void Execute(Platform::Object^ parameter) {
    if (_executeHandler != nullptr && CanExecute(parameter))
    _executeHandler(parameter);
  }

 virtual event EventHandler<Platform::Object^>^ 
    CanExecuteChanged;

private:
  ExecuteCommandDelegate^ _executeHandler;
  CanExecuteCommandDelegate^ _canExecuteHandler;
};
```

该类利用委托，构造函数中接受两个委托；第一个用于执行命令，第二个用于指示命令是否启用。

以下是一个公开命令以使书籍被借出的 ViewModel：

```cpp
public ref class LibraryViewModel sealed : ObservableObject {
public:
  property IVector<Book^>^ Books {
    IVector<Book^>^ get() { return _books; }
  }

  property ICommand^ LoanBookCommand {
    ICommand^ get() { return _loanBookCommand; }
  }

internal:
  LibraryViewModel();

private:
  Platform::Collections::Vector<Book^>^ _books;
  ICommand^ _loanBookCommand;
};
```

命令是在 ViewModel 的构造函数中创建的：

```cpp
LibraryViewModel::LibraryViewModel() {
  _loanBookCommand = ref new DelegateCommand
  (ref new ExecuteCommandDelegate([](Object^ parameter) {
    // execute the command
    auto book = (Book^)parameter;
    book->IsOnLoan = true;
  }), nullptr);	// command is always enabled
}
```

ViewModel 是无控制（视图）的，这意味着我们可以在没有任何可见用户界面的情况下构建它。它公开了用于数据绑定到相关视图的属性和用于执行来自视图的操作的命令。实际操作通常会修改适当模型中的某些状态。

### 注意

视图和 ViewModel 之间通常是一对一的映射。虽然有时可以共享，但不建议这样做。

## 有关 MVVM 的更多信息

这是 MVVM 的快速介绍。由于这是一种众所周知的模式（多亏了它在 WPF 和 Silverlight 中的使用），因此网络上有很多相关资料。可以添加的一些内容包括支持导航的 ViewModel（以便不直接访问`Frame`控件）、ViewModel 定位器服务（允许更轻松地在视图和其对应的 ViewModel 之间进行绑定）等。

### 注意

有关 MVVM 的更多信息，请参阅维基百科[`en.wikipedia.org/wiki/Model_View_ViewModel`](http://en.wikipedia.org/wiki/Model_View_ViewModel)。

在 C++中实现 WinRT MVVM 框架有些麻烦，因为（目前）不可能将这样的框架公开为 Windows 运行时组件，而只能作为 C++静态或动态库。

尽管如此，数据和视图之间的分离是重要的，除了最简单的应用程序外，所有应用程序都将受益。

# 总结

在本章中，我们了解了数据绑定是什么以及如何使用它。数据绑定是一个非常强大的概念，在 WinRT 中的实现非常强大。来自 Win32 或 MFC 背景的开发人员应该意识到，连接显示和数据需要采用不同的方法。数据绑定提供了一种声明性模型，支持数据和显示之间的分离，因此应用程序逻辑只处理数据，实际上并不关心哪些控件（如果有）绑定到该数据。

MVVM 概念使这种分离更加清晰，并为逐步增强应用程序奠定了基础，而不会增加维护头疼和逻辑复杂性。

在下一章中，我们将看看如何构建可重用的 WinRT 组件，以及自定义元素。
