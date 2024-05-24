# Xamarin.Forms 项目（二）

> 原文：[`zh.annas-archive.org/md5/BCF2270FBE70F13E76739867E1CF82CA`](https://zh.annas-archive.org/md5/BCF2270FBE70F13E76739867E1CF82CA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：使用动画创建具有丰富 UX 的匹配应用程序

在本章中，我们将为匹配应用程序创建基本功能。但由于隐私问题，我们不会对人们进行评分。相反，我们将从互联网上的随机来源下载图像。这个项目适用于任何想要了解如何编写可重用控件的人。我们还将研究如何使用动画使我们的应用程序更加愉快。这个应用程序不会是一个 MVVM 应用程序，因为我们想要将控件的创建和使用与 MVVM 的轻微开销隔离开来。

本章将涵盖以下主题：

+   创建自定义控件

+   如何将应用程序样式设置为带有描述性文本的照片

+   使用 Xamarin.Forms 进行动画

+   订阅自定义事件

+   反复使用自定义控件

+   处理平移手势

# 技术要求

要完成此项目，您需要安装 Visual Studio for Mac 或 Windows 以及必要的 Xamarin 组件。有关如何设置您的环境的更多详细信息，请参阅第一章*Xamarin 简介*。

# 项目概述

我们中的许多人都曾面临过左右滑动的困境。突然间，您可能会想知道：这是如何工作的？滑动魔术是如何发生的？在这个项目中，我们将学习所有这些。我们将首先定义一个`MainPage`文件，其中我们应用程序的图像将驻留。之后，我们将创建图像控件，并逐渐向其添加 GUI 和功能，直到我们完美地掌握了完美的滑动体验。

此项目的构建时间约为 90 分钟。

# 创建匹配应用程序

在这个项目中，我们将学习如何创建可添加到 XAML 页面的可重用控件。为了保持简单，我们不会使用 MVVM，而是使用裸露的 Xamarin.Forms，没有任何数据绑定。我们的目标是创建一个允许用户向左或向右滑动图像的应用程序，就像大多数流行的匹配应用程序一样。

好了，让我们开始创建项目吧！

# 创建项目

就像第二章中的待办事项应用程序*构建我们的第一个 Xamarin.Forms 应用*一样，本章将从干净的文件|新建项目方法开始。在本章中，我们将选择.NET 标准方法，而不是共享代码方法；如果您不确定为什么要这样做，请参考第二章*构建我们的第一个 Xamarin.Forms 应用*以更深入地了解它们之间的区别。

让我们开始吧！

# 创建新项目

打开 Visual Studio 并单击文件|新建|项目：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/2c4f5dc4-6442-4bb5-b899-ac02fcd8589a.png)

这将打开新项目对话框。展开 Visual C#节点，然后单击跨平台。从列表中选择移动应用程序（Xamarin.Forms）项目。通过为项目命名来完成表单。在这种情况下，我们将称我们的应用程序为`Swiper`。单击确定继续下一个对话框：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/6dd491eb-f2d5-4c88-b17d-e476c30252a0.png)

下一步是选择项目模板和代码共享策略。选择空白以创建最少的 Xamarin.Forms 应用程序，并确保代码共享策略设置为.NET 标准。通过单击确定完成设置向导，让 Visual Studio 为您搭建项目。这可能需要几分钟。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/c7b99529-fb5f-4e21-9645-2a0355e5a7f4.png)

就这样，应用程序就创建好了。让我们继续更新 Xamarin.Forms 到最新版本。

# 更新 Xamarin.Forms NuGet 包

目前，您的项目将使用的 Xamarin.Forms 版本很可能有点旧。为了纠正这一点，我们需要更新 NuGet 包。请注意，您应该只更新 Xamarin.Forms 包，而不是 Android 包；做后者可能会导致您的包与彼此不同步，导致应用程序根本无法构建。要更新 NuGet 包，请执行以下步骤：

1.  右键单击解决方案资源管理器中的我们的解决方案。

1.  点击“管理解决方案的 NuGet 包...”：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/06856d6f-77d3-495c-a68b-027bd539551a.png)

这将在 Visual Studio 中打开 NuGet 包管理器。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/e4b51aa2-5c58-477b-91ec-c03889265b91.png)

要将 Xamarin.Forms 更新到最新版本，请执行以下步骤：

1.  点击“更新”选项卡。

1.  检查 Xamarin.Forms 并点击“更新”。

1.  接受任何许可协议。

更新最多需要几分钟。检查输出窗格以找到有关更新的信息。此时，我们可以运行应用程序以确保它正常工作。我们应该在屏幕中央看到“欢迎使用 Xamarin.Forms！”的文字：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/f88d39be-89c8-4780-ac84-18b8c6582c74.png)

# 设计 MainPage 文件

创建了一个全新的空白 Xamarin.Forms 应用程序，名为`Swiper`，其中包含一个名为`MainPage.xaml`的页面。这位于由所有特定于平台的项目引用的.NET 标准项目中。我们需要用一个新的布局替换 XAML 模板，该布局将包含我们的`Swiper`控件。

让我们通过用我们需要的内容替换默认内容来编辑已经存在的`MainPage.xaml`文件：

1.  打开`MainPage.xaml`文件。

1.  用以下加粗标记的 XAML 代码替换页面的内容：

```cs
<?xml version="1.0" encoding="utf-8"?>
<ContentPage  

             x:Class="Swiper.MainPage">

 <Grid Padding="0,40" x:Name="MainGrid">
 <Grid.RowDefinitions>
 <RowDefinition Height="400" />
 <RowDefinition Height="*" />
 </Grid.RowDefinitions>
<Grid Grid.Row="1" Padding="30"> <!-- Placeholder for later --> </Grid>
 </Grid>
</ContentPage>
```

`ContentPage`节点内的 XAML 定义了应用程序中的两个网格。网格只是其他控件的容器。它根据行和列来定位这些控件。外部网格在这种情况下定义了两行，将覆盖整个屏幕的可用区域。第一行高度为 400 个单位，第二行的`height="*"`使用了剩余的可用空间。

内部网格，它在第一个网格内定义，并且使用属性`Grid.Row="1"`分配给第二行。行和列索引是从零开始的，所以`"1"`实际上指的是第二行。我们将在本章后面向这个网格添加一些内容，但现在我们将其保留为空白。

两个网格都定义了它们的填充。您可以输入一个数字，表示所有边都有相同的填充，或者像这种情况一样输入两个数字。我们输入了`0,40`，这意味着左右两侧应该有零单位的填充，顶部和底部应该有 40 个单位的填充。还有第三个选项，使用四个数字，按照特定顺序设置*左*侧、*顶部*、*右*侧和*底部*的填充。

最后要注意的一件事是，我们给外部网格一个名称，`x:Name="MainGrid"`。这将使它可以直接从`MainPage.xaml.cs`文件中定义的代码后台访问。由于在这个示例中我们没有使用 MVVM，我们需要一种方法来访问网格而不使用数据绑定。

# 创建 Swiper 控件

这个项目的主要部分涉及创建`Swiper`控件。控件是一个自包含的 UI，带有相应的代码后台。它可以作为元素添加到任何 XAML 页面中，也可以在代码后台文件中的代码中添加。在这个项目中，我们将从代码中添加控件。

# 创建控件

创建`Swiper`控件是一个简单的过程。我们只需要确保选择正确的项模板，即内容视图：

1.  在.NET 标准库项目中，创建一个名为`Controls`的文件夹。

1.  右键单击“控件”文件夹，选择“添加”，然后点击“新建项...”。

1.  在“添加新项”对话框框的左窗格中选择 Visual C#项目，然后选择 Xamarin.Forms。

1.  选择内容视图（C#）项目。确保不选择 C#版本；这只会创建一个`C#`文件，而不是一个`XAML`文件。

1.  将控件命名为`SwiperControl.xaml`。

1.  点击添加：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/b193f73c-c111-45c4-ba8c-bcf13b827ac8.png)

这将为 UI 添加一个 XAML 文件和一个 C#代码后台文件。它应该看起来像下面的截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/2dfdd5eb-85b8-4b27-a121-856276cff123.png)

# 定义主网格

让我们设置`Swiper`控件的基本结构：

1.  打开`SwiperControl.xaml`文件。

1.  用粗体标记的代码替换内容：

```cs
<?xml version="1.0" encoding="UTF-8"?>
<ContentView  

             x:Class="Swiper.Controls.SwiperControl">
    <ContentView.Content>
 <Grid>
 <Grid.ColumnDefinitions>
 <ColumnDefinition Width="100" />
 <ColumnDefinition Width="*" />
 <ColumnDefinition Width="100" />
 </Grid.ColumnDefinitions> 
 <!-- ContentView for photo here -->

            <!-- StackLayout for like here -->

            <!-- StackLayout for deny here -->
        </Grid> 
    </ContentView.Content>
</ContentView>
```

这定义了一个具有三列的网格。最左边和最右边的列将占据`100`个单位的空间，中间将占据其余的可用空间。两侧的空间将是我们将添加标签以突出用户所做选择的区域。我们还添加了三个注释，作为即将到来的 XAML 的占位符。

# 为照片添加内容视图

现在我们将通过添加定义我们希望照片看起来的 XAML 来扩展`SwiperControl.xaml`文件。我们的最终结果将看起来像下面的照片。由于我们将从互联网上获取图像，我们将显示一个加载文本，以确保用户了解正在发生什么。为了使其看起来像即时打印的照片，我们在照片下面添加了一些手写文本：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/fc24bad2-9388-46f0-b350-a800700d8816.png)

上面的照片是我们希望照片看起来的样子。为了使其成为现实，我们需要向`SwiperControl`添加一些 XAML：

1.  打开`SwiperControl.xaml`。

1.  将粗体的 XAML 添加到以下注释中：`<!-- ContentView for photo here -->`。确保不要替换页面的整个`ContentView`；只需在注释下面添加如下。页面的其余部分应保持不变：

```cs
<!-- ContentView for photo here -->
<ContentView x:Name="photo" Padding="40" Grid.ColumnSpan="3" >
    <Grid x:Name="photoGrid" BackgroundColor="Black" Padding="1" >
        <Grid.RowDefinitions>
            <RowDefinition Height="*" />
            <RowDefinition Height="40" />
         </Grid.RowDefinitions>

        <BoxView BackgroundColor="White" Grid.RowSpan="2" />

        <Image x:Name="image" Margin="10"
               BackgroundColor="#AAAAAA"
               Aspect="AspectFill" />

        <Label x:Name="loadingLabel"
                Text="Loading..."
                TextColor="White"
                FontSize="Large"
                FontAttributes="Bold"
                HorizontalOptions="Center"
                VerticalOptions="Center" />

        <Label x:Name="descriptionLabel" 
               Margin="10,0" 
               Text="A picture of grandpa" 
               Grid.Row="1"
               FontFamily="Bradley Hand" />
    </Grid>
</ContentView>
```

`ContentView`控件定义了一个新的区域，我们可以在其中添加其他控件。`ContentView`的一个非常重要的特性是它只接受一个子控件。大多数情况下，我们会添加其中一个可用的布局控件。在这种情况下，我们将使用`Grid`控件来布局控件，如前面的代码所示。

网格定义了两行：

+   一个用于照片本身的行，在分配了其他行的空间后占据所有可用空间

+   一个用于评论的行，其高度恰好为`40`个单位

`Grid`本身设置为使用黑色背景和`1`的填充。这与`BoxView`结合使用，`BoxView`具有白色背景，创建了我们在控件周围看到的框架。`BoxView`还设置为跨越网格的两行（`Grid.RowSpan="2"`），占据网格的整个区域，减去填充。

接下来是`Image`控件。它的背景颜色设置为漂亮的灰色（`#AAAAAA`），边距为`40`，这将使其与周围的框架分离一点。它还有一个硬编码的名称（`x:Name="image"`），这将允许我们从代码后台与其交互。最后一个属性叫做`Aspect`，确定如果图像控件与源图像的比例不同，我们应该怎么做。在这种情况下，我们希望填充整个图像区域，但不显示任何空白区域。这实际上会裁剪图像的高度或宽度。

最后，我们通过添加两个标签来结束，这些标签也有硬编码的名称以供以后参考。

# 创建 DescriptionGenerator

在图像的底部，我们看到了一个描述。由于我们没有来自即将到来的图像源的图像的一般描述，我们需要创建一个生成器来制作描述。下面是我们将如何做：

1.  在.NET Standard 项目中创建一个名为`Utils`的文件夹。

1.  在该文件夹中创建一个名为`DescriptionGenerator`的新类。

1.  为`System.Linq`添加一个`using`语句（`using System.Linq;`）。

1.  将以下代码添加到类中：

```cs
public class DescriptionGenerator
{
    private string[] _adjectives = { "nice", "horrible", "great", 
    "terribly old", "brand new" };                           
    private string[] _other = { "picture of grandpa", "car", "photo 
    of a forest", "duck" };
    private static Random random = new Random();

    public string Generate()
    {
        var a = _adjectives[random.Next(_adjectives.Count())];
        var b = _other[random.Next(_other.Count())];
        return $"A {a} {b}";
    }
} 
```

这个类只有一个目的。它从`_adjectives`数组中取一个随机单词，并将其与`_other`数组中的一个随机单词结合起来。通过调用`Generate()`方法，我们得到一个全新的组合。请随意在数组中输入自己的单词。请注意，`Random`实例是一个静态字段。这是因为如果我们在时间上创建了太接近的`Random`类的新实例，它们将以相同的值进行种子化，并返回相同的随机数序列。

# 创建一个图片类

为了抽象出我们想要显示的图像的所有信息，我们将创建一个封装了这些信息的类。我们的`Picture`类中没有太多信息，但这是一个很好的编码实践：

1.  在`Utils`文件夹中创建一个名为`Picture`的新类。

1.  将以下代码添加到类中：

```cs
public class Picture
{
 public Uri Uri { get; set; }
  public string Description { get; set; }

 public Picture()
 {
 Uri = new Uri($"https://picsum.photos/400/400/?random&ts= 
 {DateTime.Now.Ticks}");

 var generator = new DescriptionGenerator();
 Description = generator.Generate();
 }
}
```

`Picture`类有两个公共属性：

+   图像的`URI`，指向其在互联网上的位置

+   该图像的描述

在构造函数中，我们创建一个新的**统一资源标识符**（**URI**），它指向一个我们可以使用的测试照片的公共来源。宽度和高度在 URI 的查询字符串部分中指定。我们还附加了一个随机时间戳，以避免 Xamarin.Forms 缓存图像。这样每次请求图像时都会生成一个唯一的 URI。

然后，我们使用我们创建的`DescriptionGenerator`类来为图像生成一个随机描述。

# 将图片绑定到控件

让我们开始连接`Swiper`控件，以便开始显示图像。我们需要设置图像的源，然后根据图像的状态控制加载标签的可见性。由于我们使用的是从互联网获取的图像，可能需要几秒钟才能下载。这必须向用户传达，以避免对正在发生的事情产生困惑。

# 设置源

我们首先设置图像的源。`image`控件（在代码中称为`image`）有一个`source`属性。这个属性是抽象类型`ImageSource`。有几种不同类型的图像源可以使用。我们感兴趣的是`UriImageSource`，它接受一个 URI，下载图像，并允许图像控件显示它。

让我们扩展`Swiper`控件以设置源和描述：

1.  打开`Controls/Swiper.Xaml.cs`文件（`Swiper`控件的代码后端）。

1.  为`Swiper.Utils`添加一个使用语句（`using Swiper.Utils;`）。

1.  将加粗标记的代码添加到构造函数中：

```cs
public SwiperControl()
{
    InitializeComponent();

   var picture = new Picture();
 descriptionLabel.Text = picture.Description;
 image.Source = new UriImageSource() { Uri = picture.Uri };
} 
```

我们创建了一个`Picture`类的新实例，并通过设置该控件的文本属性将描述分配给 GUI 中的`descriptionLabel`。然后，我们将图像的源设置为`UriImageSource`类的新实例，并将 URI 从图片实例分配给它。这将开始从互联网下载图像，并在下载完成后立即显示它。

# 控制加载标签

在图像下载时，我们希望在图像上方显示一个居中的加载文本。这已经在我们之前创建的 XAML 文件中，所以我们真正需要做的是在图像下载完成后隐藏它。我们将通过控制`loadingLabel`的`IsVisibleProperty`来实现这一点，通过将其绑定到图像的`IsLoading`属性。每当图像上的`IsLoading`属性发生变化时，绑定就会改变标签上的`IsVisible`属性。这是一个很好的一劳永逸的方法。

让我们添加控制加载标签所需的代码：

1.  打开`Swiper.xaml.cs`代码后端文件。

1.  将加粗标记的代码添加到构造函数中：

```cs
public SwiperControl()
{
    InitializeComponent();

    var picture = new Picture();
    descriptionLabel.Text = picture.Description;
    image.Source = new  UriImageSource() { Uri = picture.Uri };
 loadingLabel.SetBinding(IsVisibleProperty, "IsLoading");
    loadingLabel.BindingContext = image; 
} 
```

在上述代码中，`loadingLabel`设置了一个绑定到`IsVisibleProperty`，实际上属于所有控件继承的`VisualElement`类。它告诉`loadingLabel`监听绑定上下文中分配的对象的`IsLoading`属性的变化。在这种情况下，这是`image`控件。

# 处理平移手势

该应用程序的核心功能之一是平移手势。平移手势是指用户按住控件并在屏幕上移动它。当我们添加多个图像时，我们还将为`Swiper`控件添加随机旋转，使其看起来像是堆叠的照片。

我们首先向`SwiperControl`添加一些字段：

1.  打开`SwiperControl.xaml.cs`文件。

1.  在类中添加以下字段：

```cs
private readonly double _initialRotation;
private static readonly Random _random = new Random();
```

第一个字段`_initialRotation`存储图像的初始旋转。我们将在构造函数中设置这个值。第二个字段是一个包含`Random`对象的`static`字段。您可能还记得，最好创建一个静态随机对象，以确保不会使用相同的种子创建多个随机对象。种子是基于时间的，因此如果我们在时间上创建对象太接近，它们会生成相同的随机序列，因此实际上并不会那么随机。

接下来我们要做的是为`PanUpdated`事件创建一个事件处理程序，我们将在本节末尾绑定到它：

1.  打开`SwiperControl.xaml.cs`代码后台文件。

1.  将`OnPanUpdated`方法添加到类中：

```cs
private void OnPanUpdated(object sender, PanUpdatedEventArgs e)
{
    switch (e.StatusType)
    {
        case GestureStatus.Started:
             PanStarted();
             break;

        case GestureStatus.Running:
             PanRunning(e);
             break;

        case GestureStatus.Completed:
             PanCompleted();
             break;
     }
} 
```

代码非常简单。我们处理一个事件，该事件将`PanUpdatedEventArgs`对象作为第二个参数。这是处理事件的标准方法。然后我们有一个`switch`子句，检查事件所指的状态。

平移手势可以有三种状态：

+   `GestureStatus.Started`: 当开始拖动时，此状态会被触发一次

+   `GestureStatus.Running`: 然后会多次触发此事件，每次您移动手指时都会触发一次

+   `GestureStatus.Completed`: 当您松开时，事件会最后一次被触发

对于这些状态中的每一个，我们调用处理不同状态的特定方法。现在我们将继续添加这些方法：

1.  打开`SwiperControl.xaml.cs`代码后台文件。

1.  将这三个方法添加到类中：

```cs
private void PanStarted()
{
    photo.ScaleTo(1.1, 100);
}

private void PanRunning(PanUpdatedEventArgs e)
{
    photo.TranslationX = e.TotalX;
    photo.TranslationY = e.TotalY;
    photo.Rotation = _initialRotation + (photo.TranslationX / 25);
}

private void PanCompleted()
{
    photo.TranslateTo(0, 0, 250, Easing.SpringOut);
    photo.RotateTo(_initialRotation, 250, Easing.SpringOut);
    photo.ScaleTo(1, 250);
}

```

让我们从`PanStarted()`开始。当用户开始拖动图像时，我们希望添加它在表面上稍微抬起的效果。这是通过将图像缩放 10%来实现的。Xamarin.Forms 有一组出色的函数来实现这一点。在这种情况下，我们在图像控件（名为`Photo`）上调用`ScaleTo()`方法，并告诉它缩放到`1.1`，这对应于其原始大小的 10%。我们还告诉它在`100`毫秒内执行此操作。这个调用也是可等待的，这意味着我们可以在控件完成动画之前等待执行下一个调用。在这种情况下，我们将使用一种忘记并继续的方法。

接下来是`PanRunning()`，在平移操作期间会多次调用。这个方法接受一个参数，即来自`PanRunning()`事件处理程序的`PanUpdatedEventArgs`。我们也可以只传入`X`和`Y`值作为参数，以减少代码的耦合。这是您可以尝试的一些东西。该方法从事件的`TotalX`/`TotalY`属性中提取`X`和`Y`分量，并将它们分配给图像控件的`TranslationX`/`TranslationY`属性。我们还根据图像移动的距离微调旋转。

最后要做的是在释放图像时将所有内容恢复到初始状态。这可以在`PanCompleted()`中完成。首先，我们将图像平移（或移动）回其原始本地坐标（`0,0`）在`250`毫秒内。我们还添加了一个缓动函数，使其略微超出目标，然后再次动画。我们可以尝试使用不同的预定义缓动函数；这些对于创建漂亮的动画非常有用。最后，我们将图像缩放回其原始大小在`250`毫秒内。

现在是时候在构造函数中添加代码，以连接平移手势并设置一些初始旋转值：

1.  打开`SwiperControl.xaml.cs`代码后台文件。

1.  在构造函数中添加粗体文本。请注意，构造函数中还有更多代码，所以不要复制和粘贴整个方法，只需添加粗体文本：

```cs
public SwiperControl()
{
    InitializeComponent();

    var panGesture = new PanGestureRecognizer();
 panGesture.PanUpdated += OnPanUpdated;
 this.GestureRecognizers.Add(panGesture); _initialRotation = _random.Next(-10, 10);
    photo.RotateTo(_initialRotation, 100, Easing.SinOut); 

    <!-- other code omitted for brevity -->
}
```

所有 Xamarin.Forms 控件都有一个名为`GestureRecognizers`的属性。有不同类型的手势识别器，例如`TapGestureRecognizer`或`SwipeGestureRecognizer`。在我们的情况下，我们对`PanGestureRecognizer`感兴趣。我们创建一个新的`PanGestureRecognizer`，并通过将其连接到我们之前创建的`OnPanUpdated()`方法来订阅`PanUpdated`事件。然后将其添加到`Swiper`控件的`GestureRecognizers`集合中。

然后我们设置图像的初始旋转，并确保我们存储它，以便我们可以修改旋转，然后将其旋转回原始状态。

# 测试控件

我们现在已经编写了所有代码来测试控件：

1.  打开`MainPage.xaml.cs`。

1.  添加`using`语句用于`Swiper.Controls`（`using Swiper.Controls;`）。

1.  在构造函数中添加粗体标记的代码：

```cs
public MainPage()
{
    InitializeComponent();
    MainGrid.Children.Add(new SwiperControl());
} 
```

如果构建顺利，我们应该得到如下图所示的图像：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/c04e8f44-09a8-4a7d-9488-46ef907f3e0c.png)

我们还可以拖动图像（平移）。注意当您开始拖动时的轻微抬起效果以及基于平移量的图像旋转，即总移动量。如果您放开图像，它会动画回到原位。

# 创建决策区域

没有每一侧屏幕上的特殊放置区域，交友应用程序就不完整。我们在这里想做一些事情：

+   当用户将图像拖动到任一侧时，应该出现文本，显示*LIKE*或*DENY*（决策区域）

+   当用户将图像放在决策区域时，应用程序应该从页面中删除图像

我们将通过向`SwiperControl.xaml`文件添加一些 XAML 代码来创建这些区域，然后继续添加必要的代码来实现这一点。值得注意的是，这些区域实际上并不是放置图像的热点区域，而是用于在控件表面上显示标签。实际的放置区域是根据您拖动图像的距离来计算和确定的。

# 扩展网格

`Swiper`控件有三列定义。如果图像被拖到页面的任一侧，我们希望为用户添加某种视觉反馈。我们将通过在每一侧添加一个带有`Label`的`StackLayout`来实现这一点。

# 添加用于喜欢照片的 StackLayout

首先要做的是在控件的右侧添加用于喜欢照片的`StackLayout`：

1.  打开`Controls/SwiperControl.xaml`。

1.  在注释`<!-- StackLayout for like here -->`下添加以下代码：

```cs
<StackLayout x:Name="likeStackLayout" Grid.Column="2"
             Opacity="0" Padding="0, 100">
    <Label Text="LIKE" 
           TextColor="Lime" 
           FontSize="30" 
           Rotation="30" 
           FontAttributes="Bold" />
</StackLayout>
```

`StackLayout`是我们要显示的内容的容器。它有一个名称，并且被分配在第三列中（由于从零开始索引，代码中写着`Grid.Column="2"`）。`Opacity`设置为`0`，使其完全不可见，并且`Padding`调整为使其从顶部向下移动一点。

在`StackLayout`内，我们将添加一个`Label`。

# 添加用于拒绝照片的 StackLayout

下一步是在控件的左侧添加用于拒绝照片的`StackLayout`：

1.  打开`Controls/SwiperControl.xaml`。

1.  在注释`<!-- StackLayout for deny here -->`下添加以下代码：

```cs
<StackLayout x:Name="denyStackLayout" Opacity="0" 
             Padding="0, 100" HorizontalOptions="End">
    <Label Text="DENY" 
           TextColor="Red"
           FontSize="30"
           Rotation="-20" 
           FontAttributes="Bold" />
</StackLayout> 
```

左侧`StackLayout`的设置与之相同，只是应该在第一列中，这是默认设置，因此不需要添加`Grid.Column`属性。我们还指定了`HorizontalOptions="End"`，这意味着内容应右对齐。

# 确定屏幕大小

为了能够计算用户拖动图像的百分比，我们需要知道控件的大小。这在 Xamarin.Forms 布局控件之后才确定。

我们将重写`OnSizeAllocated()`方法，并在类中添加一个名为`_screenWidth`的字段，以便通过以下几个步骤跟踪窗口的当前宽度：

1.  打开`SwiperControl.xaml.cs`。

1.  将以下代码添加到文件中。将字段放在类的开头，将`OnSizeAllocated()`方法放在构造函数下面：

```cs
private double _screenWidth = -1;

protected override void OnSizeAllocated(double width, double height)
{
    base.OnSizeAllocated(width, height);

    if (Application.Current.MainPage == null)
    {
        return;
    }

    _screenWidth = Application.Current.MainPage.Width;
} 
```

`_screenWidth`字段用于在解析后立即存储宽度。我们通过重写`OnSizeAllocated()`方法来实现这一点，该方法在 Xamarin.Forms 分配控件的大小时调用。这被调用多次。第一次调用实际上是在设置宽度和高度之前以及设置当前应用程序的`MainPage`之前。此时，宽度和高度设置为`-1`，并且`Application.Current.MainPage`为 null。我们通过对`Application.Current.MainPage`进行空检查并在其为 null 时返回来寻找这种状态。我们也可以检查宽度上的`-1`值。任一方法都可以工作。但是，如果它有一个值，我们希望将其存储在我们的`_screenWidth`字段中以供以后使用。

Xamarin.Forms 会在应用程序框架发生变化时调用`OnSizeAllocated()`方法。这对于 UWP 应用程序来说最为重要，因为它们在用户可以轻松更改的窗口中。Android 和 iOS 应用程序不太可能再次调用此方法，因为应用程序将占据整个屏幕的房地产。

# 添加夹取函数

为了能够计算状态，我们需要稍后夹取一个值。在撰写本文时，这个函数已经在 Xamarin.Forms 中，但它被标记为内部函数，这意味着我们不应该真的使用它。据传言，它将很快在 Xamarin.Forms 的后续版本中公开，但目前，我们需要重新定义它：

1.  打开`SwiperControl.xaml.cs`。

1.  在类中添加以下`static`方法：

```cs
private static double Clamp(double value, double min, double max)
{
     return (value < min) ? min : (value > max) ? max : value;
} 
```

该方法接受一个要夹取的值，一个最小边界和一个最大边界。如果值大于或小于设置的边界，则返回值本身或边界值。

# 添加计算状态的代码

为了计算图像的状态，我们需要定义我们的区域，然后创建一个函数，该函数接受当前移动量并根据我们平移图像的距离更新 GUI 决策区域的不透明度。

# 定义一个用于计算状态的方法

让我们添加`CalculatePanState()`方法来计算我们已经平移图像的距离，以及它是否应该开始影响 GUI，按照以下几个步骤进行：

1.  打开`Controls/SwiperControl.xaml.cs`。

1.  将属性添加到顶部，将`CalculatePanState()`方法添加到类中的任何位置，如下面的代码所示：

```cs
private const double DeadZone = 0.4d;
private const double DecisionThreshold = 0.4d;

private void CalculatePanState(double panX)
{
    var halfScreenWidth = _screenWidth / 2;
    var deadZoneEnd = DeadZone * halfScreenWidth;

    if (Math.Abs(panX) < deadZoneEnd)
    {
        return;
    }

    var passedDeadzone = panX < 0 ? panX + deadZoneEnd : panX - 
    deadZoneEnd;
    var decisionZoneEnd = DecisionThreshold * halfScreenWidth;
    var opacity = passedDeadzone / decisionZoneEnd;

    opacity = Clamp(opacity, -1, 1);

    likeStackLayout.Opacity = opacity;
    denyStackLayout.Opacity = -opacity;
} 
```

我们将两个值定义为常量：

+   `DeadZone`定义了当平移图像时，中心点两侧可用空间的 40%（`0.4`）是死区。如果我们在这个区域释放图像，它将简单地返回到屏幕中心而不采取任何行动。

+   下一个常量是`DecisionThreshold`，它定义了另外 40%（`0.4`）的可用空间。这用于插值`StackLayout`在布局两侧的不透明度。

然后，我们使用这些值来检查平移操作的状态。如果`X`（`panX`）的绝对平移值小于死区，我们将返回而不采取任何行动。如果不是，则我们计算我们已经超过死区的距离以及我们进入决策区的距离。我们根据这个插值计算不透明度值，并将值夹取在`-1`和`1`之间。

最后，我们为`likeStackLayout`和`denyStackLayout`设置透明度为这个值。

# 连接平移状态检查

在图像被平移时，我们希望更新状态：

1.  打开`Controls/SwiperControl.xaml.cs`。

1.  将以下代码添加到`PanRunning()`方法中：

```cs
private void PanRunning(PanUpdatedEventArgs e)
{
    photo.TranslationX = e.TotalX;
    photo.TranslationY = e.TotalY;
    photo.Rotation = _initialRotation + (photo.TranslationX / 25);

    CalculatePanState(e.TotalX);
} 
```

`PanRunning()`方法的这个添加将在*x*轴上的总移动量传递给`CalculatePanState()`方法，以确定我们是否需要调整控件左侧或右侧的`StackLayout`的透明度。

# 添加退出逻辑

到目前为止，一切都很好，除了一个问题，即如果我们将图像拖到边缘然后放开，文本会保留。我们需要确定用户何时停止拖动图像，以及图像是否处于决策区。

# 检查图像是否应退出

我们希望有一个简单的函数来确定一张图片是否已经移动足够远，以便算作该图片的退出：

1.  打开`Controls/SwiperControl.xaml.cs`。

1.  在类中添加`CheckForExitCritera()`方法，如下所示：

```cs
private bool CheckForExitCriteria()
{
    var halfScreenWidth = _screenWidth / 2;
    var decisionBreakpoint = DeadZone * halfScreenWidth;
    return (Math.Abs(photo.TranslationX) > decisionBreakpoint); 
} 
```

此函数计算我们是否已经越过死区并进入决策区。我们需要使用`Math.Abs()`方法获取总绝对值进行比较。我们也可以使用`<`和`>`运算符，但我们使用这种方法是因为它更可读。这是代码风格和品味的问题，随意按照自己的方式进行。

# 删除图像

如果我们确定图像已经移动足够远，使其退出，我们希望将其从屏幕上动画移出，然后从页面中删除图像：

1.  打开`Controls/SwiperControl.xaml.cs`。

1.  在类中添加`Exit()`方法，如下所示：

```cs
private void Exit()
{
    Device.BeginInvokeOnMainThread(async () =>
    {
        var direction = photo.TranslationX < 0 ? -1 : 1;

        await photo.TranslateTo(photo.TranslationX + 
        (_screenWidth * direction),
        photo.TranslationY, 200, Easing.CubicIn);
        var parent = Parent as Layout<View>;
        parent?.Children.Remove(this);
    });
}      
```

`Exit()`方法执行以下操作：

1.  我们首先确保此调用在 UI 线程上完成，这也被称为`MainThread`。这是因为只有 UI 线程才能执行动画。

1.  我们还需要异步运行此线程，以便一举两得。由于这个方法是关于将图像动画到屏幕的一侧，我们需要确定在哪个方向进行动画。

1.  我们通过确定图像的总平移是正数还是负数来执行此操作。

1.  然后我们使用这个值通过`photo.TranslateTo()`调用来等待翻译。

1.  我们等待此调用，因为我们不希望代码执行继续，直到完成。完成后，我们将控件从父级的子级集合中移除，导致它永远消失。

# 更新 PanCompleted

决定图像是否应消失或仅返回到其原始状态是在`PanCompleted()`方法中触发的。在这里，我们连接了前两节中创建的两种方法：

1.  打开`Controls/SwiperControl.xaml.cs`。

1.  在`PanCompleted()`方法中添加粗体代码：

```cs
private void PanCompleted()
{
 if (CheckForExitCriteria())
 {
 Exit();
 }

 likeStackLayout.Opacity = 0;
 denyStackLayout.Opacity = 0;

    photo.TranslateTo(0, 0, 250, Easing.SpringOut);
    photo.RotateTo(_initialRotation, 250, Easing.SpringOut);
    photo.ScaleTo(1, 250);
} 
```

本节中的最后一步是使用`CheckForExitCriteria()`方法和`Exit()`方法，如果满足退出条件，则执行这些条件。如果不满足退出条件，我们需要重置`StackLayout`的状态和不透明度，使一切恢复正常。

# 向控件添加事件

在控件本身中我们还剩下最后一件事要做，那就是添加一些事件，指示图像是否已被*喜欢*或*拒绝*。我们将使用一个干净的接口，允许控件的简单使用，同时隐藏所有实现细节。

# 声明两个事件

为了使控件更容易从应用程序本身进行交互，我们需要为`Like`和`Deny`添加事件：

1.  打开`Controls/SwiperControl.xaml.cs`。

1.  在类的开头添加两个事件声明，如下所示：

```cs
public event EventHandler OnLike;
public event EventHandler OnDeny; 
```

这是两个带有开箱即用的事件处理程序的标准事件声明。

# 触发事件

我们需要在`Exit()`方法中添加代码来触发我们之前创建的事件：

1.  打开`Controls/SwiperControl.xaml.cs`。

1.  在`Exit()`方法中添加粗体代码：

```cs
private void Exit()
{
    Device.BeginInvokeOnMainThread(async () =>
    {
        var direction = photo.TranslationX < 0 ? -1 : 1;

 if (direction > 0)
 {
 OnLike?.Invoke(this, new EventArgs());
 }

 if (direction < 0)
 {
 OnDeny?.Invoke(this, new EventArgs());
 }

        await photo.TranslateTo(photo.TranslationX + (_screenWidth 
        * direction),
        photo.TranslationY, 200, Easing.CubicIn);
        var parent = Parent as Layout<View>;
        parent?.Children.Remove(this);
    });
}
```

在这里，我们注入代码来检查我们是喜欢还是不喜欢一张图片。然后根据这些信息触发正确的事件。

# 连接 Swiper 控件

我们现在已经到达本章的最后部分。在本节中，我们将连接图像并使我们的应用成为一个可以永远使用的闭环应用程序。我们将添加 10 张图像，这些图像将在应用程序启动时从互联网上下载。每次删除一张图像时，我们将简单地添加另一张图像。

# 添加图像

让我们首先创建一些代码，将图像添加到 MainView 中。我们将首先添加初始图像，然后创建逻辑，以便在每次喜欢或不喜欢图像时向堆栈底部添加新图像。

# 添加初始照片

为了使照片看起来像是堆叠在一起，我们至少需要 10 张照片：

1.  打开`MainPage.xaml.cs`。

1.  将“AddInitalPhotos（）”方法和“InsertPhotoMethod（）”添加到类中：

```cs
private void AddInitialPhotos()
{
    for (int i = 0; i < 10; i++)
    {
        InsertPhoto();
    }
}

private void InsertPhoto()
{
    var photo = new SwiperControl();
    this.MainGrid.Children.Insert(0, photo);
} 
```

首先，我们创建一个名为“AddInitialPhotos（）”的方法，该方法将在启动时调用。该方法简单地调用“InsertPhoto（）”方法 10 次，并每次向`MainGrid`添加一个新的`SwiperControl`。它将控件插入到堆栈的第一个位置，从而有效地将其放在堆栈底部，因为控件集合是从开始到结束渲染的。

# 从构造函数中进行调用

我们需要调用此方法才能使魔术发生：

1.  打开`MainPage.xaml.cs`。

1.  将粗体中的代码添加到构造函数中，并确保它看起来像下面这样：

```cs
public MainPage()
{
    InitializeComponent();
    AddInitialPhotos();
} 
```

这里没有什么可说的。在初始化`MainPage`之后，我们调用该方法添加 10 张我们将从互联网上下载的随机照片。

# 添加计数标签

我们还希望为应用程序添加一些价值观。我们可以通过在`Swiper`控件集合下方添加两个标签来实现这一点。每当用户对图像进行评分时，我们将递增两个计数器中的一个，并显示结果。

因此，让我们添加 XAML 以显示标签所需的内容：

1.  打开`MainPage.xaml`。

1.  用粗体标记的代码替换注释`<!-- Placeholder for later -->`：

```cs
<Grid Grid.Row="1" Padding="30">
    <Grid.RowDefinitions>
 <RowDefinition Height="auto" />
 <RowDefinition Height="auto" />
 <RowDefinition Height="auto" />
 <RowDefinition Height="auto" />
 </Grid.RowDefinitions>

 <Label Text="LIKES" />
 <Label x:Name="likeLabel" 
 Grid.Row="1"
 Text="0" 
 FontSize="Large" 
 FontAttributes="Bold" />

 <Label Grid.Row="2" 
 Text="DENIED" />
 <Label x:Name="denyLabel"
 Grid.Row="3" 
 Text="0" 
 FontSize="Large" 
 FontAttributes="Bold" />
</Grid> 
```

此代码添加了一个具有四个自动高度行的新`Grid`。这意味着我们计算每行内容的高度，并将其用于布局。这基本上与`StackLayout`相同，但我们想展示一种更好的方法。

在每行中添加一个`Label`，并将其中两个命名为`likeLabel`和`denyLabel`。这两个命名的标签将保存已喜欢的图像数量以及已拒绝的图像数量。

# 订阅事件

最后一步是连接`OnLike`和`OnDeny`事件，并向用户显示总计数。

# 添加方法以更新 GUI 并响应事件

我们需要一些代码来更新 GUI 并跟踪计数：

1.  打开`MainPage.xaml.cs`。

1.  将以下代码添加到类中，如下所示：

```cs
private int _likeCount;
private int _denyCount;

private void UpdateGui()
{
    likeLabel.Text = _likeCount.ToString();
    denyLabel.Text = _denyCount.ToString();
}

private void Handle_OnLike(object sender, EventArgs e)
{
    _likeCount++;
    InsertPhoto();
    UpdateGui();
}

private void Handle_OnDeny(object sender, EventArgs e)
{
    _denyCount++;
    InsertPhoto();
    UpdateGui();
} 
```

顶部的两个字段跟踪喜欢和拒绝的数量。由于它们是值类型变量，它们默认为零。

为了使这些标签的更改传播到 UI，我们创建了一个名为“UpdateGui（）”的方法。这将获取两个前述字段的值，并将其分配给两个标签的`Text`属性。

接下来的两个方法是将处理`OnLike`和`OnDeny`事件的事件处理程序。它们增加适当的字段，添加新照片，然后更新 GUI 以反映更改。

# 连接事件

每次创建新的`SwiperControl`时，我们需要连接事件：

1.  打开“MainPage.xaml.cs”。

1.  将粗体中的代码添加到“InsertPhoto（）”方法中：

```cs
private void InsertPhoto()
{
    var photo = new SwiperControl();
 photo.OnDeny += Handle_OnDeny;
 photo.OnLike += Handle_OnLike;

    this.MainGrid.Children.Insert(0, photo);
} 
```

添加的代码连接了我们之前定义的事件处理程序。这些事件确实使与我们的新控件交互变得容易。自己尝试一下，并玩一下您创建的应用程序。

# 摘要

干得好！在本章中，我们学习了如何创建一个可重用的外观良好的控件，可用于任何 Xamarin.Forms 应用程序。为了增强应用程序的用户体验（UX），我们使用了一些动画，为用户提供了更多的视觉反馈。我们还在 XAML 的使用上有所创意，定义了一个看起来像是带有手写描述的照片的控件的 GUI。

之后，我们使用事件将控件的行为暴露给`MainPage`，以限制应用程序与控件之间的接触表面。最重要的是，我们涉及了`GestureRecognizers`的主题，这可以在处理常见手势时使我们的生活变得更加轻松。

在下一章中，我们将看看如何在 iOS 和 Android 设备上后台跟踪用户的位置。为了可视化我们正在跟踪的内容，我们将使用 Xamarin.Forms 中的地图组件。


# 第四章：使用 GPS 和地图构建位置跟踪应用程序

在本章中，我们将创建一个位置跟踪应用程序，将用户的位置保存并显示为热力图。我们将看看如何在 iOS 和 Android 设备上后台运行任务，以及如何使用自定义渲染器来扩展 Xamarin.Forms 地图的功能。

本章将涵盖以下主题：

+   在 iOS 设备上后台跟踪用户位置

+   在 Android 设备上后台跟踪用户位置

+   如何在 Xamarin.Forms 应用程序中显示地图

+   如何使用自定义渲染器扩展 Xamarin.Forms 地图的功能

# 技术要求

为了能够完成项目，您需要安装 Visual Studio for Mac 或 PC，以及 Xamarin 组件。有关如何设置您的环境的更多详细信息，请参阅第一章，“Xamarin 简介”。

# 项目概述

许多应用程序可以通过添加地图和位置服务而变得更加丰富。在这个项目中，我们将构建一个名为**MeTracker**的位置跟踪应用程序。该应用程序将跟踪用户的位置并将其保存到 SQLite 数据库中，以便我们可以将结果可视化为热力图。为了构建这个应用程序，我们将学习如何在 iOS 和 Android 上设置后台进程，因为我们无法在 iOS 和 Android 之间共享代码。对于地图，我们将使用`Xamarin.Forms.Maps`组件并扩展其功能以构建热力图。为此，我们将使用 iOS 的自定义渲染器和 Android 的自定义渲染器，以便我们可以使用平台 API。

# 入门

我们可以使用 PC 上的 Visual Studio 2017 或 Mac 上的 Visual Studio 来完成此项目。要使用 Visual Studio 在 PC 上构建 iOS 应用程序，您必须连接 Mac。如果您根本没有访问 Mac，您可以只完成此项目的 Android 部分。

# 构建 MeTracker 应用程序

现在是时候开始构建应用程序了。创建一个**移动应用程序（Xamarin.Forms）**。我们将在新项目对话框的**跨平台**选项卡下找到该模板。我们将项目命名为`MeTracker`。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/1f1e8d6f-a293-4877-b4b6-c3ab000085f6.png)

使用.NET Standard 作为代码共享策略，并选择 iOS 和 Android 作为平台。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/aec81384-04d7-4520-a668-6571e93d02ce.png)

确保使用 Android 版本 Oreo（API 级别 26）或更高版本进行编译。我们可以在项目属性的“应用程序”选项卡下设置这一点。

更新模板添加的 NuGet 包，以确保我们使用最新版本。

# 创建存储用户位置的存储库

我们要做的第一件事是创建一个存储库，我们可以用来保存用户的位置。

# 为位置数据创建模型

在创建存储库之前，我们将通过以下步骤创建一个代表用户位置的模型类：

1.  创建一个新的文件夹，我们可以用于此和其他模型，名为`Models`。

1.  在`Models`文件夹中创建一个名为`Location`的类，并为`Id`、`Latitude`和`Longitude`添加属性。

1.  创建两个构造函数，一个为空的构造函数，另一个以`latitude`和`longitude`作为参数的构造函数，使用以下代码：

```cs
using System;

namespace MeTracker.Models
{
    public class Location
    {
        public Location() {}

        public Location(double latitude, double longitude)
        {
            Latitude = latitude;
            Longitude = longitude;
        }

        public int Id { get; set; }
        public double Latitude { get; set; }
        public double Longitude { get; set; }
    }
}
```

# 创建存储库

现在我们已经创建了一个模型，我们可以继续创建存储库。首先，我们将通过以下步骤为存储库创建一个接口：

1.  在`MeTracker`项目中，创建一个名为`Repositories`的新文件夹。

1.  在我们的新文件夹中，我们将创建一个名为`ILocationRepository`的接口。

1.  在我们为`interface`创建的新文件中编写以下代码：

```cs
using MeTracker.Models;
using System;
using System.Threading.Tasks;

namespace MeTracker.Repositories
{
    public interface ILocationRepository
    {
        Task Save(Location location);
    }
}
```

1.  为`MeTracker.Models`和`System.Threading.Tasks`添加`using`指令，以解析`Location`和`Task`的引用。

一旦我们有了一个`interface`，我们需要通过以下步骤创建其实现：

1.  在`MeTracker`项目中，创建一个名为`LocationRepository`的新类。

1.  实现`ILocationRepository`接口，并在`Save`方法中添加`async`关键字，使用以下代码：

```cs
using System;
using System.Threading.Tasks;
using MeTracker.Models;

namespace MeTracker.Repositories
{
    public class LocationRepository : ILocationRepository 
    {
        public async Task Save(Location location)
        {
        }
    }
}
```

为了存储数据，我们将使用 SQLite 数据库和对象关系映射器（ORM）SQLite-net，以便我们可以针对领域模型编写代码，而不是使用 SQL 对数据库进行操作。这是由 Frank A. Krueger 创建的开源库。让我们通过以下步骤来设置这个：

1.  在`MeTracker`项目中安装 NuGet 包`sqlite-net-pcl`。

1.  转到`Location`模型类，并为`Id`属性添加`PrimaryKeyAttribute`和`AutoIncrementAttribute`。当我们添加这些属性时，`Id`属性将成为数据库中的主键，并将自动创建一个值。

1.  在`LocationRepository`类中编写以下代码，以创建与 SQLite 数据库的连接。`if`语句用于检查我们是否已经创建了连接。如果是这样，我们将不会创建新的连接；相反，我们将使用已经创建的连接：

```cs
private SQLiteAsyncConnection connection;

private async Task CreateConnection()
{
    if (connection != null)
    {
        return;
    }

   var databasePath = 
   Path.Combine(Environment.GetFolderPath
   (Environment.SpecialFolder .MyDocuments), "Locations.db");

 connection = new SQLiteAsyncConnection(databasePath);
 await connection.CreateTableAsync<Location>();
} 
```

现在，是时候实现`Save`方法了，该方法将以位置对象作为参数，并将其存储在数据库中。

现在，我们将在`Save`方法中使用`CreateConnection`方法，以确保在尝试将数据保存到数据库时创建连接。当我们知道有一个活动连接时，我们可以使用`InsertAsync`方法，并将`Save`方法的`location`参数作为参数传递。

编辑`LocationRepository`类中的`Save`方法，使其看起来像以下代码：

```cs
public async Task Save(Location location)
{
    await CreateConnection();
    await connection.InsertAsync(location);
}
```

# Xamarin.Essentials

**Xamarin.Essentials**是由 Microsoft 和 Xamarin 创建的库，使开发人员能够从共享代码中使用特定于平台的 API。Xamarin.Essentials 目标是 Xamarin.iOS、Xamarin.Android 和 UWP。在这个项目中，我们将使用 Xamarin.Essentials 来执行各种任务，包括获取位置和在主线程上执行代码。

# 安装 NuGet 包

在撰写本文时，Xamarin.Essentials 处于预览状态。要找到预览中的 NuGet 包，我们需要勾选包括预览版本的复选框。

# 在 Android 上配置 Xamarin.Essentials

我们需要通过调用初始化方法在 Android 上初始化 Xamarin.Essentials。我们通过以下步骤来实现这一点：

1.  在 Android 项目中，打开`MainActivity.cs`文件。

1.  在`global::Xamarin.Forms.Forms.Init`方法下添加粗体代码：

```cs
protected override void OnCreate(Bundle savedInstanceState)
{
    TabLayoutResource = Resource.Layout.Tabbar;
    ToolbarResource = Resource.Layout.Toolbar;

    base.OnCreate(savedInstanceState);

    global::Xamarin.Forms.Forms.Init(this, savedInstanceState);
    Xamarin.Essentials.Platform.Init(this, savedInstanceState);

    LoadApplication(new App());
}
```

就是这样。我们已经准备就绪。

# 为位置跟踪创建一个服务

要跟踪用户的位置，我们需要根据平台编写代码。Xamarin.Essentials 具有用于在共享代码中获取用户位置的方法，但不能在后台使用。为了能够使用我们将为每个平台编写的代码，我们需要创建一个接口。对于`ILocationRepository`接口，将只有一个在两个平台上使用的实现，而对于位置跟踪服务，我们将在 iOS 平台和 Android 平台分别有一个实现。

通过以下步骤创建`ILocationRepository`接口：

1.  在`MeTracker`项目中，创建一个新的文件夹，并命名为`Services`。

1.  在`Services`文件夹中创建一个名为`ILocationTrackingService`的新接口。

1.  在接口中，添加一个名为`StartTracking`的方法，如下所示：

```cs
 public interface ILocationTrackingService
 {
      void StartTracking();
 } 
```

目前，我们将在 iOS 和 Android 项目中只创建一个空的接口实现，稍后在本章中我们将回到每个实现：

1.  在 iOS 和 Android 项目中创建一个名为`Services`的文件夹。

1.  在 iOS 和 Android 项目的新`Service`文件夹中，按照以下代码中所示创建一个名为`LocationTrackingService`的类的空实现：

```cs
public class LocationTrackingService : ILocationTrackingService
{
     public void StartTracking()
     {
     }
}
```

# 设置应用逻辑

我们现在已经创建了我们需要跟踪用户位置并在设备上保存位置的接口。现在是时候编写代码来开始跟踪用户了。我们仍然没有任何实际跟踪用户位置的代码，但如果我们已经编写了开始跟踪的代码，那么编写这部分代码将会更容易。

# 创建一个带有地图的视图

首先，我们将创建一个带有简单地图的视图，该地图以用户位置为中心。让我们通过以下步骤来设置这一点：

1.  在`MeTracker`项目中，创建一个名为`Views`的新文件夹。

1.  在`Views`文件夹中，创建一个基于 XAML 的`ContentPage`，并将其命名为`MainView`。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/5888007b-7310-4c28-813f-7e9458ad3da0.png)

Xamarin.Forms 包中没有地图控件，但是微软和 Xamarin 提供了一个官方包，可以在 Xamarin.Forms 应用中显示地图。这个包叫做`Xamarin.Forms.Maps`，我们可以通过以下步骤从 NuGet 安装它：

1.  在`MeTracker`，`MeTracker.Android`和`MeTracker.iOS`项目中安装`Xamarin.Forms.Maps`。

1.  使用以下代码为`MainView`添加`Xamarin.Forms.Maps`的命名空间：

```cs
 <ContentPage xmlns="http://xamarin.com/schemas/2014/forms" 
              xmlns:x="http://schemas.microsoft.com/winfx/2009/xaml" 
              xmlns:map="clr- 
              namespace:Xamarin.Forms.Maps;assembly
              =Xamarin.Forms.Maps"
              x:Class="MeTracker.Views.MainView"> 
```

现在我们可以在我们的视图中使用地图了。因为我们希望`Map`覆盖整个页面，所以我们可以将它添加到`ContentPage`的根部。让我们通过以下步骤来设置这一点：

1.  将`map`添加到`ContentPage`。

1.  给地图命名，以便我们可以从代码后台访问它。将其命名为`Map`，如下所示：

```cs
 <ContentPage  

              x:Class="MeTracker.Views.MainView"> 
 <map:Map x:Name="Map" /> 
</ContentPage>
```

为了使用`map`控件，我们需要在每个平台上运行代码来初始化它，通过以下步骤：

1.  在 iOS 项目中，转到`AppDelegate.cs`。

1.  在`FinishedLaunching`方法中，在`Xamarin.Forms`的`Init`之后，添加`global::Xamarin.FormsMaps.Init()`来初始化 iOS 应用中的`map`控件，使用以下代码：

```cs
public override bool FinishedLaunching(UIApplication app, NSDictionary options)
{
     global::Xamarin.Forms.Forms.Init();
     global::Xamarin.FormsMaps.Init();

     LoadApplication(new App());

     return base.FinishedLaunching(app, options);
} 
```

继续为 Android 初始化：

1.  在 Android 项目中，转到`MainActivity.cs`。

1.  在`OnCreate`方法中，在`Xamarin.Forms`的`Init`之后，添加`global::Xamarin.FormsMaps.Init(this, savedInstanceState)`来初始化 iOS 上的`map`控件。

1.  通过以下代码初始化 Xamarin.Essentials：`Xamarin.Essentials.Platform.Init(this, savedInstanceState)`。

```cs
protected override void OnCreate(Bundle savedInstanceState)
{
    TabLayoutResource = Resource.Layout.Tabbar;
    ToolbarResource = Resource.Layout.Toolbar;

     base.OnCreate(savedInstanceState);
     global::Xamarin.Forms.Forms.Init(this, savedInstanceState);
     global::Xamarin.FormsMaps.Init(this, savedInstanceState);

     Xamarin.Essentials.Platform.Init(this, savedInstanceState); 

     LoadApplication(new App());
} 
```

对于 Android，我们还需要决定用户回答权限对话框后发生什么，并将结果发送给 Xamarin.Essentials。我们将通过将以下代码添加到`MainActivity.cs`来实现这一点：

```cs
public override void OnRequestPermissionsResult(int requestCode,                     
                 string[] permissions, 
                 [GeneratedEnum] Android.Content.PM.Permission[]          
                 grantResults)
{     Xamarin.Essentials.Platform.OnRequestPermissionsResult(requestCode,   
                 permissions, grantResults);
                 base.OnRequestPermissionsResult(requestCode,   
                 permissions, grantResults);
}
```

对于 Android，我们需要一个**API 密钥**来获取 Google Maps 的地图。有关如何获取 API 密钥的 Microsoft 文档可以在[`docs.microsoft.com/en-us/xamarin/android/platform/maps-and-location/maps/obtaining-a-google-maps-api-key`](https://docs.microsoft.com/en-us/xamarin/android/platform/maps-and-location/maps/obtaining-a-google-maps-api-key)找到。以下是获取 API 密钥的步骤：

1.  打开`AndroidMainfest.xml`，它位于 Android 项目的`Properties`文件夹中。

1.  将元数据元素插入到应用程序元素中，如下所示：

```cs
 <application android:label="MeTracker.Android">
      <meta-data android:name="com.google.android.maps.v2.API_KEY" 
      android:value="{YourKeyHere}" />
</application> 
```

我们还希望地图以用户的位置为中心。我们将在`MainView.xaml.cs`的构造函数中实现这一点。因为我们希望异步运行获取用户位置的操作，并且它需要在主线程上执行，所以我们将使用`MainThread.BeginInvokeOnMainThread`来包装它。我们将使用 Xamarin.Essentials 来获取用户的当前位置。当我们有了位置信息后，我们可以使用`Map`的`MoveToRegion`方法。我们可以通过以下步骤来设置这一点：

1.  在`MeTracker`项目中，打开`MainView.xaml.cs`。

1.  将粗体字中的代码添加到`MainView.xaml.cs`类的构造函数中：

```cs
public MainView ()
{
    InitializeComponent ();

MainThread.BeginInvokeOnMainThread(async() =>
 {
 var location = await Geolocation.GetLocationAsync();
 Map.MoveToRegion(MapSpan.FromCenterAndRadius(
 new Position(location.Latitude, location.Longitude), 
 Distance.FromKilometers(5)));
 });
}
```

# 创建一个 ViewModel

在创建实际的视图模型之前，我们将创建一个所有视图模型都可以继承的抽象基础视图模型。这个基础视图模型的想法是我们可以在其中编写通用代码。在这种情况下，我们将通过以下步骤实现`INotifyPropertyChanged`接口：

1.  在`MeTracker`项目中创建一个名为`ViewModels`的文件夹。

1.  编写以下代码并解析所有引用：

```cs
public abstract class ViewModel : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler PropertyChanged;

    public void RaisePropertyChanged(params string[] propertyNames)
    {
        foreach(var propertyName in propertyNames)
        {
            PropertyChanged?.Invoke(this, new  
            PropertyChangedEventArgs(propertyName));
        }
    }
} 
```

下一步是创建实际的视图模型，它将使用`ViewModel`作为基类。通过以下步骤来设置：

1.  在`MeTracker`项目中，在`ViewModels`文件夹中创建一个名为`MainViewModel`的新类。

1.  使`MainViewModel`继承`ViewModel`。

1.  添加一个`ILocationTrackingService`类型的只读字段，并命名为`locationTrackingService`。

1.  添加一个`ILocationRepository`类型的只读字段，并命名为`locationRepository`。

1.  创建一个构造函数，参数为`ILocationTrackingService`和`ILocationRepository`。

1.  使用参数的值设置我们在*步骤*3 和*步骤*4 中创建的字段的值，如下面的代码所示：

```cs
public class MainViewModel : ViewModel
{
         private readonly ILocationRepository locationRepository;
         private readonly ILocationTrackingService 
         locationTrackingService;

         public MainViewModel(ILocationTrackingService 
         locationTrackingService,
         ILocationRepository locationRepository)
         {
             this.locationTrackingService = 
             locationTrackingTrackingService;
             this.locationRepository = locationRepository;
         } 
}
```

为了使 iOS 应用程序开始跟踪用户的位置，我们需要通过以下步骤在主线程上运行启动跟踪的代码：

1.  在新创建的`MainViewModel`的构造函数中，使用 Xamarin.Essentials 的`MainThread.BeginInvokeOnMainThread`调用主线程。Xamarin.Forms 有一个用于在主线程上调用代码的辅助方法，但如果我们使用 Xamarin.Essentials 的方法，我们可以在 ViewModel 中没有任何对 Xamarin.Forms 的依赖。如果在 ViewModels 中没有任何对 Xamarin.Forms 的依赖，我们可以在将来添加其他平台的应用程序中重用它们。

1.  在传递给`BeginInvokeOnMainThread`方法的操作中调用`locationService.StartTracking`，如下面的代码所示：

```cs
public MainViewModel(ILocationTrackingService 
                     locationTrackingService, 
                     ILocationRepository locationRepository)
{
    this.locationTrackingService = locationTrackingTrackingService;
    this.locationRepository = locationRepository;

 MainThread.BeginInvokeOnMainThread(async() =>
 {
 locationTrackingService.StartTracking();
 });
}

```

最后，我们需要将`MainViewModel`注入到`MainView`的构造函数中，并将`MainViewModel`实例分配给视图的绑定上下文，通过以下步骤进行。这将允许数据绑定被处理，并且`MainViewModel`的属性将绑定到用户界面中的控件：

1.  在`MeTracker`项目中，转到`Views/MainView.xaml.cs`文件的构造函数。

1.  将`MainViewModel`作为构造函数的参数，并将其命名为`viewModel`。

1.  将`BindingContext`设置为`MainViewModel`的实例，如下面的代码所示：

```cs
public MainView(MainViewModel viewModel)
{
    InitializeComponent();

 BindingContext = viewModel; 

    MainThread.BeginInvokeOnMainThread(async () =>
    {
        var location = await 
        Geolocation.GetLastKnownLocationAsync();
        Map.MoveToRegion(MapSpan.FromCenterAndRadius(
        new Position(location.Latitude, location.Longitude), 
        Distance.FromKilometers(5)));
    });
}
```

# 创建一个解析器

在这个项目中，我们将使用依赖注入，我们将使用一个名为 Autofac 的库。Autofac 是一个开源的**控制反转**（**IoC**）容器。我们将创建一个`Resolver`类，以便在本章后面将要添加到容器中的类型可以轻松地解析。为此，我们将通过以下步骤进行：

1.  在`MeTracker`，`MeTracker.Android`和`MeTracker.iOS`项目中从 NuGet 安装 Autofac。

1.  在`MeTracker`项目中，在项目的根目录创建一个名为`Resolver`的新类。

1.  创建一个名为`container`的`private static IContainer`字段。

1.  创建一个名为`Initialized`的`static`方法，它具有一个`IContainer`参数，并设置`container`字段的值，如下面的代码所示：

```cs
using Autofac;
using System;
using System.Collections.Generic;
using System.Text;

namespace MeTracker
{
    public class Resolver
    {
        private static IContainer container;

        public static void Initialize(IContainer container)
        {
            Resolver.container = container;
        }
    }
}
```

`Initialize`方法将在 Autofac 配置完成后调用，我们将在创建引导程序时进行配置。这个方法简单地获取作为参数的`container`并将其存储在`static`容器字段中。

现在，我们需要一个方法来访问它。创建一个名为`Resolve`的静态方法。这个方法将是通用的，当我们使用它时，我们将指定它的类型作为将要解析的类型。使用`container`字段来解析类型，如下面的代码所示：

```cs
public static T Resolve<T>()
{
     return container.Resolve<T>();
} 
```

`Resolve<T>`方法接受一个类型作为参数，并在容器中查找有关如何构造此类型的任何信息。如果有，我们就返回它。

所以，现在我们有了我们将用来解析对象类型实例的`Resolver`，我们需要对其进行配置。这是引导程序的工作。

# 创建引导程序

要配置依赖注入并初始化`Resolver`，我们将创建一个引导程序。我们将有一个共享的引导程序，以及其他针对每个平台的引导程序，以满足其特定的配置。我们需要它们是特定于平台的原因是，我们将在 iOS 和 Android 上有不同的`ILocationTrackingService`实现。要创建引导程序，我们需要按照以下步骤进行：

1.  在`MeTracker`项目中创建一个新类，并命名为`Bootstrapper`。

1.  在新类中编写以下代码：

```cs
using Autofac;
using MeTracker.Repositories;
using MeTracker.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using Xamarin.Forms;

namespace MeTracker
{
    public class Bootstrapper
    {
        protected ContainerBuilder ContainerBuilder { get; private 
        set; }

        public Bootstrapper()
        {
            Initialize();
            FinishInitialization();
        }

        protected virtual void Initialize()
        {
            ContainerBuilder = new ContainerBuilder();

            var currentAssembly = Assembly.GetExecutingAssembly();

            foreach (var type in currentAssembly.DefinedTypes.
                     Where(e => e.IsSubclassOf(typeof(Page))))
            {
                ContainerBuilder.RegisterType(type.AsType());
            }

            foreach (var type in currentAssembly.DefinedTypes.
                     Where(e => e.IsSubclassOf(typeof(ViewModel))))
            {
                ContainerBuilder.RegisterType(type.AsType());
            }

            ContainerBuilder.RegisterType<LocationRepository>
            ().As<ILocationRepository>();
        }

        private void FinishInitialization()
        {
            var container = ContainerBuilder.Build();
            Resolver.Initialize(container);
        }
    }
}
```

# 创建 iOS 引导程序

在 iOS 引导程序中，我们将有特定于 iOS 应用程序的配置。要创建 iOS 应用程序，我们需要按照以下步骤进行：

1.  在 iOS 项目中，创建一个新类，并命名为`Bootstrapper`。

1.  使新类继承自`MeTracker.Bootstrapper`。

1.  编写以下代码：

```cs
using Autofac;
using MeTracker.iOS.Services;
using MeTracker.Services;

namespace MeTracker.iOS
{
    public class Bootstrapper : MeTracker.Bootstrapper
    {
        public static void Execute()
        {
            var instance = new Bootstrapper();
        }

        protected override void Initialize()
        {
            base.Initialize();

            ContainerBuilder.RegisterType<LocationTrackingService>()
            .As<ILocationTrackingService>().SingleInstance();
        }
    }
}
```

1.  转到 iOS 项目中的`AppDelegate.cs`。

1.  在`FinishedLaunching`方法中的`LoadApplication`调用之前，调用平台特定引导程序的`Init`方法，如下面的代码所示：

```cs
public override bool FinishedLaunching(UIApplication app, NSDictionary options)
{
      global::Xamarin.Forms.Forms.Init();
      global::Xamarin.FormsMaps.Init();
      Bootstrapper.Init();

      LoadApplication(new App());

      return base.FinishedLaunching(app, options);
} 
```

# 创建 Android 引导程序

在 Android 引导程序中，我们将有特定于 Android 应用程序的配置。要在 Android 中创建引导程序，我们需要按照以下步骤进行：

1.  在 Android 项目中，创建一个新类，并命名为`Bootstrapper`。

1.  使新类继承自`MeTracker.Bootstrapper`。

1.  编写以下代码：

```cs
using Autofac;
using MeTracker.Droid.Services;
using MeTracker.Services;

namespace MeTracker.Droid
{ 
    public class Bootstrapper : MeTracker.Bootstrapper
    {
         public static void Init()
         {
             var instance = new Bootstrapper();
         }

         protected override void Initialize()
         {
             base.Initialize();

             ContainerBuilder.RegisterType<LocationTrackingService()
             .As<ILocationTrackingService>().SingleInstance();
         }
    }
} 
```

1.  进入 Android 项目中的`MainActivity.cs`文件。

1.  在`OnCreate`方法中的`LoadApplication`调用之前，调用平台特定引导程序的`Init`方法，如下面的代码所示：

```cs
protected override void OnCreate(Bundle savedInstanceState)
{
     TabLayoutResource = Resource.Layout.Tabbar;
     ToolbarResource = Resource.Layout.Toolbar;

     base.OnCreate(savedInstanceState);
     Xamarin.Essentials.Platform.Init(this, savedInstanceState);

     global::Xamarin.Forms.Forms.Init(this, savedInstanceState);
     global::Xamarin.FormsMaps.Init(this, savedInstanceState);

 Bootstrapper.Init();

     LoadApplication(new App());
} 
```

# 设置 MainPage

在我们首次启动应用程序之前的最后一步是通过以下步骤在`App.xaml.cs`文件中设置`MainPage`属性。但首先，我们可以删除我们启动项目时创建的`MainPage.xaml`文件和`MainPage.xaml.cs`文件，因为我们这里不使用它们：

1.  删除`MeTracker`项目中的`MainPage.xaml`和`MainPage.xaml.cs`，因为我们将把`MainView`设置为用户首次看到的第一个视图。

1.  使用`Resolver`来创建`MainView`的实例。

1.  在构造函数中将`MainPage`设置为`MainView`的实例，如下面的代码所示：

```cs
public App()
{
     InitializeComponent();
     MainPage = Resolver.Resolve<MainView>();
} 
```

解析器使用 Autofac 来找出我们创建`MainView`实例所需的所有依赖项。它查看`MainView`的构造函数，并决定它需要一个`MainViewModel`。如果`MainViewModel`有进一步的依赖项，那么该过程将遍历所有这些依赖项并构建我们需要的所有实例。

现在我们将能够运行该应用程序。它将显示一个以用户当前位置为中心的地图。我们现在将添加代码来使用后台位置跟踪来跟踪位置。

# iOS 上的后台位置跟踪

位置跟踪的代码是我们需要为每个平台编写的。对于 iOS，我们将使用`CoreLocation`命名空间中的`CLLocationManager`。

# 在后台启用位置更新

当我们想在 iOS 应用程序中后台执行任务时，我们需要在`info.plist`文件中声明我们想要做什么。以下步骤显示了我们如何做到这一点：

1.  在`MeTracker.iOS`项目中，打开`info.plist`。

1.  转到 Capabilities 选项卡。

1.  选择启用后台模式和位置更新，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/d435c61a-a1ae-4858-9b37-45fa9be0f004.png)

如果我们用 XML 编辑器直接在`info.plist`文件中打开它，我们也可以直接启用后台模式。在这种情况下，我们将添加以下 XML：

```cs
<key>UIBackgroundModes</key>
<array>
     <string>location</string>
</array>
```

# 获取使用用户位置的权限

在我们可以请求使用用户位置的权限之前，我们需要添加一个描述，说明我们将使用位置。自从 iOS 11 推出以来，我们不再允许只请求始终跟踪用户位置的权限；用户必须能够只在使用应用时允许我们跟踪他们的位置。我们将通过以下步骤向`info.plist`文件中添加描述：

1.  用 XML（文本）编辑器打开`MeTracker.iOS`项目中的`info.plist`。

1.  添加键`NSLocationWhenInUseUsageDescription`，并附上描述。

1.  添加键`NSLocationAlwaysAndWhenInUsageDescription`，并附上描述，如下面的代码所示：

```cs
<key>NSLocationWhenInUseUsageDescription</key>
<string>We will use your location to track you</string>
<key>NSLocationAlwaysAndWhenInUseUsageDescription</key>
<string>We will use your location to track you</string>
```

# 订阅位置更新

现在我们已经为位置跟踪准备好了`info.plist`文件，是时候编写实际的代码来跟踪用户的位置了。如果我们不将`CLLocationManager`设置为不暂停位置更新，当位置数据不太可能改变时，iOS 可能会自动暂停位置更新。在这个应用程序中，我们不希望发生这种情况，因为我们希望多次保存位置，以便我们可以确定用户是否经常访问特定位置。让我们通过以下步骤来设置这个：

1.  在`MeTracker.iOS`项目中打开`LocationTrackingService`。

1.  为`CLLocationManager`添加一个私有字段。

1.  在`StartTracking`方法中创建`CLLocationMananger`的实例。

1.  将`PausesLocationUpdatesAutomatically`设置为`false`。

1.  将`AllowBackgroundLocationUpdates`设置为`true`（如下所示的代码），以便即使应用在后台运行时，位置更新也会继续进行：

```cs
public void StartTracking()
{
    locationManager = new CLLocationManager
 {
 PausesLocationUpdatesAutomatically = false,
 AllowsBackgroundLocationUpdates = true }; // Add code here
}

```

下一步是请求用户允许跟踪他们的位置。我们将请求始终跟踪他们的位置的权限，但用户可以选择只在使用应用时允许我们跟踪他们的位置。因为用户也可以选择拒绝我们跟踪他们的位置的权限，所以在开始之前我们需要进行检查。让我们通过以下步骤来设置这个：

1.  通过在`locationManager`上连接`AuthorizationChanged`事件来添加授权更改的事件监听器。

1.  在事件监听器中，创建一个`if`语句来检查用户是否允许我们跟踪他们的位置。

1.  调用我们最近在`CLLocationManager`中创建的实例的`RequestAlwaysAuthorization`方法。

1.  代码应该放在`// Add code here`注释下，如下面的粗体所示：

```cs
public void StartTracking()
{
    locationManager = new CLLocationManager
    {
        PausesLocationUpdatesAutomatically = false,
        AllowsBackgroundLocationUpdates = true
    };

    // Add code here
 locationManager.AuthorizationChanged += (s, args) =>
 { 
 if (args.Status == CLAuthorizationStatus.Authorized)
 {
            // Next section of code goes here
 }
 };

    locationManager.RequestAlwaysAuthorization();
}
```

在开始跟踪用户位置之前，我们将设置我们希望从`CLLocationManager`接收的数据的准确性。我们还将添加一个事件处理程序来处理位置更新。让我们通过以下步骤来设置这个：

1.  将`DesiredAccuracy`设置为`CLLocation.AccurracyBestForNavigation`。在后台运行应用程序时的一个限制是，`DesiredAccuracy`需要设置为`AccurracyBest`或`AccurracyBestForNavigation`。

1.  为`LocationsUpdated`添加一个事件处理程序，然后调用`StartUpdatingLocation`方法。

1.  代码应该放在`// Next section goes here`注释下，并且应该看起来像下面片段中的粗体代码：

```cs
   locationManager.AuthorizationChanged += (s, args) =>
    {
        if (args.Status == CLAuthorizationStatus.Authorized)
        {
            // Next section of code goes here
 locationManager.DesiredAccuracy = 
            CLLocation.AccurracyBestForNavigation;
            locationManager.LocationsUpdated += 
            async (object sender, CLLocationsUpdatedEventArgs e) =>
                {
                    // Final block of code goes here
                };

            locationManager.StartUpdatingLocation();
        }
    };

```

我们设置的精度越高，电池消耗就越高。如果我们只想跟踪用户去过哪里而不是一个地方有多受欢迎，我们还可以设置`AllowDeferredLocationUpdatesUntil`。这样，我们可以指定用户在更新位置之前必须移动特定距离。我们还可以使用`timeout`参数指定我们希望多久更新一次位置。跟踪用户在某个地方停留的最节能解决方案是使用`CLLocationManager`的`StartMonitoringVisits`方法。

现在，是时候处理`LocationsUpdated`事件了。让我们按照以下步骤进行：

1.  添加一个名为`locationRepository`的私有字段，类型为`ILocationRepository`。

1.  添加一个构造函数，该构造函数以`ILocationRepository`作为参数。将参数的值设置为`locationRepository`字段。

1.  在`CLLocationsUpdatedEventArgs`的`Locations`属性上读取最新位置。

1.  创建`MeTracker.Models.Location`的实例，并将最新位置的纬度和经度传递给它。

1.  使用`ILocationRepository`的`Save`方法保存位置。

1.  代码应放置在`//最终的代码块放在这里`的注释处，并且应该看起来像以下片段中的粗体代码：

```cs
locationManager.LocationsUpdated += 
    async (object sender, CLLocationsUpdatedEventArgs e) =>
    {
 var lastLocation = e.Locations.Last();
 var newLocation = new 
        Models.Location(lastLocation.Coordinate.Latitude,

        lastLocation.Coordinate.Longitude);

 await locationRepository.Save(newLocation);
    };

```

我们已经完成了 iOS 应用的跟踪部分。现在我们将为 Android 实现后台跟踪。之后，我们将可视化数据。

# 使用 Android 进行后台位置跟踪

在 Android 中进行后台更新的方式与我们在 iOS 中实现的方式非常不同。使用 Android，我们需要创建一个`JobService`并对其进行调度。

# 添加所需的权限以使用用户的位置

要在后台跟踪用户的位置，我们需要请求五个权限，如下表所示：

| `ACCESS_COARSE_LOCATION` | 获取用户的大致位置 |
| --- | --- |
| `ACCESS_FINE_LOCATION` | 获取用户的精确位置 |
| `ACCESS_NETWORK_STATE` | 因为 Android 中的位置服务使用来自网络的信息来确定用户的位置 |
| `ACCESS_WIFI_STATE` | 因为 Android 中的位置服务使用来自 Wi-Fi 网络的信息来确定用户的位置 |
| `RECEIVE_BOOT_COMPLETED` | 以便在设备重新启动后可以重新启动后台作业 |

权限可以从`MeTracker.Android`项目的属性中的 Android 清单选项卡或`Properties`文件夹中的`AndroidManifest.xml`文件中设置。当从 Android 清单选项卡进行更改时，更改也将写入`AndroidMainfest.xml`文件，因此无论您喜欢哪种方法都无所谓。

以下是在`MeTracker.Android`项目的属性中的 Android 清单选项卡中设置权限的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/783ecaab-f536-46f5-82ec-95ff0eefd4d8.png)

`uses-permission`元素应添加到`AndroidManifest.xml`文件中的`manifest`元素中，如下面的代码所示：

```cs
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
<uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION" />
<uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
<uses-permission android:name="android.permission.ACCESS_WIFI_STATE" /> 
```

# 创建后台作业

要在后台跟踪用户的位置，我们需要通过以下步骤创建一个后台作业：

1.  在 Android 项目中，在`Services`文件夹中创建一个名为`LocationJobService`的新类。

1.  将类设置为`public`，并将`Android.App.Job.JobService`添加为基类。

1.  实现`OnStartJob`和`OnStopJob`的抽象方法，如下面的代码所示：

```cs
public class LocationJobService : JobService
{ 
     public override bool OnStopJob(JobParameters @params)
     {
         return true;
     }

     public override bool OnStartJob(JobParameters @params)
     {
         return true;
     } 
}
```

Android 应用中的所有服务都需要添加到`AndroidManifest.xml`文件中。我们不必手动执行此操作；相反，我们可以向类添加属性，然后该属性将在`AndroidManifest.xml`文件中生成。我们将使用`Name`和`Permission`属性来设置所需的信息，如下面的代码所示：

```cs
 [Service(Name = "MeTracker.Droid.Services.LocationJobService",
 Permission = "android.permission.BIND_JOB_SERVICE")]
          public class LocationJobService : JobService

```

# 调度后台作业

当我们创建了一个作业，我们可以安排它。我们将从`MeTracker.Android`项目中的`LocationTrackingService`中执行此操作。要配置作业，我们将使用`JobInfo.Builder`类。

我们将使用`SetPersisted`方法来确保作业在重新启动后重新启动。这就是为什么我们之前添加了`RECEIVE_BOOT_COMPLETED`权限。

要安排作业，至少需要一个约束。在这种情况下，我们将使用`SetOverrideDeadline`。这将指定作业需要在指定的时间（以毫秒为单位）之前运行。

`SetRequiresDeviceIdle`代码短语可用于确保作业仅在设备未被用户使用时运行。如果我们希望确保在用户使用设备时不减慢设备速度，可以将`true`传递给该方法。

`SetRequiresBatteryNotLow`代码短语可用于指定作业在电池电量低时不运行。如果没有充分的理由在电池电量低时运行作业，我们建议始终将其设置为`true`。这是因为我们不希望我们的应用程序耗尽用户的电池。

因此，让我们通过以下步骤实现在`Services`文件夹中的 Android 项目中找到的`LocationTrackingService`：

1.  根据我们指定的 ID（这里我们将使用`1`）和组件名称（我们从应用程序上下文和 Java 类创建）创建`JobInfo.Builder`。组件名称用于指定哪些代码将在作业期间运行。

1.  使用`SetOverrideDeadline`方法，并将`1000`传递给它，以使作业在创建作业后不到一秒钟就运行。

1.  使用`SetPersisted`方法并传递`true`，以确保作业在设备重新启动后仍然持续存在。

1.  使用`SetRequiresDeviceIdle`方法并传递`false`，以便即使用户正在使用设备，作业也会运行。

1.  使用`SetRequiresBatteryLow`方法并传递`true`，以确保我们不会耗尽用户的电池。此方法是在 Android API 级别 26 中添加的。

1.  `LocationTrackingService`的代码现在应该如下所示：

```cs
using Android.App;
using Android.App.Job;
using Android.Content;
using MeTracker.Services;

namespace MeTracker.Droid.Services
{
    public class LocationTrackingService : ILocationTrackingService
    { 
        var javaClass = 
        Java.Lang.Class.FromType(typeof(LocationJobService));
        var componentName = new ComponentName(Application.Context, 
        javaClass);
        var jobBuilder = new JobInfo.Builder(1, componentName);

        jobBuilder.SetOverrideDeadline(1000);
        jobBuilder.SetPersisted(true);
        jobBuilder.SetRequiresDeviceIdle(false);
        jobBuilder.SetRequiresBatteryNotLow(true);

        var jobInfo = jobBuilder.Build();
    }
}
```

`JobScheduler`服务是一个系统服务。要获取系统服务的实例，我们将通过以下步骤使用应用程序上下文：

1.  使用`Application.Context`上的`GetSystemService`方法来获取`JobScheduler`。

1.  将结果转换为`JobScheduler`。

1.  在`JobScheduler`类上使用`Schedule`方法，并传递`JobInfo`对象来安排作业，如下面的代码所示：

```cs
var jobScheduler =    
  (JobScheduler)Application.Context.GetSystemService
  (Context.JobSchedulerService);
  jobScheduler.Schedule(jobInfo); 
```

# 订阅位置更新

一旦我们安排了作业，我们可以编写代码来指定作业应该做什么，即跟踪用户的位置。为此，我们将使用`LocationManager`，这是一个`SystemService`。使用`LocationManager`，我们可以请求单个位置更新，或者我们可以订阅位置更新。在这种情况下，我们希望订阅位置更新。

我们将首先创建`ILocationRepository`接口的实例，用于将位置保存到 SQlite 数据库中。让我们通过以下步骤来设置这个：

1.  为`LocationJobService`创建一个构造函数。

1.  为`ILocationRepository`接口创建一个私有的只读字段，名称为`locationRepository`。

1.  在构造函数中使用`Resolver`来创建`ILocationRepository`的实例，如下面的代码所示：

```cs
private ILocationRepository locationRepository;
public LocationJobService()
{
     locationRepository = Resolver.Resolve<ILocationRepository>();
}
```

在订阅位置更新之前，我们将添加一个监听器。为此，我们将通过以下步骤使用`Android.Locations.ILocationListener`接口：

1.  将`Android.Locations.ILocationListener`添加到`LocationJobService`。

1.  实现接口。

1.  删除所有`throw new NotImplementedException();`的实例，该实例是在让 Visual Studio 生成接口的实现时添加的。

1.  在`OnLocationChanged`方法中，将`Android.Locations.Location`对象映射到`Model.Location`对象。

1.  使用`LocationRepository`类上的`Save`方法，如下所示：

```cs
public void OnLocationChanged(Android.Locations.Location location)
{
    var newLocation = new Models.Location(location.Latitude, 
    location.Longitude);
 locationRepository.Save(newLocation);
} 
```

创建监听器后，我们可以通过以下步骤订阅位置更新：

1.  转到`LocationJobService`中的`StartJob`方法。

1.  创建`LocationManager`类型的静态字段。

1.  使用`GetSystemService`获取`LocationManager`在`ApplicationContext`上。

1.  要订阅位置更新，请使用`RequestLocationUpdates`方法，如下所示：

```cs
public override bool OnStartJob(JobParameters @params)
{      
     locationManager =  
     (LocationManager)ApplicationContext.GetSystemService
     (Context.LocationService);
 locationManager.RequestLocationUpdates
     (LocationManager.GpsProvider, 1000L, 0.1f, this);

     return true;
}
```

我们传递给`RequestLocationUpdates`方法的第一个参数确保我们从 GPS 获取位置。第二个确保位置更新之间至少间隔`1000`毫秒。第三个参数确保用户必须移动至少`0.1`米才能获得位置更新。最后一个指定我们应该使用哪个监听器。因为当前类实现了`Android.Locations.ILocationListener`接口，我们将传递`this`。

# 创建热力图

为了可视化我们收集到的数据，我们将创建一个热力图。我们将在地图上添加许多点，并根据用户在特定位置停留的时间来设置它们的不同颜色。最受欢迎的地方将有温暖的颜色，而最不受欢迎的地方将有冷色。

# 向`LocationRepository`添加一个`GetAll`方法

为了可视化数据，我们需要编写代码，以便从数据库中读取数据。让我们通过以下步骤来设置这个：

1.  在`MeTracker`项目中，打开`ILocationRepository.cs`文件。

1.  添加一个`GetAll`方法，使用以下代码返回`Location`对象的列表：

```cs
 Task<List<Location>> GetAll() ;
```

1.  在`MeTracker`项目中，打开实现`ILocationRepository`的`LocationRepository.cs`文件。

1.  实现新的`GetAll`方法，并返回数据库中所有保存的位置，如下所示：

```cs
public async Task<List<Location>> GetAll()
{
      await CreateConnection();

      var locations = await connection.Table<Location>
      ().ToListAsync();

      return locations;
}
```

# 为可视化数据准备数据

在我们可以在地图上可视化数据之前，我们需要准备数据。我们将首先创建一个新的模型，用于准备好的数据。让我们通过以下步骤设置这个：

1.  在`MeTracker`项目的`Models`文件夹中，创建一个新的类并命名为`Point`。

1.  添加`Location`，`Count`和`Heat`的属性，如下所示：

```cs
namespace MeTracker.Models
{ 
    public class Point
    {
         public Location Location { get; set; }
         public int Count { get; set; } = 1;
         public Xamarin.Forms.Color Heat { get; set; }
    }
} 
```

`MainViewModel`将存储我们以后会找到的位置。让我们通过以下步骤添加一个用于存储`Points`的属性：

1.  在`MeTracker`项目中，打开`MainViewModel`类。

1.  添加一个名为`points`的`private`字段，它具有`List<Point>`类型。

1.  创建一个名为`Points`的属性，它具有`List<Point>`类型。

1.  在`get`方法中，返回`points`字段的值。

1.  在`set`方法中，将`points`字段设置为新值，并调用`RaisePropertyChanged`并将属性的名称作为参数。

1.  在`LoadData`方法的末尾，将`pointList`变量分配给`Points`属性，如下所示：

```cs
private List<Models.Point> points;
public List<Models.Point> Points
{
      get => points;
      set
      {
           points = value;
           RaisePropertyChanged(nameof(Points));
      }
}
```

现在我们有了存储点的位置，我们必须添加代码来添加位置。我们将通过实现`MainViewModel`类的`LoadData`方法来实现这一点，并确保在位置跟踪开始后立即在主线程上调用它。

我们将首先对保存的位置进行分组，以便所有在 200 米范围内的位置将被视为一个点。我们将跟踪我们在该点内记录位置的次数，以便稍后决定地图上该点的颜色。让我们通过以下步骤设置这个：

1.  添加一个名为 LoadData 的`async`方法，它返回`MainViewModel`的`Task`。

1.  在`ILocationTrackingService`的`StartTracking`方法调用后，从构造函数中调用`LoadData`方法，如下所示：

```cs
public MainViewModel(ILocationTrackingService 
                     locationTrackingService, 
                     ILocationRepository locationRepository)
{
    this.locationTrackingService = locationTrackingService;
    this.locationRepository = locationRepository;

    MainThread.BeginInvokeOnMainThread(async() => 
    {
         locationTrackingService.StartTracking();
 await LoadData();
    });
}
```

`LoadData`方法的第一步是从 SQLite 数据库中读取所有跟踪位置。当我们有了所有的位置后，我们将循环遍历它们并创建点。为了计算位置和点之间的距离，我们将使用`Xamarin.Essentials.Location`中的`CalculateDistance`方法，如下面的代码所示：

```cs
private async Task LoadData()
{ 
    var locations = await locationRepository.GetAll();
 var pointList = new List<Models.Point>();

 foreach (var location in locations)
 {
 //If no points exist, create a new one an continue to the next  
        location in the list
 if (!pointList.Any())
 {
 pointList.Add(new Models.Point() { Location = location });
 continue;
 }

 var pointFound = false;

 //try to find a point for the current location
 foreach (var point in pointList)
 {
 var distance =   
            Xamarin.Essentials.Location.CalculateDistance(
 new Xamarin.Essentials.Location(
            point.Location.Latitude, point.Location.Longitude),
 new Xamarin.Essentials.Location(location.Latitude,                             
            location.Longitude), DistanceUnits.Kilometers);

 if (distance < 0.2)
 {
 pointFound = true;
 point.Count++;
 break;
 }
 }

 //if no point is found, add a new Point to the list of points
 if (!pointFound)
 {
 pointList.Add(new Models.Point() { Location = location });
 }

        // Next section of code goes here
    }
} 
```

当我们有了点的列表，我们可以计算每个点的热度颜色。我们将使用颜色的**色调、饱和度和亮度**（HSL）表示，如下面的列表所述：

+   **色调**：色调是色轮上从 0 到 360 的度数，0 是红色，240 是蓝色。因为我们希望我们最受欢迎的地方是红色（热的），我们最不受欢迎的地方是蓝色（冷的），我们将根据用户到达该点的次数计算每个点的值在 0 到 240 之间。这意味着我们只会使用比例的三分之二。

+   **饱和度**：饱和度是一个百分比值：0%是灰色，而 100%是全彩。在我们的应用程序中，我们将始终使用 100%（在代码中表示为`1`）。

+   **亮度**：亮度是光的百分比值：0%是黑色，100%是白色。我们希望它是中性的，所以我们将使用 50%（在代码中表示为`0.5`）。

我们需要做的第一件事是找出用户在最受欢迎和最不受欢迎的地方分别去过多少次。我们通过以下步骤找出这一点：

1.  首先，检查点的列表是否为空。

1.  获取点列表中`Count`属性的`Min`和`Max`值。

1.  计算最小值和最大值之间的差异。

1.  代码应添加到`LoadData`方法底部的`// 下一段代码放在这里`注释处，如下面的代码所示：

```cs
private async Task LoadData()
{ 
    // The rest of the method has been commented out for brevity

    // Next section of code goes here
 if (pointList == null || !pointList.Any())
 {
 return;
 } 
 var pointMax = pointList.Select(x => x.Count).Max();
 var pointMin = pointList.Select(x => x.Count).Min();
 var diff = (float)(pointMax - pointMin);

    // Last section of code goes here
}
```

现在我们将能够通过以下步骤计算每个点的热度：

1.  循环遍历所有点。

1.  使用以下计算来计算每个点的热度。

1.  代码应添加到`LoadData()`方法底部的`// 最后一段代码放在这里`注释处，如下面的粗体所示：

```cs
private async Task LoadData()
{ 
    // The rest of the method has been commented out for brevity

    // Next section of code goes here
  if (pointList == null || !pointList.Any())
    {
        return;
    }

    var pointMax = pointList.Select(x => x.Count).Max();
    var pointMin = pointList.Select(x => x.Count).Min();
    var diff = (float)(pointMax - pointMin);

 // Last section of code goes here
 foreach (var point in pointList)
 {
 var heat = (2f / 3f) - ((float)point.Count / diff);
 point.Heat = Color.FromHsla(heat, 1, 0.5);
 }

    Points = pointList;
}
```

这就是在`MeTracker`项目中设置位置跟踪的全部内容。现在让我们把注意力转向可视化我们得到的数据。

# 创建自定义渲染器

**自定义渲染器**是扩展 Xamarin.Forms 的强大方式。正如在第一章中提到的，*Xamarin 简介*，Xamarin.Forms 是使用渲染器构建的，因此对于每个 Xamarin.Forms 控件，都有一个渲染器来创建本机控件。通过覆盖现有的渲染器或创建新的渲染器，我们可以扩展和自定义 Xamarin.Forms 控件的呈现方式。我们还可以使用渲染器从头开始创建新的 Xamarin.Forms 控件。

渲染器是特定于平台的，因此当我们创建自定义渲染器时，我们必须为要更改或使用来扩展控件行为的每个平台创建一个渲染器。为了使我们的渲染器对 Xamarin.Forms 可见，我们将使用`ExportRenderer`程序集属性。这包含有关渲染器所用的控件以及将使用哪个渲染器的信息。

# 为地图创建自定义控件

为了在地图上显示热力图，我们将创建一个新的控件，我们将使用自定义渲染器。我们通过以下步骤设置这一点：

1.  在`MeTracker`项目中，创建一个名为`Controls`的新文件夹。

1.  创建一个名为`CustomMap`的新类。

1.  将`Xamarin.Forms.Maps.Map`添加为新类的基类，如下面的代码所示：

```cs
using System.Collections.Generic;
using Xamarin.Forms;
using Xamarin.Forms.Maps;

namespace MeTracker.Controls
{
    public class CustomMap : Map
    {
    }
} 
```

如果我们想要绑定数据的属性，我们需要创建一个`BindableProperty`。这应该是类中的一个`public static`字段。我们还需要创建一个*常规*属性。属性的命名非常重要。`BindableProperty`的名称需要是`{NameOfTheProperty}Property`；例如，我们将在以下步骤中创建的`BindableProperty`的名称将是`PointsProperty`，因为属性的名称是`Points`。使用`BindableProperty`类上的静态`Create`方法创建`BindableProperty`。这需要至少四个参数，如下列表所示：

+   `propertyName`：这是属性的名称作为字符串。

+   返回类型：这是从属性返回的类型。

+   `declaringType`：这是声明`BindableProperty`的类的类型。

+   `defaultValue`：如果未设置值，将返回的默认值。这是一个可选参数。如果未设置，Xamarin.Forms 将使用`null`作为默认值。

属性的`set`和`get`方法将调用基类中的方法，从`BindableProperty`中`set`或`get`值：

1.  在`MeTracker`项目中，创建一个名为`PointsProperty`的`BindableProperty`，如下所示。

1.  创建一个`List<Models.Point>`类型的名为`Points`的属性。记得将`GetValue`的结果转换为与属性相同的类型，因为`GetValue`将以类型对象返回值：

```cs
public static BindableProperty PointsProperty =   
  BindableProperty.Create(nameof(Points), 
  typeof(List<Models.Point>), typeof(CustomMap), new   
  List<Models.Point>());

public List<Models.Point> Points
{
      get => GetValue(PointsProperty) as List<Models.Point>;
      set => SetValue(PointsProperty, value);
} 
```

当我们创建了自定义地图控件后，我们将通过以下步骤使用它来替换`MainView`中的`Map`控件：

1.  在`MainView.xaml`文件中，声明自定义控件的命名空间。

1.  用我们创建的新控件替换`Map`控件。

1.  在`MainViewModel`的`Points`属性中添加绑定，如下所示：

```cs
<ContentPage  

              x:Class="MeTracker.Views.MainView">
         <ContentPage.Content>
         **<map:CustomMap x:Name="Map" Points="{Binding Points}" />**
         </ContentPage.Content>
</ContentPage> 
```

# 创建自定义渲染器以扩展 iOS 应用中的地图

首先，我们将通过以下步骤为 iOS 创建自定义渲染器。因为我们想要扩展功能，所以我们将使用`MapRenderer`作为基类：

1.  在`MeTracker.iOS`项目中创建一个名为`Renderers`的文件夹。

1.  在此文件夹中创建一个新类，并命名为`CustomMapRenderer`。

1.  将`MapRenderer`添加为基类。

1.  添加`ExportRenderer`属性，如下所示：

```cs
 using System.ComponentModel;
 using System.Linq;
 using MapKit;
 using MeTracker.Controls;
 using MeTracker.iOS.Renderers;
 using Xamarin.Forms;
 using Xamarin.Forms.Maps.iOS;
 using Xamarin.Forms.Platform.iOS; 

  [assembly:ExportRenderer(typeof(CustomMap),
  typeof(CustomMapRenderer))]
  namespace MeTracker.iOS.Renderers
{
     public class CustomMapRenderer : MapRenderer
     { 
     }
}
```

当我们为自定义渲染器编写控件的属性更改时，将调用`OnElementPropertyChanged`方法。该方法是一个虚方法，这意味着我们可以重写它。我们希望监听`CustomMap`控件中`Points`属性的任何更改。

为此，请按以下步骤操作：

1.  覆盖`OnElementPropertyChanged`方法。每当元素（Xamarin.Forms 控件）中的属性值更改时，此方法将运行。

1.  添加一个`if`语句来检查更改的是否是`Points`属性，如下所示：

```cs
protected override void OnElementPropertyChanged(object sender, 
     PropertyChangedEventArgs e)
{
     base.OnElementPropertyChanged(sender, e);

     if (e.PropertyName == CustomMap.PointsProperty.PropertyName)
     { 
          //Add code here
     }
}
```

为了创建热力图，我们将向地图添加圆圈作为覆盖物，每个点一个圆圈。但在此之前，我们需要添加一些代码来指定如何渲染覆盖物。让我们通过以下步骤设置这个：

1.  创建一个`mapView`变量。将`Control`属性转换为`MKMapView`并将其赋值给变量。

1.  创建一个`customMap`变量。将`Element`属性转换为`CustomMap`并将其赋值给变量。

1.  使用带有`MKMapView`和`IMKOverlay`参数的表达式创建一个操作，并将其分配给`map`视图上的`OverlayRenderer`属性。

1.  将`overlay`参数转换为`MKCircle`并将其分配给一个名为`circle`的新变量。

1.  验证圆圈变量不为`null`。

1.  使用坐标从`CustomMap`对象的点列表中找到点对象。

1.  创建一个新的`MKCircleRenderer`对象，并将圆圈变量传递给构造函数。

1.  将`FillColor`属性设置为点的热色。使用扩展方法`ToUIColor`将其转换为`UIColor`。

1.  将`Alpha`属性设置为`1.0f`，以确保圆不会是透明的。

1.  返回`circleRenderer`变量。

1.  如果圆变量为`null`，则返回`null`。

1.  现在，代码应该看起来像以下片段中的粗体代码：

```cs
protected override void OnElementPropertyChanged(object sender,    
    PropertyChangedEventArgs e)
{
    base.OnElementPropertyChanged(sender, e);

    if (e.PropertyName == CustomMap.PointsProperty.PropertyName)
    { 
        var mapView = (MKMapView)Control; 
 var customMap = (CustomMap)Element;

 mapView.OverlayRenderer = (map, overlay) =>
 {
 var circle = overlay as MKCircle;

 if (circle != null)
 { 
 var point = customMap.Points.Single
 (x => x.Location.Latitude == 
                circle.Coordinate.Latitude &&
 x.Location.Longitude == 
                circle.Coordinate.Longitude);

 var circleRenderer = new MKCircleRenderer(circle)
 {
 FillColor = point.Heat.ToUIColor(),
 Alpha = 1.0f
 };

 return circleRenderer;
 }

 return null;
 };

        // Next section of code goes here
    }
}
```

我们已经实现了如何渲染地图的每个覆盖物。现在我们需要做的是遍历到目前为止收集到的所有点，并为每个点创建一个`Overlay`。让我们通过以下步骤来设置这一点：

1.  循环遍历所有点。

1.  使用`MKCircle`类上的`static`方法`Circle`创建一个圆覆盖物，如下面的代码所示。第一个参数是`Circle`的位置，第二个参数是`Circle`的半径。

1.  使用`AddOverlay`方法将覆盖添加到地图上。

1.  现在，代码应该看起来像以下片段中的粗体代码：

```cs
// Next section of code goes hereforeach (var point in customMap.Points)
{
        var overlay = MKCircle.Circle(
        new CoreLocation.CLLocationCoordinate2D
        (point.Location.Latitude, point.Location.Longitude), 100);

    mapView.AddOverlay(overlay);
}
```

这结束了如何扩展 iOS 上的`Maps`控件的部分。让我们为 Android 做同样的事情。

# 在 Android 应用程序中扩展地图创建一个自定义渲染器

现在，我们将为 Android 创建一个自定义渲染器。结构与我们用于 iOS 的相同。我们将以与 iOS 相同的方式使用`ExportRenderer`属性，并且还将`MapRenderer`类添加为基类。但这是特定于 Android 的`MapRenderer`。

我们首先要为我们的`CustomMap`控件创建一个自定义渲染器。渲染器将继承自`MapRenderer`基类，以便我们可以扩展任何现有的功能。为此，请按照以下步骤进行：

1.  在`MeTracker.Android`项目中创建一个名为`Renderers`的文件夹。

1.  在此文件夹中创建一个新类，并将其命名为`CustomMapRenderer`。

1.  添加`MapRenderer`作为基类。

1.  添加`ExportRenderer`属性。

1.  添加一个以`Context`为参数的构造函数。将参数传递给基类的构造函数。

1.  解决所有引用，如下面的代码所示：

```cs
using System.ComponentModel;
using Android.Content;
using Android.Gms.Maps;
using Android.Gms.Maps.Model;
using MeTracker.Controls;
using MeTracker.Droid.Renderers;
using Xamarin.Forms;
using Xamarin.Forms.Maps;
using Xamarin.Forms.Maps.Android;
using Xamarin.Forms.Platform.Android; 

[assembly: ExportRenderer(typeof(CustomMap), typeof(CustomMapRenderer))]
namespace MeTracker.Droid.Renderers
{
     public class CustomMapRenderer : MapRenderer
     {
         public CustomMapRenderer(Context context) : base(context)
         {
         } 
     }
}
```

要获得一个可操作的地图对象，我们需要请求它。我们通过重写所有自定义渲染器都具有的`OnElementChanged`方法来实现这一点。每当元素发生更改时，例如在首次解析 XAML 时设置元素或在代码中替换元素时，都会调用此方法。让我们通过以下步骤来设置这一点：

1.  重写`OnElementChanged`方法。

1.  如果`ElementChangedEventArgs`的`NewElement`属性不为`null`，则使用`Control`属性上的`GetMapAsync`方法请求地图对象，如下面的代码所示：

```cs
protected override void OnElementChanged
                        (ElementChangedEventArgs<Map> e)
{
     base.OnElementChanged(e);

     if (e.NewElement != null)
     {
          Control.GetMapAsync(this);
     }
} 
```

当我们有一个地图可以操作时，虚拟的`OnMapReady`方法将被调用。为了添加我们自己的代码来处理这一点，我们通过以下步骤重写这个方法：

1.  创建一个`GoogleMap`类型的私有字段，并将其命名为`map`。

1.  重写`OnMapReady`方法。

1.  使用方法体中的参数为新字段赋值，如下面的代码所示：

```cs
protected override void OnMapReady(GoogleMap map)
{
     this.map = map;

     base.OnMapReady(map);
}
```

就像我们在 iOS 渲染器中所做的一样，我们需要处理自定义地图的`Points`属性的更改。为此，我们重写`OnElementPropertyChanged`方法，每当我们正在编写渲染器的控件上的属性发生更改时，都会调用此方法。让我们通过以下步骤来做到这一点：

1.  重写`OnElementPropertyChanged`方法。每当`Element`（Xamarin.Forms 控件）的属性值发生更改时，此方法都会运行。

1.  添加一个`if`语句来检查是否已更改了`Points`属性，如下面的代码所示：

```cs
protected override void OnElementPropertyChanged(object sender,    
     PropertyChangedEventArgs e)
{
     base.OnElementPropertyChanged(sender, e);

     if(e.PropertyName == CustomMap.PointsProperty.PropertyName)
     { 

     }
}
```

现在，我们可以添加代码来处理`Points`属性被设置的特定事件，通过在地图上绘制位置。为此，请按照以下步骤进行：

1.  对于每个点，创建一个`CircleOptions`类的实例。

1.  使用`InvokeStrokeWidth`方法将圆的描边宽度设置为`0`。

1.  使用`InvokeFillColor`方法设置圆的颜色。使用`ToAndroid`扩展方法将颜色转换为`Android.Graphics.Color`。

1.  使用`InvokeRadius`方法将圆的大小设置为`200`。

1.  使用`InvokeCenter`方法设置圆在地图上的位置。

1.  使用`map`对象上的`AddCircle`方法将圆添加到地图中。

1.  代码应该与以下片段中的粗体代码相同：

```cs
protected override void OnElementPropertyChanged(object sender, 
     PropertyChangedEventArgs e)
{
     base.OnElementPropertyChanged(sender, e);

     if(e.PropertyName == CustomMap.PointsProperty.PropertyName)
     { 
    var element = (CustomMap)Element;

        foreach (var point in element.Points)
 {
 var options = new CircleOptions();
 options.InvokeStrokeWidth(0);
 options.InvokeFillColor(point.Heat.ToAndroid());
 options.InvokeRadius(200);
 options.InvokeCenter(new 
            LatLng(point.Location.Latitude, 
            point.Location.Longitude));
            map.AddCircle(options);
 }
    }
}
```

# 在恢复应用程序时刷新地图

我们要做的最后一件事是确保在应用程序恢复时地图与最新的点保持同步。这样做的最简单方法是在`App.xaml.cs`文件中将`MainPage`属性设置为`MainView`的新实例，方式与构造函数中一样，如下面的代码所示：

```cs
protected override void OnResume()
{
     MainPage = Resolver.Resolve<MainView>();
} 
```

# 总结

在本章中，我们为 iOS 和 Android 构建了一个跟踪用户位置的应用程序。当我们构建应用程序时，我们学习了如何在 Xamarin.Forms 中使用地图以及如何在后台运行位置跟踪。我们还学会了如何使用自定义控件和自定义渲染器扩展 Xamarin.Forms。有了这些知识，我们可以创建在后台执行其他任务的应用程序。我们还学会了如何扩展 Xamarin.Forms 中的大多数控件。

下一个项目将是一个实时聊天应用程序。在下一章中，我们将建立一个基于 Microsoft Azure 服务的无服务器后端。一旦我们构建了应用程序，我们将在以后的章节中使用该后端。**
