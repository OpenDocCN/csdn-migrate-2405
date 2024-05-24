# 使用 UNO 平台创建跨平台 C# 应用（二）

> 原文：[`zh.annas-archive.org/md5/1FD2D236733A02B9975D919E422AEDD3`](https://zh.annas-archive.org/md5/1FD2D236733A02B9975D919E422AEDD3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：使您的应用程序移动化

本章将向您展示如何使用 Uno 平台为移动设备开发应用程序。这样的应用程序可能与在桌面设备或 Web 上运行的应用程序有很大的不同，并带来了您必须考虑的挑战。

在本章中，我们将涵盖以下主题：

+   为运行 iOS 和 Android 的移动设备构建

+   在偶尔连接的环境中使用远程数据

+   为其运行的平台设计应用程序的样式

+   利用应用程序所在设备的功能

在本章结束时，您将创建一个在 Android 和 iOS 设备上运行的移动应用程序，每个平台上的外观都不同，并与远程服务器通信以检索和发送数据。

# 技术要求

本章假设您已经设置好了开发环境，并安装了必要的项目模板，就像我们在*第一章* *介绍 Uno 平台*中所介绍的那样。本章的源代码可以在[`github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/tree/main/Chapter04`](https://github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/tree/main/Chapter04)找到。

本章的代码使用以下库：[`github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/tree/main/SharedLibrary`](https://github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/tree/main/SharedLibrary)。

本章还从远程 Web 服务器检索数据，您可以使用[`github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/tree/main/WebApi`](https://github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/tree/main/WebApi)的代码重新创建。

查看以下视频以查看代码的运行情况：[`bit.ly/3jKGRkI`](https://bit.ly/3jKGRkI)

# 介绍应用程序

我们将在本章中构建的应用程序称为**Network Assist**。这是一个将提供给所有员工使用的应用程序。对于在公共场合工作的人来说，这是特别有用的。这个应用程序的真实版本将有许多功能，但我们只会实现两个：

+   显示下一班火车将到达每个车站的时间

+   记录和报告发生在网络周围的事件的细节。

由于这个应用程序将被员工在整个网络上执行工作时使用，它将被构建为在 Android 和 iOS 设备上运行。

“移动”是什么意思？

很容易认为“移动”只是关于应用程序所在的设备，但这样做是有限制的。“移动”可以是“Android 和 iOS 设备”的一个有用的简称。然而，重要的是要记住，移动不仅仅是指手机（或平板电脑）。使用设备的人也是移动的。考虑将使用应用程序的人通常比运行应用程序的设备更重要。设备只是要考虑的一个因素。一个人可能在过程中使用多个设备，因此需要体验在他们在设备之间移动时也是移动的 - 也许在一个设备上开始一个任务，然后在另一个设备上完成它。

我们构建 Network Assist 应用程序为移动应用程序的主要原因是因为将使用它的人将整天四处旅行。正因为人是移动的，我们才构建了一个在“移动”设备上运行的“移动”应用程序。

与其花费大量时间事先解释功能，不如开始构建应用程序。我们将在编写代码时扩展需求。

## 创建应用程序

我们将从创建应用程序的解决方案开始：

1.  在 Visual Studio 中，使用**多平台应用程序（Uno 平台）**模板创建一个新项目。

1.  将项目命名为`NetworkAssist`。你可以使用不同的名称，但需要相应地调整所有后续的代码片段。

1.  删除所有平台头项目，*除了* **Android**，**iOS**和**UWP**。

始终保留 UWP 头在解决方案中

即使您不打算发布应用程序的 UWP 版本，保留 UWP 头在解决方案中也有两个原因。首先，当诊断任何编译错误时，这可能是有帮助的，以检查代码是否存在基本问题，或者问题是否与 Uno 特定的工具有关。其次，更重要的是，当选择 UWP 头时，Visual Studio 可以提供额外的工具和智能感知。通过在项目中添加 UWP 头，您的 Uno 平台开发体验将更加简单。

1.  为了避免写更多的代码，我们将添加对共享库项目的引用。在`UnoBookRail.Common.csproj`文件中，右键单击解决方案节点，然后点击**打开**。

1.  对于每个特定平台的项目，我们需要添加对通用库项目的引用。在**解决方案资源管理器**中右键单击**Android**项目节点，然后选择**添加 > 引用... > 项目**。然后，选中**UnoBookRail.Common**的条目，然后点击**确定**。现在，*重复此过程用于 iOS 和 UWP 项目*。

基本解决方案结构现在已经准备就绪，我们可以向主页添加一些功能。

## 创建主页

由于这将是一个简单的应用程序，我们将把所有功能放在一个页面上。设计要求是应用程序在屏幕底部有选项卡或按钮，以便在不同功能区域之间进行切换。我们将把不同的功能放在单独的控件中，并根据用户按下的按钮（或选项卡）来更改显示的控件。

这是合适的，因为用户不需要通过他们已经查看过的选项卡后退。

### 允许相机凹口、切口和安全区域

在添加任何自己的内容之前，您可能希望运行应用程序，以检查是否一切都可以编译和调试。根据您运行应用程序的设备或模拟器，您可能会看到*图 4.1*左侧的内容，显示了在 iPhone 12 模拟器上运行的默认应用程序。在这个图中，您可以看到**Hello, World!**文本重叠（或撞到）时间，并且在相机凹口后面。

如果您没有设备可以测试这个功能，一些模拟器可以模拟这个凹口。其他模拟器将有一个可配置的选项，允许在有或没有切口的情况下进行测试。在**设置 > 系统 > 开发人员选项 > 模拟具有切口的显示**下查找：

![图 4.1 - 显示允许状态栏和相机凹口的内容的前后截图](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Author_Figure_4.01_B17132.jpg)

图 4.1 - 显示允许状态栏和相机凹口的内容的前后截图

我们的应用程序不会有**Hello, World!**文本，但我们不希望我们的内容被遮挡。幸运的是，Uno 平台带有一个辅助类，可以为相机凹口留出空间，无论它们在哪种设备上或者它们的位置如何。

要使用这个辅助类，我们需要做以下几步：

1.  在`MainPage.xaml`的根元素`Page`中添加`xmlns:toolkit="using:Uno.UI.Toolkit"`。

1.  在`Page`元素内部的`Grid`元素中添加`toolkit:VisibleBoundsPadding.PaddingMask="All"`。通过设置`All`的值，如果设备横向旋转，辅助类将提供适当的空间，并且凹口将显示在屏幕的侧面。

现在运行应用程序，你会看到类似于*图 4.1*右侧图像的东西，它展示了布局已经添加了足够的空间。这样可以防止状态栏或相机凹口遮挡我们的内容。

现在我们已经处理了屏幕上的切口，我们可以实现应用程序所需的功能。

### 实现主页面的内容

由于应用程序中只有一个页面，我们现在将实现它：

1.  用以下内容替换`Grid`的现有内容：

```cs
<Grid.RowDefinitions>
    <RowDefinition Height="*" />
    <RowDefinition Height="Auto" />
</Grid.RowDefinitions>
<CommandBar VerticalAlignment="Bottom" Grid.Row="1">
    <CommandBar.PrimaryCommands>
        <AppBarButton Icon="Clock" Label="Arrivals" 
            Click="ShowArrivals" />
        <AppBarButton Label="Quick Report" 
            Click="ShowQuickReport">
            <AppBarButton.Icon>
                <FontIcon Glyph="&#xE724;" />
            </AppBarButton.Icon>
        </AppBarButton>
    </CommandBar.PrimaryCommands>
</CommandBar>
```

网格的顶行将包含不同功能元素的控件。底行将承载选择不同控件的按钮。

我们使用`CommandBar`，因为这是最适合在应用程序中提供选择功能区域按钮的 UWP 控件。这只是我们希望在 iOS 和 Android 上看到的外观的近似值，我们将很快解决这些问题。

注意

XAML 提供了多种方法来实现相似的结果。在本章的代码中，我们使用了最简单的方法来在所有平台上提供一致的输出。

1.  现在我们需要自定义控件来显示不同的功能。首先右键单击`Views`，以匹配存储 UI 相关控件的约定。

如果您愿意，可以将`MainPage`文件移入`Views`文件夹，但这对应用程序的功能并不重要。

1.  在新文件夹中，右键单击并选择`ArrivalsControl`。重复此操作以添加名为`QuickReportControl`的控件。

1.  现在我们将控件添加到`MainPage.xaml`。在页面级别声明一个新的 XML 命名空间别名，值为`xmlns:views="using:Network Assist.Views"`。在`Grid`标签的开头和`CommandBar`之前，添加以下内容以创建我们新控件的实例：

```cs
<views:ArrivalsControl x:Name="Arrivals" Visibility="Visible" />
<views:QuickReportControl x:Name="QuickReport" Visibility="Collapsed" />
```

1.  在代码后台文件（`MainPage.xaml.cs`）中，我们需要添加处理 XAML 中`AppBarButtons`引用的`Click`事件的方法：

```cs
public void ShowArrivals(object sender, RoutedEventArgs args) 
{
    Arrivals.Visibility = Visibility.Visible; 
    QuickReport.Visibility = Visibility.Collapsed;
}
public void ShowQuickReport(object sender, RoutedEventArgs args) 
{
    Arrivals.Visibility = Visibility.Collapsed; 
    QuickReport.Visibility = Visibility.Visible;
}
```

我们将在这里使用点击事件和代码后台，因为逻辑与 UI 紧密耦合，并且不会受益于编写的测试。可以使用`ICommand`实现和绑定来控制每个控件何时显示，但如果您希望这样实现，可以自行实现。

MVVM 和代码后台

在本章中，我们将使用代码后台文件和**Model-View-ViewModel**（**MVVM**）模式的组合。有三个原因。首先，它使我们可以使代码更短，更简单，这样您就更容易跟随。其次，它避免了解释特定的 MVVM 框架或实现的需要，而我们可以专注于与应用程序相关的代码。最后，它表明 Uno 平台不会强迫您以特定方式工作。您可以使用您喜欢的编码风格、模式或框架。

主页面已经运行，现在我们可以添加显示即将到达的详细信息的功能。

## 显示即将到达的详细信息

显示即将到达的要求如下：

+   显示站点列表，并在选择一个站点时，显示每个方向的下三列火车的到达时间。

+   数据可以刷新以确保始终有最新的信息可用。

+   显示检索到最后一条数据的时间。

+   如果未选择站点或检索数据时出现问题，则会显示提示。

+   应用程序指示正在检索数据时。

您可以在本章结束时创建的最终功能示例中看到以下图示：

![图 4.2 - iPhone 上显示的即将到达的详细信息（左）和 Android 设备上（右）](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_4.02_B17132.jpg)

图 4.2 - iPhone 上显示的即将到达的详细信息（左）和 Android 设备上（右）

用于显示即将到达的用户控件将是应用程序中最复杂的 UI 部分。看起来可能有很多步骤，但每一步都很简单：

1.  首先在`ArrivalsControl.xaml`中的`Grid`中添加两个列定义和四个行定义：

```cs
<Grid.ColumnDefinitions>
    <ColumnDefinition Width="*" />
    <ColumnDefinition Width="Auto" />
</Grid.ColumnDefinitions>
<Grid.RowDefinitions>
    <RowDefinition Height="Auto" />
    <RowDefinition Height="Auto" />
    <RowDefinition Height="Auto" />
    <RowDefinition Height="*" />
</Grid.RowDefinitions>
```

1.  顶部行将包含一个用于选择车站的`ComboBox`控件和一个用于请求刷新数据的`Button`元素：

```cs
<ComboBox x:Name="StationList"
    HorizontalAlignment="Stretch" 
    VerticalAlignment="Stretch"
    ItemsSource="{x:Bind VM.ListOfStations}"
    SelectedItem="{x:Bind VM.SelectedStation, 
        Mode=TwoWay}"
    SelectionChanged="OnStationListSelectionChanged"
    SelectionChangedTrigger="Always">
    <ComboBox.ItemTemplate>
        <DataTemplate xmlns:network="using:UnoBookRail.Common.Network".
```

1.  接下来的两行将使用`TextBlocks`来显示上次检索数据的时间以及检索数据时是否出现问题：

```cs
<TextBlock 
    Grid.Row="1" 
    Grid.ColumnSpan="2" 
    Margin="4"
    HorizontalAlignment="Stretch"
    HorizontalTextAlignment="Right"
    Text="{x:Bind VM.DataTimestamp, Mode=OneWay}" />
<TextBlock 
    Grid.Row="2" 
    Grid.ColumnSpan="2"
    Margin="4"
    HorizontalAlignment="Stretch"
    HorizontalTextAlignment="Right"
    Foreground="Red" 
    TextWrapping="WrapWholeWords"
    Text="Connectivity issues: data may not be up to 
          date!"
    Visibility="{x:Bind VM.ShowErrorMsg, 
        Mode=OneWay}"/>
```

1.  `ListView`将使用我们在控件级别定义的一些数据模板。在打开的`UserControl`标签之后添加以下内容：

```cs
<UserControl.Resources>
  <DataTemplate x:Key="HeaderTemplate">
       <Grid HorizontalAlignment="Stretch" 
           Background="{ThemeResource 
               ApplicationPageBackgroundThemeBrush}">
      <TextBlock 
          Margin="0" 
          FontWeight="Bold"
          Style="{StaticResource 
                  SubheaderTextBlockStyle}"
          Text="{Binding Platform}" />
    </Grid>
  </DataTemplate>
  <DataTemplate x:Key="ItemTemplate">
    <Grid Margin="0,10">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="100" />
        <ColumnDefinition Width="*" />
      </Grid.ColumnDefinitions>
      <TextBlock 
          Margin="0,10"
          Style="{StaticResource TitleTextBlockStyle}"
          Text="{Binding DisplayedTime}" />
      <TextBlock 
          Grid.Column="1" 
          Margin="0,10"
          Style="{StaticResource TitleTextBlockStyle}"
          Text="{Binding Destination}" />
    </Grid>
  </DataTemplate>
</UserControl.Resources>
```

1.  第四行，也是最后一行，包含一个`ListView`，显示即将到达的到站时间：

```cs
<ListView Grid.Row="3" 
    Grid.ColumnSpan="2"
    ItemTemplate="{StaticResource ItemTemplate}"
    ItemsSource="{x:Bind VM.ArrivalsViewSource}"
    SelectionMode="None">
    <ListView.GroupStyle>
        <GroupStyle HeaderTemplate="{StaticResource 
            HeaderTemplate}" />
    </ListView.GroupStyle>
</ListView>
```

1.  第四行还包含一个`Grid`，其中包含其他信息控件，根据需要显示在`ListView`上或替代`ListView`：

```cs
<Grid Grid.Row="3" Grid.ColumnSpan="2">
    <TextBlock HorizontalAlignment="Stretch"
        VerticalAlignment="Center"
        HorizontalTextAlignment="Center"
        Style="{StaticResource 
                SubheaderTextBlockStyle}"
        Text="Select a station" TextWrapping="NoWrap"
        Visibility="{x:Bind VM.ShowNoStnMsg,
            Mode=OneWay}" />
    <ProgressRing Width="100" Height="100"
        IsActive="True" IsEnabled="True"
        Visibility="{x:Bind VM.IsBusy, Mode=OneWay}"
    />
</Grid>
```

1.  我们在这里添加了相当多的 XAML。看看它的外观的第一步是连接 ViewModel，以便我们可以访问相关属性和命令。将`ArrivalsControlxaml.cs`的内容更改为以下内容：

```cs
public sealed partial class ArrivalsControl : UserControl {
    private ArrivalsViewModel VM to help keep the code concise) in the constructor, and it's this class that contains most of the logic.The code-behind also includes a method to handle the `SelectionChanged` event on the `ComboBox`. This is currently necessary as a workaround for a bug due to the order that `ComboBox` events are raised in. The bug is logged at [`github.com/unoplatform/uno/issues/5792`](https://github.com/unoplatform/uno/issues/5792). Once fixed, it should be possible to bind to a `Command` on the ViewModel to perform the equivalent functionality.
```

1.  将以下`using`声明添加到文件顶部，以便编译器可以找到我们刚刚添加的类型：

```cs
using NetworkAssist.ViewModels;
using UnoBookRail.Common.Network;
```

1.  现在我们准备创建一个包含剩余功能逻辑的 ViewModel。我们将首先创建一个名为`ViewModels`的文件夹。在该文件夹中，创建一个名为`ArrivalsViewModel`的类。

1.  为了避免在遵循 MVVM 模式时编写常见的代码，需要在每个平台头项目中添加对`Microsoft.Toolkit.Mvvm` NuGet 包的引用*：

```cs
Install-Package Microsoft.Toolkit.Mvvm -Version 7.0.2
```

1.  更新`ArrivalsViewModel`类，使其继承自`Microsoft.Toolkit.Mvvm.ComponentModel.ObservableObject`。

1.  `ArrivalsViewModel`将使用来自不同位置的类型，因此我们需要引用以下命名空间：

```cs
using Microsoft.Toolkit.Mvvm.Input;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using System.Windows.Input;
using UnoBookRail.Common.Network;
using Windows.UI.Xaml.Data;
```

1.  首先，在类中添加以下字段：

```cs
private static DataService _data = DataService.Instance;
private List<Station> _listOfStations;
private ObservableCollection<StationArrivalDetails> 
_arrivals = 
    new ObservableCollection<StationArrivalDetails>();
private Station _selectedStation = null;
private string _dataTimestamp;
private bool _isBusy;
private bool _showErrorMsg;
```

1.  我们的`ViewModel`需要以下属性，因为它们在我们之前定义的 XAML 绑定中被引用。它们将使用我们刚刚添加的后备字段：

```cs
public List<Station> ListOfStations 
{
    get => _listOfStations;
    set => SetProperty(ref _listOfStations, value);
}
public bool ShowErrorMsg 
{
    get => _showErrorMsg;
    set => SetProperty(ref _showErrorMsg, value);
}
public Station SelectedStation 
{
    get => _selectedStation;
    set {
        if (SetProperty(ref _selectedStation, value)) 
        {
            OnPropertyChanged(nameof(ShowNoStnMsg));
        }
    }
}
public ObservableCollection<StationArrivalDetails> Arrivals 
{
    get => _arrivals;
    set => SetProperty(ref _arrivals, value);
}
public string DataTimestamp 
{
    get => _dataTimestamp;
    set => SetProperty(ref _dataTimestamp, value);
}
public bool IsBusy 
{
    get => _isBusy;
    set => SetProperty(ref _isBusy, value);
}
public IEnumerable<object> ArrivalsViewSource => new CollectionViewSource() 
{
    Source = Arrivals,
    IsSourceGrouped = true
}.View;
public bool ShowNoStnMsg => SelectedStation == null;
public ICommand RefreshCommand { get; }
public ICommand SelectionChangedCommand { get; }
```

1.  我们将使用构造函数来初始化车站列表和命令：

```cs
public ArrivalsViewModel() 
{
    ListOfStations = _data.GetAllStations();
    RefreshCommand = new AsyncRelayCommand(async () =>
        { await LoadArrivalsDataAsync(); });
    SelectionChangedCommand = new AsyncRelayCommand(
        async () => { await LoadArrivalsDataAsync(); 
            });
}
```

1.  现在，添加处理检索和显示数据的方法：

```cs
public async Task LoadArrivalsDataAsync(int stationId = 0)
{
  if (stationId < 1) 
  {
    // if no value passed use the previously selected 
    // Id.
    stationId = SelectedStation?.Id ?? 0;
  }
  else 
  { 
    // We've changed station so clear current details
    Arrivals.Clear();
    DataTimestamp = string.Empty;
    ShowErrorMsg = false;
  }
  if (stationId > 0) 
  {
    IsBusy = true;
    try {
      var arr = await 
          _data.GetArrivalsForStationAsync(stationId);
      ShowErrorMsg = false;
      if (arr.ForStationId == stationId) 
      {
        DataTimestamp = 
            $"Updated at {arr.Timestamp:t}";
        Arrivals.Clear();
        if (!string.IsNullOrEmpty(
            arr.DirectionOneName)) 
        {
          var d1details = new StationArrivalDetails
              (arr.DirectionOneName);
          d1details.AddRange(arr.DirectionOneDetails);
          Arrivals.Add(d1details);
        }
        if (!string.IsNullOrEmpty(
            arr.DirectionTwoName)) 
        {
          var d2details = new StationArrivalDetails(
              arr.DirectionTwoName);
          d2details.AddRange(arr.DirectionTwoDetails);
          Arrivals.Add(d2details);
        }
      }
    }
    catch (Exception exc) {
      // Log this or take other appropriate action
      ShowErrorMsg = true;
    }
    finally {
      IsBusy = false;
    }
  }
}
```

1.  您可能已经注意到数据是从单例`DataService`类中检索的。我们将首先创建一个简单版本，稍后再扩展。通常约定将此类放在名为`Services`的目录中，尽管您也可以将其放在`ViewModels`文件夹中：

```cs
using System.Linq;
using System.Threading.Tasks;
using UnoBookRail.Common.Network;
public class DataService 
{
    private static readonly Lazy<DataService> ds =
        new Lazy<DataService>(() => new
            DataService());
    private static readonly Lazy<Stations> stations =
        new Lazy<Stations>(() => new Stations());
    public static DataService Instance => ds.Value;
    private DataService() { }
    public List<Station> GetAllStations() => 
        stations.Value.GetAll().OrderBy(s => 
            s.Name).ToList();
    public async Task<Arrivals> 
        GetArrivalsForStationAsync method may seem overly complex.
```

1.  现在我们有了`DataService`类，可以检索到达详情，但是我们需要做更多工作来显示它们。我们还需要另一个类。这是`StationArrivalDetails`，它允许我们按站台和列车行驶方向对信息进行分组。在`ViewModels`目录中创建这个类：

```cs
using UnoBookRail.Common.Network;
public class StationArrivalDetails : 
List<ArrivalDetail> 
{
    public StationArrivalDetails(string platform) 
    {
        Platform = platform;
    }
    public string Platform { get; set; }
}
```

Uno 中使用分组数据的 CollectionViewSource

在 Uno 平台上显示分组列表比在 UWP 上更复杂。如果您以前在 UWP 应用程序中使用过`CollectionViewSource`，那么您可能已经在 XAML 中定义了它，而不是作为`IEnumerable<object>`。不幸的是，为了 Uno 平台能够正确渲染 Android 和 iOS 上的所有组和标题，我们需要将我们的`CollectionViewSource`定义为`IEnumerable<IEnumerable>`。如果不这样做，我们将在 iOS 上看到缺少组标题，而在 Android 上只能看到第一组的内容。

现在我们有一个可用的应用程序，但在接下来的两个部分中，我们将进行两项改进。在那里，我们将改善应用程序的外观并使用一些本机控件，但在此之前，我们将切换到使用来自远程源的“实时”数据，而不是应用程序自带的数据。

# 检索远程数据

很少有应用程序仅使用其自带的数据。**网络辅助**提供的价值是基于提供实时信息。知道火车实际到达的时间比知道计划到达时间更有价值。为了收集这些信息，应用程序必须连接到远程实时数据源。

大多数移动应用程序连接到外部数据源，最常见的方式是通过 HTTP(S)。如果您只开发运行在桌面上的应用程序，您可能可以假设始终有可用的连接。对于移动应用程序，必须考虑设备为**偶尔连接**。

由于不可能假设应用程序始终可用连接或连接速度很快，因此在设计应用程序时必须考虑这一点。这些问题适用于所有移动应用程序，并不是 Uno 平台开发中的独特问题。正确处理偶尔的连接性和数据可用性的方式因应用程序而异。这个问题太大，我们无法在这里完全覆盖，但重要的是提出来。至少，考虑偶尔的连接性意味着需要考虑重试失败的连接请求和管理数据。我们之前在`LoadArrivalsDataAsync`方法中编写的代码已经以一种粗糙的缓存形式，通过在刷新数据时不丢弃当前信息，直到成功请求并有新数据可用于显示。虽然应用程序中显示的信息可能会很快过时，但相对于不显示任何内容，显示应用程序承认为几分钟前的内容更为合适。

在另一个应用程序中，将数据保存在文件或数据库中可能更合适，以便在远程数据不可用时检索和显示。*第五章*，*使您的应用程序准备好面对现实*，展示了如何使用 SQLite 数据库来实现这一点。

我们将很快看到应用程序如何处理连接到远程数据的失败，但首先，我们将看看如何连接到远程数据。

## 连接到远程数据源

本书的 GitHub 存储库位于[`github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform`](https://github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform)，其中包括一个**WebAPI**项目，该项目将为应用程序返回火车到站数据。

您可以选择运行代码并通过本地机器访问，或者您可以连接到[`unobookrail.azurewebsites.net/`](https://unobookrail.azurewebsites.net/)上提供的版本。如果连接到托管版本，请注意它基于服务器的本地时间，并且这可能与您所在的地方不同。如果服务器不断表示下一班火车还有很长时间，因为服务器所在地的凌晨，如果您自己运行项目，您将看到更多不同的数据：

1.  我们将使用`System.Net.Http.HttpClient`连接到服务器。为了能够做到这一点，我们必须在*Android 和 iOS*项目中添加对`System.Net.Http`的包引用：

```cs
Install-Package System.Net.Http -Version 4.3.4
```

1.  由于 API 返回的数据是 JSON 格式，因此我们还将在*所有平台项目*中添加对`Newtonsoft.Json`库的引用，以便我们可以对响应进行反序列化：

```cs
Install-Package Newtonsoft.Json -Version 12.0.3
```

1.  我们现在准备检索远程数据。所有更改都将在`DataService.cs`文件中进行。首先添加一个`HttpClient`的实例。我们将使用这个实例进行所有请求：

```cs
using System.Net.Http;
private static readonly HttpClient _http = new HttpClient();
```

1.  要连接到服务器，我们需要指定它的位置。由于我们最终将进行多个请求，因此在一个地方定义服务器域是明智的。我们将通过`__ANDROID__`常量来实现这一点，该常量可用于`#if`预处理指令。有关更多信息，请参见*第二章**，编写您的第一个 Uno 平台应用程序*。

如果您从 Android 模拟器连接到本地托管的 WebAPI 实例，则需要使用 IP 地址`10.0.2.2`进行连接。这是模拟器用来指代主机机器的特殊 IP 地址。您可以使用条件编译来指定这一点，就像前面的代码片段中所示。如果您连接到外部服务器，您可以直接设置地址，不需要任何条件代码。

1.  现在我们可以更新`GetArrivalsForStationAsync`方法以获取实时数据。*用以下内容替换*当前的实现：

```cs
using Newtonsoft.Json;
public async Task<Arrivals> GetArrivalsForStationAsync(int stationId) 
{
  var url = $"{WebApiDomain}/stations/?stationid=
      {stationId}";
  var rawJson = await _http.GetStringAsync(url);
  return JsonConvert.DeserializeObject<Arrivals>
      (rawJson);
}
```

如果现在运行应用程序，数据将来自远程位置。您可能会注意到数据检索不再是瞬间完成的，等待时会显示一个忙指示器。我们在应用程序的原始版本中添加了显示进度指示器的代码，但直到现在才看到它显示出来。这突显了在处理需要时间检索的数据时可能出现的另一个潜在问题。*在发生某事时让用户了解情况至关重要*。我们在这里使用`ProgressRing`来指示发生了某事。如果没有这个，用户可能会想知道是否有任何事情发生，并变得沮丧或反复按刷新按钮。

到目前为止，我们已经从远程源检索到数据，并在此过程中让用户了解情况，但是当事情出错时，我们需要做更多。所以，我们接下来会看看这一点。

## 使用 Polly 处理异常并重试请求

处理异常并重试失败的请求的需求几乎适用于所有应用程序。幸运的是，有许多解决方案可以帮助我们处理一些复杂性。**Polly** ([`github.com/App-vNext/Polly`](https://github.com/App-vNext/Polly))是一个流行的开源库，用于处理瞬态错误，我们将在我们的应用程序中使用。让我们来看一下：

1.  我们将首先向*所有平台项目*添加对`Polly.Extensions.Http`包的引用：

```cs
Install-Package Polly.Extensions.Http -Version 3.0.0
```

这扩展了标准的 Polly 功能，并简化了处理与 HTTP 相关的故障。

1.  我们现在将再次更新`GetArrivalsForStationAsync`方法，使其使用 Polly 的`HandleTransientHttpError`。这告诉 Polly 如果 HTTP 响应是服务器错误（HTTP 5xx）或超时错误（HTTP 408），则重试请求。

对`WaitAndRetryAsync`的调用告诉 Polly 最多重试三次。我们还使用`policy.ExecuteAsync`指定每个请求之间的延迟，并将其传递给我们希望应用策略的操作。

1.  如果请求因我们策略未覆盖的原因而失败，我们之前创建的代码会导致屏幕顶部显示一条消息，如下面的屏幕截图所示，指示问题所在。其他应用可能需要以不同方式记录或报告此类问题，但通常不适合什么都不做：

![图 4.3 - 应用程序显示连接问题的消息](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_4.03_B17132.jpg)

图 4.3 - 应用程序显示连接问题的消息

现在我们有了一个可以可靠地从远程源提供有用数据的应用程序。我们想要做的最后一件事是改善它在不同平台上的外观。

# 使您的应用程序看起来像属于每个平台

到目前为止，应用程序中的所有内容都使用了 Uno Platform 提供的默认样式。因为 Uno Platform 基于 UWP 和 WinUI，我们的应用程序的样式是基于 Fluent Design 系统的，因为这是 Windows 的默认样式。如果我们希望我们的应用程序看起来这样，这是可以的，但是如果我们希望我们的应用程序使用 Android 或 iOS 的默认样式怎么办？幸运的是，Uno Platform 为我们提供了解决方案。它为我们提供了**Material**和**Cupertino**样式的库，我们可以应用到我们的应用程序中。虽然这些库分别是为 Android 和 iOS 设备本地化的，但它们可以在任何地方使用。

现在，我们将使用这些库提供的资源，将 Material Design 样式应用于我们应用程序的 Android 版本，将 Cupertino 样式应用于 iOS 版本。

## 将 Material 样式应用于应用程序的 Android 版本

让我们开始吧：

1.  我们将首先向*Android 项目*添加对`Uno.Material`软件包的引用。请注意，这是一个预发布软件包，因此如果您通过 UI 搜索，请启用此软件包：

```cs
Install-Package Uno.Material -Version 1.0.0-dev.790
```

1.  虽然`Uno.Material`库知道如何为控件设置样式，但它并不包含所有资产和引用以使用它们。为此，*在 Android 项目*中*添加*`Xamarin.AndroidX.Lifecycle.LiveData`和`Xamarin.AndroidX.AppCompat.AppCompatResources`软件包：

```cs
Install-Package Xamarin.AndroidX.AppCompat.AppCompatResources -Version 1.2.0.5
Install-Package Xamarin.AndroidX.Lifecycle.LiveData -Version 2.3.1
```

1.  要在 Android 库中使用样式，我们必须通过在`App.xaml`中引用它们来将它们添加到应用程序中可用的样式中：

```cs
<Application
    x:Class="NetworkAssist.App"
    xmlns="http://schemas.microsoft.com/winfx/2006/
           xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/
             xaml"
    xmlns:android="http://uno.ui/android"
    xmlns:local="using:NetworkAssist"
    xmlns:mc="http://schemas.openxmlformats.org/
             markup-compatibility/2006"
    mc:Ignorable="android">
    <Application.Resources>
        <ResourceDictionary>
            <ResourceDictionary.MergedDictionaries>
                <XamlControlsResources xmlns=
                "using:Microsoft.UI.Xaml.Controls" />
                <android:MaterialColors xmlns=
                    "using:Uno.Material" />
                <android:MaterialResources xmlns=
                     "using:Uno.Material" />
            </ResourceDictionary.MergedDictionaries>
        </ResourceDictionary>
    </Application.Resources>
</Application>
```

1.  一些控件将自动应用 Material 样式，而其他控件将需要直接应用样式。为了展示这一点，我们将为刷新`Button`应用特定样式。

在`ArrivalsControl.xaml`中，*在文件顶部添加 Android 命名空间别名*。我们只在 Android 上运行时才会使用这个。然后，将样式应用于`Button`元素：

```cs
Button control looks on the arrivals control, but it hasn't improved the buttons in CommandBar at the bottom of the shell page. Let's address this now.
```

1.  与使用 Windows `CommandBar`不同，Material Design 系统具有一个单独的控件，更适合在屏幕底部显示与导航相关的按钮。这称为`BottomNavigationBar`。我们将首先将其添加到`MainPage.xaml`中，并将现有的`CommandBar`包装在一个`Grid`中，该`Grid`仅在 Windows 上显示：

```cs
Click events as before. It's only the control that's displaying them that we're changing.NoteAfter adding the `Xamarin.AndroidX` packages, you may get a compilation error related to a file called `abc_vector_test.xml`. This error is due to compatibility inconsistencies between different preview versions of the packages and Visual Studio. This error can be addressed by opening the **Properties** section of the **Android** project, selecting **Android Options**, and unchecking the **Use incremental Android packaging system (aap2)** option. This may lead to a separate build warning and slightly slower builds, but the code will now compile. Hopefully, future updates that are made to these packages will help us avoid this issue.
```

1.  如果现在运行应用程序，您会看到按钮和导航栏是紫色的。这是`Uno.Material`库中定义的颜色方案的一部分。您可以通过包含提供预定义 Material 颜色的不同值的`ResourceDictionary`来使用自己的颜色方案。然后，当您添加*步骤 2*中显示的资源时，您可以引用它。有关如何执行此操作的指南，请参阅[`platform.uno/docs/articles/features/uno-material.html#getting-started`](https://platform.uno/docs/articles/features/uno-material.html#getting-started)。

现在我们已经改善了 Android 上应用程序的外观，让我们为 iOS 做同样的事情。

## 将 Cupertino 样式应用于应用程序的 iOS 版本

让我们开始吧：

1.  单独的软件包包含 Cupertino 样式，因此我们必须在 iOS 项目中添加对`Uno.Cupertino`的引用：

```cs
Install-Package Uno.Cupertino -Version 1.0.0-dev.790
```

与上一节中的 Material 软件包一样，我们需要通过添加以下内容在`App.xaml`中加载此软件包的资源：

```cs
xmlns:ios="http://uno.ui/ios"
mc:Ignorable="android ios">
<Application.Resources>
    <ResourceDictionary>
        <ResourceDictionary.MergedDictionaries>
            <XamlControlsResources xmlns=
                "using:Microsoft.UI.Xaml.Controls" />
            <android:MaterialColors xmlns=
                "using:Uno.Material" />
            <android:MaterialResources xmlns=
                "using:Uno.Material" />
            <ios:CupertinoColors xmlns=
                "using:Uno.Cupertino" />
            <ios:CupertinoResources xmlns=
               "using:Uno.Cupertino" />
       </ResourceDictionary.MergedDictionaries>
    </ResourceDictionary>
</Application.Resources>
```

1.  此软件包尚未包含原生选项卡栏控件（`UITabBar`），但我们可以轻松创建与苹果的人机界面指南相匹配的内容。

*在`MainPage.xaml`中*添加*以下内容，添加到`win:Grid`元素之后：

```cs
Click events that we did previously, but we're using a new converter for ForegroundColor of the Buttons. For this, you'll need to *create a folder* called Converters and *create a file* called CupertinoButtonColorConverter.cs containing the following code:

```

使用 Windows.UI.Xaml.Data;

public class CupertinoButtonColorConverter：IValueConverter

{

public object Convert(object value, Type targetType，

对象参数，字符串语言）

{

如果（value？.ToString() == parameter？.ToString()）

{

return App.Current.Resources[

"CupertinoBlueBrush"];

}

否则

{

return App.Current.Resources[

"CupertinoSecondaryGrayBrush"];

}

}

public object ConvertBack(object value, Type

targetType，对象参数，字符串语言）

=> 抛出未实现的异常();

}

```cs

```

1.  与 Android 项目一样，Cupertino 样式不会自动应用于应用程序中的按钮。但是，我们可以创建一个*隐式样式*，将其应用于整个应用程序中的所有`Button`元素，而不是直接将样式应用于每个`Button`元素。要做到这一点，*修改* `App.xaml`以添加样式，如下所示：

```cs
<Application.Resources>
    <ResourceDictionary>
        <ResourceDictionary.MergedDictionaries>
            <XamlControlsResources xmlns=
                "using:Microsoft.UI.Xaml.Controls" />
            <android:MaterialColors xmlns=
                "using:Uno.Material" />
            <android:MaterialResources xmlns=
                "using:Uno.Material" />
            <ios:CupertinoColors xmlns=
                "using:Uno.Cupertino"  />
            <ios:CupertinoResources xmlns=
                "using:Uno.Cupertino" />
        </ResourceDictionary.MergedDictionaries>
        <ios:Style TargetType="Button"
BasedOn="{StaticResource 
                CupertinoButtonStyle}" />
    </ResourceDictionary>
</Application.Resources>
```

隐式样式可以用于任何平台，因此，如果您愿意，您可以在应用程序的 Android 版本中执行类似的操作。

现在我们有一个看起来属于每个平台的应用程序，并且它可以显示我们从外部服务器检索的内容。现在，让我们看看如何使用设备的功能来创建数据并将其发送到远程源。

# 访问设备功能

我们将向应用程序添加的最后一个功能与我们迄今为止所做的不同。到目前为止，我们已经研究了消耗数据，但现在我们将研究如何创建数据。

公司对应用程序的要求是，它提供了一种让员工在发生事故时捕获信息的方式。所谓的“事故”可以是企业可能需要记录或了解的任何事情。它可能是一些小事，比如顾客在公司财产上绊倒，也可能是一起重大事故。所有这些事件都有一个共同点：捕获详细信息比依靠人们以后记住细节更有益。目标是让员工尽可能快速、简单地捕获图像或一些文本，以增加捕获的信息量。软件将使用事件发生的时间和位置以及记录者的信息来增强捕获的信息。这些信息将被汇总并在一个单独的后端系统中进一步记录。

让我们创建一种简单的方式来满足这些要求，以演示 Uno 平台如何提供一种在不同平台上使用 UWP API 的方式：

1.  使用相机并获取设备位置，我们需要指示应用程序将需要必要的权限来执行此操作。我们在每个平台上指定权限的方式略有不同。

在 Android 上，打开项目的`info.plist`并使用`Package.appxmanfiest`打开它，转到`CameraCaptureUI`。

1.  我们可以通过在`QuickReportControl.xaml`的`Grid`中添加以下内容来创建 UI：

```cs
Button elements on Android. This is to highlight the importance of each button.
```

1.  在`QuickReportControl.xaml.cs`中，让我们添加处理用户单击按钮添加照片时发生的情况的代码：

```cs
using Windows.Media.Capture;
using Windows.UI.Xaml.Media.Imaging;
Windows.Storage.StorageFile capturedPhoto;
private async void CaptureImageClicked(object sender, RoutedEventArgs e) 
{
    try 
    {
         var captureUI = new CameraCaptureUI and call CaptureFileAsync to ask it to capture a photograph. When that returns successfully (it isn't canceled by the user), we display the image on the screen and store it in a field to send it to the server later.
```

1.  现在我们将创建一个方法来封装检索设备位置的逻辑：

```cs
using Windows.Devices.Geolocation;
using System.Threading.Tasks;
private async Task<string> GetLocationAsync() 
{
    try 
    {
        var accessStatus = await 
            Geolocator.RequestAccessAsync();
        switch (accessStatus) 
        {
            case GeolocationAccessStatus.Allowed:
                 var geolocator = new Geolocator();
                 var pos = await 
                     geolocator.GetGeopositionAsync();
                 return $"{pos.Coordinate.Latitude},
                    {pos.Coordinate.Longitude},
                        {pos.Coordinate.Altitude}";
            case GeolocationAccessStatus.Denied:
                return "Location access denied";
            case GeolocationAccessStatus.Unspecified:
                return "Location Error";
        }
    }
    catch (Exception ex) 
    {
        // Log the exception as appropriate
    }
    return string.Empty;
}
```

1.  最后一步是为“成功”提交有效数据时添加事件处理程序。应用程序会检查这一点，并向用户显示适当的消息。

注意

您可能认为允许用户与应用程序交谈并记录他们的声音会更方便。这是一个明智的建议，也是可以很容易在将来添加的内容。我们在这里没有包括它，因为大多数设备都具有内置功能，可以使用语音转文字来输入详细信息。使用设备的现有功能可能比复制已有功能更快捷、更容易。

现在，我们的应用程序已经完成了这最后一部分功能。您可以在下图中看到它的运行效果：

![图 4.4-快速报告屏幕在 iPhone 上运行（左）并显示所选图像，以及 Android 设备（右）显示输入的一些口述文本](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_4.04_B17132.jpg)

图 4.4-快速报告屏幕在 iPhone 上运行（左）并显示所选图像，以及 Android 设备（右）显示输入的一些口述文本

# 总结

在本章中，我们构建了一个可以在 iOS 和 Android 设备上运行的应用程序。这使您了解了创建“移动”应用程序的含义，处理远程数据，将本机平台主题应用于应用程序，并使用本机设备功能。

在下一章中，我们将构建另一个移动应用程序。这将与迄今为止制作的应用程序不同，因为它旨在供客户使用，而不是公司员工使用。除其他事项外，我们将利用这个应用程序来研究可访问性、本地化和使用 SQLite 数据库。


# 第五章：使您的应用程序准备好面向现实世界

在上一章中，我们介绍了使用 Uno Platform 编写面向 UnoBookRail 员工的第一个移动应用程序。在本章中，我们也将编写一个移动应用程序；但是，我们将专注于使其准备好供客户使用。在本章中，您将编写一个在设备上持久保存用户偏好和更大数据集的应用程序。此外，您还将学习如何通过自定义应用程序图标使您的应用程序对用户更具吸引力，以及如何编写可以供使用辅助技术的人使用的应用程序。

为了做到这一点，我们将在本章中涵盖以下主题：

+   介绍应用程序

+   使用`ApplicationData` API 和 SQLite 在本地持久化数据

+   使您的应用程序准备好供客户使用

+   本地化您的应用程序

+   使用自定义应用程序图标和启动画面

+   使您的应用程序适用于所有用户

在本章结束时，您将创建一个在 iOS 和 Android 上运行的移动应用程序，该应用程序已准备好供客户使用，并且已进行本地化和可访问。

# 技术要求

本章假设您已经设置好了开发环境，包括安装了项目模板，就像在*第一章*中介绍的那样，*介绍 Uno Platform*。本章的源代码位于[`github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/tree/main/Chapter05`](https://github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/tree/main/Chapter05)。

本章的代码使用了来自[`github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/tree/main/SharedLibrary`](https://github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/tree/main/SharedLibrary)的库。

查看以下视频以查看代码的实际操作：[`bit.ly/3AywuqQ`](https://bit.ly/3AywuqQ)

# 介绍应用程序

在本章中，我们将构建 UnoBookRail DigitalTicket 应用程序，这是一个面向想要使用 UnoBookRail 从 A 到 B 的 UnoBookRail 客户的应用程序。虽然这个应用程序的真实版本可能有很多功能，但在本章中，我们只会开发以下功能：

+   预订 UnoBookRail 网络两个站点之间的行程车票

+   查看所有预订的车票以及车票的 QR 码

+   本地化应用程序，并允许用户选择用于应用程序的语言

作为其中的一部分，我们还将确保我们的应用程序是可访问的，并允许不同能力水平的更多人使用我们的应用程序。现在让我们开始创建应用程序并添加第一部分内容。

## 创建应用程序

首先，我们需要为我们的应用程序设置解决方案：

1.  首先，使用**Multi-Platform App (Uno Platform)** 模板创建一个新的应用程序。

1.  将项目命名为`DigitalTicket`。当然，您也可以使用不同的名称；但是，在本章中，我们将假设该应用程序被命名为 DigitalTicket，并使用相应的命名空间。

1.  删除除**Android**、**iOS**和**UWP**之外的所有平台头。请注意，即使在网络上提供此功能可能会有好处，我们也会删除 WASM 头。虽然 WASM 在移动设备上运行得相当不错，但并不理想，为了简单起见，我们将继续不使用应用程序的 WASM 版本。

1.  将 UnoBookRail 共享库添加到解决方案中，因为我们稍后将需要其功能。为此，请右键单击解决方案文件，选择`UnoBookRail.Common.csproj`文件，然后单击**打开**。

1.  在每个头项目中引用共享库项目。为此，请右键单击头项目，选择**添加** | **引用…** | **项目**，选中**UnoBookRail.Common**，然后单击**确定**。由于我们需要在每个头中引用该库，请为每个头重复此过程，即 Android、iOS 和 UWP。

由于我们的应用程序还将遵循`Microsoft.Toolkit.MVVM`包，您还需要添加对其的引用：

1.  在解决方案视图中右键单击解决方案节点，然后选择**管理解决方案的 NuGet 包…**。

1.  搜索`Microsoft.Toolkit.MVVM`并选择**NuGet**包。

1.  在项目列表中选择 Android、iOS 和 UWP 头部，然后点击**安装**。

与上一章类似，我们还需要修改我们的应用程序以留出相机刘海的空间，以避免应用程序的内容被遮挡：

1.  为此，在`MainPage.xaml`文件中添加以下命名空间：`xmlns:toolkit="using:Uno.UI.Toolkit"`。

1.  之后，在我们的`MainPage.xaml`文件内的网格中添加`toolkit:VisibleBoundsPadding.PaddingMask="All"`。

## 创建主导航和预订流程

由于我们的应用程序将包含不同的功能，我们将把应用程序的功能拆分成不同的页面，我们将导航到这些页面。在`MainPage`内，我们将有我们的导航和相关代码：

1.  首先，通过右键单击`Views`创建一个 views 文件夹。

1.  现在，在`JourneyBookingPage.xaml`、`OwnedTicketsPage.xaml`和`SettingsPage.xaml`内添加以下三个页面。

1.  由于我们以后会需要它，创建一个`Utils`文件夹，并添加一个`LocalizedResources`类，其中包含以下代码：

```cs
public static class LocalizedResources
{
    public static string GetString(string key) {
        return key;
    }
}
```

目前，这个类只会返回字符串，这样我们就可以引用该类，而不必以后更新代码。不过，在本章的后面，我们将更新实现以返回提供的键的本地化版本。

1.  之后，在共享项目中创建一个`ViewModels`文件夹，并创建一个`NavigationViewModel`类。

1.  将以下内容添加到您的`NavigationViewModel`类：

```cs
using DigitalTicket.Views;
using Microsoft.Toolkit.Mvvm.ComponentModel;
using Microsoft.UI.Xaml.Controls;
using System;
namespace DigitalTicket.ViewModels
{
    public class NavigationViewModel : 
        ObservableObject
    {
        private Type pageType;
        public Type PageType
        {
            get
            {
                return pageType;
            }
            set
            {
                SetProperty(ref pageType, value);
            }
        }
        public void NavigationView_SelectionChanged(
          NavigationView navigationView, 
            NavigationViewSelectionChangedEventArgs
              args)
        {
            if (args.IsSettingsSelected)
            {
                PageType = typeof(SettingsPage);
            }
            else
            {
                switch ((args.SelectedItem as 
                   NavigationViewItem).Tag.ToString())
                {
                    case "JourneyPlanner":
                        PageType = 
                          typeof(JourneyBookingPage);
                        break;
                    case "OwnedTickets":
                        PageType = 
                          typeof(OwnedTicketsPage);
                        break;
                }
            }
        }
    }
}
```

此代码将公开`MainPage`应该导航到的页面类型，并提供选择更改侦听器以在应用程序导航更改时更新。为了确定正确的页面类型，我们将使用所选项的`Tag`属性。

1.  现在，用以下内容替换`MainPage`的内容：

```cs
    ...
    xmlns:muxc="using:Microsoft.UI.Xaml.Controls">
    <Grid toolkit:VisibleBoundsPadding.PaddingMask=
        "All">
        <muxc:NavigationView x:Name="AppNavigation"
            PaneDisplayMode="LeftMinimal"             
            IsBackButtonVisible="Collapsed" 
            Background="{ThemeResource 
                ApplicationPageBackgroundThemeBrush}"
            SelectionChanged="{x:Bind 
                navigationVM.NavigationView_
                     SelectionChanged, Mode=OneTime}">
            <muxc:NavigationView.MenuItems>
                <muxc:NavigationViewItem 
                    x:Name="JourneyBookingItem" 
                    Content="Journey Booking"
                    Tag="JourneyPlanner"/>
                <muxc:NavigationViewItem 
                    Content="Owned tickets"
                    Tag="OwnedTickets"/>
                <muxc:NavigationViewItem Content="All 
                    day tickets - soon" 
                    Tag="AllDayTickets" 
                    IsEnabled="False"/>
                <muxc:NavigationViewItem 
                    Content="Network plan - soon" 
                    IsEnabled="False"/>
                <muxc:NavigationViewItem 
                    Content="Line overview - soon"
                    IsEnabled="False"/>
            </muxc:NavigationView.MenuItems>
            <Frame x:Name="ContentFrame" 
                Padding="0,40,0,0"/>
             </muxc:NavigationView>
    </Grid>
```

这是我们应用程序的主要导航。我们使用`NavigationView`控件来实现这一点，它允许我们轻松地拥有一个可以使用汉堡按钮打开的侧边窗格。在其中，我们提供不同的导航选项，并将`Tag`属性设置为`NavigationViewModel`使用。由于在本章中我们只允许预订行程和拥有的票证列表，我们暂时禁用了其他选项。

1.  用以下内容替换您的`MainPage`类：

```cs
using DigitalTicket.ViewModels;
using DigitalTicket.Views;
using System;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Navigation;
namespace DigitalTicket
{
    public sealed partial class MainPage : Page
    {
        public NavigationViewModel navigationVM = new 
            NavigationViewModel();
        public MainPage()
        {
            InitializeComponent();
            if (navigationVM.PageType is null)
            {
                AppNavigation.SelectedItem = 
                    JourneyBookingItem;
                navigationVM.PageType = 
                    typeof(JourneyBookingPage);
                navigationVM.PageTypeChanged += 
                    NavigationVM_PageTypeChanged;
            }
        }
        protected override void OnNavigatedTo(
            NavigationEventArgs e)
        {
            base.OnNavigatedTo(e);
            if (e.Parameter is Type navigateToType)
            {
                if (navigateToType == 
                    typeof(SettingsPage))
                {
                    AppNavigation.SelectedItem = 
                        AppNavigation.SettingsItem;
                }
                navigationVM.PageType = 
                    navigateToType;
                ContentFrame.Navigate(navigateToType);
            }
        }
        private void NavigationVM_PageTypeChanged(
           object sender, EventArgs e)
        {
            ContentFrame.Navigate(
                navigationVM.PageType);
        }
    }
}
```

通过这样，`MainPage`在创建时将创建必要的视图模型，并根据此更新显示的内容。`MainPage`还监听`OnNavigatedTo`事件，以根据传递给它的参数更新显示的项目。最后，我们还监听`NavigationViewModels`属性更改事件。

请注意，我们重写了`OnNavigatedTo`函数，以便允许导航到`MainPage`，以及在`MainPage`内导航到特定页面。虽然我们现在不需要这个，但以后我们会用到。让我们继续填充行程预订页面的内容：

1.  在`ViewModels`文件夹内创建`JourneyBookingOption`类。

1.  将以下代码添加到`JourneyBookingOption`类：

```cs
using DigitalTicket.Utils;
using UnoBookRail.Common.Tickets;
namespace DigitalTicket.ViewModels
{
    public class JourneyBookingOption
    {
        public readonly string Title;
        public readonly string Price;
        public readonly PricingOption Option;
        public JourneyBookingOption(PricingOption 
            option)
        {
            Title = LocalizedResources.GetString(
              option.OptionType.ToString() + "Label");
            Price = option.Price;
            Option = option;
        }
    }
}
```

由于这是一个用于显示选项的数据对象，它只包含属性。由于标题将显示在应用程序内并且需要本地化，我们使用`LocalizedResources.GetString`函数来确定正确的值。

1.  现在在`ViewModels`文件夹中创建`JourneyBookingViewModel`类，并添加 GitHub 上看到的代码（[`github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/blob/main/Chapter05/DigitalTicket.Shared/ViewModels/JourneyBookingViewModel.cs`](https://github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/blob/main/Chapter05/DigitalTicket.Shared/ViewModels/JourneyBookingViewModel.cs)）。请注意，有几行被注释掉，那是因为我们稍后会需要这些行；但是，现在我们还没有添加必要的代码。

1.  更新`JourneyBookingPage.xaml.cs`和`JourneyBookingPage.xaml`，使它们与 GitHub 上看到的一样。

1.  将以下条目复制到`Strings/en`文件夹中的`Strings.resw`文件中。请注意，您不必逐字复制`Comments`列，因为它只是为其他两列提供指导和上下文：

![表 5.1](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Table_01.jpg)

您可能会注意到，一些控件设置了`x:Uid`属性，这就是为什么需要`Strings.resw`文件中的条目。我们将在*本地化您的应用程序*部分介绍这些工作原理；现在，我们只会添加代码和相应的条目到我们的资源文件中。现在，如果您启动应用程序，您应该会看到*图 5.1*中显示的内容：

![图 5.1 - Android 上的旅程预订页面](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Author_Figure_5.01_B17132.jpg)

图 5.1 - Android 上的旅程预订页面

现在您的用户可以配置他们的旅程，选择车票并预订，尽管车票名称不够理想。我们将在*本地化您的应用程序*部分中解决这个问题。为简单起见，我们将不处理实际付款，并假设付款信息与用户帐户关联。

在本节中，我们添加了应用程序的初始代码和导航。我们还添加了旅程预订页面，尽管目前实际上还没有预订车票，但我们稍后会更改。在下一节中，我们将介绍如何使用两种不同的方法在用户设备上本地持久化数据，即`ApplicationData` API 和 SQLite。

# 使用 ApplicationData API 和 SQLite 在本地持久化数据

虽然在许多情况下，数据可以从互联网上获取，就像我们在*第四章*中看到的那样，*移动化您的应用程序*，通常需要在用户设备上持久化数据。这可能是需要在没有互联网连接时可用的数据，或者是设备特定的数据，例如设置。我们将首先使用`ApplicationData` API 持久化小块数据。

## 使用 ApplicationData API 存储数据

由于我们将本地化我们的应用程序，我们还希望用户能够选择应用程序的语言。为此，首先在我们的共享项目中创建一个`Models`文件夹，并添加一个`SettingsStore`类。现在，将以下代码添加到`SettingsStore`类中：

```cs
using Windows.Storage;
public static class SettingsStore
{
    private const string AppLanguageKey = 
        "Settings.AppLanguage";
    public static void StoreAppLanguageOption(string 
         appTheme)
    {
        ApplicationData.Current.LocalSettings.Values[
            AppLanguageKey] = appTheme.ToString();
    }
    public static string GetAppLanguageOption()
    {
        if (ApplicationData.Current.LocalSettings.Values.
            Keys.Contains(AppLanguageKey))
        {
            return ApplicationData.Current.LocalSettings.
                Values[AppLanguageKey].ToString();
        }
        return "SystemDefault";
    }
}
```

访问应用程序的默认本地应用程序存储，我们使用`ApplicationData.Current.LocalSettings`对象。`ApplicationData` API 还允许您访问存储数据的不同方式，例如，您可以使用它来访问应用程序的本地文件夹，使用`ApplicationData.Current.LocalFolder`。在我们的情况下，我们将使用`ApplicationData.Current.LocalSettings`来持久化数据。`LocalSettings`对象是一个`ApplicationDataContainer`对象，您可以像使用字典一样使用它。请注意，`LocalSettings`对象仅支持字符串和数字等简单数据类型。现在我们已经添加了一种存储要显示应用程序语言的方法，我们需要让用户更改语言：

1.  首先，在我们的`ViewModels`文件夹中创建一个名为`SettingsViewModel`的新类。您可以在此处找到此类的代码：[`github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/blob/main/Chapter05/DigitalTicket.Shared/ViewModels/SettingsViewModel.cs`](https://github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/blob/main/Chapter05/DigitalTicket.Shared/ViewModels/SettingsViewModel.cs)。

1.  现在，我们更新我们的设置页面，以包括更改应用程序语言的 UI。为此，请将`SettingsPage.xaml`中的`Grid`元素替换为以下内容：

```cs
<StackPanel Padding="10,0,10,10">
    <ComboBox x:Name="LanguagesComboBox"
        Header="Choose the app's language"
        SelectedIndex="{x:Bind 
            settingsVM.SelectedLanguageIndex,
                Mode=TwoWay}"/>
</StackPanel>
```

1.  除此之外，我们还需要更新`SettingsPage.xaml.cs`。请注意，我们将在代码后台设置`ComboBox`的`ItemsSource`，以确保在`ComboBox`创建并准备就绪后设置`ItemsSource`，以便`ComboBox`能够正确更新。为此，请添加以下代码：

```cs
using DigitalTicket.ViewModels;
...
private SettingsViewModel settingsVM = new SettingsViewModel();
public SettingsPage()
{
    InitializeComponent();
    LanguagesComboBox.ItemsSource = 
        settingsVM.LanguageOptions;
}
```

1.  最后，为了确保在应用程序启动时将尊重所选的语言，将以下代码添加到`App.xaml.cs`的`OnLaunched`函数中，并为`DigitalTicket.Models`和`DigitalTicket.ViewModels`添加导入：

```cs
ApplicationLanguages.PrimaryLanguageOverride = 
SettingsViewModel.GetPrimaryLanguageOverrideFromLanguage(
SettingsStore.GetAppLanguageOption());
```

现在我们已经添加了语言选项，让我们试一下。如果您现在启动应用程序并使用左侧的导航转到设置页面，您应该会看到类似于*图 5.2*左侧的内容。现在，如果您选择`SettingsViewModel`重新加载`MainPage`和所有其他页面，并设置`ApplicationLanguages.PrimaryLanguageOverride`属性，我们将在*本地化您的应用程序*部分更多地讨论此属性，并且还将更新应用程序，以便所有当前可见的文本也根据所选择的语言进行更新：

![图 5.2–左：设置页面；右：切换语言为德语后的导航](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_5.02_B17132.jpg)

图 5.2–左：设置页面；右：切换语言为德语后的导航

## 使用 SQLite 存储数据

虽然`ApplicationData` API 适用于存储小数据块，但是如果要持久化更大的数据集，则`ApplicationData` API 并不理想，因为使用`ApplicationData.Current.LocalSettings`对象存储的条目存在空间限制。换句话说，对象键的长度只能为 255 个字符，UWP 上的条目大小只能为 8 千字节。当然，这并不意味着您不能在应用程序中存储更大或更复杂的数据集。这就是`sqlite-net-pcl`库的作用，因为该库适用于我们应用程序支持的每个平台。`sqlite-net-pcl`包括 SQLite 的跨平台实现，并允许我们轻松地将对象序列化为 SQLite 数据库。

让我们首先向我们的应用程序添加对`sqlite-net-pcl`的引用。为此，请在解决方案视图中右键单击解决方案，单击`sqlite-net-pcl`。由于在编写本书时，最新的稳定版本是**1.7.335**，请选择该版本并在项目列表中选择 Android、iOS 和 UWP 头。然后，单击**安装**。现在，我们需要添加代码来创建、加载和写入 SQLite 数据库：

1.  首先，我们需要添加一个类，我们希望使用 SQLite 持久化其对象。为此，在`ViewModels`文件夹中添加一个名为`OwnedTicket`的新类。您可以在 GitHub 上找到此类的源代码：[`github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/blob/main/Chapter05/DigitalTicket.Shared/ViewModels/OwnedTicket.cs`](https://github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/blob/main/Chapter05/DigitalTicket.Shared/ViewModels/OwnedTicket.cs)。

有两件重要的事情需要知道：

由于每个 SQLite 表都需要一个主键，我们添加了带有 PrimaryKey 和 AutoIncrement 属性的`DBId`属性。使用这些属性，我们让`sqlite-net-pcl`为我们管理主键，而无需自己处理。

将对象传递给`sqlite-net-pcl`以将它们持久化到 SQLite 数据库中，只有属性将被持久化。由于我们不想持久化`ShowQRCodeCommand`（实际上也不能），这只是一个字段，而不是属性。

1.  现在在`Models`文件夹中创建`OwnedTicketsRepository`类，并向其中添加以下代码：

```cs
using DigitalTicket.ViewModel;
using SQLite;
using System;
using System.IO;
using System.Threading.Tasks;
using Windows.Storage;
namespace DigitalTicket.Models
{
    public class OwnedTicketsRepository
    {
        const string DBFileName = "ownedTickets.db";
        private static SQLiteAsyncConnection database;
        public async static Task InitializeDatabase()
        {
            if(database != null)
            {
                return;
            }
            await ApplicationData.Current.LocalFolder.
                CreateFileAsync(DBFileName, 
                CreationCollisionOption.OpenIfExists);
            string dbPath = Path.Combine(
                ApplicationData.Current.LocalFolder
                    .Path, DBFileName);
            database = 
                new SQLiteAsyncConnection(dbPath);
            database.CreateTableAsync<
                OwnedTicket>().Wait();
        }
        public static Task<int> SaveTicketAsync(
            OwnedTicket ticket)
        {
            if (ticket.DBId != 0)
            {
                // Update an existing ticket.
                return database.UpdateAsync(ticket);
            }
            else
            {
                // Save a new ticket.
                return database.InsertAsync(ticket);
            }
        }
    }
}
```

`InitializeDatabase`函数处理创建我们的 SQLite 数据库文件和创建表（如果不存在），但也会在文件已经存在时加载现有数据库。在`SaveTicketsAsync`函数中，我们更新并保存传递的车票到数据库，或者如果数据库中已存在该车票，则更新该车票。

1.  更新`App.xaml.cs`以在`OnLaunched`函数的开头包含以下代码，并将`OnLaunched`函数更改为异步：

```cs
await OwnedTicketsRepository.InitializeDatabase();
```

这将在应用程序启动时初始化 SQLite 连接，因为按需创建连接并不理想，特别是在加载所拥有的车票页面时。

1.  现在更新`JourneyBookingViewModel`以将车票保存到`OwnedTicketsRepository`。为此，请删除当前创建`BookJourney`并取消注释文件顶部的`using`语句以及`JourneyBookingViewModel`构造函数中的代码。

现在让我们谈谈我们刚刚做的步骤。首先，我们创建了我们的`OwnedTicket`对象，我们将在下一节中将其写入 SQLite 并从 SQLite 中加载。

然后我们添加了`OwnedTicketsRepository`，我们用它来与我们的 SQLite 数据库交互。在可以向 SQLite 数据库发出任何请求之前，我们首先需要初始化它，为此我们需要一个文件来将 SQLite 数据库写入其中。使用以下代码，我们确保我们要将数据库写入的文件存在：

```cs
await ApplicationData.Current.LocalFolder.CreateFileAsync(DBFileName, CreationCollisionOption.OpenIfExists);
```

之后，我们为我们的数据库创建了一个`SQLiteAsyncConnection`对象。`SQLiteAsyncConnection`对象将处理与 SQLite 的所有通信，包括创建表和保存和加载数据。由于我们还需要一个表来写入我们的数据，我们使用`SQLiteAsyncConnection`为我们的`OwnedTickets`对象创建一个表，如果该表在我们的 SQLite 数据库中不存在。为了确保在对数据库进行任何请求之前执行这些步骤，我们在我们的应用程序构造函数中调用`OwnedTicketsRepository.InitializeDatabase()`。

最后一步是更新我们的`JourneyBookingViewModel`类，以便将数据持久化到 SQLite 数据库中。虽然我们只向数据库中添加新项目，但我们仍然需要注意是否正在更新现有条目或添加新条目，这就是为什么`SavedTicketAsync`函数确保我们只在没有 ID 存在时才创建项目。

## 从 SQLite 加载数据

现在我们已经介绍了如何持久化数据，当然，我们也需要加载数据；否则，我们就不需要首先持久化数据。让我们通过添加用户预订的所有车票的概述来改变这一点。由于 UnoBookRail 的客户需要在登上火车或检查车票时出示他们的车票，我们还希望能够为每张车票显示 QR 码。由于我们将使用`ZXing.Net.Mobile`来实现这一点，请立即将该**NuGet**包添加到您的解决方案中，即 Android、iOS 和 UWP 头。请注意，在撰写本文时，版本**2.4.1**是最新的稳定版本，我们将在本章中使用该版本。

在我们想要显示所有车票之前，我们首先需要从 SQLite 数据库中加载它们。为此，向我们的`OwnedTicketsRepository`类添加以下方法：

```cs
using System.Collections.Generic;
...
static Task<List<OwnedTicket>> LoadTicketsAsync()
{
    //Get all tickets.
    return database.Table<OwnedTicket>().ToListAsync();
}
```

由于`sqlite-net-pcl`，这就是我们需要做的一切。该库为我们处理了其余部分，包括读取表并将行转换为`OwnedTicket`对象。

现在我们也可以加载票了，我们可以更新本章开头创建的`OwnedTicketsPage`类，以显示用户预订的所有票。在我们的应用程序中，这意味着我们只会显示在此设备上预订的票。在真实的应用程序中，我们还会从远程服务器访问票务并将其下载到设备上；但是，由于这超出了本章的范围，我们不会这样做：

1.  在更新拥有的票页面之前，首先在`ViewModels`文件夹中添加一个`OwnedTicketsViewModel`类。该类的源代码在此处可用：[`github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/blob/main/Chapter05/DigitalTicket.Shared/ViewModels/OwnedTicketsViewModel.cs`](https://github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/blob/main/Chapter05/DigitalTicket.Shared/ViewModels/OwnedTicketsViewModel.cs)。

1.  现在，更新`OwnedTicketsPage.xaml`和`OwnedTicketsPage.xaml.cs`。您可以在 GitHub 上找到这两个文件的源代码：[`github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/tree/main/Chapter05/DigitalTicket.Shared/Views`](https://github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/tree/main/Chapter05/DigitalTicket.Shared/Views)。

现在，如果启动应用程序并导航到拥有的票页面，您应该会看到一个空页面。如果您已经预订了一张票，您应该会看到*图 5.3*左侧的内容。如果您点击票下方的小、宽、灰色框，您应该会看到*图 5.3*右侧的内容：

![图 5.3 - 左：拥有单张票的票务列表；右：拥有的票和已预订票的 QR 码](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_5.03_B17132.jpg)

图 5.3 - 左：拥有单张票的票务列表；右：拥有的票和已预订票的 QR 码

当然，这还不是最终的 UI；用户应该看到指示他们尚未预订票的文本，而不是空白屏幕。不过，目前预计文本缺失，按钮也没有标签，因为它们使用的是`x:Uid`，而不是设置了`Text`或`Content`属性。在下一节中，我们将看看`x:Uid`是什么，并更新我们的应用程序，以便所有标签都能正确显示。

# 使您的应用程序准备好迎接客户

在本节中，我们将更新我们的应用程序，以便为我们的客户做好准备，包括本地化支持，使应用程序更易于客户使用。添加本地化支持后，我们将更新应用程序的图标和启动画面，以便用户更容易识别。

## 本地化您的应用程序

如果您正在开发一个面向客户的应用程序，能够以客户的母语提供翻译非常重要，特别是针对来自不同国家的客户的应用程序。在上一节中，我们已经添加了`x:Uid`属性并向`Strings.resw`文件添加了条目；但是，还有其他本地化资源的方法，我们将在后面介绍。我们将从`x:Uid`开始本地化文本。

### 使用 x:Uid 本地化您的 UI

使用`x:Uid`和资源文件（.resw 文件）是本地化应用程序的最简单方法，特别是因为添加新的翻译（例如，为新语言）非常容易。但是如何使用`x:Uid`和.resw 文件本地化您的应用程序呢？

`x:Uid`属性可以添加到你的 XAML 代码的任何元素上。除了在你想要提供翻译的控件上设置`x:Uid`属性之外，你还需要添加这些翻译。这就是`.resw`文件发挥作用的地方。简而言之，`resw`文件是包含必要条目的 XML 文档。然而，最容易想到的方法是将它们视为一张包含三个属性的条目列表，通常表示为表格。这些属性（或列）如下：

+   **Name**：你可以用来查找资源的名称。这个路径也将用于确定要设置哪个控件上的哪个属性。

+   **Value**：设置的文本或查找此资源时返回的文本。

+   **Comment**：你可以使用这一列提供解释该行的注释。当将应用程序翻译成新语言时，这是特别有用的，因为你可以使用注释找出最佳翻译是什么。查看*图 5.4*中的**Comment**列，了解它们可能如何使用。

在 Visual Studio 中打开`.resw`文件时，显示将如*图 5.4*所示：

![图 5.4 - 在 Visual Studio 中查看.resw 文件](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_5.04_B17132.jpg)

图 5.4 - 在 Visual Studio 中查看.resw 文件

当在 XAML 代码中使用`x:Uid`属性与`.resw`文件结合使用时，你需要注意如何编写资源的名称条目。名称条目需要以控件的`x:Uid`值开头，后跟一个点（`.`）和应该设置的属性的名称。因此，在前面的示例中，如果我们想要本地化`TextBlock`元素的文本，我们将添加一个名称值为`ButtonTextBlock.Text`的条目，因为我们想设置`TextBlock`元素的`Text`属性。

“但是本地化是如何运作的呢？”你可能会问。毕竟，我们只添加了一个条目；它怎么知道选择哪种语言呢？这就是为什么你放置`.resw`文件的文件夹很重要。在你的项目中，你需要有一个`Strings`文件夹。在该文件夹中，对于你想要将应用本地化的每种语言，你需要创建一个文件夹，比如`en-GB`，而对于*德语（德国）*，你需要创建一个名为`de-DE`的文件夹。在你为每种想要支持的语言创建的文件夹中，你需要放置`.resw`文件，以便本地化能够正常工作。请注意，如果某种语言不可用，资源查找将尝试找到下一个最佳匹配。你可以在这里了解更多关于这个过程的信息，因为你的 Uno 平台应用在每个平台上的行为都是相同的：[`docs.microsoft.com/windows/uwp/app-resources/how-rms-matches-lang-tags`](https://docs.microsoft.com/windows/uwp/app-resources/how-rms-matches-lang-tags)。

重要提示

要小心命名这些文件夹。资源查找将根据文件夹的名称进行。如果文件夹的名称有拼写错误或不符合 IETF BCP 47 标准，资源查找可能会失败，你的用户将看到缺少标签和文本，或者资源查找将退回到已翻译文本的语言混合。

我们已经有一个用于英文文本资源的文件夹；然而，我们也想支持德语翻译。为此，在`Strings`文件夹内创建一个名为`de-DE`的新文件夹。现在，添加一个名为`Resources.resw`的新`.resw`文件，并添加以下条目：

![表 5.2](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Table_02.jpg)

如果现在启动应用并将应用的语言切换为德语，你会看到预订页面现在已本地化。如果你的设备语言已设置为德语，而不是以英语显示页面，现在应该显示为德语，即使你现在不切换到德语选项。

### 从代码后台访问资源

使用`x:Uid`并不是本地化应用程序的唯一方法；我们现在将看到如何可以从代码后台访问资源。例如，当您想要本地化集合中的项目时，例如我们应用程序中拥有的票证列表。要访问字符串资源，您可以使用`ResourceLoader`类。我们在本章开头添加了`LocalizedResources`类；然而，直到现在，它还没有访问任何资源。现在通过添加以下导入并替换`GetString`函数来更新`LocalizedResources`：

```cs
using Windows.ApplicationModel.Resources;
...
private static ResourceLoader cachedResourceLoader;
public static string GetString(string name)
{
    if (cachedResourceLoader == null)
    {
        cachedResourceLoader = 
            ResourceLoader.GetForViewIndependentUse();
    }
    if (cachedResourceLoader != null)
    {
        return cachedResourceLoader.GetString(name);
    }
    return null;
}
```

由于我们将经常使用加载的资源，我们正在缓存该值，以避免调用`GetForViewIndependentUse`，因为这是昂贵的。

现在我们已经介绍了`x:Uid`的工作原理以及如何从代码后台访问本地化资源，让我们更新应用程序的其余部分以进行本地化。首先，通过向我们的`.resw`文件添加必要的条目来开始。以下是您需要为`MainPage.xaml`文件及其英语和德语条目的条目表：

![Table 5.3](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Table_03.jpg)

现在，请将`MainPage.xaml`文件中的`NavigationViewItems`属性替换为以下内容：

```cs
<muxc:NavigationViewItem x:Name="JourneyBookingItem" x:Uid="JourneyBookingItem" Tag="JourneyPlanner"/>
<muxc:NavigationViewItem x:Uid="OwnedTicketsItem" Tag="OwnedTickets"/>
<muxc:NavigationViewItem x:Uid="AllDayTicketsItem" Tag="AllDayTickets" IsEnabled="False"/>
<muxc:NavigationViewItem x:Uid="NetworkPlanItem" IsEnabled="False"/>
<muxc:NavigationViewItem x:Uid="LineOverViewItemItem" IsEnabled="False"/>
```

要将应用程序的其余部分本地化，请查看 GitHub 上的源代码。您还可以在那里找到英语和德语的更新的`Resources.resw`文件。请注意，我们选择不本地化车站名称，因为本地化街道和地名可能会让客户感到困惑。

重要提示

您还可以本地化其他资源，如图像或音频文件。为此，您需要将它们放在正确命名的文件夹中。例如，如果您想本地化名为`Recipe.png`的图像，您需要将该图像的本地化版本放在`Assets/[语言标识符]`文件夹中，其中`语言标识符`是图像所属语言的 IETF BCP 47 标识符。您可以在这里了解有关自定义和本地化资源的更多信息：[`docs.microsoft.com/windows/uwp/app-resources/images-tailored-for-scale-theme-contrast`](https://docs.microsoft.com/windows/uwp/app-resources/images-tailored-for-scale-theme-contrast)。

在本节中，我们介绍了如何使用`x:Uid`和资源文件本地化您的应用程序。随着您的应用程序变得更大并提供更多语言，使用多语言应用程序工具包可能会有所帮助。它使您更容易地检查哪些语言键未被翻译，并集成到 Visual Studio 中。您可以在这里了解更多信息：[`developer.microsoft.com/en-us/windows/downloads/multilingual-app-toolkit/`](https://developer.microsoft.com/en-us/windows/downloads/multilingual-app-toolkit/)。

## 自定义应用程序的外观

在将应用程序发布到商店时，您希望您的应用程序能够被用户识别并传达您的品牌。然而，到目前为止，我们开发的所有应用程序都使用了标准的 Uno 平台应用程序图标。幸运的是，Uno 平台允许我们更改应用程序的图标，并允许我们为应用程序设置启动图像。

### 更新应用程序的图标

让您的应用程序被用户识别的最重要的事情之一就是为您的应用程序添加图标。更新应用程序的图标很容易。您可以在这里找到我们将使用的图像：[`github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/blob/main/Chapter05/DigitalTicket.Shared/Assets/AppIcon.png`](https://github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/blob/main/Chapter05/DigitalTicket.Shared/Assets/AppIcon.png)。

#### 更新 Android 应用程序的图标

要更新 Android 应用程序的应用程序图标，您只需将 Android 项目的 drawable 文件夹中的`Icon.png`文件替换为所需的应用程序徽标。请注意，您还需要在项目属性中选择正确的图像。为此，请双击`Appicon`，您将在**Properties**节点内的`AndroidManifest.xml`文件中选择`android:icon`条目。

#### 更新 iOS 应用程序的图标

更新我们的 iOS 应用程序图标需要更多的工作。对于 iOS 应用程序，您需要根据应用程序安装的设备不同的尺寸来设置应用程序图标。要查看尺寸列表并更新 iOS 应用程序的应用图标，只需展开 iOS 项目的**Assets Catalog**节点，然后双击其中的**Media**条目。在**AppIcons**选项卡中，您可以选择不同设备和类别的图像和尺寸。并不需要为每个尺寸提供图像；但是，您至少应该为每个类别提供一个图标。

#### 更新 UWP 应用程序的图标

更新 UWP 头部的应用程序图标的最简单方法是使用`Package.appxmanifest`文件。为此，请双击`Package.appxmanifest`，然后在**Visual Assets**选项卡中选择**App icon**选项。要更新应用程序的图标，请选择源图像，选择目标文件夹，然后单击**Generate**。这将生成不同尺寸的应用程序图标，并因此将您的应用程序图标更新为指定的图像。

#### 更新其他项目的图标

虽然我们的应用程序将不会在其他平台上可用，并且我们已经删除了相应平台的头部，但您可能希望在其他项目中更新其他平台的图标：

+   `Assets/xcassets/AppIcon.appiconset`文件夹。如果重命名图像，请确保还更新`Contents.json`文件。

+   **基于 Skia 的项目**：在 Visual Studio 中右键单击项目并选择**属性**。在**应用程序**选项卡中，您可以使用**资源**部分中的**浏览**按钮选择一个新图标。

+   `favicon.ico`在项目的**Assets**文件夹中。

### 自定义您的应用程序启动画面

更新您的应用程序图标并不是使您的应用程序更具识别性的唯一方法。除了应用程序图标之外，您还可以自定义应用程序的启动画面。请注意，目前只有 Android、iOS、UWP 和 WASM 应用程序支持设置启动画面。与图标一样，您可以在 GitHub 上找到此类图像资源。

#### 更新 Android 启动画面

要向 Android 应用程序添加启动画面，您首先需要添加您的启动画面图像。在我们的情况下，我们将其命名为`SplashScreen.png`。之后，将以下条目添加到`Resource/values/Styles.xml`文件中：

```cs
<item name="android:windowBackground">@drawable/splash</item>
```

然后，您需要在`Resources/drawable`文件夹中添加`splash.xml`文件，并添加以下代码：

```cs
<?xml version="1.0" encoding="utf-8"?>
    <layer-list xmlns:android=
        "http://schemas.android.com/apk/res/android">
    <item>
        <!-- background color -->
        <color android:color="#008cff"/>
    </item>
    <item>
    <!-- splash image -->
        <bitmap android:src="img/splashscreen"
                android:tileMode="disabled"
                android:gravity="center" />
    </item>
</layer-list>
```

#### 更新 iOS 应用程序的启动画面

与任何 iOS 应用程序一样，启动画面需要是一个故事板。Uno Platform 使得很容易显示一个单一图像作为启动画面。只需这些简单的步骤：

1.  在解决方案资源管理器中，选择 iOS 项目并按下**显示所有文件**按钮。

1.  现在您将能够看到一个名为**LaunchScreeen.storyboard**的文件。右键单击此文件并选择**包含在项目中**。这将在启动应用程序时自动使用。

如果运行应用程序，您将看到 Uno Platform 标志在启动应用程序时显示。您可以通过替换图像来轻松更改此内容。

1.  在`SplashScreen@2x.png`和`SplashScreen@3x.png`中。这些是故事板使用的文件。用您想要的图像替换它们。

1.  要更改用于背景的颜色，您可以在 Xcode Interface Builder 中打开故事板并更改颜色。或者，您可以在 XML 编辑器中打开故事板文件，并更改颜色的`red`、`green`和`blue`属性，使用`backgroundColor`键。

可以使用任何您希望的内容作为启动屏幕的故事板文件。要做到这一点，您需要使用 Xcode Interface Builder。在版本**16.9**之前，Visual Studio 包括一个 iOS 故事板编辑器，但现在不再可用。要现在编辑故事板，您需要在 Visual Studio for Mac 中打开项目，右键单击文件，然后选择**打开方式** | **Xcode Interface Builder**。

#### 更新 UWP 应用程序的启动画面

与更新 UWP 应用程序的应用程序图标类似，使用`Package.appxmanifest`文件和`#008CFF`。现在，单击**生成**以生成 UWP 应用程序的启动画面图像。

#### 更新 WASM 应用程序的启动画面

要更新 WASM 头的启动画面，请将新的启动画面图像添加到 WASM 项目的`AppManifest.js`文件中的`WasmScripts`文件夹中，以引用该图像，并在必要时更新启动画面颜色。

如果您已成功按照我们的应用程序步骤进行操作，您应该能够在 Android 应用程序列表中看到应用程序，就像*图 5.5*左侧所示。一旦启动应用程序，您的应用程序在显示旅程预订页面之前应该看起来像*图 5.5*右侧所示。请注意，此处提供的图标和启动画面仅为示例。在真实的应用程序中，您应该确保您的应用程序图标即使很小也看起来不错：

![图 5.5 – 左：应用程序列表中的 DigitalTicket；右：DigitalTicket 的启动画面](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Author_Figure_5.05_B17132.jpg)

图 5.5 – 左：应用程序列表中的 DigitalTicket；右：DigitalTicket 的启动画面

## 确保每个人都能使用您的应用程序

为确保每个人都能使用您的应用程序，您需要使其具有无障碍性。在开发应用程序时，无障碍性至关重要。所有能力水平的人都会使用您的应用程序；如果您的应用程序不具有无障碍性，将使您的客户生活更加困难，甚至可能使他们无法使用您的应用程序。

在考虑无障碍性时，大多数人首先想到的是通过为屏幕阅读器添加标签和替代文本来使应用程序对盲人无障碍。然而，无障碍性涉及的远不止这些。例如，视力较低但不是盲人的人可能不使用屏幕阅读器，而是选择使用高对比度主题使应用程序更易于使用，或者选择增大字体大小以便更容易阅读文本。提供暗色主题通常被视为纯粹的美学方面；然而，它在无障碍性方面也很重要。一些人可能能够更好地阅读文本，而某些残障人士可能会更难使用您的应用程序。

如果您已经熟悉 UWP 中可用的 API 来制作应用程序，那么在使您的 Uno 平台应用程序具有无障碍性时会有一些不同之处。由于您的应用程序将在不同的平台上运行，而这些平台都有不同的 API 来提供无障碍应用程序，Uno 平台在无障碍性方面只提供了一部分可用属性。在撰写本文时，只支持以下属性，并且在每个平台上都可以使用：

+   `AutomationProperties.AutomationId`: 您可以设置此属性以便使用辅助技术更轻松地导航到控件。

+   `AutomationProperties.Name`: 辅助技术将使用此属性向用户宣布控件。

+   `AutomationProperties.LabeledBy`: 设置此属性时，将使用此属性指定的控件来宣布设置了此属性的控件。

+   `AutomationProperties.AccessibilityView`: 使用此属性，您可以指示控件不应该被辅助技术向用户宣布，或者您想要包括通常不会被宣布的控件。

除了之前列出的属性外，Uno 平台还在每个平台上支持高对比度主题。由于我们使用 Uno 平台提供的标准控件，我们不需要特别关注这一点，因为 Uno 平台已经为我们的应用程序提供了正确的高对比度外观。但是，如果您编写自己的控件，您还应该检查您的应用程序的高对比度版本，以确保其可接受。

重要提示

您应该始终本地化辅助技术将使用的资源。不这样做可能会使您的应用程序无法访问，因为用户可能会遇到语言障碍，特别是如果辅助技术期望从一种语言中读出单词，而实际上却是另一种语言的单词。

为了确保您的应用程序对使用辅助技术的人员可访问，您需要使用辅助技术测试您的应用程序。在下一节中，您可以找到启动平台默认屏幕阅读器的说明。

### 在不同平台上启动屏幕阅读器

由于激活系统辅助技术的步骤因平台而异，我们将逐一进行介绍，从 Android 开始。

#### Android 上的 TalkBack

启动**设置**应用程序，打开**辅助功能**页面。按下**TalkBack**，并点击开关以启用 TalkBack。最后，按下**确定**关闭对话框。

#### iOS 上的 VoiceOver

打开**设置**应用程序，打开**通用**下的**辅助功能**选项。然后，在**视觉**类别中点击**VoiceOver**，并点击开关以启用它。

#### macOS 上的 VoiceOver

启动**系统偏好设置**，点击**辅助功能**。然后，在**视觉**类别中点击**VoiceOver**。勾选**启用 VoiceOver**以使用**VoiceOver**。

#### Windows 上的 Narrator（适用于 UWP 和 WASM）

要在 Windows 上启动**Narrator**屏幕阅读器，您只需同时按下 Windows 徽标键、*Ctrl*和*Enter*。

### 更新我们的应用程序以实现可访问性

在本章中，我们尚未确保我们的应用程序是可访问的。虽然许多控件已经可以自行访问，例如，按钮控件将宣布其内容，但仍然有一些控件需要我们在可访问性方面进行改进。如果用户使用辅助技术使用应用程序，不是所有内容都会以有意义的方式进行宣布。让我们通过更新应用程序的 UI 来改变这一点，以设置所有必要的属性。为此，我们将首先更新我们的旅程预订页面。

我们旅程预订页面上的两个`ComboBox`控件目前只会被宣布为`ComboBox`控件，因此使用辅助技术的用户不知道`ComboBox`控件实际用途。由于我们已经添加了描述其目的的`TextBlock`元素，我们将更新它们以使用`AutomationProperties.LabeledBy`属性：

```cs
<TextBlock x:Name="StartPointLabel" x:Uid="StartPointLabel" FontSize="20"/>
<ComboBox ItemsSource="{x:Bind journeyBookingVM.AllStations}" x:Uid="StartPointComboBox"
    AutomationProperties.LabeledBy="{x:Bind 
        StartPointLabel}"
    SelectedItem="{x:Bind 
        journeyBookingVM.SelectedStartpoint,Mode=TwoWay}"
    HorizontalAlignment="Stretch" 
        DisplayMemberPath="Name"/>
<TextBlock x:Name="EndPointLabel" x:Uid="EndPointLabel" FontSize="20"/>
<ComboBox ItemsSource="{x:Bind journeyBookingVM.AvailableDestinations, Mode=OneWay}" x:Uid="EndPointComboBox"
    AutomationProperties.LabeledBy="{x:Bind EndPointLabel}"
    SelectedItem="{x:Bind 
        journeyBookingVM.SelectedEndpoint,Mode=TwoWay}"
    HorizontalAlignment="Stretch" 
    DisplayMemberPath="Name"/>
```

现在，当用户使用辅助技术导航到`ComboBox`控件时，`ComboBox`控件将使用由`AutomationProperties.LabeledBy`引用的`TextBlock`元素的文本进行宣布。由于该页面上的其余控件已经为我们处理了可访问性，让我们继续进行所拥有的车票页面。

在所拥有的车票页面上，存在两个潜在问题：

+   车站名称旁边的图标将被宣布为空白图标。

+   QR 码将只被宣布为一个图像。

由于图标仅用于视觉表示，我们指示辅助技术不应使用`AutomationProperties.AccessibilityView`属性进行通告，并将其设置为`Raw`。如果您想为辅助技术包括一个控件，可以将该属性设置为`Content`。

为了确保 QR 码图像能够以有意义的方式进行通告，我们将为其添加一个描述性名称。为简单起见，我们将宣布它是当前选定车票的 QR 码。首先，您需要按照以下方式更新图像元素：

```cs
<Image x:Name="QRCodeDisplay" x:Uid="QRCodeDisplay"
    Source="{x:Bind ownedTicketsVM.CurrentQRCode,
             Mode=OneWay}"
    Grid.Row="4" MaxWidth="300" MaxHeight="300" 
        Grid.ColumnSpan="2"/>
```

之后，将以下条目添加到`Resources.resw`文件中：

**英语**：

![表格 5.4](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Table_04.jpg)

**德语**：

![表格 5.5](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Table_05.jpg)

通过添加这些条目，我们现在为显示的 QR 码提供了一个描述性名称，同时确保此文本将被本地化。

最后，我们还需要更新设置页面。由于它只包含一个单独的`ComboBox`控件，缺少名称，因此将以下条目添加到`Resources.resw`文件中：

**英语**：

![表格 5.6](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Table_06.jpg)

**德语**：

![表格 5.7](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Table_07.jpg)

在本节中，我们简要介绍了 Uno 平台中的可访问性；但是，我们没有提到还有一些限制和需要注意的事项。您可以在官方文档中阅读更多关于这些限制的信息：[`platform.uno/docs/articles/features/working-with-accessibility.html`](https://platform.uno/docs/articles/features/working-with-accessibility.html)。如果您希望了解更多关于一般可访问性的信息，您可以查看以下资源：

+   https://docs.microsoft.com/en-us/learn/paths/accessibility-fundamentals/

+   [`developer.mozilla.org/en-US/docs/Learn/Accessibility/What_is_accessibility`](https://developer.mozilla.org/en-US/docs/Learn/Accessibility/What_is_accessibility)

+   [`developers.google.com/web/fundamentals/accessibility`](https://developers.google.com/web/fundamentals/accessibility)

# 摘要

在本章中，我们构建了一个在 iOS 和 Android 上运行的面向客户的应用程序。我们介绍了如何使用 SQLite 存储数据，如何使您的应用程序具有可访问性，并使其为客户准备好。作为其中的一部分，我们介绍了如何本地化您的应用程序，让用户选择应用程序的语言，并为您的应用程序提供自定义启动画面。

在下一章中，我们将为 UnoBookRail 编写一个信息仪表板。该应用程序将面向 UnoBookRail 的员工，并在桌面和 Web 上运行。


# 第六章：显示图表和自定义 2D 图形中的数据

本章将介绍需要显示图形、报告和复杂图形的应用程序。应用程序通常包括某种图形或图表。还越来越常见的是在 UI 中包含无法轻松使用标准控件制作的元素。

随着我们在本章的进展，我们将为我们虚构的业务构建一个仪表板应用程序，显示适合业务不同部分的信息。这样的应用程序在管理报告工具中很常见。您可以想象不同的屏幕显示在每个部门墙上安装的监视器上。这使员工可以立即看到他们所在业务部门的情况。

在本章中，我们将涵盖以下主题：

+   显示图形和图表

+   使用 SkiaSharp 创建自定义图形

+   使 UI 布局对屏幕尺寸的变化做出响应

在本章结束时，您将创建一个仪表板应用程序，显示在 UWP 和 Web 上运行的财务、运营和网络信息。它还将适应不同的屏幕比例，因此每个页面的内容都会考虑不同的屏幕尺寸和纵横比。

# 技术要求

本章假设您已经设置好了开发环境，包括安装了项目模板，就像在*第一章*中介绍的那样，*介绍 Uno Platform*。本章的源代码位于[`github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/tree/main/Chapter06`](https://github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/tree/main/Chapter06)。

本章的代码使用了来自[`github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/tree/main/SharedLibrary`](https://github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/tree/main/SharedLibrary)的库。

查看以下视频，以查看代码的实际运行情况：[`bit.ly/3iDchtK`](https://bit.ly/3iDchtK)

# 介绍应用程序

本章中我们将构建的应用程序名为**Dashboard**。这是一个显示业务部门内当前活动的应用程序。这不是所有员工都可以使用的东西，但为了让我们专注于本章的特性和兴趣领域，我们不会关心访问权限是如何控制的。这个应用程序的真实版本将有许多功能，但我们只会实现三个：

+   显示当前的财务信息

+   显示实时的运营信息

+   显示火车目前在网络中的位置

由于这个应用程序将被办公室工作人员使用，它将在桌面上（通过 UWP）和在 Web 浏览器上（使用 WASM 版本）可用。

## 创建应用程序

我们将从创建应用程序的解决方案开始。

1.  在 Visual Studio 中，使用**多平台应用程序（Uno Platform）**模板创建一个新项目。

1.  给项目命名为`Dashboard`。您可以使用不同的名称，但需要相应调整所有后续的代码片段。

1.  删除所有平台头项目，**除了** **UWP** 和 **WASM**。

1.  为了避免写更多的代码，我们现在将添加对共享库项目的引用。右键单击`UnoBookRail.Common.csproj`文件中的解决方案节点，然后单击**打开**。

1.  对于每个特定于平台的项目，我们需要添加对共享库项目的引用。右键单击`UnoBookRail.Common`，然后单击**确定**。现在*重复此过程以进行 WASM 项目*。

现在基本的解决方案结构已经准备好，我们可以向主页面添加一些功能。

## 创建各个页面

我们将为要显示的每个功能区域使用单独的页面：

1.  在`Views`中创建一个新文件夹。

1.  在`Views`文件夹中，添加名为`FinancePage.xaml`、`OperationsPage.xaml`和`NetworkPage.xaml`的*三个*新页面。

现在我们将更新主页面以在这些新页面之间进行导航。

## 创建主页面

该应用程序已经包含了文件`MainPage.xaml`，我们将使用它作为在其他页面之间导航的容器：

1.  用包含每个我们将实现的单独页面选项的以下`NavigationView`控件替换`MainPage.xaml`中的网格：

```cs
<NavigationView
    PaneDisplayMode="Top"
    SelectionChanged="NavItemSelected"
    IsBackEnabled="{Binding Path=CanGoBack, 
                    ElementName=InnerFrame}"
    BackRequested="NavBackRequested"
    IsSettingsVisible="False">
    <NavigationView.MenuItems>
        <NavigationViewItem Content="Finance" />
        <NavigationViewItem Content="Operations" />
        <NavigationViewItem Content="Network" />
    </NavigationView.MenuItems>
    <Frame x:Name="InnerFrame" />
</NavigationView>
```

1.  我们现在需要添加`NavItemSelected`事件的处理程序，以执行页面之间的实际导航。在`MainPage.xaml.cs`中添加以下内容：

```cs
using Dashboard.Views;
private void NavItemSelected(NavigationView sender, NavigationViewSelectionChangedEventArgs args) 
{
  var item = (args.SelectedItem as 
              NavigationViewItem).Content.ToString();
  Type page = null;
  switch (item) {
    case "Finance":
      page = typeof(FinancePage);
      break;
    case "Operations":
      page = typeof(OperationsPage);
      break;
    case "Network":
      page = typeof(NetworkPage);
      break;
  }
  if (page != null && InnerFrame.CurrentSourcePageType
      != page) {
    InnerFrame.Navigate(page);
  }
}
```

1.  我们还需要实现`NavBackRequested`方法来处理用户按下返回按钮导航回页面。添加以下内容来实现这一点：

```cs
private void NavBackRequested(object sender, NavigationViewBackRequestedEventArgs e) 
{
    InnerFrame.GoBack();
}
```

导航

该应用程序使用自定义定义的框架和基于堆栈的导航样式。这允许用户按下内置的返回按钮返回到上一页。虽然这可能不被认为是这个应用程序最合适的方式之一，但这是开发人员在 UWP 应用程序中实现导航的最流行方式之一。因此，我们认为将其包含在本书中并展示它可以被整合到 Uno 平台应用程序中是合适的。

1.  前面的内容将允许我们在菜单中选择项目时在页面之间进行导航，但我们也希望在应用程序首次打开时显示一个页面。为此，在`MainPage`构造函数的*末尾*添加以下调用：

```cs
InnerFrame.Navigate(typeof(FinancePage));
```

重要提示

本节中的代码显示了在`NavigationView`控件中启用页面之间导航的最简单方法。这当然不是唯一的方法，也不是应该总是这样做的建议。

现在所有基础都已就绪，我们现在可以向财务页面添加一个图表。

# 使用来自 SyncFusion 的控件显示图表

SyncFusion 是一家为 Web、桌面和移动开发制作 UI 组件的公司。他们的 Uno 平台控件在撰写本文时处于测试阶段，并且在预览期间可以免费使用，通过他们的社区许可证([`www.syncfusion.com/products/communitylicense`](https://www.syncfusion.com/products/communitylicense))。有许多不同的图表类型可用，但我们将使用线图来创建一个类似于*图 6.1*所示的页面。图表显示在一些箭头旁边，提供一些一般趋势数据，以便查看它们的人可以快速了解数据的摘要。想象它们代表数据与上周、上个月和去年同一天相比较的情况：

![图 6.1-包括来自 SyncFusion 的图表的财务信息](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_6.01_B17132.jpg)

图 6.1-包括来自 SyncFusion 的图表的财务信息

## 更新引用以包括 SyncFusion 控件

SyncFusion Uno 图表控件的测试版本可在 GitHub 上获得完整的源代码：

1.  从[`github.com/syncfusion/Uno.SfChart`](https://github.com/syncfusion/Uno.SfChart)下载或克隆代码。

1.  通过右键单击解决方案并选择**添加** | **现有项目…**，将**Syncfusion.SfChart.Uno.csproj**项目添加到解决方案中。

1.  更新**Syncfusion.SfChart.Uno**项目以使用最新版本的**Uno.UI**包。这是为了避免在解决方案中的不同项目中使用不同版本的库时出现任何问题。

1.  从*UWP*和*WASM*项目中引用**Syncfusion.SfChart.Uno**项目。

我们现在可以在应用程序中使用这些控件。

重要提示

由于 SyncFusion 控件仅从源代码中获取，虽然不太可能，但当您阅读本文时它们可能已经发生了变化。希望可以获得编译版本的控件，但如果您需要达到与本文撰写时相当的状态，请使用提交**43cd434**。

## 绘制线图

我们可以通过以下步骤绘制一个简单的线图：

1.  首先将此命名空间添加到`FinancePage.xaml`中：

```cs
xmlns:sf="using:Syncfusion.UI.Xaml.Charts"
```

1.  现在用以下内容替换网格：

```cs
<RelativePanel HorizontalAlignment="Center">
  <sf:SfChart class we can specify. We define a PrimaryAxis class (for the X-axis), which reflects the hours of the day, with a SecondaryAxis class (for the Y-axis) representing the numeric values and a set of data as a LineSeries class.We also specify a `TextBlock` element to appear below the chart but be horizontally aligned. This will display arrows indicating trend information relating to the graph.
```

1.  为了提供数据，我们需要在`FinancePage.xaml.cs`中的类中添加以下内容：

```cs
public List<HourlySales> DailySales
    => FinanceInfo.DailySales
       .Select(s => new HourlySales(s.Hour, 
            s.Sales)).ToList();
public string TrendArrows => FinanceInfo.TrendArrows;
```

1.  这些属性需要您添加此`using`声明：

```cs
using UnoBookRail.Common.DashboardData;
```

1.  我们还必须创建以下类，`SfChart`对象将使用它来查找我们在 XAML 中引用的命名属性：

```cs
public class HourlySales
{
    public HourlySales(string hour, double totalSales) 
    {
        Hour = hour;
        TotalSales = totalSales;
    }
    public string Hour { get; set; }
    public double TotalSales { get; set; }
}
```

显然，我们在这里只创建了一个简单的图表，但关键是要注意它是多么容易。一个真正的仪表板可能会显示不止一个图表。您可以在存储库中包含的示例应用程序中看到您可以包含的图表的示例[`github.com/syncfusion/Uno.SfChart`](https://github.com/syncfusion/Uno.SfChart)。

我们已经看到了如何轻松地包含来自一个供应商的图表来显示财务信息。现在让我们添加另一个供应商的图表，以显示一些不同的信息。

# 使用 Infragistics 控件显示图表

Infragistics 是一家为各种平台提供 UI 和 UX 工具的公司。他们还有一系列控件可供 Uno 平台应用程序使用，在预览期间免费使用。

您可以在[`www.infragistics.com/products/uno-platform`](https://www.infragistics.com/products/uno-platform)了解更多关于这些控件的信息，或者跟随我们为应用程序添加图表，以显示与 UnoBookRail 业务的当前操作相关的信息，并创建一个看起来像*图 6.2*的页面：

![图 6.2 - 来自 Infragistics 的图表上显示的网络操作详细信息](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_6.02_B17132.jpg)

图 6.2 - 来自 Infragistics 的图表上显示的网络操作详细信息

## 更新引用

为了能够在我们的应用程序中使用这些控件，我们必须首先进行以下修改：

1.  在**UWP**项目中引用`Infragistics.Uno.Charts` NuGet 包：

```cs
Install-Package Infragistics.Uno.Charts -Version 20.2.59-alpha
```

1.  在**WASM**项目中引用`Infragistics.Uno.Wasm.Charts` NuGet 包：

```cs
Install-Package Infragistics.Uno.Wasm.Charts -Version 20.2.59-alpha
```

1.  在**WASM**项目中引用`Uno.SkiaSharp.Views`和`Uno.SkiaSharp.Wasm` NuGet 包。这是必要的，因为 Infragistics 控件使用 SkiaSharp 来绘制控件。这与我们之前使用的 SyncFusion 控件不同，后者使用 XAML：

```cs
Install-Package Uno.SkiaSharp.Views -Version 2.80.0-uno.493
Install-Package Uno.SkiaSharp.Wasm -Version 2.80.0-uno.493
```

通过这些简单的修改，我们现在可以将图表添加到我们的应用程序中。

重要提示

如果在进行上述更改后注意到任何奇怪的编译行为，请尝试清理解决方案，关闭所有打开的 Visual Studio 实例，然后重新打开解决方案。这不应该是必要的，但我们发现在某些情况下需要这样做。

您可能还会在 SyncFusion 项目的错误列表中看到条目，尽管它成功编译。这些错误可以安全地忽略。

## 绘制柱状图

现在我们将为应用程序的**Operations**页面添加内容。为简单起见，我们只添加两条信息。我们将添加一个图表，显示今天每小时使用了多少张票的类型。此外，我们将根据持票进入车站但随后没有出站的人数，显示目前在火车上或车站中的人数：

1.  将以下命名空间添加到`OperationsPage.xaml`的`Page`元素中：

```cs
xmlns:ig="using:Infragistics.Controls.Charts"
```

1.  现在将以下 XAML 添加为页面的内容：

```cs
<Grid>
  <Grid.RowDefinitions>
    <RowDefinition Height="*" />
    <RowDefinition Height="*" />
  </Grid.RowDefinitions>
  <Grid.ColumnDefinitions>
    <ColumnDefinition Width="*" />
    <ColumnDefinition Width="*" />
  </Grid.ColumnDefinitions>
  <ig:XamDataChart class. Within this, we specify the *x* and *y* axes and the data to display as a StackedColumnSeries element. Within the series, we detail the paths to the data for each fragment of the stack.Finally, we added the `TextBlock` element that displays the current passenger count.
```

1.  在`OperationsPage.xaml.cs`中添加以下`using`指令：

```cs
using UnoBookRail.Common.DashboardData;
```

这些是我们将添加到此文件的属性所需的。

1.  将以下内容添加到`OperationsPage`类中，提供图表中显示的数据：

```cs
public string PsngrCount => OperationsInfo.CurrentPassengers;
private List<PersonCount> Passengers
   => OperationsInfo.Passengers.Select(p 
       => new PersonCount(p.Hour, p.Children,
           p.Adults, p.Seniors)).ToList();
```

1.  现在我们需要添加刚刚引用的`PersonCount`类：

```cs
public class PersonCount 
{
    public PersonCount(string hour, double child,
        double adult, double senior) 
    {
        Hour = hour;
        Children = child;
        Adults = adult;
        Seniors = senior;
    }
    public string Hour { get; set; }
    public double Children { get; set; }
    public double Adults { get; set; }
    public double Seniors { get; set; }
}
```

有了这个，我们现在有一个简单的页面图表，显示每小时旅行的乘客数量。

与 SyncFusion 图表一样，Infragistics 还有许多其他图表和控件可用。您可以在[`github.com/Infragistics/uno-samples`](https://github.com/Infragistics/uno-samples)找到这些示例。

现在我们已经看到了使用第三方库显示更复杂控件的不同方法，让我们来看看如何自己绘制更复杂的东西。

# 使用 SkiaSharp 绘制自定义图形

UWP 和 Uno 平台包括支持创建形状并提供基本绘图功能。然而，有时您需要在应用程序中显示一些无法轻松使用标准控件完成的东西，您需要精细的控制，或者在操作大量 XAML 控件时遇到性能问题。在这些情况下，可能需要直接在 UI 上进行绘制。其中一种方法是使用 SkiaSharp。SkiaSharp 是一个基于 Google 的 Skia 图形库的跨平台 2D 图形 API，我们可以在 Uno 平台应用程序中使用。为了展示使用起来有多简单，我们将创建我们应用程序的最后一部分，显示网络中火车当前位置的地图。只需几行代码，我们就可以创建出类似*图 6.3*中显示的屏幕截图的东西：

![图 6.3-在浏览器中运行时应用程序中显示的网络地图](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Author_Figure_6.03_B17132.jpg)

图 6.3-在浏览器中运行时应用程序中显示的网络地图

现在你已经看到我们要创建的东西了，让我们开始做吧。

## 更新项目引用

我们在应用程序中需要使用 SkiaSharp 的引用已经作为我们添加到使用 Infragistics 控件的引用的一部分添加。如果您已经进行了这些更改，这里就没有什么要做的了。

如果您在上一节中跟着做，并且*没有*添加 Infragistics 控件，您需要对解决方案进行以下更改：

+   在**WASM**项目中引用`Uno.SkiaSharp.Views`和`Uno.SkiaSharp.Wasm` NuGet 包：

```cs
Install-Package Uno.SkiaSharp.Views -Version 2.80.0-uno.493
Install-Package Uno.SkiaSharp.Wasm -Version 2.80.0-uno.493
```

在添加相关引用之后，我们现在准备绘制网络地图。

## 绘制网络地图

要在应用程序中绘制网络地图，我们需要采取以下步骤：

1.  在`NetworkPage.xaml`中，添加以下作为唯一的内容。这是将显示我们绘制的控件：

```cs
<skia:SKXamlCanvas xmlns:skia="using:SkiaSharp.Views.UWP" PaintSurface="OnPaintSurface" />
```

1.  要在`SKXamlCanvas`控件上绘制地图，我们需要在`NetworkPage.xaml.cs`中添加以下使用声明：

```cs
using SkiaSharp;
using SkiaSharp.Views.UWP;
using UnoBookRail.Common.Mapping;
using UnoBookRail.Common.Network;
```

1.  接下来，我们必须添加我们在 XAML 中引用的`OnPaintSurface`方法。每当控件需要重新绘制图像时，该方法将被控件调用。这将在控件首次加载时以及控件的渲染大小发生变化时发生：

```cs
private void OnPaintSurface(object sender, SKPaintSurfaceEventArgs e) 
{
    var canvas = SetUpCanvas(e);
    DrawLines(canvas);
    DrawStations(canvas);
    DrawTrains(canvas);
}
```

1.  添加`SetUpCanvas`方法来正确初始化和定位图像：

```cs
private SKCanvas SetUpCanvas(SKPaintSurfaceEventArgs e) 
{
  var canvas = e.Surface.Canvas;
  var relativeWidth = e.Info.Width / ImageMap.Width;
  var relativeHeight = 
      e.Info.Height / ImageMap.Height;
  canvas.Scale(Math.Min(relativeWidth, 
      relativeHeight));
  var x = 0f;
  var y = 0f;
  if (relativeWidth > relativeHeight) 
  {
    x = (e.Info.Width - (ImageMap.Width * 
         relativeHeight)) / 2f / relativeHeight;
  }
  else {
    y = (e.Info.Height - (ImageMap.Height * 
         relativeWidth)) / 2f / relativeWidth;
  }
  canvas.Translate(x, y);
  canvas.Clear();
  return canvas;
}
```

`SetUpCanvas`方法调整我们的绘图区域尽可能大，而不会扭曲或拉伸它，并确保它始终水平和垂直居中。最后，它清除画布并返回它，准备让其他方法在其上绘制。

1.  添加`DrawLines`方法来在画布上绘制支线：

```cs
void DrawLines(SKCanvas canvas) 
{
    var paint = new SKPaint 
    {
        Color = SKColors.Black, 
        StrokeWidth = 1,
    };
    var northPnts = 
        ImageMap.GetStations(Branch.NorthBranch);
    var mainPnts = 
        ImageMap.GetStations(Branch.MainLine);
    var southPnts = 
        ImageMap.GetStations(Branch.SouthBranch);
    SKPoint[] ToSKPointArray(List<(float X, float Y)> 
        list)
        => list.Select(p => new SKPoint(p.X, 
            p.Y)).ToArray();
    void DrawBranch(SKPoint[] stnPoints)
        => canvas.DrawPoints(SKPointMode.Polygon, 
            stnPoints, paint);
    DrawBranch(ToSKPointArray(northPnts));
    DrawBranch(ToSKPointArray(mainPnts));
    DrawBranch(ToSKPointArray(southPnts));
}
```

在上面的代码中，库返回的站点位置被转换为 Skia 特定的数组，用于绘制连接所有点的多边形。

1.  添加`DrawStations`方法来在支线上绘制站点位置：

```cs
void DrawStations(SKCanvas canvas) 
{
    var paint = new SKPaint 
    {
        Color = SKColors.Black,
        Style = SKPaintStyle.Fill,
    };
    foreach (var (X, Y) in ImageMap.Stations) 
    {
        canvas.DrawCircle(new SKPoint(X, Y), 2, 
            paint);
    }
}
```

`DrawStations`方法很简单，因为它只是为每个站点绘制一个圆圈。

1.  将`DrawTrains`方法添加到地图上显示火车当前位置的方法：

```cs
void DrawTrains(SKCanvas canvas) 
{
    var trainPaint = new SKPaint 
    {
        Color = SKColors.Cyan,
        Style = SKPaintStyle.Fill,
    };
    foreach (var train in ImageMap.GetTrainsInNetwork()) 
    {
        canvas.DrawCircle(new SKPoint(
            train.MapPosition.X, train.MapPosition.Y),
                1.8f, trainPaint);
    }
}
```

`DrawTrains`方法同样简单，因为它循环遍历提供的数据，并在每个位置绘制一个青色的圆圈。因为这是在站点圆圈之后绘制的，所以当火车在站点时，它会出现在站点上方。

重要提示

在本章中，我们只使用了一些圆圈和线条来创建我们的地图。然而，SkiaSharp 能够做的远不止我们在这里介绍的。您可能希望通过扩展我们刚刚创建的地图来探索其他可用的功能，包括包括站点名称或添加显示火车行驶方向或是否在站点的其他细节。

现在我们已经实现了应用程序的所有页面，但我们可以通过根据屏幕或窗口的大小调整内容来进一步改进。

# 响应 UI 的变化

您的应用程序将需要在不同大小的屏幕和窗口上运行。其中一些差异是由应用程序运行的不同设备引起的，但您可能还需要考虑用户可以调整大小的窗口。

可以设计页面的多个版本，并在运行时加载适当的版本。但通常更容易创建一个根据可用尺寸调整的单个页面。我们将看看如何使用可用的功能来实现这一点。

## 更改页面布局

Uno 平台允许您通过在`VisualStates`之间切换来创建响应式 UI。

可以创建`AdaptiveTrigger`元素，根据其附加的控件的大小触发。现在我们将使用自适应触发器来调整**财务**和**运营**页面，以更好地根据可用宽度布置其内容：

1.  将以下内容添加为`FinancePage.xaml`中`RelativePanel`的第一个子元素：

```cs
<VisualStateManager.VisualStateGroups>
  <VisualStateGroup>
    <VisualState>
      <VisualState.StateTriggers>
        <AdaptiveTrigger element that's applied when the panel is at least 1,200 relative pixels wide. When this visual state is triggered, the TextBlock element is set to the right of the chart and has its alignment adjusted accordingly. The left-hand side of *Figure 6.4* shows how this looks.
```

1.  现在我们可以在`OperationsPage.xaml`页面的网格中做类似的事情。在行和列定义下方立即添加以下内容：

```cs
<VisualStateManager.VisualStateGroups>
  <VisualStateGroup>
    <VisualState>
      <VisualState.StateTriggers>
        <AdaptiveTrigger MinWindowWidth="1200" />
      </VisualState.StateTriggers>
      <VisualState.Setters>
        <Setter Target="PassengerChart.
            (Grid.ColumnSpan)" Value="1"/>
        <Setter Target="PassengerChart.(Grid.RowSpan)"
             Value="2"/>
        <Setter Target="CurrentCount.(Grid.Row)" 
             Value="0"/>
        <Setter Target="CurrentCount.(Grid.Column)" 
            Value="1"/>
        <Setter Target="CurrentCount.
            (Grid.ColumnSpan)" Value="1"/>
        <Setter Target="CurrentCount.
            (Grid.RowSpan)" Value="2"/>
      </VisualState.Setters>
    </VisualState>
  </VisualStateGroup>
</VisualStateManager.VisualStateGroups>
```

通过这些设置器，我们正在利用之前创建的行和列定义。初始代码将控件放在不同的行中，而在这里我们正在更改控件，使它们位于不同的列中，并在窗口更宽时跨越行。如*图 6.4*所示，这意味着当前在火车上的人数显示在图表旁边，而不是下方：

![图 6.4-以横向布局显示的财务和运营页面](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_6.04_B17132.jpg)

图 6.4-以横向布局显示的财务和运营页面

通过这两个示例，我们已经看到了改变页面上元素重新定位以更改布局的不同方法。没有一种适合所有不同可用空间量的页面的正确方法。状态触发器可用于更改元素上的任何属性，还可以使用多个触发器，因此您可以为小型、中型和大型屏幕制定不同的布局，例如。

更改屏幕上元素的布局不是调整显示内容的唯一方法。控件本身也可以调整、调整大小和重绘以适应空间。

## 拉伸和缩放内容以适应可用空间

XAML 的一个优点是其能够动态布局控件，而不依赖于为每个元素提供特定大小。可以通过设置`HorizontalAlignment`和`VerticalAlignment`属性来调整单个 XAML 控件的大小，以控制它们如何利用可用空间。将这些属性的值设置为`Stretch`将允许它们占用其父元素中的所有可用空间。对于更复杂的情况，还可以使用`ViewBox`元素以不同的方式和方向拉伸控件。

如果您想了解如何使用 XAML 元素创建布局的更多信息，您可以在[`platform.uno/docs/articles/winui-doc-links-development.html#layouting`](https://platform.uno/docs/articles/winui-doc-links-development.html#layouting)找到一些有用的链接。

许多控件也会自动调整以使用所有或尽可能多的可用空间。我们在 SkiaSharp 绘制的地图上做到了这一点。地图被绘制得尽可能大，而不会扭曲。它被放置在可用空间的中心，无论窗口是纵向还是横向纵横比。

现在所有页面都已调整到可用空间，我们的应用程序和本章已经完成。

# 总结

在这一章中，我们构建了一个可以在 UWP 和 Web 浏览器上运行的应用程序。该应用程序使用了 SyncFusion 和 Infragistics 的图形控件。我们还使用 SkiaSharp 创建了一个自定义地图。最后，我们看了如何根据不同和变化的屏幕尺寸调整 UI 布局。

这一章是本书的这一部分的最后一章。在接下来的部分中，我们将从构建应用程序转向如何测试和部署它们。在下一章中，我们将看看如何在更广泛的测试策略中使用`Uno.UITest`库。在构建可以在多个平台上运行的应用程序时，自动化跨平台的测试可以节省大量时间并提高生产率。
