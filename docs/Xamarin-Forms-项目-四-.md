# Xamarin.Forms 项目（四）

> 原文：[`zh.annas-archive.org/md5/BCF2270FBE70F13E76739867E1CF82CA`](https://zh.annas-archive.org/md5/BCF2270FBE70F13E76739867E1CF82CA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：构建实时聊天应用程序

在本章中，我们将构建一个具有实时通信的聊天应用程序。在该应用程序中，您将能够向其他用户发送和接收消息和照片，而无需刷新页面即可看到消息。我们将看看如何使用 SignalR 实现与服务器的实时连接。

本章将涵盖以下主题：

+   如何在 Xamarin.Forms 应用程序中使用 SignalR

+   如何为 ListView 使用模板选择器

+   如何在 Xamarin.Forms 应用程序中使用 CSS 样式

# 技术要求

在构建此项目的应用程序之前，您需要构建我们在第六章*，使用 Azure 服务为聊天应用程序设置后端*中详细说明的后端。您还需要安装 Visual Studio for Mac 或 PC，以及 Xamarin 组件。有关如何设置环境的更多详细信息，请参阅第一章，*Xamarin 简介*。本章的源代码可在 GitHub 存储库中找到，网址为[`github.com/PacktPublishing/Xamarin.Forms-Projects/tree/master/Chapter-6-and-7`](https://github.com/PacktPublishing/Xamarin.Forms-Projects/tree/master/Chapter-6-and-7)。

# 项目概述

在构建聊天应用程序时，实时通信非常重要，因为用户期望消息能够几乎立即到达。为了实现这一点，我们将使用 SignalR，这是一个用于实时通信的库。SignalR 将使用 WebSockets（如果可用），如果不可用，它将有几种备用选项可以使用。在该应用程序中，用户将能够从设备的照片库发送文本和照片。

该项目的构建时间约为 180 分钟。

# 入门

我们可以使用 PC 上的 Visual Studio 2017 或 Mac 上的 Visual Studio 来完成此项目。要使用 Visual Studio 在 PC 上构建 iOS 应用程序，您必须连接 Mac。如果根本没有 Mac，您可以选择仅构建应用程序的 Android 部分。

# 构建聊天应用程序

现在是时候开始构建应用程序了。我们建议您使用与第六章相同的方法，*使用 Azure 服务为聊天应用程序设置后端*，因为这将使代码共享更容易。在该解决方案中，创建一个名为`Chat`的移动应用程序（Xamarin.Forms）：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/36568c5f-b137-44c0-bc52-0e4248b43864.png)

选择空白模板，并将.NET Standard 作为代码共享策略。选择 iOS 和 Android 作为平台。创建项目后，我们将更新所有 NuGet 包到最新版本，因为项目模板的更新频率不如模板内部使用的包频繁：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/0e6b50ff-8208-4344-b14e-bd0666082aca.png)

# 创建聊天服务

我们将首先创建一个聊天服务，该服务将被 iOS 和 Android 应用程序共同使用。为了使代码更易于测试，并且在将来想要使用其他提供程序替换聊天服务更容易，我们将按照以下步骤进行：

1.  在`Chat`项目中，添加对`Chat.Messages`项目的引用。

1.  在`Chat`项目中创建一个名为`Services`的新文件夹。

1.  在`Services`文件夹中创建一个名为`IChatService`的新接口。

1.  创建一个名为`IsConnected`的`bool`属性。

1.  创建一个名为`SendMessage`的方法，该方法以`Message`作为参数并返回`Task`。

1.  创建一个名为`CreateConnection`的方法，返回`Task`。该方法将创建并启动与 SignalR 服务的连接。

1.  创建一个名为`Dispose`的方法，返回`Task`。当应用程序进入休眠状态时，将使用该方法来确保与 SignalR 服务的连接被正确关闭：

```cs
using Chat.Events;
using Chat.Messages;
using System;
using System.Threading.Tasks;

namespace Chat.Services
{
    public interface IChatService
    {        
        bool IsConnected { get; }

        Task CreateConnection();
        Task SendMessage(Message message);
        Task Dispose();
    }     
}
```

该接口还将包含一个事件，但在将事件添加到接口之前，我们将创建一个`EventArgs`类，该事件将使用。我们将按照以下步骤进行：

1.  在`Chat`项目中，创建一个名为`Events`的新文件夹。

1.  在`Events`文件夹中创建一个名为`NewMessageEventArgs`的新类。

1.  将`EventArgs`添加为基类。

1.  创建一个名为`Message`的`Message`类型的属性，具有公共 getter 和私有 setter。

1.  创建一个空的构造函数。

1.  创建一个带有`Message`参数的构造函数。

1.  将构造函数的参数设置为`Message`属性。

以下代码是这些步骤的结果：

```cs
using Chat.Messages;
using System;
namespace Chat.Events
{
    public class NewMessageEventArgs : EventArgs
    {
        public Message Message { get; private set; }

        public NewMessageEventArgs(Message message)
        {
            Message = message;
        }
    } 
}
```

现在我们已经创建了一个新的`EventArgs`类，我们可以使用它并在接口中添加一个事件。我们将事件命名为`NewMessage`：

```cs
public interface IChatService
{
 event EventHandler<NewMessageEventArgs> NewMessage;

    bool IsConnected { get; }

    Task CreateConnection();
    Task SendMessage(Message message);
    Task Dispose();
} 
```

在服务中，我们将首先调用`GetSignalRInfo`服务，该服务是我们在第六章中创建的，*使用 Azure 服务为聊天应用程序设置后端*，以获取有关如何连接到 SignalR 服务的信息。为了序列化该信息，我们将创建一个新类：

1.  在`Chat`项目中，创建一个名为`Models`的新文件夹。

1.  创建一个名为`ConnectionInfo`的新类。

1.  为`string`添加一个名为`Url`的字符串属性。

1.  为`string`添加一个名为`AccessToken`的字符串属性：

```cs
public class ConnectionInfo
{
   public string Url { get; set; }
   public string AccessToken { get; set; }
} 
```

现在我们有了接口和一个用于获取连接信息的模型，是时候创建`IChatService`接口的实现了。要使用 SignalR，我们需要添加一个 NuGet 包，它将为我们提供必要的类。请按照以下步骤操作：

1.  在`Chat`项目中，安装 NuGet 包`Microsoft.AspNetCore.SignalR.Client`。

1.  在`Services`文件夹中，创建一个名为`ChatService`的新类。

1.  将`IChatService`接口添加并实现到`ChatService`中。

1.  为`HttpClient`添加一个名为`httpClient`的私有字段。

1.  为`HubConnection`添加一个名为`hub`的私有字段。

1.  为`SemaphoreSlim`添加一个名为`semaphoreSlim`的私有字段，并在构造函数中使用初始计数和最大计数为 1 创建一个新实例：

```cs
using Chat.Events;
using Chat.Messages;
using Microsoft.AspNetCore.SignalR.Client;
using Newtonsoft.Json;
using System;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public class ChatService : IChatService
{
    private HttpClient httpClient;
    private HubConnection hub;
    private SemaphoreSlim semaphoreSlim = new SemaphoreSlim(1, 1);     

    public event EventHandler<NewMessageEventArgs> NewMessage;
    public bool IsConnected { get; set; }

    public async Task CreateConnection() 
    {
    }

    public async Task SendMessage(Message message) 
    {
    }

    public async Task Dispose()
    {
    } 
}
```

我们将从`CreateConnection`开始，它将调用`GetSignalRInfo`函数。然后我们将使用这些信息连接到 SignalR 服务并开始监听消息。为此，请执行以下步骤：

1.  调用`SemaphoreSlim`的`WaitAsync`方法，以确保一次只有一个线程可以使用该方法。

1.  检查`httpClient`是否为`null`。如果是，创建一个新实例。我们将重用`httpClient`的实例，因为从性能的角度来看这样做更好。

1.  调用`GetSignalRInfo`并将结果序列化为`ConnectionInfo`对象：

```cs
public async Task CreateConnection()
{
    await semaphoreSlim.WaitAsync();

 if(httpClient == null)
 { 
 httpClient = new HttpClient();
 }

 var result = await     httpClient.GetStringAsync("https://{theNameOfTheFunctionApp}.azurewebsites.net/api/GetSignalRInfo");

 var info = JsonConvert.DeserializeObject<Models.ConnectionInfo>
    (result); 
}
```

当我们有关于如何连接到 SignalR 服务的信息时，我们可以使用`HubConnectionBuilder`来创建一个连接。然后我们可以开始监听消息：

1.  创建一个新的`HubConnectionBuilder`。

1.  使用`WithUrl`方法指定 SignalR 服务的 URL 作为第一个参数。第二个参数是`HttpConnectionObject`类型的`Action`。这意味着您将获得一个`HttpConnectionObject`类型的对象作为参数。

1.  在操作中，将`AccessTokenProvider`设置为一个返回`ConnectionInfo`对象上`AccessToken`属性值的`Func`。

1.  使用`HubConnectionBuilder`的`Build`方法创建一个连接对象。

1.  使用`HubConnection`对象上的`On<object>`方法添加一个在新消息到达时运行的`Action`。将该操作指定为第二个参数。对于第一个参数，我们将指定目标的名称（在第六章中指定了目标，*使用 Azure 服务为聊天应用程序设置后端*，当我们发送消息时），即`newMessage`。

1.  在`Action`中，使用`ToString`方法将传入的消息转换为字符串，并将其反序列化为`Message`对象，以便读取其`TypeInfo`属性。为此，使用`JsonConvert`类和`DeserializeObject<Message>`方法。

我们必须两次反序列化对象的原因是，第一次我们只能得到`Message`类中属性的值。当我们知道我们收到的`Message`的哪个子类时，我们可以使用这个来为该类反序列化信息。我们将其转换为`Message`，以便将其传递给`NewMessageEventArgs`对象。在这种情况下，我们不会丢失子类的属性。要访问属性，我们只需将类转换回子类。

1.  当我们知道消息的类型时，我们可以使用这个来将对象反序列化为实际类型。使用`JsonConvert`的`DeserializeObject`方法，并将 JSON 字符串和`TypeInfo`传递给它，然后将其转换为`Message`。

1.  调用`NewMessage`事件，并将`ChatService`的当前实例和一个新的`NewMessageEventArgs`对象传递给它。将`Message`对象传递给`NewMessageEventArgs`的构造函数。

1.  一旦我们有了连接对象，并且配置了消息到达时会发生什么，我们将开始使用`HubConnection`的`StartAsync`方法来监听消息。

1.  将`IsConnected`属性设置为`true`。

1.  使用`SemaphoreSlim`的`Release`方法让其他线程进入`CreateConnection`方法：

```cs
var connectionBuilder = new HubConnectionBuilder();
connectionBuilder.WithUrl(info.Url, (Microsoft.AspNetCore.Http.Connections.Client.HttpConnectionOptions obj) =>
    {
        obj.AccessTokenProvider = () => Task.Run(() => 
        info.AccessToken);
    });

hub = connectionBuilder.Build();
hub.On<object>("newMessage", (message) =>
{
     var json = message.ToString();
     var obj = JsonConvert.DeserializeObject<Message>(json);
     var msg = (Message)JsonConvert.DeserializeObject(json, 
     obj.TypeInfo);
     NewMessage?.Invoke(this, new NewMessageEventArgs(msg));
});

await hub.StartAsync();

IsConnected = true;
semaphoreSlim.Release();
```

实现的下一个方法是`SendMessage`方法。这将向 Azure 函数发送消息，该函数将将消息添加到 SignalR 服务：

1.  使用`JsonConvert`类的`Serialize`方法将`Message`对象序列化为 JSON。

1.  创建一个`StringContent`对象，并将 JSON 字符串作为第一个参数，`Encoding.UTF8`作为第二个参数，内容类型`application/json`作为最后一个参数传递给构造函数。

1.  使用`HttpClient`对象的`PostAsync`方法，将 URL 作为第一个参数，`StringContent`对象作为第二个参数，将消息发布到函数：

```cs
public async Task SendMessage(Message message)
{
    var json = JsonConvert.SerializeObject(message);

    var content = new StringContent(json, Encoding.UTF8, 
    "application/json");

    await 
    httpClient.PostAsync
("https://{TheNameOfTheFunctionApp}.azurewebsites.net/api/messages"
content);
} 
```

实现的最后一个方法是`Dispose`方法。这将在应用程序进入后台状态时关闭连接，例如当用户按下主页按钮或切换应用程序时：

1.  使用`WaitAsync`方法确保在运行该方法时没有线程尝试创建连接或释放连接。

1.  添加一个`if`语句，以确保`hub`字段不为`null`。

1.  如果不为空，调用`HubConnection`的`StopAsync`方法和`DisposeAsync`方法。

1.  将`httpClient`字段设置为`null`。

1.  将`IsConnected`设置为`false`。

1.  使用`Release`方法释放`SemaphoreSlim`：

```cs
public async Task Dispose()
{
    await semaphoreSlim.WaitAsync();

    if(hub != null)
    {
        await hub.StopAsync();
        await hub.DisposeAsync();
    }

    httpClient = null;

    IsConnected = false;

    semaphoreSlim.Release();
} 
```

# 初始化应用程序

现在我们准备为应用程序编写初始化代码。我们将设置**控制反转**（**IoC**）并进行必要的配置。

# 创建一个解析器

我们将创建一个辅助类，以便通过 Autofac 轻松解析对象图的过程。这将帮助我们基于配置的 IoC 容器创建类型。在这个项目中，我们将使用`Autofac`作为 IoC 库：

1.  在`Chat`项目中安装`NuGet`包`Autofac`。

1.  在`Chat`项目中创建一个名为`Resolver`的新类。

1.  添加一个名为`container`的`IContainer`类型（来自`Autofac`）的`private static`字段。

1.  添加一个名为`Initialize`的公共静态方法，带有`IContainer`作为参数。将参数的值设置为容器字段。

1.  添加一个名为`Resolve`的通用静态公共方法，它将返回一个基于参数类型的实例，使用`IContainer`的`Resolve`方法：

```cs
using Autofac;

public class Resolver
{
     private static IContainer container;

     public static void Initialize(IContainer container)
{
          Resolver.container = container;
     }

     public static T Resolve<T>()
     {
          return container.Resolve<T>();
     }
} 
```

# 创建一个 Bootstrapper

在这里，我们将创建一个`Bootstrapper`类，用于在应用程序启动阶段设置我们需要的常见配置。通常，Bootstrapper 的每个目标平台都有一个部分，所有平台都有一个共享部分。在这个项目中，我们只需要共享部分：

1.  在`Chat`项目中创建一个名为`Bootstrapper`的新类。

1.  添加一个名为`Init`的新的公共静态方法。

1.  创建一个新的`ContainerBuilder`并将类型注册到`container`。

1.  使用`ContainerBuilder`的`Build`方法创建一个`Container`。创建一个名为`container`的变量，它应该包含`Container`的实例。

1.  在`Resolver`上使用`Initialize`方法，并将`container`变量作为参数传递，如下所示：

```cs
using Autofac;
using Chat.Chat;
using System;
using System.Reflection;

public class Bootstrapper
{
     public static void Init()
     {
            var builder = new ContainerBuilder();

             builder.RegisterType<ChatService>().As<IChatService>
             ().SingleInstance();

             var currentAssembly = Assembly.GetExecutingAssembly();

             builder.RegisterAssemblyTypes(currentAssembly)
                      .Where(x => x.Name.EndsWith("View", 
                      StringComparison.Ordinal));

             builder.RegisterAssemblyTypes(currentAssembly)
                     .Where(x => x.Name.EndsWith("ViewModel", 
                     StringComparison.Ordinal));

             var container = builder.Build();

             Resolver.Initialize(container); 
     }
} 
```

在`App.xaml.cs`文件中，在调用`InitializeComponents`之后，在构造函数中调用`Bootstrapper`的`Init`方法：

```cs
public App()
{
    InitializeComponent();
    Bootstrapper.Init();
    MainPage = new MainPage();
} 
```

# 创建基本 ViewModel

我们现在有一个负责处理与后端通信的服务。是时候创建一个视图模型了。但首先，我们将创建一个基本视图模型，其中可以放置在应用程序的所有视图模型之间共享的代码：

1.  创建一个名为`ViewModels`的新文件夹。

1.  创建一个名为`ViewModel`的新类。

1.  将新类设置为 public 和 abstract。

1.  添加一个名为`Navigation`的`INavigation`类型的静态字段。这将用于存储 Xamarin.Forms 提供的导航服务的引用。

1.  添加一个名为`User`的`string`类型的静态字段。该字段将在连接到聊天服务时使用，以便您发送的消息将显示您的名称。

1.  添加并实现`INotifiedPropertyChanged`接口。这是必要的，因为我们想要使用数据绑定。

1.  添加一个`Set`方法，这样我们就可以更容易地从`INotifiedPropertyChanged`接口中触发`PropertyChanged`事件。该方法将检查值是否已更改。如果已更改，它将触发事件：

```cs
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using Xamarin.Forms;

public abstract class ViewModel : INotifyPropertyChanged
{
     public static INavigation Navigation { get; set; }
     public static string User { get; set; } 

     public event PropertyChangedEventHandler PropertyChanged; 
     protected void Set<T>(ref T field, T newValue, 
                           [CallerMemberName] string propertyName = 
                           null)
     {
          if (!EqualityComparer<T>.Default.Equals(field, newValue))
          {
               field = newValue;
               PropertyChanged?.Invoke(this, new 
               PropertyChangedEventArgs(propertyName));
          }
     }
} 
```

# 创建 MainView

现在我们已经设置好了`ViewModel`基类，并且已经编写了接收和发送消息的所有代码，是时候创建两个视图了。这些将充当应用程序的用户界面。

我们将从创建主视图开始。这是用户启动应用程序时将显示的视图。我们将添加一个输入控件（输入文本框），以便用户可以输入用户名，并添加一个命令以导航到聊天视图。

主视图将由以下内容组成：

+   一个名为`MainViewModel.cs`的 ViewModel 文件

+   一个名为`MainView.xaml`的 XAML 文件，其中包含布局

+   一个名为`MainView.xaml.cs`的代码后台文件，将执行数据绑定

让我们从为`MainView`创建`ViewModel`开始。

# 创建 MainViewModel

我们即将创建的`MainViewModel`将保存用户将在 UI 中输入的用户名。它还将包含一个名为`Start`的`Command`属性，该属性将绑定到用户在输入用户名后单击的`Button`：

1.  在`ViewModel`文件夹中，创建一个名为`MainViewModel.cs`的类。

1.  从`ViewModel`继承该类。

1.  将类设置为`public`。

1.  添加一个名为`Username`的`string`类型的属性。

1.  添加一个名为`Start`的`ICommand`类型的属性，并按照以下方式实现它。`Start`命令将从`Username`属性中分配`Username`并将其分配给基本`ViewModel`中的静态`User`属性。然后，它使用`Resolver`创建`ChatView`的新实例，并将其推送到导航堆栈上。

`MainViewModel`现在应该如下所示：

```cs
 using System.Windows.Input;
 using Chat.Views;
 using Xamarin.Forms;

 namespace Chat.ViewModels
 {
     public class MainViewModel : ViewModel
     {
         public string Username { get; set; }

         public ICommand Start => new Command(() =>
         {
             User = Username;

             var chatView = Resolver.Resolve<ChatView>();
             Navigation.PushAsync(chatView);
         });
     }
 }

```

现在我们有了`MainViewModel`，我们需要一个与之配套的视图。是时候创建`MainView`了。

# 创建 MainView

`MainView`将显示一个用户界面，允许用户在开始聊天之前输入名称。本节将介绍创建`MainView`的 XAML 文件和该视图的代码。

我们将首先删除模板生成的`MainPage`，并将其替换为 MVVM 友好的`MainView`。

# 替换 MainPage

当我们创建应用程序时，模板生成了一个名为`MainPage`的页面。由于我们使用 MVVM 作为模式，我们需要删除此页面，并将其替换为一个名为`MainView`的视图：

1.  在`Chat`项目的根目录中，删除名为`MainPage`的页面。

1.  创建一个名为`Views`的新文件夹。

1.  在 Views 文件夹中添加一个名为`MainView`的新 XAML 页面。

# 编辑 XAML

现在是时候向新创建的 `MainView.xaml` 文件添加一些内容了。下面提到的图标可以在与其应该添加到的同一文件夹中找到，如果你去 GitHub 上的项目，就可以找到。GitHub 的 URL 可以在本章的开头找到。这里有很多内容，所以确保检查你写的代码：

1.  将 `chat.png` 图标添加到 Android 项目中 `Resources` 文件夹内的 `Drawable` 文件夹中。

1.  将 `chat@2x.png` 图标添加到 iOS 项目中的 `Resources` 文件夹中。

1.  打开 `MainView.xaml` 文件。

1.  在 `ContentPage` 节点中添加一个 `Title` 属性。这将是应用程序导航栏中显示的标题。

1.  添加一个 `Grid`，并在其中定义两行。第一行的高度应为 `"*"`，第二行的高度应为 `"2*"`。这将把空间分成两行，第一行将占据空间的 `1/3`，第二行将占据空间的 `2/3`。

1.  添加一个 `Image`，将 `Source` 设置为 `"chat.png"`，并将其 `VerticalOptions` 和 `HorizontalOptions` 设置为 `"Center"`。

1.  添加一个 `StackLayout`，将 `Grid.Row` 设置为 `"1"`，将 `Padding` 设置为 `"10"`，将 `Spacing` 设置为 `"20"`。`Grid.Row` 属性将 `StackLayout` 定位在第二行。`Padding` 在 `StackLayout` 周围添加了 10 个单位的空间，`Spacing` 定义了在 `StackLayout` 中添加的每个元素之间的空间量。

1.  在 `StackLayout` 中，添加一个 `Entry` 节点，将其 `Text` 属性设置为 `"{Binding UserName}"`，并将 `Placeholder` 属性设置为 `"输入用户名"`。文本节点的绑定将确保当用户在 `Entry` 控件中输入值时，它会在 `ViewModel` 中更新。

1.  在 `StackLayout` 中，添加一个 `Button` 控件，将其 `Text` 属性设置为 `"Start"`，并将其 `Command` 属性设置为 `"{Binding Start}"`。当用户点击按钮时，`Command` 属性绑定将被执行。它将运行我们在 `MainViewModel` 类中定义的代码。

完成后，代码应如下所示：

```cs
 <?xml version="1.0" encoding="UTF-8"?>
 <ContentPage  

              x:Class="Chat.Views.MainView" Title="Welcome">
     <Grid>
 <Grid.RowDefinitions>
 <RowDefinition Height="*" />
 <RowDefinition Height="2*" />
 </Grid.RowDefinitions>
 <Image Source="chat.png" VerticalOptions="Center" 
                                  HorizontalOptions="Center" />
 <StackLayout Grid.Row="1" Padding="10" Spacing="20">
 <Entry Text="{Binding Username}" 
             Placeholder="Enter a username" />
 <Button Text="Start" Command="{Binding Start}" />
 </StackLayout>
 </Grid>
 </ContentPage> 
```

布局已完成，现在我们需要将焦点转向这个视图的代码，以解决一些问题。

# 修复视图的代码

与所有视图一样，在使用 MVVM 时，我们需要向视图传递一个 `ViewModel`。由于在这个项目中使用了依赖注入，我们将通过构造函数传递它，然后将其分配给视图本身的 `BindingContext`。我们还将确保启用安全区域，以避免控件部分隐藏在 iPhone X 顶部的刘海区域后面：

1.  打开 `MainView.xaml.cs` 文件。

1.  在 `MainView` 类的构造函数中添加一个名为 `viewModel` 的 `MainViewModel` 类型的参数。这个参数的参数将在运行时由 `Autofac` 注入。

1.  添加一个指令，指示应用程序在 iOS 上使用安全区域。安全区域确保应用程序不会使用屏幕顶部 iPhone X 的刘海区域旁边的空间。

1.  将 `viewModel` 参数分配给视图的 `BindingContext` 属性。

所做的更改在代码中用粗体标记如下：

```cs
using Chat.ViewModels;
using Xamarin.Forms;
using Xamarin.Forms.PlatformConfiguration.iOSSpecific;
using Xamarin.Forms.Xaml;

public partial class MainView : ContentPage
{
         public MainView(MainViewModel viewModel)
         {
             InitializeComponent();

             On<Xamarin.Forms.PlatformConfiguration.iOS>
             ().SetUseSafeArea(true);

             BindingContext = viewModel;
         }
     } 
```

我们的 `MainView` 完成了，但我们仍然需要告诉应用程序使用它作为入口视图。

# 设置主视图

入口视图，也称为应用程序的 `MainPage`，在初始化 Xamarin.Forms 应用程序时设置。通常，在 App 类的构造函数中设置。我们将通过之前创建的解析器创建 `MainView`，并将其包装在 `NavigationPage` 中，以在应用程序运行的设备上启用特定于平台的导航：

1.  打开 `App.xaml.cs` 文件。

1.  通过使用解析器将一个 `MainView` 类的实例解析为一个名为 `mainView` 的变量。

1.  通过将 `mainView` 变量作为构造函数参数传递并将其赋值给一个名为 `navigationPage` 的变量，创建一个新的 `NavigationPage` 实例。

1.  将`navigationPage.Navigation`属性分配给`ViewModel`类型上的静态`Navigation`属性。稍后在页面之间导航时将使用此属性。

1.  将`navigationPage`变量分配给`App`类的`MainPage`属性。这将设置我们应用程序的起始视图：

```cs
public App()
{
    InitializeComponent();
    Boostrapper.Init();

 var mainView = Resolver.Resolve<MainView>();
 var navigationPage = new NavigationPage(mainView);
 ViewModel.Navigation = navigationPage.Navigation;
 MainPage = navigationPage;
} 
```

这就是`MainView`；简单而容易。现在让我们转向更有趣的东西：`ChatView`，它将用于发送和接收消息。

# 创建 ChatView

`ChatView`是一个标准的聊天客户端。它将有一个用于显示传入和传出消息的区域，底部有一个文本字段，用户可以在其中输入消息。它还将有一个用于拍照的按钮和一个用于发送消息的按钮，如果用户没有在屏幕键盘上按回车键。

我们将首先创建`ChatViewModel`，它包含所有逻辑，充当视图和模型之间的粘合剂。在这种情况下，我们的模型由`ChatService`表示。

之后，我们将创建`ChatView`，它处理**图形用户界面**（**GUI**）的渲染。

# 创建 ChatViewModel

如前所述，`ChatViewModel`是视觉表示（`View`）和模型（基本上是我们的`ChatService`）之间的粘合剂。`ChatViewModel`将处理消息的存储和与`ChatService`的通信，通过将发送和接收消息的功能连接起来。

# 创建类

`ChatViewModel`是一个简单的类，它继承自我们之前创建的`ViewModel`基类。在第一个代码练习中，我们将创建这个类，添加相关的`using`语句，并添加一个名为 Messages 的属性，用于存储我们收到的消息。视图将使用消息集合来在`ListView`中显示消息。

由于这是一个大块的代码，我们建议您先编写它，然后按照编号列表来了解已添加到类中的内容：

1.  在`Chat`项目的`ViewModels`文件夹中创建一个名为`ChatViewModel`的新类。

1.  将类设置为`public`，并从`ViewModel`基类继承，以从基类获得共同的基本功能。

1.  添加一个名为`chatService`的`readonly`属性，类型为`IChatService`。这将存储一个实现`IChatService`的对象的引用，并使`ChatService`的具体实现可替换。将任何服务公开为接口是一个良好的实践。

1.  添加一个名为`Messages`的公共属性，类型为`public ObservableCollection<Message>`，带有私有的 setter。这个集合将保存所有消息。私有的 setter 使得该属性无法从类外部访问。这通过确保消息只能在类内部插入来维护集合的完整性。

1.  添加一个名为`chatService`的构造函数参数，类型为`IChatService`。当我们使用依赖注入时，这是`Autofac`将注入实现`IChatService`的对象的地方。

1.  在构造函数中，将`chatService`参数分配给`chatService`属性。这将存储对`ChatService`的引用，以便我们在`ChatViewModel`的生命周期内使用它。

1.  在构造函数中，将`Messages`属性实例化为一个新的`ObservableCollection<Message>`。

1.  在构造函数中，创建一个`Task.Run`语句，如果`chatService.IsConnected`属性为`false`，则调用`chatService.CreateConnection()`方法。通过发送一个新的`UserConnected`消息来结束`Task.Run`语句：

```cs
 using System;
 using System.Collections.ObjectModel;
 using System.IO;
 using System.Linq;
 using System.Threading.Tasks;
 using System.Windows.Input;
 using Acr.UserDialogs;
 using Chat.Messages;
 using Chat.Services;
 using Plugin.Media;
 using Plugin.Media.Abstractions;
 using Xamarin.Forms;

 namespace Chat.ViewModels
 {
     public class ChatViewModel : ViewModel
     {
         private readonly IChatService chatService;
         public ObservableCollection<Message> Messages { get; 
         private set; }

         public ChatViewModel(IChatService chatService)
         {
             this.chatService = chatService;

             Messages = new ObservableCollection<Message>();

             Task.Run(async() =>
             {
                 if(!chatService.IsConnected)
                 {
                     await chatService.CreateConnection();
                 }

                 await chatService.SendMessage(new 
                 UserConnectedMessage(User));
             });
         }
    }
}
```

现在我们已经实例化了`ChatViewModel`，是时候添加一个属性，用于保存用户当前输入的内容。

# 添加文本属性

在 GUI 的底部，将有一个文本字段（输入控件），允许用户输入消息。这个输入将与`ChatViewModel`中的一个我们称为`Text`的属性进行数据绑定。每当用户更改文本时，将设置此属性。这是经典的数据绑定：

1.  添加一个名为`text`的新私有字段，类型为`string`。

1.  添加一个名为`Text`的公共属性，在 getter 中返回私有文本字段，并在 setter 中调用基类的`Set()`方法。`Set`方法在`ViewModel`基类中定义，并且如果`ChatViewModel`中的属性发生变化，它将向视图引发事件，有效地保持它们的同步：

```cs
private string text;
public string Text
{
    get => text;
    set => Set(ref text, value);
} 
```

现在我们已经准备好进行数据绑定。让我们看一些从`ChatService`接收消息的代码。

# 接收消息

当从服务器通过 SignalR 发送消息时，`ChatService`将解析此消息并将其转换为一个 Message 对象。然后它将引发一个名为`NewMessage`的事件，该事件在 ChatService 中定义。

在本节中，我们将实现一个事件处理程序来处理这些事件，并将它们添加到 Messages 集合中，除非集合中已经存在具有相同 ID 的消息。

同样，按照以下步骤并查看代码：

1.  在`ChatViewModel`中，创建一个名为`ChatService_NewMessage`的方法，它将是一个标准的事件处理程序。它有两个参数：`sender`，类型为`object`，和`e`，类型为`Events.NewMessageEventArgs`。

1.  在这个方法中加入`Device.BeginInvokeOnMainThread()`，因为我们将要向消息集合中添加消息。添加到此集合的项目将修改视图，任何修改视图的代码都必须在 UI 线程上运行。

1.  在`Device.BeginInvokeOnMainThread`中，如果集合中不存在具有特定`Message.Id`的消息，则将来自`e.Message`的传入消息添加到`Messages`集合中。这是为了避免消息重复。

该方法应如下所示：

```cs
private void ChatService_NewMessage(object sender, Events.NewMessageEventArgs e)
{
    Device.BeginInvokeOnMainThread(() =>
    {
        if (!Messages.Any(x => x.Id == e.Message.Id))
        {
            Messages.Add(e.Message);
        }
    });
} 
```

当定义事件处理程序时，我们需要在构造函数中将其挂钩：

1.  找到`ChatViewModel`类的构造函数。

1.  将`chatService.NewMessage`事件与我们刚刚创建的`ChatService_NewMessage`处理程序连接起来。这样做的一个好地方是在实例化`Messages`集合下面。

加粗标记的代码是我们应该添加到`ChatViewModel`类中的：

```cs
public ChatViewModel(IChatService chatService)
{
    this.chatService = chatService;

    Messages = new ObservableCollection<Message>();

    chatService.NewMessage += ChatService_NewMessage;

    Task.Run(async() =>
    {
        if(!chatService.IsConnected)
        {
            await chatService.CreateConnection();
        }

        await chatService.SendMessage(new UserConnectedMessage(User));
    });
} 
```

应用现在将能够接收消息。那么如何发送消息呢？敬请关注！

# 创建 LocalSimpleTextMessage 类

为了更容易识别消息是来自服务器还是由执行代码的设备上的用户发送的，我们将创建一个`LocalSimpleTextMessage`：

1.  在`Chat.Messages`项目中创建一个名为`LocalSimpleTextMessage`的新类。

1.  将`SimpleTextMessage`添加为基类。

1.  创建一个以`SimpleTextMessage`为参数的构造函数。

1.  将值设置为参数中的所有基本属性的值，如下面的代码所示：

```cs
public class LocalSimpleTextMessage : SimpleTextMessage
{
    public LocalSimpleTextMessage(SimpleTextMessage message)
    {
        Id = message.Id;
        Text = message.Text;
        Timestamp = message.Timestamp;
        Username = message.Username;
        TypeInfo = message.TypeInfo;
    }
}
```

# 发送文本消息

发送文本消息也非常简单。我们需要创建一个可以为 GUI 进行数据绑定的命令。当用户按下回车键或点击发送按钮时，命令将被执行。当用户执行这两个操作之一时，命令将创建一个新的`SimpleTextMessage`并传入当前用户以标识消息给其他用户。我们将从`ChatViewModel`的`text`属性中复制文本，而这个属性又与`Entry`控件同步。

然后，我们将把消息添加到消息集合中，触发将处理消息的`ListView`更新的操作。之后，我们将把消息传递给`ChatService`并清除`ChatViewModel`的文本属性。通过这样做，我们通知 GUI 它已经改变，并让数据绑定魔法清除字段。

参考以下步骤并查看代码：

1.  创建一个名为`Send`的`ICommand`类型的新属性。

1.  分配一个新的`Command`实例，并按照以下步骤实现它。

1.  通过将基类的 User 属性作为参数传递来创建`SimpleTextMessage`类的新实例。将该实例分配给名为`message`的变量。

1.  将消息变量的`Text`属性设置为`ChatViewModel`类的`Text`属性。这将复制稍后由 GUI 定义的聊天输入中的当前文本。

1.  创建一个`LocalSimpleTextMessage`对象，并将消息变量作为构造函数参数传入。`LocalSimpleTextMessage`是`SimpleTextMessage`，使视图能够识别它作为应用用户发送的消息，并在聊天区域的右侧有效地呈现它。将`LocalSimpleTextMessage`实例添加到 Messages 集合中。这将在视图中显示消息。

1.  调用`chatService.SendMessage()`方法并将消息变量作为参数传递。

1.  清空`ChatViewModel`的`Text`属性以清除 GUI 中的输入控件：

```cs
public ICommand Send => new Command(async()=> 
{
    var message = new SimpleTextMessage(User)
    {
        Text = this.Text
    };

    Messages.Add(new LocalSimpleTextMessage(message));

    await chatService.SendMessage(message);

    Text = string.Empty;
}); 
```

如果不能发送照片，聊天应用有何用？让我们在下一节中实现这一点。

# 安装 Acr.UserDialogs 插件

`Acr.UserDialogs`是一个插件，可以在代码中使用几个标准用户对话框，这些对话框在各个平台之间共享。要安装和配置它，我们需要遵循一些步骤：

1.  将`Acr.UserDialogs` NuGet 包安装到`Chat-`，`Chat.iOS`和`Chat.Android`项目中。

1.  在`MainActivity.cs`文件中，在`OnCreate`方法中添加`UserDialogs.Init(this)`：

```cs
protected override void OnCreate(Bundle savedInstanceState)
{
    TabLayoutResource = Resource.Layout.Tabbar;
    ToolbarResource = Resource.Layout.Toolbar;

    base.OnCreate(savedInstanceState);

    UserDialogs.Init(this);

    global::Xamarin.Forms.Forms.Init(this, savedInstanceState);
    LoadApplication(new App());
}
```

# 安装媒体插件

我们将使用`Xam.Plugin.Media` NuGet 包来访问设备的照片库。我们需要在解决方案的`Chat-`，`Chat.iOS`和`Chat.Android`项目中安装该包。但是，在使用该包之前，我们需要为每个平台进行一些配置。我们将从 Android 开始：

1.  该插件需要`WRITE_EXTERNAL_STORAGE`和`READ_EXTERNAL_STORAGE`权限。插件将为我们添加这些权限，但我们需要在`MainActivity.cs`中覆盖`OnRequestPermissionResult`。

1.  调用`OnRequestPermissionsResult`方法。

1.  在`MainActivity.cs`文件的`OnCreate`方法中，在 Xamarin.Forms 初始化后添加`CrossCurrentActivity.Current.Init(this, savedInstanceState)`，如下面的代码所示：

```cs
public override void OnRequestPermissionsResult(int requestCode, string[] permissions, Android.Content.PM.Permission[] grantResults)
{
   Plugin.Permissions.PermissionsImplementation.Current.OnRequestPermissionsResult(requestCode, permissions, grantResults);
} 
```

我们还需要为用户可以选择照片的文件路径添加一些配置：

1.  在 Android 项目的`Resources`文件夹中添加一个名为`xml`的文件夹。

1.  在新文件夹中创建一个名为`file_paths.xml`的新 XML 文件。

1.  将以下代码添加到`file_paths.xml`：

```cs
<?xml version="1.0" encoding="utf-8"?>
<paths xmlns:android="http://schemas.android.com/apk/res/android">
    <external-files-path name="my_images" path="Pictures" />
    <external-files-path name="my_movies" path="Movies" />
</paths>
```

设置插件的最后一件事是在 Android 项目的`AndroidManifest.xml`字段中的应用程序元素中添加以下代码：

```cs
<manifest  android:versionCode="1" android:versionName="1.0" package="xfb.Chat">
<uses-sdk android:minSdkVersion="21" android:targetSdkVersion="27" />
     <application android:label="Chat.Android">
      <provider 
      android:name="android.support.v4.content.FileProvider"   
      android:authorities="${applicationId}.fileprovider" 
      android:exported="false" android:grantUriPermissions="true">
 <meta-data android:name="android.support.FILE_PROVIDER_PATHS" 
      android:resource="@xml/file_paths"></meta-data>
 </provider>
     </application>
 </manifest> 
```

对于 iOS 项目，我们唯一需要做的就是在`info.plist`中添加以下四个用途描述：

```cs
<key>NSPhotoLibraryUsageDescription</key>
<string>This app needs access to photos.</string>
<key>NSPhotoLibraryAddUsageDescription</key>
<string>This app needs access to the photo gallery.</string>
```

# 发送照片

为了能够发送照片，我们将不得不使用照片的来源。在我们的情况下，我们将使用相机作为来源。相机将在拍摄后将照片作为流返回。我们需要将该流转换为字节数组，然后最终将其 Base64 编码为一个易于通过 SignalR 发送的字符串。

我们即将创建的名为`ReadFully()`的方法接受一个流并将其转换为字节数组，这是实现 Base64 编码字符串的一步。这是一个标准的代码片段，它创建一个缓冲区，当我们读取`Stream`参数并将其以块的形式写入`MemoryStream`直到读取完整的流时，将使用该缓冲区，因此方法的名称。

跟着检查代码：

1.  创建一个名为`ReadFully`的方法，该方法接受名为`input`的`stream`作为参数并返回一个`byte`数组。

1.  声明一个`byte[]`类型的`buffer`变量，并将其初始化为 16KB 大小的字节数组（`16 * 1024`）。

1.  在使用语句内，创建一个名为`ms`的新`MemoryStream`。

1.  将`Stream`的输入读取到`ms`变量中：

```cs
private byte[] ReadFully(Stream input)
{
    byte[] buffer = new byte[16 * 1024];
    using (MemoryStream ms = new MemoryStream())
    {
        int read;
        while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
        {
            ms.Write(buffer, 0, read);
        }
        return ms.ToArray();
    }
} 
```

接下来，我们有一大块代码。该代码公开了一个命令，当用户在应用程序中点击照片按钮时将执行该命令。它首先配置了`CrossMedia`（一个媒体插件），指示照片的质量，然后启动了照片选择器。当照片选择器从`async`调用`PickPhotoAsync()`返回时，我们开始上传照片。为了通知用户，我们使用`UserDialogs.Instance.ShowLoading`创建一个带有消息的加载覆盖，以指示我们正在上传照片。

然后我们将获取照片的流，使用`ReadFully()`方法将其转换为字节数组，并将其 Base64 编码为字符串。该字符串将被包装在一个`PhotoMessage`实例中，添加到`ChatViewModel`的本地`Message`集合中，然后发送到服务器。

按照以下步骤并学习代码：

1.  创建一个名为`Photo`的`ICommand`类型的新属性。为其分配一个新的`Command`实例。

1.  创建一个匿名的`async`方法（lambda 表达式），并将即将定义的代码添加到其中。您可以在随后的代码部分中看到该方法的完整代码。

1.  创建`PickMediaOptions`类的一个新实例，并将`CompressionQuality`属性设置为`50`。

1.  使用`async`方法调用`CrossMedia.Current.PickPhotoAsync`，并将结果保存到名为`photo`的本地变量中。

1.  安装 NuGet 包。

1.  通过调用`UserDialogs.Instance.ShowLoading()`显示一个消息对话框，文本为“正在上传照片”。

1.  通过调用`photo`变量的`GetStream()`方法获取照片流，并将其保存到名为`stream`的变量中。

1.  通过调用`ReadFully()`方法将流转换为字节数组。

1.  使用`Convert.ToBase64String()`方法将字节数组转换为 Base64 编码的字符串。将字符串保存到名为`base64photo`的变量中。

1.  创建一个新的`PhotoMessage`实例，并将`User`作为构造函数参数传递。将`Base64Photo`属性设置为`base64photo`变量，将`FileEnding`属性设置为`photo.Path`字符串的文件结束，使用字符串对象的`Split`函数。将新的`PhotoMessage`实例存储在名为`message`的变量中。

1.  将消息对象添加到`Messages`集合中。

1.  通过调用异步的`chatService.SendMessage()`方法将消息发送到服务器。

1.  通过调用`UserDialogs.Instance.HideLoading()`隐藏加载对话框。

以下代码显示了如何实现这一点：

```cs
public ICommand Photo => new Command(async() =>
{
    var options = new PickMediaOptions();
    options.CompressionQuality = 50;

    var photo = await CrossMedia.Current.PickPhotoAsync();

    UserDialogs.Instance.ShowLoading("Uploading photo");

    var stream = photo.GetStream();
    var bytes = ReadFully(stream);

    var base64photo = Convert.ToBase64String(bytes);

    var message = new PhotoMessage(User)
    {
        Base64Photo = base64photo,
        FileEnding = photo.Path.Split('.').Last()
    };

    Messages.Add(message);
    await chatService.SendMessage(message);

    UserDialogs.Instance.HideLoading();
}); 
```

`ChatViewModel`已经完成。现在是时候可视化我们的 GUI 了。

# 创建 ChatView

ChatView 负责创建用户将与之交互的用户界面。它将显示本地和远程消息，包括文本和照片，并在远程用户加入聊天时通知用户。我们将首先创建一个转换器，将以 Base64 编码的字符串表示的照片转换为可用作 XAML 中图像控件源的`ImageSource`。

# 创建 Base64ToImageConverter

当我们使用手机相机拍照时，它将作为字节数组交给我们。为了将其发送到服务器，我们将其转换为 Base64 编码的字符串。为了在本地显示该消息，我们需要将其转换回字节数组，然后将该字节数组传递给`ImageSource`类的辅助方法，以创建`ImageSource`对象的实例。该对象将对`Image`控件有意义，并显示图像。

由于这里有很多代码，我们建议您按照步骤进行，并在跟随时仔细查看每行代码：

1.  在`Chat`项目中创建一个名为`Converters`的文件夹。

1.  在`Converters`文件夹中创建一个名为`Base64ImageConverter`的新类；让该类实现`IValueConverter`接口。

1.  在类的`Convert()`方法中，将名为 value 的对象参数转换为名为`base64String`的字符串。

1.  使用`System.Convert.FromBase64String()`方法将`base64String`转换为字节数组。将结果保存到名为`bytes`的变量中。

1.  通过将字节数组传递到其构造函数来创建一个新的`MemoryStream`。将流保存到名为`stream`的变量中。

1.  调用`ImageSource.FromStream()`方法，并将流作为返回流变量的 lambda 表达式传递。返回创建的`ImageSource`对象。

1.  不需要实现`ConvertBack()`方法，因为我们永远不会通过数据绑定将图像转换回 Base64 编码的字符串。我们只需让它抛出`NotImplementedException`：

```cs
using System;
using System.Globalization;
using Xamarin.Forms;
using System.IO;

namespace Chat.Converters
{
    public class Base64ToImageConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, 
                              object parameter, CultureInfo culture)
        {
            var base64string = (string)value;
            var bytes = 
            System.Convert.FromBase64String(base64string);
            var stream = new MemoryStream(bytes);
            return ImageSource.FromStream(() => stream);
        }

        public object ConvertBack(object value, Type targetType,
                                  object parameter, CultureInfo 
                                  culture)
        {
            throw new NotImplementedException();
        }
    }
} 
```

现在是时候开始向视图添加一些实际的 XAML 代码了。我们将首先创建主要的布局骨架，然后逐渐构建，直到完成视图。

# 创建骨架 ChatView

这个 XAML 文件将包含我们发送和接收的消息列表的视图。创建这个文件相当大，所以在这一部分，我建议你复制 XAML 并仔细研究每一步：

1.  在`Views`文件夹中创建一个名为`ChatView`的新`XAML Content Page`。

1.  为`Chat.Selectors`和`Chat.Converters`添加 XML 命名空间，并将它们命名为`selectors`和`converters`。

1.  添加一个`ContentPage.Resources`节点，稍后将包含此视图的资源。

1.  将`ScrollView`添加为页面内容。

1.  将`Grid`作为`ScrollView`的唯一子元素，并通过将`x:Name`属性设置为`MainGrid`来命名它。

1.  创建一个包含三行的`RowDefinitions`元素。第一行的高度应为`*`，第二行的高度为`1`，第三行的高度根据平台使用`OnPlatform`元素进行设置。

1.  为稍后插入的`ListView`保存一些空间。

1.  通过将`HeightRequest`属性设置为`1`，`BackgroundColor`属性设置为`#33000000`，将`Grid.Row`属性设置为`1`，添加一个`BoxView`，它将充当视觉分隔符。这将在网格的一单位高的行中定位`BoxView`，有效地在屏幕上绘制一条单行。

1.  添加另一个`Grid`，通过将`Grid.Row`属性设置为`2`来使用第三行的空间。还可以通过将`Padding`属性设置为`10`来添加一些填充。在网格中定义三行，高度分别为`30`、`*`和`30`：

```cs
<?xml version="1.0" encoding="UTF-8"?>
<ContentPage  

             x:Class="Chat.Views.ChatView">
    <ContentPage.Resources>
        <!-- TODO Add resources -->
    </ContentPage.Resources>
    <ScrollView>
        <Grid x:Name="MainGrid">
            <Grid.RowDefinitions>
                <RowDefinition Height="*" />
                <RowDefinition Height="1" />
                <RowDefinition>
                    <RowDefinition.Height>
                        <OnPlatform x:TypeArguments="GridLength">
                            <On Platform="iOS" Value="50" />
                            <On Platform="Android" Value="100" />
                        </OnPlatform>
                    </RowDefinition.Height>
                </RowDefinition>
            </Grid.RowDefinitions>

            <!-- TODO Add ListView -->

            <BoxView Grid.Row="1" HeightRequest="1" 
            BackgroundColor="#33000000" />
            <Grid Grid.Row="2" Padding="10">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="30" />
                    <ColumnDefinition Width="*" />
                    <ColumnDefinition Width="30" />
                </Grid.ColumnDefinitions>
                <!-- TODO Add buttons and entry controls -->

             </Grid>
         </Grid>
     </ScrollView>
 </ContentPage> 
```

现在我们已经完成了页面的主要骨架，我们需要开始添加一些具体的内容。首先，我们将添加`ResourceDictionary`来创建一个`DataTemplate`选择器，用于为不同的聊天消息选择正确的布局。然后，我们需要使用`Base64ToImageConverter`，为此，我们需要在视图中定义它。

# 添加 ResourceDictionary

现在是时候向视图添加一些资源了。在这种情况下，我们将添加一个模板选择器，稍后我们将创建它，以及我们之前创建的`Base64ToImageConverter`。模板选择器将查看我们将绑定到`ListView`的每一行，该行将呈现消息并选择最适合该消息的布局模板。为了能够从 XAML 中使用这些代码片段，我们需要定义 XAML 解析器找到它们的方法：

1.  在`ContentPage.Resources`元素内部找到`<!-- TODO Add resources -->`注释。

1.  在*步骤 1*中的注释下面，按照示例中的 XAML 添加 XAML：

```cs
        <ResourceDictionary>
            <selectors:ChatMessageSelector 
            x:Key="SelectMessageTemplate" />
            <converters:Base64ToImageConverter x:Key="ToImage" />
        </ResourceDictionary>
```

这将创建我们定义的每个资源的一个实例，并使其可以访问到视图的其余部分。

# 添加 ListView

我们将使用`ListView`来显示聊天应用中的消息。再次，按照步骤并查看代码，确保你理解每一步：

1.  在`ChatView.xaml`文件中找到`<!-- TODO Add ListView -->`注释。

1.  添加一个`ListView`，并将`x:Name`属性设置为`MessageList`。

1.  通过将`ItemsSource`属性设置为`{Binding Messages}`来对`ListView`进行数据绑定。这将使`ListView`意识到`ObservableCollection<Message>`中的更改，该集合通过`Messages`属性公开。每当添加或删除消息时，`ListView`都会更新以反映这一变化。

1.  将我们在上一节中定义的`SelectMessageTemplate`资源添加到`ItemTemplate`属性。这将在每次添加项目时运行一些代码，以确保我们以编程方式选择特定消息的正确视觉模板。别担心，我们很快就会写那段代码。

1.  通过将`HasUnevenRows`属性设置为`true`，确保`ListView`能够创建不均匀高度的行。

1.  我们需要设置的最后一个属性是`SeparatorVisibility`，我们将其设置为`None`，以避免在每一行之间添加一行。

1.  我们定义了一个占位符，我们将在其中添加资源。我们将添加的资源是我们将用于呈现不同类型消息的不同`DataTemplate`。

XAML 应该如下所示：

```cs
<ListView x:Name="MessageList" ItemsSource="{Binding Messages}" 
 ItemTemplate="{StaticResource SelectMessageTemplate}" 
 HasUnevenRows="true" SeparatorVisibility="None">
   <ListView.Resources>
     <ResourceDictionary>
       <!-- Resources go here later on --> 
     </ResourceDictionary>
   </ListView.Resources>
</ListView>
```

# 添加模板

我们现在将添加五个不同的模板，每个模板对应应用程序发送或接收的特定消息类型。每个这些模板都放在前一节代码片段中的`<!--稍后放置资源-->`注释下。

我们不会逐步解释每个模板，因为它们包含的 XAML 应该在这一点上开始感到熟悉。

每个模板都以相同的方式开始：根元素是具有设置名称的`DataTemplate`。名称很重要，因为我们很快将在代码中引用它。`DataTemplate`的第一个子元素始终是`ViewCell`，并将`IsEnabled`属性设置为`false`，以避免用户能够与内容交互。我们只是想显示它。此元素之后的内容是构建行的实际内容。

`ViewCell`内部的绑定也将针对`ListView`呈现的每个项目或行进行本地化。在这种情况下，这将是`Message`类的一个实例，因为我们正在将`ListView`的数据绑定到`Message`对象的集合。您将在代码中看到一些`StyleClass`属性。在最终使用**层叠样式表**（**CSS**）对应用程序进行最终样式设置时，将使用这些属性。

我们的任务是在`<!--稍后放置资源-->`注释下编写每个模板。

`SimpleText`是当消息是远程消息时选择的`DataTemplate`。它将在列表视图的左侧呈现，就像您可能期望的那样。它显示了`username`和`text`消息：

```cs
<DataTemplate x:Key="SimpleText">
    <ViewCell IsEnabled="false">
        <Grid Padding="10">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*" />
                <ColumnDefinition Width="*" />
            </Grid.ColumnDefinitions>
            <Frame StyleClass="remoteMessage" HasShadow="false">
                <StackLayout>
                 <Label Text="{Binding Username}" 
                  StyleClass="chatHeader" />
                 <Label Text="{Binding Text}" StyleClass="chatText" />
                </StackLayout>
            </Frame>
        </Grid>
    </ViewCell>
</DataTemplate>
```

`LocalSimpleText`模板与`SimpleText`数据模板相同，只是通过将`Grid.Column`属性设置为`1`，有效地使用右列，它在`ListView`的右侧呈现：

```cs
<DataTemplate x:Key="LocalSimpleText">
    <ViewCell IsEnabled="false">
        <Grid Padding="10">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*" />
                <ColumnDefinition Width="*" />
            </Grid.ColumnDefinitions>
            <Frame Grid.Column="1" StyleClass="localMessage" 
            HasShadow="false">
                <StackLayout>
                  <Label Text="{Binding Username}" 
                  StyleClass="chatHeader" />
                  <Label Text="{Binding Text}" StyleClass="chatText" />
                </StackLayout>
            </Frame>
        </Grid>
    </ViewCell>
</DataTemplate> 
```

当用户连接到聊天时使用此`DataTemplate`：

```cs
<DataTemplate x:Key="UserConnected">
    <ViewCell IsEnabled="false">
        <StackLayout Padding="10" BackgroundColor="#33000000" 
        Orientation="Horizontal">
            <Label Text="{Binding Username}" StyleClass="chatHeader" 
            VerticalOptions="Center" />
            <Label Text="connected" StyleClass="chatText" 
            VerticalOptions="Center" />
        </StackLayout>
    </ViewCell>
</DataTemplate>
```

通过 URL 访问服务器上上传的照片。此`DataTemplate`基于 URL 显示图像，并用于远程图像：

```cs
<DataTemplate x:Key="Photo">
    <ViewCell IsEnabled="false">
        <Grid Padding="10">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*" />
                <ColumnDefinition Width="*" />
            </Grid.ColumnDefinitions>
            <StackLayout>
                <Label Text="{Binding Username}" 
                 StyleClass="chatHeader" />
                <Image Source="{Binding Url}" Aspect="AspectFill" 
                HeightRequest="150" HorizontalOptions="Fill" />
            </StackLayout>
        </Grid>
    </ViewCell>
</DataTemplate>
```

包含用户发送并直接基于我们从相机生成的 Base64 编码图像进行渲染的照片的消息。由于我们不想等待图像上传，我们使用这个`DataTemplate`，它利用我们之前编写的`Base64ImageConverter`将字符串转换为可以由 Image 控件显示的`ImageSource`：

```cs
<DataTemplate x:Key="LocalPhoto">
    <ViewCell IsEnabled="false">
        <Grid Padding="10">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*" />
                <ColumnDefinition Width="*" />
            </Grid.ColumnDefinitions>
            <StackLayout Grid.Column="1">
                <Label Text="{Binding Username}" 
                StyleClass="chatHeader" />
                <Image Source="{Binding Base64Photo, Converter=
                {StaticResource ToImage}}" 
                Aspect="AspectFill" HeightRequest="150" 
                HorizontalOptions="Fill" />
            </StackLayout>
        </Grid>
    </ViewCell>
</DataTemplate>
```

这些就是我们需要的所有模板。现在是时候添加一些代码，以确保我们选择正确的模板来显示消息。

# 创建模板选择器

使用模板选择器是一种根据正在进行数据绑定的项目注入不同布局的强大方式。在这种情况下，我们将查看要显示的每条消息，并为它们选择最佳的`DataTemplate`。代码有些重复，所以我们将使用与 XAML 相同的方法——简单地添加代码，让您自己学习它：

1.  在`Chat`项目中创建一个名为`Selectors`的文件夹。

1.  在`Selectors`文件夹中创建一个名为`ChatMessagesSelector`的新类，并从`DataTemplateSelector`继承它。

1.  添加以下代码，它将查看每个数据绑定的对象，并从我们刚刚添加的资源中提取正确的`DataTemplate`：

```cs
using Chat.Messages;
using Xamarin.Forms;

namespace Chat.Selectors
{
    public class ChatMessagesSelector : DataTemplateSelector
    {
        protected override DataTemplate OnSelectTemplate(object 
        item, BindableObject container)
        {
            var list = (ListView)container;

            if(item is LocalSimpleTextMessage)
            {
                return   
            (DataTemplate)list.Resources["LocalSimpleText"];
            }
            else if(item is SimpleTextMessage)
            {
                return (DataTemplate)list.Resources["SimpleText"];
            }
            else if(item is UserConnectedMessage)
            {
                return 
            (DataTemplate)list.Resources["UserConnected"];
            }
            else if(item is PhotoUrlMessage)
            {
                return (DataTemplate)list.Resources["Photo"];
            }
            else if (item is PhotoMessage)
            {
                return (DataTemplate)list.Resources["LocalPhoto"];
            }

            return null;
        }
    }
}
```

# 添加按钮和输入控件

现在我们将添加用户用于编写聊天消息的按钮和输入。我们使用的图标可以在本章的 GitHub 存储库中找到。对于 Android，图标将放在`Resource`文件夹内的`Drawable`文件夹中，而对于 iOS，它们将放在`Resource`文件夹中。GitHub 上的同一文件夹中有这些图标：

1.  在`ChatView.xaml`文件中找到`<!-- TODO Add buttons and entry controls -->`的注释。

1.  添加一个`ImageButton`。`Source`应设置为`photo.png`，`Command`设置为`{Binding Photo}`，`VerticalOptions`和`HorizontalOptions`设置为`Center`。`Source`用于显示图像；当用户点击图像时，`Command`将被执行，`HorizontalOptions`和`VerticalOptions`将用于将图像居中在控件的中间。

1.  添加一个`Entry`控件，允许用户输入要发送的消息。`Text`属性应设置为`{Binding Text}`。将`Grid.Column`属性设置为`1`，将`ReturnCommand`设置为`{Binding Send}`，以在用户按下*Enter*时执行`ChatViewModel`中的发送命令。

1.  一个`ImageButton`，`Grid.Column`属性设置为`2`，`Source`设置为`send.png`，`Command`设置为`{Binding Send}`（与返回命令相同）。水平和垂直居中：

```cs
<ImageButton Source="photo.png" Command="{Binding Photo}"
             VerticalOptions="Center" HorizontalOptions="Center" />
             <Entry Text="{Binding Text}" Grid.Column="1" 
             ReturnCommand="{Binding Send}" />
<ImageButton Grid.Column="2" Source="send.png" 
             Command="{Binding Send}" 
             VerticalOptions="Center" HorizontalOptions="Center" />
```

# 修复代码后面

现在 XAML 已经完成，我们需要在代码后面做一些工作。我们将首先修改类为部分类，然后添加一些`using 语句`：

1.  打开`ChatView.xaml.cs`文件。

1.  将类标记为`partial`。

1.  添加一个名为`viewModel`的`ChatViewModel`类型的`private`字段，它将保存对`ChatViewModel`的本地引用。

1.  为`Chat.ViewModels`，`Xamarin.Forms`和`Xamarin.Forms.PlatformConfiguration.iOSSpecific`添加`using 语句`。

现在该类应该如下所示。粗体代码表示应该已经更改的内容：

```cs
using System.Linq;
using Chat.ViewModels;
using Xamarin.Forms;
using Xamarin.Forms.PlatformConfiguration.iOSSpecific;

namespace Chat.Views
{
    public partial class ChatView : ContentPage
    {
        private ChatViewModel viewModel;

        public ChatView()
        {
            InitializeComponent();
        }
    }
}
```

当有新消息到达时，将其添加到`ChatViewModel`中的 Messages 集合中。为了确保`MessageList`和`ListView`适当滚动以使新消息可见，我们需要编写一些额外的代码：

1.  创建一个名为`Messages_CollectionChanged`的新方法，它以对象作为第一个参数，以`NotifyCollectionChangedEventArgs`作为第二个参数。

1.  调用`MessageList.ScrollTo()`方法，并通过调用`viewModel.Messages.Last()`将`viewModel.Messages`集合中的最后一条消息传递给它。第二个参数应设置为`ScrollPosition.End`，表示我们要使整个消息`ListView`行可见。第三个参数应设置为`true`以启用动画。

该方法现在应该如下所示：

```cs
private void Messages_CollectionChanged(object sender, 
            System.Collections.Specialized.NotifyCollectionChangedEventArgs e)
{
    MessageList.ScrollTo(viewModel.Messages.Last(), 
    ScrollToPosition.End, true);
}
```

现在是时候扩展构造函数，使其以`ChatViewModel`作为参数，并以我们习惯的方式设置`BindingContext`。构造函数还将确保在渲染控件时使用安全区域，并确保我们连接到处理`ChatViewModel`的`Messages`集合中的更改所必需的事件：

1.  在`ChatView`类中修改构造函数，使其以`ChatViewModel`作为唯一参数，并将参数命名为`viewModel`。

1.  将构造函数中的`viewModel`参数分配给类中的本地`viewModel`字段。

1.  在`InitializeComponent()`方法的调用中，添加一个特定于平台的调用`SetUseSafeArea(true)`方法，以确保应用程序在 iPhone X 上可视上是安全的，不会部分隐藏在顶部的刘海后面：

```cs
 public ChatView(ChatViewModel viewModel)
 {
     this.viewModel = viewModel;

     InitializeComponent();
     On<Xamarin.Forms.PlatformConfiguration.iOS>
     ().SetUseSafeArea(true);

 viewModel.Messages.CollectionChanged += 
     Messages_CollectionChanged;
 BindingContext = viewModel;
 }
```

每次视图出现时，都会调用`OnAppearing()`方法。这个方法是虚拟的，我们可以重写它。我们将使用这个特性来确保`MainGrid`的高度是正确的。这是因为我们必须将所有内容包装在`ScrollView`中，因为视图在键盘出现时必须能够滚动。如果我们不计算`MainGrid`的宽度，它可能会比屏幕大，因为`ScrollView`允许它扩展。

1.  覆盖`OnAppearing()`方法。

1.  通过调用特定于平台的方法`On<Xamarin.Forms.PlatformConfiguration.iOS>().SafeAreaInsets()`来计算要使用的安全区域。这将返回一个`Xamarin.Forms.Thickness`对象，其中包含我们需要的插入信息，以便计算`MainGrid`的高度。将`Thickness`对象分配给名为`safeArea`的变量。

1.  将`MainGrid.HeightRequest`属性设置为视图的高度（`this.Height`），然后减去`safeArea`的`Top`和`Bottom`属性：

```cs
protected override void OnAppearing()
{
    base.OnAppearing();
    var safeArea = On<Xamarin.Forms.PlatformConfiguration.iOS>
    ().SafeAreaInsets();
    MainGrid.HeightRequest = this.Height - safeArea.Top - 
    safeArea.Bottom;
} 
```

# 样式

样式是应用程序的重要组成部分。就像 HTML 一样，您可以通过直接设置每个控件的属性或在应用程序的资源字典中设置`Style`元素来进行样式设置。然而，最近，Xamarin.Forms 出现了一种新的样式设置方式，即使用层叠样式表，通常称为 CSS。

由于 CSS 并不能覆盖所有情况，我们还将回退到标准的应用程序资源字典样式。

# 使用 CSS 进行样式设置

Xamarin.Forms 支持通过 CSS 文件进行样式设置。它具有您从普通 CSS 中期望的功能的子集，但是每个版本的支持都在不断改进。我们将使用两种不同的选择器来应用样式。

首先，让我们创建样式表，然后再讨论其内容：

1.  在`Chat`项目中创建一个名为`Css`的文件夹。

1.  在`Css`文件夹中创建一个新的文本文件，并将其命名为`Styles.css`。

1.  将以下样式表复制到该文件中：

```cs
button {
 background-color: #A4243B;
 color: white;
}

.chatHeader {
 color: white;
 font-style: bold;
 font-size: small;
}

.chatText {
 color: white;
 font-size: small;
}

.remoteMessage {
 background-color: #F04D6A;
 padding: 10;
}

.localMessage {
 background-color: #24A43B;
 padding: 10;
}

```

第一个选择器 button 适用于整个应用程序中的每个按钮控件。它将背景颜色设置为`#A4243B`，前景颜色设置为`白色`。您几乎可以为 Xamarin.Forms 中的每种类型的控件执行此操作。

我们使用的第二个选择器是类选择器，以句点开头，例如`.chatHeader`。这些选择器在 XAML 中与`StyleClass`属性一起使用。回顾一下我们之前创建的`ChatView.xaml`文件，您将在模板资源中找到这些内容。

CSS 中的每个属性都映射到控件本身的属性。还有一些特定于 Xamarin.Forms 的属性可以使用，但这些超出了本书的范围。如果您在互联网上搜索 Xamarin.Forms 和 CSS，您将找到深入了解此内容所需的所有信息。

# 应用样式表

样式表本身是不够的。我们需要将其应用到我们的应用程序中。我们还需要在 NavigationPage 上设置一些样式，因为我们无法直接从 CSS 中访问它。

我们将添加一些资源和对样式表的引用。复制代码并参考步骤来学习每行代码的作用：

1.  在`Chat`项目中的`App.xaml`文件中打开。

1.  在`Application.Resources`节点中，添加一个`<StyleSheet Source="/Css/Styles.css" />`节点来引用样式表。

1.  以下是`StyleSheet`节点。添加一个`TargetType`设置为`"NavigationPage"`的`Style`节点，并为`BarBackgroundColor`属性创建一个值为`"#273E47"`的 setter，为`BarTextColor`属性创建一个值为`"White"`的 setter。

`App.xaml`文件现在应如下所示：

```cs
<?xml version="1.0" encoding="utf-8"?>
<Application  

             x:Class="Chat.App">
    <Application.Resources>
        <StyleSheet Source="/Css/Styles.css" />
        <ResourceDictionary>
 <Style TargetType="NavigationPage">
 <Setter Property="BarBackgroundColor" Value="#273E47" />
 <Setter Property="BarTextColor" Value="White" />
 </Style>
 </ResourceDictionary>
    </Application.Resources>
</Application> 
```

# 处理生命周期事件

最后，我们需要添加一些生命周期事件，以便在应用程序进入睡眠状态或再次唤醒时处理我们的 SignalR 连接：

1.  打开`App.Xaml.cs`文件。

1.  在类中的某个地方添加以下代码：

```cs
protected override void OnSleep()
{
    var chatService = Resolver.Resolve<IChatService>();
    chatService.Dispose();
}

protected override void OnResume()
{
    Task.Run(async() =>
    {
        var chatService = Resolver.Resolve<IChatService>();

        if (!chatService.IsConnected)
        {
            await chatService.CreateConnection();
        }
    });

    Page view = null;

    if(ViewModel.User != null)
    {
        view = Resolver.Resolve<ChatView>();
    }
    else
    {
        view = Resolver.Resolve<MainView>();
    }

    var navigationPage = new NavigationPage(view);
    MainPage = navigationPage;
} 
```

当用户最小化应用程序时，将调用`OnSleep()`方法，并通过关闭活动连接来处理任何正在运行的`chatService`。`OnResume()`方法有更多的内容。如果没有活动连接，它将重新创建连接，并根据用户是否已设置，解析到正确的视图。如果用户不存在，它将显示`MainView`；否则它将显示`ChatView`。最后，它将选定的视图包装在导航页面中。

# 总结

到此为止 - 干得好！我们现在已经创建了一个连接到后端的聊天应用程序。我们已经学会了如何使用 SignalR，如何用 CSS 样式化应用程序，如何在`ListView`中使用模板选择器，以及如何使用值转换器将`byte[]`转换为 Xamarin.Forms 的`ImageSource`。

在下一章中，我们将深入探讨增强现实世界！我们将使用 UrhoSharp 和 ARKit（iOS）以及 ARCore（Android）共同为 iOS 和 Android 创建一个 AR 游戏。


# 第八章：创建增强现实游戏

在本章中，我们将使用 Xamarin.Forms 探索**增强现实**（**AR**）。我们将使用自定义渲染器注入特定于平台的代码，使用**UrhoSharp**来渲染场景和处理输入，并使用`MessagingCenter`在应用程序中传递内部消息。

本章将涵盖以下主题：

+   设置项目

+   使用 ARKit

+   使用 ARCore

+   学习如何使用 UrhoSharp 来渲染图形和处理输入

+   使用自定义渲染器注入特定于平台的代码

+   使用`MessagingCenter`发送消息

# 技术要求

为了能够完成这个项目，我们需要安装 Visual Studio for Mac 或 PC，以及 Xamarin 组件。有关如何设置您的环境的更多详细信息，请参见第一章，*Xamarin 简介*。

您不能在模拟器上运行 AR。要运行 AR，您需要一个物理设备，以及以下软件：

+   在 iOS 上，您需要 iOS 11 或更高版本，以及一个 A9 处理器或更高版本的设备

+   在 Android 上，您需要 Android 8.1 和支持 ARCore 的设备

# 基本理论

本节将描述 AR 的工作原理。实现在不同平台之间略有不同。谷歌的实现称为**ARCore**，苹果的实现称为**ARKit**。

AR 的全部内容都是关于在相机反馈的基础上叠加计算机图形。这听起来是一件简单的事情，除了您必须以极高的精度跟踪相机位置。谷歌和苹果都编写了一些很棒的 API 来为您完成这个魔术，借助手机的运动传感器和相机数据。我们添加到相机反馈上的计算机图形与周围真实物体的坐标空间同步，使它们看起来就像是图像上看到的一部分。

# 项目概述

在本章中，我们将创建一个探索 AR 基础知识的游戏。我们还将学习如何在 Xamarin.Forms 中集成 AR 控制。Android 和 iOS 以不同的方式实现 AR，因此我们需要在途中统一平台。我们将使用 UrhoSharp，一个开源的 3D 游戏引擎，来进行渲染。这只是使用.NET 和 C#与 Urho3D 绑定的**Urho3D**引擎。

游戏将在 AR 中渲染盒子，用户需要点击以使其消失。然后，您可以通过学习 Urho3D 引擎来扩展游戏。

共享代码将放置在一个共享项目中。这与我们迄今为止采取的通常的.NET 标准库方法不同。这样做的原因是，UrhoSharp 在撰写本书时不支持.NET 标准。学习如何创建共享项目也是一个好主意。共享库中的代码本身不会编译。它需要链接到平台项目（如 iOS 或 Android），然后编译器可以编译所有源文件以及平台项目。这与直接将文件复制到该项目中完全相同。因此，通过定义一个共享项目，我们不需要重复编写代码。

这种策略还解锁了另一个强大的功能：**条件编译**。考虑以下示例：

```cs
#if __IOS__ 
   // Only compile this code on iOS
#elif __ANDROID__ 
   // Only compile this code on Android
#endif
```

上述代码显示了如何在共享代码文件中插入特定于平台的代码。这在这个项目中将非常有用。

该项目的预计构建时间为 90 分钟。

# 开始项目

是时候开始编码了！但首先，请确保您已经按照第一章中描述的设置好了开发环境，*Xamarin 简介*。

本章将是一个经典的*文件|新建项目*章节，将逐步指导您完成创建应用程序的过程。完全不需要下载。

# 创建项目

打开 Visual Studio，然后点击“文件”|“新建”|“项目”，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/6fca819a-f5c0-424e-a0b6-26d2133d2da9.png)

这将打开“新建项目”对话框。展开“Visual C#”节点，然后单击“跨平台”。在列表中选择“移动应用程序（Xamarin.Forms）”项目。通过为您的项目命名来完成表单。在本示例中，我们将称我们的应用程序为`WhackABox`。点击“确定”继续到下一个对话框，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/e3f05ec6-796d-4724-b354-c25d2171e43c.png)

下一步是选择项目模板和代码共享策略。选择“空白模板”选项以创建最基本的 Xamarin.Forms 应用程序，并确保代码共享策略设置为“共享项目”。在“平台”标题下取消选中“Windows（UWP）”复选框，因为此应用程序只支持**iOS**和 Android。点击“确定”完成设置向导，让 Visual Studio 为您创建项目。这可能需要几分钟。请注意，本章我们将使用共享项目——这一点非常重要！您可以在以下截图中看到需要选择的字段和选项：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/78e4bcf2-f5d5-49a6-a4c1-e3dbefafd2df.png)

就这样，应用程序已经创建好了。让我们继续更新 Xamarin.Forms 到最新版本。

# 更新 Xamarin.Forms NuGet 包

目前，您的项目创建时使用的 Xamarin.Forms 版本很可能有点过时。为了纠正这一点，我们需要更新 NuGet 包。请注意，您应该只更新 Xamarin.Forms 包，而不是 Android 包；更新 Android 包可能导致包不同步，导致应用程序根本无法构建。要更新 NuGet 包，请按以下步骤操作：

1.  在“解决方案资源管理器”中右键单击我们的解决方案。

1.  点击“管理解决方案的 NuGet 包...”，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/542a5038-c9cb-4647-b14f-c940a60a2f88.png)

这将在 Visual Studio 中打开 NuGet 包管理器，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/3a9e444d-fd64-499a-bcc6-afb117c82756.png)

要将 Xamarin.Forms 更新到最新版本，请按以下步骤操作：

1.  点击“更新”选项卡。

1.  勾选“Xamarin.Forms”复选框，然后点击“更新”。

1.  接受任何许可协议。

更新最多需要几分钟。查看输出窗格以获取有关更新的信息。此时，我们可以运行应用程序以确保其正常工作。我们应该在屏幕中央看到“欢迎使用 Xamarin.Forms！”的文本。

# 将 Android 目标设置为 8.1

ARCore 可用于 Android 8.1 及更高版本。因此，我们将通过以下步骤验证 Android 项目的目标框架：

1.  在“解决方案资源管理器”中的 Android 项目下双击“属性”节点。

1.  验证目标框架版本至少为 Android 8.0（Oreo），如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/09fe6cca-4790-4b04-8d7e-d6b20d0c4706.png)

如果目标框架不是至少 Android 8.0（Oreo），则需要选择 Android 8.1（或更高版本）。如果目标框架名称旁边有一个星号，则需要通过以下步骤安装该 SDK：

1.  在工具栏中找到 Android SDK Manager。

1.  点击突出显示的按钮打开 SDK Manager，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/5c98de95-7c5c-4683-8f35-e1186ecf9de8.png)

这是系统上安装的所有 Android SDK 版本的控制中心：

1.  展开您想要安装的 SDK 版本。在我们的情况下，这应该至少是 Android 8.1 - Oreo。

1.  选择 Android SDK 平台<版本号>节点。您还可以安装模拟器映像，供模拟器运行所选版本的 Android。

1.  点击“应用更改”，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/17c557be-4452-4ce7-83c0-23a5e57fd5ab.png)

# 向 Android 添加相机权限

为了在 Android 中访问相机，我们必须在 Android 清单中添加所需的权限。可以通过以下步骤完成：

1.  在解决方案资源管理器中打开 Android 项目节点。

1.  双击属性节点以打开 Android 的属性。

1.  单击左侧的 Android 清单选项卡，然后向下滚动，直到看到所需权限部分。

1.  定位相机权限并选中复选框。

1.  通过单击*Ctrl* +* S*或文件和保存来保存文件。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/5be70e8f-186b-4838-8e0c-a49cd316f4a7.png)

现在我们已经配置了 Android，在准备编写一些代码之前，我们只需要在 iOS 上做一个小小的改变。

# 为 iOS 添加相机使用说明

在 iOS 中，您需要指定为什么需要访问相机。这样做的方法是在 iOS 项目的根文件夹中的`info.plist`文件中添加条目。`info.plist`文件是一个 XML 文件，您可以在任何文本编辑器中编辑。但是，更简单的方法是使用 Visual Studio 提供的通用 PList 编辑器。

使用通用 PList 编辑器添加所需的相机使用说明，如下所示：

1.  定位`WhackABox.iOS`项目。

1.  右键单击`info.plist`，然后单击“使用...”，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/f854d634-aaab-4c4c-bdcb-6b714cb06938.png)

1.  选择通用 PList 编辑器，然后单击确定，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/98665692-d865-434f-9658-4389050799c0.png)

1.  在属性列表的底部找到加号（+）图标。

1.  单击加号（+）图标以添加新键。确保密钥位于文档的根目录下，而不是在另一个属性下，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/abd89c94-b4d9-419f-af0e-8f374d027598.png)

通用 PList 编辑器通过给属性提供更用户友好的名称来帮助您找到正确的属性。让我们添加我们需要的值来描述我们为什么要使用相机：

1.  在新创建的行上打开下拉菜单。

1.  选择隐私-相机使用说明。

1.  在右侧的值字段中写一个好的理由，如下面的屏幕截图所示。原因字段是一个自由文本字段，因此请使用简单的英语描述您的应用程序为什么需要访问相机：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/14005e35-6acb-427d-be52-79da6f75f4e3.png)

就是这样。 Android 和 iOS 的设置已经完成，现在我们可以专注于有趣的部分-编写代码！

您还可以在任何文本编辑器中打开`Info.plist`文件，因为它是一个 XML 文件。密钥的名称是

`NSCameraUsageDescription`，并且必须作为根节点的直接子节点添加。

# 定义用户界面

我们将首先定义将包装 AR 组件的用户界面。首先，我们将定义一个自定义控件，我们将使用它作为注入包含 AR 组件的`UrhoSurface`的占位符。然后，我们将在包含有关我们在 AR 中找到多少平面以及世界中有多少活动箱子的网格中添加此控件。游戏的目标是在 AR 中使用手机找到箱子，并点击它们使它们消失。

让我们首先定义自定义的`ARView`控件。

# 创建 ARView 控件

`ARView`控件属于共享项目，因为它将成为两个应用程序的一部分。它是一个标准的 Xamarin.Forms 控件，直接从`Xamarin.Forms.View`继承。它不会加载任何 XAML（因此它只是一个单一的类），也不会包含任何功能，只是简单地被定义，因此我们可以将它添加到主网格中。

转到 Visual Studio，并按照以下三个步骤创建`ARView`控件：

1.  在`WhackABox`项目中，添加一个名为`Controls`的文件夹。

1.  在`Controls`文件夹中创建一个名为`ARView`的新类。

1.  将以下代码添加到`ARView`类中：

```cs
using Xamarin.Forms;

namespace WhackABox.Controls
{
    public class ARView : View
    {
    }
} 
```

我们在这里创建了一个简单的类，没有实现，它继承自`Xamarin.Forms.View`。这样做的目的是利用每个平台的自定义渲染器，允许我们指定特定于平台的代码插入到我们放置这个控件的 XAML 中。您的项目现在应该如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/3dc949c2-7455-4476-b9c9-3b7018741a3b.png)

`ARView`控件就那样坐在那里是不行的。我们需要将它添加到`MainPage`中。

# 修改 MainPage

我们将替换`MainPage`的全部内容，并添加对`WhackABox.Controls`命名空间的引用，以便我们可以使用`ARView`控件。让我们通过以下步骤来设置这个：

1.  在`WhackABox`项目中，打开`MainPage.xaml`文件。

1.  编辑 XAML 以使其看起来像以下代码。粗体的 XAML 表示必须添加的新元素：

```cs
<?xml version="1.0" encoding="utf-8">
<ContentPage  

           x:Class="WhackABox.MainPage">

 **<Grid>**
 **<Grid.ColumnDefinitions>**
 **<ColumnDefinition Width="*" />**
 **<ColumnDefinition Width="*" />**
 **</Grid.ColumnDefinitions>**

 **<Grid.RowDefinitions>**
 **<RowDefinition Height="100" />**
 **<RowDefinition Height="*" />**
 **</Grid.RowDefinitions>**

 **<StackLayout Grid.Row="0" Padding="10">**
 **<Label Text="Plane count" />**
 **<Label Text="0" FontSize="Large"  
             x:Name="planeCountLabel" />**
 **</StackLayout>**

 **<StackLayout** **Grid.Row="0"** **Grid.Column="1" Padding="10">**
 **<Label Text="Box count" />**
 **<Label Text="0" FontSize="Large"   
          x:Name="boxCountLabel"/>**
 **</StackLayout>**

 **<controls:ARView Grid.Row="1" Grid.ColumnSpan="2" />**
 **</Grid>**
 </ContentPage> 
```

现在我们有了代码，让我们一步一步地来看：

+   首先，我们定义一个控件命名空间，指向代码中的`WhackABox.Controls`命名空间。这个命名空间用于在 XAML 末尾定位`ARView`控件。

+   然后，我们通过将其设置为`Grid`来定义内容元素。一个页面只能有一个子元素，在这种情况下是一个`Grid`。`Grid`定义了两列和两行。列将`Grid`分成两个相等的部分，其中有一行在顶部高度为`100`个单位，另一行占据了下面所有可用的空间。

+   我们使用前两个单元格来添加`StackLayout`的实例，其中包含游戏中平面数量和箱子数量的信息。这些`StackLayout`的实例在网格中的位置由`Grid.Row=".."`和`Grid.Column=".."`属性定义。请记住，行和列是从零开始的。实际上，您不必为行或列`0`添加属性，但有时为了提高代码可读性，这样做可能是一个好习惯。

+   最后，我们有`ARView`控件，它位于第 1 行，但通过指定`Grid.ColumnSpan="2"`跨越了两列。

下一步是安装 UrhoSharp，它将是我们用来渲染表示现实增强部分的图形的库。

# 添加 Urhosharp

Urho 是一个开源的 3D 游戏引擎。UrhoSharp 是一个包，其中包含了对 iOS 和 Android 二进制文件的绑定，使我们能够在.NET 中使用 Urho。这是一个非常有竞争力的软件，我们只会使用它的一小部分来在应用程序中渲染平面和箱子。我们建议您了解更多关于 UrhoSharp 的信息，以添加您自己的酷功能到应用程序中。

安装 UrhoSharp 只需要为每个平台下载一个 NuGet 包。iOS 平台使用 UrhoSharp NuGet 包，Android 使用 UrhoSharp.ARCore 包。此外，在 Android 中，我们需要添加一些代码来连接生命周期事件，但我们稍后会讲到。基本上，我们将在每个平台上设置一个`UrhoSurface`。我们将访问这个平台以向节点树添加节点。然后根据它们的类型和属性来渲染这些节点。

但首先，我们需要安装这些包。

# 为 iOS 安装 UrhoSharp NuGet 包

对于 iOS，我们只需要添加 UrhoSharp NuGet 包。这个包包含了我们 AR 应用所需的一切。您可以按照以下步骤添加该包：

1.  右键单击`WhackABox.iOS`项目。

1.  点击“管理 NuGet 包...”，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/7beed9e8-ee72-4937-8275-18b877598992.png)

1.  这将打开 NuGet 包管理器。点击窗口左上角的“浏览”链接。

1.  在搜索框中输入`UrhoSharp`，然后按*Enter*。

1.  选择 UrhoSharp 包，并在窗口右侧点击“安装”，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/30731bb9-fc86-4d9b-aa35-cbb970ec2fef.png)

这就是 iOS 的全部内容。Android 设置起来有点棘手，因为它需要一个特殊的 UrhoSharp 包和一些代码来连接一切。

# 为 Android 安装 UrhoSharp.ARCore Nuget 包

对于 Android，我们将添加 UrhoSharp.ARCore 包，其中包含 ARCore 的扩展。它依赖于 UrhoSharp，因此我们不必专门添加该包。您可以按照以下方式添加 UrhoSharp.ARCore 包：

1.  右键单击`WhackABox.Android`项目。

1.  单击“管理 NuGet 包...”，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/39392973-f2c7-4730-8438-00c3ac2c14fd.png)

1.  这将打开 NuGet 包管理器。单击窗口左上角的“浏览”链接。

1.  在搜索框中输入`UrhoSharp.ARCore`，然后按*Enter*。

1.  选择 UrhoSharp.ARCore 包，然后单击窗口右侧的“安装”，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/54863d4c-bb64-4284-a05e-97865506710e.png)

这就是全部——您的项目中所有对 UrhoSharp 的依赖项都已安装。现在我们必须连接一些生命周期事件。

# 添加 Android 生命周期事件

在 Android 中，`Urho`需要知道一些特定事件，并能够相应地做出响应。我们还需要使用`MessagingCenter`添加内部消息，以便稍后在应用程序中对`OnResume`事件做出反应。在初始化 ARCore 时我们将会做到这一点。但现在，按照以下方式添加 Android 事件的五个必需重写：

1.  在 Android 项目中，打开`MainActivity.cs`。

1.  在`MainActivity`类的任何位置添加以下代码中的五个重写。

1.  通过为`Urho.Droid`和`Xamarin.Forms`添加`using`语句来解决未解析的引用，如下所示：

```cs
protected override void OnResume()
{
    base.OnResume();
    UrhoSurface.OnResume();

    MessagingCenter.Send(this, "OnResume");
}

protected override void OnPause()
{
    UrhoSurface.OnPause();
    base.OnPause();
}

protected override void OnDestroy()
{
    UrhoSurface.OnDestroy();
    base.OnDestroy();
}

public override void OnBackPressed()
{
    UrhoSurface.OnDestroy();
    Finish();
}

public override void OnLowMemory()
{
    UrhoSurface.OnLowMemory();
    base.OnLowMemory();
} 
```

这些事件一一映射到内部的 UrhoSharp 事件，除了`OnBackPressed`，它调用`UrhoSharp.OnDestroy()`。这样做是为了内存管理，以便 UrhoSharp 知道何时清理。

`MessagingCenter`库是一个内置的 Xamarin.Forms 发布-订阅库，用于在应用程序中传递内部消息。它依赖于 Xamarin.Forms。我们创建了一个名为`TinyPubSub`的自己的库，它打破了这种依赖关系，并且具有稍微更容易的 API（以及一些附加功能）。您可以在 GitHub 上查看它：[`github.com/TinyStuff/TinyPubSub`](https://github.com/TinyStuff/TinyPubSub)。

# 定义 PlaneNode

在`Urho`中，您将使用包含节点树的场景。节点可以是游戏中的几乎任何东西，比如渲染器、声音播放器，或者只是子节点的占位符。

正如我们在讨论 AR 基础知识时所说的，平面是在平台之间共享的常见实体。我们需要创建一个代表平面的共同基础，这可以通过扩展`Urho`节点来实现。位置和旋转将由节点本身跟踪，但我们需要添加一个属性来跟踪平面的原点和大小，由 ARKit 和 ARCore 表示为平面的范围。

我们现在将添加这个类，并在每个平台上实现 AR 相关代码时使用它。这样做的代码很简单，可以通过以下步骤设置：

1.  在`WhackABox`项目中，在项目的根目录创建一个名为`PlaneNode.cs`的新文件。

1.  添加以下类的实现：

```cs
using Urho;

namespace WhackABox
{
    public class PlaneNode :Node
    {
        public string PlaneId { get; set; }
        public float ExtentX { get; set; }
        public float ExtentZ { get; set; }
    }
} 
```

`PlaneId`将是一个标识符，允许我们跟踪此节点代表的特定于平台的平面。在 iOS 中，这将是一个字符串，而在 Android 中，它将是转换为字符串的平面对象的哈希码。`ExtentY`和`ExtentZ`属性表示平面的大小（以米为单位）。我们现在准备开始创建游戏逻辑，并将我们的应用程序连接到 AR SDK。

# 为 ARView 控件添加自定义渲染器

自定义渲染器是将特定于平台的行为扩展到自定义控件的一种非常聪明的方式。它们还可以用于覆盖已定义的控件上的行为。事实上，Xamarin.Forms 中的所有控件都使用渲染器将 Xamarin.Forms 控件转换为特定于平台的控件。

我们将创建两个渲染器，一个用于 iOS，一个用于 Android，它们将初始化我们将要渲染的`UrhoSurface`。`UrhoSurface`的实例化在每个平台上都有所不同，这就是为什么我们需要两种不同的实现。

# 对于 iOS

自定义渲染器是从另一个渲染器继承的类。它允许我们为重要事件添加自定义代码，例如在解析 XAML 文件时创建 XAML 元素时。由于`ARView`控件继承自`View`，我们将使用`ViewRenderer`作为基类。通过以下步骤创建`ARViewRenderer`：

1.  在 iOS 项目中，创建一个名为`Renderers`的文件夹。

1.  在该文件夹中添加一个名为`ARViewRenderer`的新类。

1.  将以下代码添加到类中：

```cs
using System.Threading.Tasks;
using Urho.iOS;
using WhackABox.Controls;
using WhackABox.iOS.Renderers;using Xamarin.Forms;
using Xamarin.Forms.Platform.iOS;

 [assembly: ExportRenderer(typeof(ARView), typeof(ARViewRenderer))]

 namespace WhackABox.iOS.Renderers
{
    public class ARViewRenderer : ViewRenderer<ARView, UrhoSurface>
    {
          protected async override void 
          OnElementChanged(ElementChangedEventArgs<ARView> e)
        {
            base.OnElementChanged(e);

            if (Control == null)
            {
                await Initialize();
            }
         }

         private async Task Initialize()
         {
             var surface = new UrhoSurface();
             SetNativeControl(surface);
             await surface.Show<Game>();
         }
     }
}
```

`ExportRenderer`属性将此渲染器注册到 Xamarin.Forms，以便它知道当解析（或编译）`ARView`元素时，应该使用此特定的渲染器进行渲染。它接受两个参数：第一个是我们要注册渲染器的`Control`，第二个是渲染器的类型。此属性必须放在命名空间声明之外。

`ARViewRenderer`类继承自`ViewRenderer<ARView, UrhoSurface>`。这指定了此渲染器为哪个控件创建，以及它应该渲染哪个本地控件。在这种情况下，`ARView`将被一个`UrhoSurface`控件本地替换，这本身是一个 iOS 特定的`UIView`。

我们重写`OnElementChanged()`方法，该方法在`ARView`元素每次更改时被调用，无论是创建还是替换。然后我们可以检查`Control`属性是否已设置。控件是`UrhoSurface`类型，因为我们在类定义中声明了它。如果它是`null`，那么我们就调用`Initialize()`来创建它。

创建非常简单。我们只需创建一个新的`UrhoSurface`控件，并将本地控件设置为这个新创建的对象。然后我们调用`Show<Game>()`方法来启动游戏，指定代表我们的`Urho`游戏的类。请注意，`Game`类尚未定义，但它将很快定义，就在我们为 Android 创建自定义渲染器之后。

# 对于 Android

Android 的自定义渲染器与 iOS 的自定义渲染器做的事情相同，但还需要检查权限。通过以下步骤创建 Android 的`ARViewRenderer`：

1.  在 Android 项目中，创建一个名为`Renderers`的文件夹。

1.  在该文件夹中添加一个名为`ARViewRenderer`的新类。

1.  将以下代码添加到类中：

```cs
 using System.Threading.Tasks;
 using Android;
 using Android.App;
 using Android.Content;
 using Android.Content.PM;
 using Android.Support.V4.App;
 using Android.Support.V4.Content;
 using WhackABox.Droid.Renderers;
 using WhackABox;
 using WhackABox.Controls;
 using WhackABox.Droid;
 using Urho.Droid;
 using Xamarin.Forms;
 using Xamarin.Forms.Platform.Android;

  [assembly: ExportRenderer(typeof(ARView), 
  typeof(ARViewRenderer))]
  namespace WhackABox.Droid.Renderers
 {
     public class ARViewRenderer : ViewRenderer<ARView,  
     Android.Views.View>
     {
         private UrhoSurfacePlaceholder surface;
         public ARViewRenderer(Context context) : base(context)
         {
             MessagingCenter.Subscribe<MainActivity>(this,  
             "OnResume", async (sender) =>
             {
                 await Initialize();
             });
         }

         protected async override void 
         OnElementChanged(ElementChangedEventArgs<ARView> e)
         {
             base.OnElementChanged(e);

             if (Control == null)
             {
                 await Initialize();
             }
         }

         private async Task Initialize()
         {
             if (ContextCompat.CheckSelfPermission(Context, 
                 Manifest.Permission.Camera) != Permission.Granted)
             {
                 ActivityCompat.RequestPermissions(Context as  
                 Activity, new[] { Manifest.Permission.Camera },  
                 42);
                 return;
             }

             if (surface != null)
                 return;

             surface = UrhoSurface.CreateSurface(Context as 
             Activity);
             SetNativeControl(surface);

             await surface.Show<Game>();
         }
     }
 }

```

这个自定义渲染器也继承自`ViewRenderer<T1, T2>`，其中第一个类型是渲染器本身的类型，第二个是渲染器将生成的本地控件的类型。在这种情况下，本地控件将是一个继承自`Android.Views.View`的控件。渲染器创建一个`UrhoSurfacePlaceholder`实例，并将其分配为本地控件。`UrhoSurfacePlaceholder`是一个包装`Urho`在 Android 上使用的**Simple DirectMedia Layer**（**SDL**）库的一些功能的类，用于访问媒体功能。它的最后一步是基于即将存在的`Game`类启动游戏。我们将在本章的下一部分中定义这个类。

# 创建游戏

要编写一个使用`Urho`的应用程序，我们需要创建一个从`Urho.Application`继承的类。这个类定义了一些虚拟方法，我们可以用来设置场景。我们将使用的方法是`Start()`。然而，在那之前，我们需要创建这个类。这个类将被分成三个文件，使用部分类来描述，如下列表所述：

+   `Game.cs`文件中将包含跨平台的代码

+   `Game.iOS.cs`文件中将包含仅在应用的 iOS 版本中编译的代码

+   `Game.Android.cs`文件中将包含仅在应用的 Android 版本中编译的代码

我们将使用条件编译来实现。我们在项目介绍中讨论了条件编译。简单来说，这意味着我们可以使用称为**预处理指令**的东西来确定在编译时是否应该包含代码。实际上，这意味着我们将通过在`Game.iOS.cs`和`Game.Android.cs`中定义相同的`InitializeAR()`方法来在 Android 和 iOS 中编译不同的代码。在初始化期间，我们将调用此方法，并且根据我们在其上运行的平台，它将以不同的方式实现。这只能通过共享项目完成。

Visual Studio 对条件编译有很好的支持，并且将根据您设置为启动项目的项目或您在代码文件本身上方的工具栏中选择的项目来解析正确的引用。

对于这个项目，我们可以将`Game.iOS.cs`文件移动到 iOS 项目中，将`Game.Android.cs`文件移动到 Android 项目中，并删除条件编译预处理语句。应用程序将编译正常，但为了学习如何工作，我们将把它们包含在共享项目中。这也可能是一个积极的事情，因为我们将相关代码聚集在一起，使架构更容易理解。

# 添加共享的部分 Game 类

我们首先创建包含共享代码的`Game.cs`文件。让我们通过以下步骤设置这个：

1.  在`WhackABox`项目中，在项目的根目录下创建一个名为`Game.cs`的新文件。

1.  将以下代码添加到类中：

```cs
using System;
using System.Linq;
using Urho;
using Urho.Shapes;

namespace WhackABox
{
    public partial class Game : Application
    {
        private Scene scene; 

        public Game(ApplicationOptions options) : base(options)
        {
        } 
    }
}
```

首先要注意的是类中的`partial`关键字。这告诉编译器这不是整个实现，还会在其他文件中存在更多的代码。那些文件中的代码将被视为在这个文件中; 这是将大型实现拆分成不同文件的好方法。

`Game`继承自`Urho.Application`，它将处理关于游戏本身的大部分工作。我们定义了一个名为`scene`的`Scene`类型的属性。在`Urho`中，`Scene`代表游戏的一个屏幕（例如，我们可以为游戏的不同部分或菜单定义不同的场景）。在这个游戏中，我们只会定义一个场景，稍后将对其进行初始化。一个`scene`维护了组成它的节点的层次结构，每个节点可以有任意数量的子节点和任意数量的组件。它是组件在工作。例如，稍后我们将渲染盒子，这将由一个附加了`Box`组件的节点表示。

`Game`类本身是从我们在前面部分定义的自定义渲染器中实例化的，并且它在构造函数中以`ApplicationOptions`实例作为参数。这需要传递给基类。现在我们需要编写一些将是 AR 特定的并且将在以后编写的代码中使用的方法。

# CreateSubPlane

第一个方法是`CreateSubPlane()`方法。当应用程序找到可以放置对象的平面时，它将创建一个节点。我们很快将为每个平台编写该代码。该节点还定义了一个子平面，将定位一个代表该平面位置和大小的盒子。我们已经在本章前面定义了`PlaneNode`类。

让我们通过以下步骤添加代码：

1.  在`WhackABox`项目中，打开`Game.cs`类。

1.  将以下`CreateSubPlane()`方法添加到类中：

```cs
private void CreateSubPlane(PlaneNode planeNode)
{
    var node = planeNode.CreateChild("subplane");
    node.Position = new Vector3(0, 0.05f, 0);

    var box = node.CreateComponent<Box>();
    box.Color = Color.FromHex("#22ff0000");
} 
```

任何从**`Urho.Node`**继承的类，比如`PlaneNode`，都有`CreateChild()`方法。这允许我们创建一个子节点并为该节点指定一个名称。稍后将使用该名称来查找特定的子节点执行操作。我们将节点定位在与父节点相同的位置，只是将其提高`0.05`米（5 厘米）以上平面。

为了看到平面，我们添加了一个半透明红色的`box`组件。`box`是通过在我们的节点上调用`CreateComponent()`创建的组件。颜色以 AARRGGBB 模式定义，其中 AA 是 alpha 分量（透明度），RRGGBB 是标准的红绿蓝格式。我们使用颜色的十六进制表示。

# UpdateSubPlane

ARKit 和 ARCore 都会持续更新平面。我们感兴趣的是子平面位置和其范围的变化。通过扩展，我们指的是平面的大小。让我们通过以下步骤来设置这个：

1.  在`WhackABox`项目中，打开`Game.cs`类。

1.  在`Game.cs`类的任何位置添加`UpdateSubPlane()`方法，如下面的代码所示：

```cs
private void UpdateSubPlane(PlaneNode planeNode, Vector3 position)
{
    var subPlaneNode = planeNode.GetChild("subplane");
    subPlaneNode.Scale = new Vector3(planeNode.ExtentX, 0.05f, 
    planeNode.ExtentZ);
    subPlaneNode.Position = position;
}
```

该方法接受我们想要更新的`PlaneNode`以及一个新的位置。我们通过查询当前节点中名为`"subplane"`的任何节点来定位子平面。请记住，我们在`AddSubPlane()`方法中命名了子平面。现在我们可以很容易地通过名称访问节点。我们通过从`PlaneNode`中获取`ExtentX`和`ExtentZ`属性来更新子平面节点的比例。在调用`UpdateSubPlane()`之前，平面节点将通过一些特定于平台的代码进行更新。最后，我们将子平面的位置设置为传递的`position`参数。

# FindNodeByPlaneId

我们需要一个快速找到节点的方法。ARKit 和 ARCore 都会持续更新平面。我们感兴趣的是子平面位置和其范围的变化。通过扩展，我们指的是平面的大小。让我们通过以下步骤来设置这个：

`PlaneNode`是一个`string`，因为 ARKit 以类似**全局唯一标识符**（**GUID**）的形式定义了平面 ID。GUID 是一系列十六进制数字的结构化序列，可以以`string`格式表示，如下面的代码所示：

```cs
private PlaneNode FindNodeByPlaneId(string planeId) =>
                    scene.Children.OfType<PlaneNode>()
                    .FirstOrDefault(e => e.PlaneId == planeId); 
```

该方法使用`Linq`查询场景，并查找具有给定平面 ID 的第一个子节点。如果找不到，则返回`null`，因为`null`是引用类型对象的默认值。

这些都是我们在共享代码中下降到 ARKit 和 ARCore 之前需要的所有方法。

# 添加特定于平台的部分类

现在是利用条件编译的时候了。我们将创建两个部分类，一个用于 iOS，一个用于 Android，它们将有条件地编译到`Game`类中。

在这一部分，我们将简单地为这些文件设置骨架代码。

# 添加特定于 iOS 的部分类

让我们从在 iOS 上创建`Game`的`partial`类开始，并将整个代码文件包装在一个预处理指令中，指定这段代码只会在 iOS 上编译：

1.  在`WhackABox`项目中，添加一个名为`Game.iOS.cs`的新文件。

1.  如果 Visual Studio 没有自动完成，可以在代码中重命名`Game`类。

1.  使类`public`和`partial`。

1.  添加`#if`和`#endif`预处理指令，以允许条件编译，如下面的代码所示：

```cs
#if __IOS__ 
namespace WhackABox
{
    public partial class Game
    {
    }
}
#endif
```

代码的第一行是一个预处理指令，编译器将使用它来确定`#if`和`#endif`指令内的代码是否应该包含在编译中。如果包含，将定义一个`partial`类。这个类中的代码可以是特定于 iOS 的，即使我们在共享项目中定义它。Visual Studio 足够智能，可以将这个部分中的任何代码视为直接存在于 iOS 项目中。在这里实例化`UIView`不会有问题，因为该代码永远不会被编译到除 iOS 之外的任何平台。

# 添加特定于 Android 的部分类

同样适用于 Android：只有文件名和预处理指令会改变。让我们通过以下步骤来设置这个：

1.  在`WhackABox`项目中，添加一个名为`Game.Android.cs`的新文件。

1.  如果 Visual Studio 没有自动完成，就在代码中重命名`Game`类。

1.  使类`public`和`partial`。

1.  添加`#if`和`#endif`条件编译语句，如下面的代码所示：

```cs
#if __ANDROID__namespace WhackABox
{
    public partial class Game
    { 
    }
}
#endif
```

与 iOS 一样，只有在`#if`和`#endif`语句之间才会编译 Android 的代码。

现在让我们开始添加一些特定于平台的代码。

# 编写 ARKit 特定的代码

在本节中，我们将为 iOS 编写特定于平台的代码，该代码将初始化 ARKit，查找平面，并创建节点以供 UrhoSharp 在屏幕上渲染。我们将利用一个在 iOS 中包装 ARKit 的`Urho`组件。我们还将编写所有将定位、添加和移除节点的函数。ARKit 使用`anchors`，它们充当将叠加的图形粘合到现实世界的虚拟点。我们特别寻找`ARPlaneAnchor`，它代表 AR 世界中的平面。还有其他类型的锚点可用，但对于这个应用程序，我们只需要找到水平平面。

让我们首先定义`ARKitComponent`，以便以后可以使用它。

# 定义 ARKitComponent

我们首先添加一个将在稍后初始化的`ARKitComponent`的`private`字段。让我们通过以下步骤设置这一点：

1.  在`WhackABox`项目中，打开`Game.iOS.cs`。

1.  添加一个持有`ARKitComponent`的`private`字段，如下面的代码中所示：

```cs
#if __IOS__using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using ARKit;
using Urho;
using Urho.iOS;

namespace WhackABox
{
    public partial class Game
    {
        private ARKitComponent arkitComponent;
    }
}
#endif
```

确保添加所有`using`语句，以确保我们后来使用的所有代码都解析正确的类型。

# 编写用于添加和更新锚点的处理程序

现在我们将添加必要的代码，以添加和更新锚点。我们还将添加一些方法来帮助设置节点在 ARKit 更新锚点后的方向。

# SetPositionAndRotation

`SetPositionAndRotation()`方法将被添加和更新锚点使用，因此我们需要在创建由 ARKit 引发的事件处理程序之前定义它。让我们通过以下步骤设置这一点：

1.  在`WhackABox`项目中，打开`Game.iOS.cs`文件。

1.  按照下面的代码，在类中添加`SetPositionAndRotation()`方法：

```cs
private void SetPositionAndRotation(ARPlaneAnchor anchor, PlaneNode 
                                    node)
{
     arkitComponent.ApplyOpenTkTransform(node, anchor.Transform, 
                                         true);

     node.ExtentX = anchor.Extent.X;
     node.ExtentZ = anchor.Extent.Z;

     var position = new Vector3(anchor.Center.X, anchor.Center.Y, -
                                anchor.Center.Z);
     UpdateSubPlane(node, position);
} 
```

该方法接受两个参数。第一个是由 ARKit 定义的`ARPlaneAnchor`，第二个是我们在场景中拥有的`PlaneNode`。该方法的目的是确保`PlaneNode`与 ARKit 传递的`ARPlaneAnchor`对象同步。`arkitComponent`有一个名为`ApplyOpenTkTransform()`的辅助方法，将`ARPlaneAnchor`对象的位置和旋转转换为`Urho`使用的位置和旋转对象。然后我们更新平面的`Extent`（大小）到`PlaneNode`，并从`ARPlaneAnchor`获取`anchor`中心位置。最后，我们调用之前定义的方法来更新持有`Box`组件的子平面节点，该组件将实际将平面渲染为半透明红色框。

我们需要一个处理更新和添加功能的方法。

# 更新或添加平面节点

`UpdateOrAddPlaneNode()`正如其名称所示：它以`ARPlaneAnchor`作为参数，要么更新要么添加一个新的`PlaneNode`到`scene`。让我们通过以下步骤设置这一点：

1.  在`WhackABox`项目中，打开`Game.iOS.cs`文件。

1.  按照下面的代码描述，添加`UpdateOrAddPlaneNode()`方法：

```cs
private void UpdateOrAddPlaneNode(ARPlaneAnchor anchor)
{
    var node = FindNodeByPlaneId(anchor.Identifier.ToString());

    if (node == null)
    {
        node = new PlaneNode()
        {
            PlaneId = anchor.Identifier.ToString(),
            Name = $"plane{anchor.GetHashCode()}"
        };

        CreateSubPlane(node);
        scene.AddChild(node);
    }

    SetPositionAndRotation(anchor, node);
} 
```

一个节点要么已经存在于场景中，要么需要被添加。代码的第一行调用`FindNodeByPlaneId()`来查询具有给定`PlaneId`的对象。对于 iOS，我们使用`anchor.Identifier`属性来跟踪 iOS 定义的平面。如果这个调用返回`null`，这意味着该平面不在场景中，我们需要创建它。为此，我们实例化一个新的`PlaneNode`，给它一个`PlaneId`和一个用于调试目的的用户友好的名称。然后我们通过调用`CreateSubPlane()`来创建子平面来可视化平面本身，我们之前定义过，并将节点添加到`scene`中。最后，我们更新位置和旋转。对于每次调用`UpdateOrAddPlaneNode()`方法，我们都这样做，因为对于新节点和现有节点来说都是一样的。现在是时候编写我们最终将直接连接到 ARKit 的处理程序了。

# OnAddAnchor

让我们添加一些代码。`OnAddAnchor()`方法将在每次 ARKit 更新描述我们在虚拟世界中使用的点的锚点集合时被调用。我们特别寻找`ARPlaneAnchor`类型的锚点。

通过以下两个步骤在`Game.iOS.cs`类中添加`OnAddAnchor()`方法：

1.  在`WhackABox`项目中，打开`Game.iOS.cs`文件。

1.  在类中的任何地方添加`OnAddAnchor()`方法，如下面的代码所示：

```cs
private void OnAddAnchor(ARAnchor[] anchors)
{
    foreach (var anchor in anchors.OfType<ARPlaneAnchor>())
    {
        UpdateOrAddPlaneNode(anchor);
    }
}
```

该方法以`ARAnchors`数组作为参数。我们过滤出`ARPlaneAnchor`类型的锚点，并遍历列表。对于每个`ARPlaneAnchor`，我们调用之前创建的`UpdateOrAddPlaneNode()`方法来向场景中添加一个节点。现在让我们为 ARKit 想要更新锚点时做同样的事情。

# OnUpdateAnchors

每当 ARKit 接收到关于锚点的新信息时，它将调用此方法。我们与之前的代码一样，遍历列表以更新场景中`anchor`的范围和位置：

1.  在`WhackABox`项目中，打开`Game.iOS.cs`文件。

1.  在类中的任何地方添加`OnUpdateAnchors()`方法，如下面的代码所示：

```cs
private void OnUpdateAnchors(ARAnchor[] anchors)
{
    foreach (var anchor in anchors.OfType<ARPlaneAnchor>())
    {
        UpdateOrAddPlaneNode(anchor);
    }
}
```

该代码是`OnAddAnchors()`方法的副本。它根据 ARKit 提供的信息更新场景中的所有节点。

我们还需要编写一些代码来移除 ARKit 已经移除的锚点。

# 编写一个处理移除锚点的处理程序

当 ARKit 决定一个锚点无效时，它将从场景中移除它。这种情况并不经常发生，但处理这个调用是一个好习惯。

# OnRemoveAnchors

让我们通过以下步骤添加一个处理移除`ARPlaneAnchor`的方法：

1.  在`WhackABox`项目中，打开`Game.iOS.cs`文件。

1.  在类中的任何地方添加`OnRemoveAnchors()`方法，如下面的代码所示：

```cs
private void OnRemoveAnchors(ARAnchor[] anchors)
{
    foreach (var anchor in anchors.OfType<ARPlaneAnchor>())
    {
        FindNodeByPlaneId(anchor.Identifier.ToString())?.Remove();
    }
} 
```

与`Add`和`Remove`函数一样，这个方法接受一个`ARAnchor`数组。我们遍历这个数组，寻找`ARPlaneAnchor`类型的锚点。然后我们调用`FindNodeByPlaneId()`方法寻找表示这个平面的节点。如果不是`null`，那么我们调用移除该节点。请注意在`Remove()`调用之前的空值检查运算符。

# 初始化 ARKit

现在我们来到了 iOS 特定代码的最后部分，这是我们初始化 ARKit 的地方。这个方法叫做`InitializeAR()`，不需要参数。它与 Android 的方法相同，但由于它们永远不会同时编译，因为使用了条件编译，调用这个方法的代码将不会知道区别。

初始化 ARKit 的代码很简单，`ARKitComponent`为我们做了很多工作。让我们通过以下步骤设置它：

1.  在`WhackABox`项目中，打开`Game.iOS.cs`文件。

1.  在类中的任何地方添加`InitializeAR()`方法，如下面的代码所示：

```cs
private void InitializeAR()
{
    arkitComponent = scene.CreateComponent<ARKitComponent>();
    arkitComponent.Orientation = 
    UIKit.UIInterfaceOrientation.Portrait;
    arkitComponent.ARConfiguration = new 
    ARWorldTrackingConfiguration
    {
        PlaneDetection = ARPlaneDetection.Horizontal
    };
    arkitComponent.DidAddAnchors += OnAddAnchor;
    arkitComponent.DidUpdateAnchors += OnUpdateAnchors;
    arkitComponent.DidRemoveAnchors += OnRemoveAnchors;
    arkitComponent.RunEngineFramesInARKitCallbakcs = 
    Options.DelayedStart;
    arkitComponent.Run();
} 
```

代码首先创建了一个`ARKitComponent`。然后我们设置了允许的方向，并创建了一个`ARWorldTrackingConfiguration`类，说明我们只对水平平面感兴趣。为了响应平面的添加、更新和移除，我们附加了之前创建的事件处理程序。

我们指示 ARKit 组件延迟调用回调函数，以便 ARKit 能够正确初始化。请注意`RunEngineFramesInARKitCallbakcs`属性中的拼写错误。这是一个很好的例子，说明为什么需要对代码进行审查，因为更改这个名称将很难保持向后兼容。命名是困难的。

最后一件事是告诉 ARKit 开始运行。我们通过调用`arkitComponent.Run()`方法来实现这一点。

# 编写特定于 ARCore 的代码

现在是时候为 Android 与 ARCore 做同样的事情了。就像 iOS 一样，我们将把所有特定于 Android 的代码放在自己的文件中。这个文件就是我们之前创建的`Game.Android.cs`。

# 定义 ARCoreComponent

首先，我们将添加一个字段，用于存储对`ARCoreComponent`的引用。这个组件包装了与 ARCore 的大部分交互。`ARCoreComponent`定义在我们在本章开头安装的 UrhoSharp.ARCore NuGet 包中。

通过以下步骤添加一些`using`语句和字段：

1.  在`WhackABox`项目中，打开`Game.Android.cs`文件。

1.  按照以下代码描述添加`arCore`私有字段。同时确保添加了粗体标记的`using`语句：

```cs
#if __ANDROID__
using Com.Google.AR.Core;
using Urho;
using Urho.Droid;

namespace WhackABox
{
    public partial class Game
    {
        private ARCoreComponent arCore;
    }
}
#endif

```

`using`语句将允许我们在这个文件中解析所需的类型，而`arCore`属性将是我们在访问 ARCore 函数时的简写。

我们将继续向这个类添加一些方法。

# SetPositionAndRotation

每当检测到或更新平面时，我们需要添加或更新一个`PlaneNode`。`SetPositionAndRotation()`方法会更新传递的`PlaneNode`，并根据`AR.Core.Plane`对象的内容设置该节点的属性。让我们通过以下步骤来设置这一点：

1.  在`WhackABox`项目中，打开`Game.Android.cs`文件。

1.  按照以下代码在类中添加`SetPositionAndRotation()`方法：

```cs
private void SetPositionAndRotation(Com.Google.AR.Core.Plane plane,  
                                    PlaneNode node)
{
    node.ExtentX = plane.ExtentX;
    node.ExtentZ = plane.ExtentZ;
    node.Rotation = new Quaternion(plane.CenterPose.Qx(),
                                   plane.CenterPose.Qy(),
                                   plane.CenterPose.Qz(),
                                   -plane.CenterPose.Qw());

    node.Position = new Vector3(plane.CenterPose.Tx(),
                                plane.CenterPose.Ty(),
                                -plane.CenterPose.Tz());
}
```

前面的代码更新了节点的平面范围并创建了一个旋转`Quaternion`。如果你不知道`Quaternion`是什么，不要担心，很少有人知道，但它们似乎以一种非常灵活的方式神奇地保存了模型的旋转信息。`plane.CenterPose`属性是一个包含平面位置和方向的矩阵。最后，我们根据`CenterPose`属性更新节点的位置。

下一步是创建一个处理来自 ARCore 的帧更新的方法。

# 编写 ARFrame 更新的处理程序

Android 处理来自 ARCore 的更新与 ARKit 有些不同，后者暴露了三种不同的事件，用于添加、更新和移除节点。当使用 ARCore 时，我们会在任何更改发生时被调用，而将处理这些更改的处理程序将是我们即将添加的处理程序。

通过以下步骤添加该方法：

1.  在`WhackABox`项目中，打开`Game.Android.cs`文件。

1.  按照以下代码在类中的任何位置添加`OnARFrameUpdated()`方法：

```cs
private void OnARFrameUpdated(Frame arFrame)
{
    var all = arCore.Session.GetAllTrackables(
                  Java.Lang.Class.FromType(
                  typeof(Com.Google.AR.Core.Plane)));

    foreach (Com.Google.AR.Core.Plane plane in all)
    {
        var node = 
        FindNodeByPlaneId(plane.GetHashCode().ToString());

        if (node == null)
        {
            node = new PlaneNode
            {
                PlaneId = plane.GetHashCode().ToString(),
                Name = $"plane{plane.GetHashCode()}"
            };

            CreateSubPlane(node);
            scene.AddChild(node);
        }

        SetPositionAndRotation(plane, node);
        UpdateSubPlane(node, Vector3.Zero);
    }
} 
```

我们首先查询`arCore`组件跟踪的所有平面。然后我们遍历这个列表，通过调用`FindNodeByPlaneId()`方法，使用平面的哈希码作为标识符，来查看我们在场景中是否有任何节点。如果找不到任何节点，我们就创建一个新的`PlaneNode`，并将哈希码分配为`PlaneId`。然后我们创建一个包含`Box`组件以可视化平面的子平面，最后将其添加到场景中。然后我们更新平面的位置和旋转，并调用更新子平面。现在我们已经编写了处理程序，需要将其连接起来。

# 初始化 ARCore

为了初始化 ARCore，我们将添加两种方法。第一种是一个方法，负责 ARCore 的配置，称为“OnConfigRequested（）”。第二种是将从共享的`Game`类中稍后调用的“InitializeAR（）”方法。这个方法也在 iOS 特定的代码中定义，但是正如我们之前讨论的，当我们为 Android 编译时，这个方法在 iOS 中永远不会被编译，因为我们使用条件编译，它会过滤掉未选择平台的代码。

# OnConfigRequested

ARCore 需要知道一些东西，就像 iOS 一样。在 Android 中，这是通过定义一个 ARCore 组件在初始化时调用的方法来完成的。要创建该方法，请按照以下步骤进行：

1.  在`WhackABox`项目中，打开`Game.Android.cs`文件。

1.  在类中的任何位置添加“OnConfigRequested（）”方法，如下面的代码所示：

```cs
private void OnConfigRequested(Config config)
{
    config.SetPlaneFindingMode(Config.PlaneFindingMode.Horizontal);
    config.SetLightEstimationMode

    (Config.LightEstimationMode.AmbientIntensity);
    config.SetUpdateMode(Config.UpdateMode.LatestCameraImage);
} 
```

该方法接受一个`Config`对象，该对象将存储您在此方法中进行的任何配置。首先，我们设置要查找的平面类型。对于这个游戏，我们对“水平”平面感兴趣。我们定义要使用的光估计模式的类型，最后，我们选择要使用的更新模式。在这种情况下，我们要使用最新的相机图像。您可以在配置期间进行很多微调，但这超出了本书的范围。一定要查看 ARCore 的文档，了解更多关于它强大功能的信息。

现在我们已经有了初始化 ARCore 所需的所有代码。

# InitializeAR

如前所述，“InitializeAR（）”方法与 iOS 特定的代码共享相同的名称，但由于使用条件编译，编译器只会在构建中包含其中一个。让我们按照以下步骤设置这个：

1.  在`WhackABox`项目中，打开`Game.Android.cs`文件。

1.  在类中的任何位置添加“InitializeAR（）”方法，如下面的代码所示：

```cs
private void InitializeAR()
{
    arCore = scene.CreateComponent<ARCoreComponent>();
    arCore.ARFrameUpdated += OnARFrameUpdated;
    arCore.ConfigRequested += OnConfigRequested;
    arCore.Run();
} 
```

第一步是创建 UrhoSharp 提供的`ARCoreComponent`。这个组件包装了本地 ARCore 类的初始化。然后我们添加两个事件处理程序：一个用于处理帧更新，一个在初始化期间调用。我们做的最后一件事是在`ARCoreComponent`上调用“Run（）”方法，以开始跟踪世界。

现在我们已经配置好了 ARKit 和 ARCore，准备开始编写实际的游戏了。

# 编写游戏

在这一部分，我们将通过设置相机、灯光和渲染器来初始化 Urho。相机是确定对象渲染位置的对象。AR 组件负责更新相机的位置，以虚拟跟踪您的手机，以便我们渲染的任何对象都在与您所看到的相同的坐标空间中。首先，我们需要一个相机，它将是场景的观察点。

# 添加相机

添加相机是一个简单的过程，如下面的步骤所示：

1.  在`WhackABox`项目中，打开`Game.cs`文件。

1.  在类中添加“相机”属性，如下面的代码所示。您应该将其放在类本身的声明之后，但在类内的任何位置放置它都可以。

1.  在类中的任何位置添加“InitializeCamera（）”方法，如下面的代码所示：

```cs
private Camera camera; 

private void InitializeCamera()
{
    var cameraNode = scene.CreateChild("Camera");
    camera = cameraNode.CreateComponent<Camera>();
} 
```

在 UrhoSharp 中，一切都是一个节点，就像在 Unity 中一切都是一个 GameObject，包括“相机”。我们创建一个新节点，称为“相机”，然后在该节点上创建一个“相机”组件，并保留对它的引用以供以后使用。

# 配置渲染器

UrhoSharp 需要将场景渲染到一个“视口”中。一个游戏可以有多个视口，基于多个摄像头。想象一下你开车的游戏。主要的“视口”将是驾驶员视角的游戏。另一个“视口”可能是后视镜，实际上它们本身就是摄像头，将它们所看到的渲染到主“视口”上。让我们按照以下步骤设置这个：

1.  在`WhackABox`项目中，打开`Game.cs`文件。

1.  添加`viewport`属性到类中，如下面的代码所示。您应该将其放在类本身的声明之后，但在类内的任何位置放置它都可以。

1.  在类中的任何位置添加`InitializeRenderer()`方法，如下面的代码所示：

```cs
private Viewport viewport; 

private void InitializeRenderer()
{
    viewport = new Viewport(Context, scene, camera, null);
    Renderer.SetViewport(0, viewport);
}
```

`viewport`属性将保存对`viewport`的引用，以备后用。`viewport`是通过实例化一个新的`viewport`类来创建的。该类的构造函数需要基类提供的`Context`，在初始化游戏时我们将创建的`scene`，一个相机以知道从空间的哪个点进行渲染，以及一个渲染路径，默认为`null`。渲染路径允许在渲染时对帧进行后处理。这也超出了本书的范围，但也值得一看。

现在，让光明存在。

# 添加光

为了使对象可见，我们需要定义一些光照。我们通过创建一个定义游戏中我们想要的光照类型的方法来实现这一点。让我们通过以下步骤来设置这一点：

1.  在`WhackABox`项目中，打开`Game.cs`文件。

1.  在类中的任何位置添加`InitializeLights()`方法，如下面的代码所示：

```cs
private void InitializeLights()
{
    var lightNode = camera.Node.CreateChild();
    lightNode.SetDirection(new Vector3(1f, -1.0f, 1f));
    var light = lightNode.CreateComponent<Light>();
    light.Range = 10;
    light.LightType = LightType.Directional;
    light.CastShadows = true;
    Renderer.ShadowMapSize *= 4;
} 
```

同样，UrhoSharp 中的一切都是节点，光也不例外。我们通过访问存储的相机组件并访问它所属的节点，在相机节点上创建一个通用节点。然后我们设置该节点的方向并创建一个`Light`组件来定义光。光的范围将是 10 个单位的长度。类型是方向性的，这意味着它将从节点的位置沿着定义的方向发光。它还将投射阴影。我们将`ShadowMapSize`设置为默认值的四倍，以给阴影贴图更多的分辨率。

在这一点上，我们已经有了初始化 UrhoSharp 和 AR 组件所需的一切。

# 实现游戏启动

`Game`类的基类提供了一些虚拟方法，我们可以重写。其中之一是`Start()`，它将在自定义渲染器设置`UrhoSurface`后不久被调用。

通过以下步骤添加方法：

1.  在`WhackABox`项目中，打开`Game.cs`文件。

1.  在类中的任何位置添加`Start()`方法，如下面的代码所示：

```cs
protected override void Start()
{
   scene = new Scene(Context);
   var octree = scene.CreateComponent<Octree>();

    InitializeCamera();
    InitializeLights();
    InitializeRenderer();

    InitializeAR();
} 
```

我们一直在谈论的场景是在这个方法的第一行创建的。这是我们在运行 UrhoSharp 时看到的场景。它跟踪我们添加到其中的所有节点。UrhoSharp 中的所有 3D 游戏都需要一个`Octree`，这是一个实现空间分区的组件。它被 3D 引擎用来在 3D 空间中快速找到对象，而不必在每一帧中查询每一个对象。方法的第二行直接在场景上创建了这个组件。

接下来，我们有四种方法来初始化相机、灯光和渲染器，并调用两种`InitializeAR()`方法中的一种，这取决于我们正在编译的平台。如果此时启动应用程序，您应该会看到它找到平面并对其进行渲染，但没有其他操作。是时候添加一些与之交互的东西了。

# 添加框

我们现在要专注于向我们的增强现实世界添加虚拟框。我们将编写两种方法。第一个是`AddBox()`方法，它将在平面上的随机位置添加一个新框。第二个是`OnUpdate()`方法的重写，UrhoSharp 在每帧调用它来执行游戏逻辑。

# AddBox()

要向平面添加框，我们需要添加一个方法来实现。这个方法叫做`AddBox()`。让我们通过以下步骤来设置这一点：

1.  在`WhackABox`项目中，打开`Game.cs`文件。

1.  在类中添加`random`属性（最好在顶部，但在类的任何位置都可以）。

1.  在类中的任何位置添加`AddBox()`方法，如下面的代码所示：

```cs
private static Random random = new Random(); 

private void AddBox(PlaneNode planeNode)
{
    var subPlaneNode = planeNode.GetChild("subplane");

    var boxNode = planeNode.CreateChild("Box");
    boxNode.SetScale(0.1f);

    var x = planeNode.ExtentX * (float)(random.NextDouble() - 0.5f);
    var z = planeNode.ExtentZ * (float)(random.NextDouble() - 0.5f);

    boxNode.Position = new Vector3(x, 0.1f, z) +  
    subPlaneNode.Position;

    var box = boxNode.CreateComponent<Box>();
    box.Color = Color.Blue;
} 
```

我们创建的静态`random`对象将用于随机化平面上方块的位置。我们想要使用静态的`Random`实例，因为我们不想冒险创建可能以相同值进行种子化的多个实例，因此返回完全相同的随机数序列。该方法首先通过调用`planeNode.GetChild("subplane")`找到我们传入的`PlaneNode`实例的子平面。然后我们创建一个将渲染方块的节点。为了使方块适应世界，我们需要将比例设置为`0.1`，这将使其大小为 10 厘米。

然后，我们使用`ExtentX`和`ExtentZ`属性随机化方块的位置，乘以一个介于`0`和`1`之间的新随机值，我们首先从中减去`0.5`。这是为了使位置居中，因为父节点的位置是平面的中心。然后，我们将方块节点的位置设置为随机位置，并且在平面上方 0.1 个单位。我们还需要添加子平面的位置，因为它可能与父节点有一点偏移。最后，我们添加要渲染的实际方块，并将颜色设置为蓝色。

现在让我们添加代码来调用`AddBox()`方法，基于一些游戏逻辑。

# OnUpdate()

大多数游戏使用游戏循环。这会调用一个`Update()`方法，该方法接受输入并计算游戏的状态。UrhoSharp 也不例外。我们游戏的基类有一个虚拟的`OnUpdate()`方法，我们可以覆盖它，以便我们可以编写每帧都会执行的代码。这个方法经常被调用，通常大约每秒 50 次。

现在我们将覆盖`Update()`方法，添加游戏逻辑，每隔一秒添加一个新的方块。让我们通过以下步骤设置这个逻辑：

1.  在`WhackABox`项目中，打开`Game.cs`文件。

1.  将`newBoxTtl`字段和`newBoxIntervalInSeconds`字段添加到代码顶部的类中。

1.  在类中的任何位置添加`OnUpdate()`方法，如下面的代码所示：

```cs
private float newBoxTtl;
private readonly float newBoxIntervalInSeconds = 2; 

protected override void OnUpdate(float timeStep)
{
    base.OnUpdate(timeStep);

    newBoxTtl -= timeStep;

    if (newBoxTtl < 0)
    {
        foreach (var node in scene.Children.OfType<PlaneNode>())
        {
            AddBox(node);
        }

        newBoxTtl += newBoxIntervalInSeconds;
    }
} 
```

第一个字段`newBoxTtl`，其中`Ttl`是**存活时间**（**TTL**），是一个内部计数器，将减去自上一帧以来经过的毫秒数。当它低于`0`时，我们将向场景的每个平面添加一个新的方块。我们通过查询场景的`Children`集合并仅返回`PlaneNode`类型的子项来找到所有`PlaneNode`的实例。第二个字段`newBoxIntervalInSeconds`表示`newBoxTtl`达到`0`后我们将添加多少秒到`newBoxTtl`。为了知道自上一帧以来经过了多少时间，我们使用 UrhoSharp 传递给`OnUpdate()`方法的`timeStep`参数。该参数的值是自上一帧以来的秒数。通常是一个小值，如果更新循环以每秒 50 帧运行，它将是`0.016`。它可能会有所不同，这就是为什么您会想要使用这个值来进行`newBoxTtl`的减法运算。

如果现在运行游戏，您将看到方块出现在检测到的平面上。但是，我们仍然无法与它们交互，它们看起来相当无聊。让我们继续使它们旋转。

# 使方块旋转

您可以通过创建一个从`Urho.Component`继承的类来向 UrhoSharp 添加自己的组件。我们将创建一个组件，使方块围绕三个轴旋转。

# 创建旋转组件

正如我们提到的，组件是从`Urho.Component`继承的类。这个基类定义了一个名为`OnUpdate()`的虚拟方法，其行为与`Game`类本身的`Update()`方法相同。这使我们能够向组件添加逻辑，以便它可以修改它所属节点的状态。

让我们通过以下步骤创建`rotate`组件：

1.  在`WhackABox`项目中，在项目的根目录中创建一个名为`Rotator.cs`的新类。

1.  添加以下代码：

```cs
using Urho;

namespace WhackABox
{
    public class Rotator : Component
    {
        public Vector3 RotationSpeed { get; set; }

        public Rotator()
        {
            ReceiveSceneUpdates = true;
        }

        protected override void OnUpdate(float timeStep)
        {
            Node.Rotate(new Quaternion(
                RotationSpeed.X * timeStep,
                RotationSpeed.Y * timeStep,
                RotationSpeed.Z * timeStep),
                TransformSpace.Local);
        }
    }
}
```

`RotationSpeed`属性将用于确定围绕任何特定轴的旋转速度。当我们在下一步中将组件分配给箱子节点时，它将被设置。为了使组件能够在每一帧接收到对`OnUpdate()`方法的调用，我们需要将`ReceiveSceneUpdates`属性设置为`true`。如果不这样做，组件将不会在每次更新时被 UrhoSharp 调用。出于性能原因，默认情况下它被设置为`false`。

所有有趣的事情都发生在`OnUpdate()`方法的`override`中。我们创建一个新的四元数来表示新的旋转状态。同样，我们不需要详细了解这是如何工作的，只需要知道四元数属于高等数学的神秘世界。我们将`RotationSpeed`向量中的每个轴乘以`timeStep`来生成一个新值。`timeStep`参数是自上一帧以来经过的秒数。我们还将旋转定义为围绕此框的本地坐标空间。

现在组件已经创建，我们需要将它添加到箱子中。

# 分配 Rotator 组件

添加`Rotator`组件就像添加任何其他组件一样简单。让我们通过以下步骤来设置这个：

1.  在`WhackABox`项目中，打开`Game.cs`文件。

1.  更新`AddBox()`方法，通过在以下代码中加粗标记的代码来添加：

```cs
private void AddBox(PlaneNode planeNode)
{
    var subPlaneNode = planeNode.GetChild("subplane");

    var boxNode = planeNode.CreateChild("Box");
    boxNode.SetScale(0.1f);

    var x = planeNode.ExtentX * (float)(random.NextDouble() - 0.5f);
    var z = planeNode.ExtentZ * (float)(random.NextDouble() - 0.5f);

    boxNode.Position = new Vector3(x, 0.1f, z) + 
    subPlaneNode.Position;

    var box = boxNode.CreateComponent<Box>();
    box.Color = Color.Blue;

 var rotationSpeed = new Vector3(10.0f, 20.0f, 30.0f);
 var rotator = new Rotator() { RotationSpeed = rotationSpeed };
 boxNode.AddComponent(rotator);
} 
```

首先，我们通过创建一个新的`Vector3`结构并将其分配给一个名为`rotationSpeed`的新变量来定义我们希望箱子如何旋转。在这种情况下，我们希望它围绕*x*轴旋转`10`个单位，围绕*y*轴旋转`20`个单位，围绕*z*轴旋转`30`个单位。我们使用`rotationSpeed`变量来设置我们在添加的代码的第二行中实例化的`Rotator`组件的`RotationSpeed`属性。

最后，我们将组件添加到`box`节点。现在箱子应该以有趣的方式旋转。

# 添加箱子命中测试

现在我们有了不断堆叠的旋转箱子。我们需要添加一种方法来移除箱子。最简单的方法是添加一个功能，当我们触摸它们时移除箱子，但我们要比这更花哨一点：每当我们触摸一个箱子时，我们希望它在从场景中移除之前缩小并消失。为此，我们将使用我们新获得的组件知识，然后添加一些代码来确定我们是否触摸到一个箱子。

# 添加死亡动画

我们即将添加的`Death`组件与我们在上一节中创建的`Rotator`组件具有相同的模板。让我们通过以下步骤来添加它并查看代码：

1.  在`WhackABox`项目中，创建一个名为`Death.cs`的新类。

1.  用以下代码替换类中的代码：

```cs
 using Urho;
 using System;

 namespace WhackABox
 {
     public class Death : Component
     {
         private float deathTtl = 1f;
         private float initialScale = 1;

         public Action OnDeath { get; set; }

         public Death()
         {
             ReceiveSceneUpdates = true;
         }

         public override void OnAttachedToNode(Node node)
         {
             initialScale = node.Scale.X;
         }

         protected override void OnUpdate(float timeStep)
         {
             Node.SetScale(deathTtl * initialScale);

             if (deathTtl < 0)
             {
                 Node.Remove();
             }

             deathTtl -= timeStep;
         }
     }
 } 
```

我们首先定义两个字段。`deathTtl`字段确定动画持续的时间（以秒为单位）。`initialScale`字段在组件附加到节点时跟踪节点的比例。为了接收更新，我们需要在构造函数中将`ReceiveSceneUpdates`设置为`true`。当组件附加到节点时，将调用重写的`OnAttachedToNode()`方法。我们使用这个方法来设置`initialScale`字段。组件附加后，我们开始在每一帧上调用`OnUpdate()`。在每次调用时，我们根据`deathTtl`字段乘以`initialScale`字段设置节点的新比例。当`deathTtl`字段达到零时，我们将节点从场景中移除。如果我们没有达到零，那么我们减去自上一帧被调用以来的时间量，这是由`timeStep`参数给出的。现在我们需要做的就是弄清楚何时向箱子添加`Death`组件。

# DetermineHit()

我们需要一个方法，可以解释屏幕 2D 表面上的触摸，并使用从摄像机到我们正在查看的场景的虚拟射线来找出我们击中的箱子。这个方法叫做`DetemineHit`。让我们通过以下步骤来设置这个方法：

1.  在`WhackABox`项目中，打开`Game.cs`文件。

1.  在类中的任何位置添加`DetemineHit()`方法，如下面的代码所示：

```cs
private void DetermineHit(float x, float y)
{
    var cameraRay = camera.GetScreenRay(x, y);
    var result = scene.GetComponent<Octree>
    ().RaycastSingle(cameraRay);

    if (result?.Node?.Name?.StartsWith("Box") == true)
    {
        var node = result?.Node;

        if (node.Components.OfType<Death>().Any())
        {
            return;
        }

        node.CreateComponent<Death>();
    }
} 
```

传递给方法的`x`和`y`参数的范围是从`0`到`1`，其中`0`表示屏幕的左边缘或顶部边缘，`1`表示屏幕的右边缘或底部边缘。屏幕的确切中心将是`x=0.5`和`y=0.5`。由于我们想从相机获取一个射线，我们可以直接在相机组件上使用一个叫做`GetScreenRay()`的方法。它返回一个从场景中相机的射线，与相机设置的方向相同。我们使用这个射线，并将其传递给`Octree`组件的`RaycastSingle()`方法，如果命中，则返回一个包含单个节点的结果。

我们检查结果，执行多个空值检查，最后检查节点的名称是否以`Box`开头。如果是这样，我们检查我们击中的箱子是否已经注定，通过检查是否附加了`Death`组件来判断。如果有，我们`return`。如果没有，我们创建一个`Death`组件并让箱子死去。

到目前为止一切看起来都很好。现在我们需要一些东西来调用`DetermineHit()`方法。

# OnTouchBegin()

在 UrhoSharp 中，触摸被处理为事件，这意味着它们需要事件处理程序。让我们通过以下步骤为`TouchBegin`事件创建一个处理程序：

1.  在`WhackABox`项目中，打开`Game.cs`文件。

1.  在代码中的任何位置添加`OnTouchBegin()`方法，如下所示：

```cs
private void OnTouchBegin(TouchBeginEventArgs e)
{
    var x = (float)e.X / Graphics.Width;
    var y = (float)e.Y / Graphics.Height;

    DetermineHit(x, y);
}
```

当触摸被注册时，将调用此方法，并将有关该触摸事件的信息作为参数发送。此参数有一个`X`和一个`Y`属性，表示我们触摸的屏幕上的点。由于`DetermineHit()`方法希望值在`0`到`1`的范围内，我们需要将屏幕的宽度和高度除以`X`和`Y`坐标。

完成后，我们调用`DetermineHit()`方法。要完成这一部分，我们只需要连接事件。

# 连接输入

现在剩下的就是将事件连接到 UrhoSharp 的`Input`子系统。这是通过在`Start()`方法中添加一行代码来完成的，如下所示的步骤：

1.  在`WhackABox`项目中，打开`Game.cs`文件。

1.  在`Start()`方法中，添加以下代码片段中加粗的代码：

```cs
protected override void Start()
{
 scene = new Scene(Context);
 var octree = scene.CreateComponent<Octree>();

 InitializeCamera();
 InitializeLights();
 InitializeRenderer();

 Input.TouchBegin += OnTouchBegin;

 InitializeAR();
} 
```

这将`TouchBegin`事件连接到我们的`OnTouchBegin`事件处理程序。

如果现在运行游戏，当你点击它们时，箱子应该会动画并消失。现在我们需要一些统计数据，显示有多少飞机和有多少箱子还活着。

# 更新统计数据

在本章的开头，我们在 XAML 中添加了一些控件，显示了游戏中存在的飞机和箱子的数量。现在是时候添加一些代码来更新这些数字了。我们将使用内部消息传递来解耦游戏和我们用来显示这些信息的 Xamarin.Forms 页面。

游戏将向主页发送一个包含我们需要的所有信息的类的消息。主页将接收此消息并更新标签。

# 定义一个统计类

我们将在 Xamarin.Forms 中使用`MessagingCenter`，它允许我们发送消息的同时发送一个对象。我们需要创建一个可以携带我们想要传递的信息的类。让我们通过以下步骤来设置这个：

1.  在`WhackABox`项目中，创建一个名为`GameStats.cs`的新类。

1.  将以下代码添加到类中：

```cs
public class GameStats
{
    public int NumberOfPlanes { get; set; }
    public int NumberOfBoxes { get; set; }
} 
```

这个类将是一个简单的数据载体，指示我们有多少飞机和箱子。

# 通过 MessagingCenter 发送更新

当一个节点被创建或移除时，我们需要将统计信息发送给任何正在监听的东西。为了做到这一点，我们需要一个新的方法，它将遍历场景并计算我们有多少飞机和箱子，然后发送一条消息。让我们通过以下步骤来设置这个方法：

1.  在`WhackABox`项目中，打开`Game.cs`文件。

1.  在类中的任何地方添加一个名为`SendStats()`的方法，如下面的代码所示：

```cs
private void SendStats()
{
    var planes = scene.Children.OfType<PlaneNode>();
    var boxCount = 0;

    foreach (var plane in planes)
    {
        boxCount += plane.Children.Count(e => e.Name == "Box");
    }

    var stats = new GameStats()
    {
        NumberOfBoxes = boxCount,
        NumberOfPlanes = planes.Count()
    };

    Xamarin.Forms.Device.BeginInvokeOnMainThread(() =>
    {
        Xamarin.Forms.MessagingCenter.Send(this, "stats_updated",  
        stats);
    });
} 
```

该方法检查`scene`对象的所有子节点，以查找`PlaneNode`类型的节点。我们遍历所有这些节点，并计算节点的子节点中有多少个名称为`Box`，然后在名为`boxCount`的变量中指示这个数字。当我们有了这个信息，我们创建一个`GameStats`对象，并用盒子计数和平面计数进行初始化。

最后一步是发送消息。我们必须确保我们正在使用 UI 线程（`MainThread`），因为我们将要更新 GUI。只有 UI 线程才允许触摸 GUI。这是通过将`MessagingCenter.Send()`调用包装在`BeginInvokeOnMainThread()`中来完成的。

发送的消息是`stats_updated`。它包含统计信息作为参数。现在让我们使用`SendStats()`方法。

# 连接事件

场景中有很多事件可以连接。我们将连接到`NodeAdded`和`NodeRemoved`以确定何时需要发送统计信息。让我们通过以下步骤设置这一点：

1.  在`WhackABox`项目中，打开`Game.cs`文件。

1.  在`Start()`方法中，添加以下代码中加粗的行：

```cs
protected override void Start()
{
    scene = new Scene(Context);
    scene.NodeAdded += (e) => SendStats();
 scene.NodeRemoved += (e) => SendStats();
    var octree = scene.CreateComponent<Octree>();

    InitializeCamera();
    InitializeLights();
    InitializeRenderer();

    Input.TouchEnd += OnTouchEnd;

    InitializeAR();
} 
```

每当节点被添加或移除时，都会向 GUI 发送一个新消息。

# 更新 GUI

这将是我们添加到游戏中的最后一个方法。它处理信息更新，并更新 GUI 中的标签。让我们通过以下步骤添加它：

1.  在`WhackABox`项目中，打开`MainPage.xaml.cs`文件。

1.  在代码中的任何地方添加一个名为`StatsUpdated()`的方法，如下面的片段所示：

```cs
private void StatsUpdated(Game sender, GameStats stats)
{
    boxCountLabel.Text = stats.NumberOfBoxes.ToString();
    planeCountLabel.Text = stats.NumberOfPlanes.ToString();
}
```

该方法接收我们发送的`GameStats`对象，并更新 GUI 中的两个标签。

# 订阅 MainForm 中的更新

要添加的最后一行代码将`StatsUpdated`处理程序连接到传入的消息。让我们通过以下步骤设置这一点：

1.  在`WhackABox`项目中，打开`MainPage.xaml.cs`文件。

1.  在构造函数中，添加以下代码中加粗的行：

```cs
public MainPage()
{
    InitializeComponent();
    MessagingCenter.Subscribe<Game, GameStats>(this,  
    "stats_updated", StatsUpdated);
} 
```

这行代码将传入消息与内容`stats_updated`连接到`StatsUpdated`方法。现在运行游戏，走出去寻找那些方块吧！

完成的应用程序看起来像以下截图，随机出现旋转的方块：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/b06e11ed-7438-49eb-b0c0-2de12f314dd6.png)

# 总结

在本章中，我们学习了如何通过使用自定义渲染器将 AR 集成到 Xamarin.Forms 中。我们利用了 UrhoSharp 来使用跨平台渲染、组件和输入管理来与世界交互。我们还学习了一些关于`MessagingCenter`的知识，它可以用于在应用程序的不同部分之间发送内部进程消息，以减少耦合。

接下来，我们将深入机器学习，并创建一个可以识别图像中的热狗的应用程序。
