# Xamarin.Forms 项目（三）

> 原文：[`zh.annas-archive.org/md5/BCF2270FBE70F13E76739867E1CF82CA`](https://zh.annas-archive.org/md5/BCF2270FBE70F13E76739867E1CF82CA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：为多种形态因素构建天气应用程序

Xamarin.Forms 不仅可以用于创建手机应用程序；它也可以用于创建平板电脑和台式电脑应用程序。在本章中，我们将构建一个可以在所有这些平台上运行的应用程序。除了使用三种不同的形态因素外，我们还将在三种不同的操作系统上工作：iOS、Android 和 Windows。

本章将涵盖以下主题：

+   如何在 Xamarin.Forms 中使用`FlexLayout`

+   如何使用`VisualStateManager`

+   如何为不同的形态因素使用不同的视图

+   如何使用行为

# 技术要求

要开发这个项目，我们需要安装 Visual Studio for Mac 或 PC，以及 Xamarin 组件。有关如何设置您的环境的更多详细信息，请参阅 Xamarin 简介。

# 项目概述

iOS 和 Android 的应用程序可以在手机和平板上运行。很多时候，应用程序只是针对手机进行了优化。在本章中，我们将构建一个可以在不同形态因素上运行的应用程序，但我们不仅仅针对手机和平板——我们还将针对台式电脑。桌面版本将用于**Universal Windows Platform** (**UWP**)。

我们要构建的应用程序是一个天气应用程序，根据用户的位置显示天气预报。

# 入门

我们可以使用 Visual Studio 2017 for PC 或 Visual Studio for Mac 来开发这个项目。要使用 Visual Studio for PC 构建 iOS 应用程序，您必须连接 Mac。如果您根本没有 Mac，您可以选择只在这个项目的 Windows 和 Android 部分上工作。同样，如果您只有 Mac，您可以选择只在这个项目的 iOS 和 Android 部分上工作。

# 构建天气应用程序

是时候开始构建应用程序了。使用.NET Standard 作为代码共享策略，创建一个新的空白 Xamarin.Forms 应用程序，并选择 iOS、Android 和 Windows (UWP)作为平台。我们将项目命名为`Weather`。

作为这个应用程序的数据源，我们将使用外部天气 API。这个项目将使用`OpenWeatherMap`，这是一个提供几个免费 API 的服务。您可以在[`openweathermap.org/api`](https://openweathermap.org/)找到这个服务。在这个项目中，我们将使用名为`5 day / 3 hour forecast`的服务，它提供了五天的三小时间隔的天气预报。要使用`OpenWeather` API，我们必须创建一个帐户以获取 API 密钥。如果您不想创建 API 密钥，我们可以使用模拟数据。

# 为天气数据创建模型

在编写代码从外部天气服务获取数据之前，我们将创建模型，以便从服务中反序列化结果，以便我们有一个通用模型，可以用来从服务返回数据。

从服务中反序列化结果时，生成模型的最简单方法是在浏览器中或使用工具（如 Postman）调用服务，以查看 JSON 的结构。我们可以手动创建类，也可以使用一个可以从 JSON 生成 C#类的工具。可以使用的一个工具是**quicktype**，可以在[`quicktype.io/`](https://quicktype.io/)找到。

如果手动生成它们，请确保将命名空间设置为`Weather.Models`。

正如所述，您也可以手动创建这些模型。我们将在下一节中描述如何做到这一点。

# 手动添加天气 API 模型

如果选择手动添加模型，则按照以下说明进行。我们将添加一个名为`WeatherData.cs`的单个代码文件，其中包含多个类：

1.  在`Weather`项目中，创建一个名为`Models`的文件夹。

1.  添加一个名为`WeatherData.cs`的文件。

1.  添加以下代码：

```cs
using System.Collections.Generic;

namespace Weather.Models
{
    public class Main
    {
        public double temp { get; set; }
        public double temp_min { get; set; }
        public double temp_max { get; set; }
        public double pressure { get; set; }
        public double sea_level { get; set; }
        public double grnd_level { get; set; }
        public int humidity { get; set; }
        public double temp_kf { get; set; }
    }

    public class Weather
    {
        public int id { get; set; }
        public string main { get; set; }
        public string description { get; set; }
        public string icon { get; set; }
    }

    public class Clouds
    {
        public int all { get; set; }
    }

    public class Wind
    {
        public double speed { get; set; }
        public double deg { get; set; }
    }

    public class Rain
    {
    }

    public class Sys
    {
        public string pod { get; set; }
    }

    public class List
    {
        public long dt { get; set; }
        public Main main { get; set; }
        public List<Weather> weather { get; set; }
        public Clouds clouds { get; set; }
        public Wind wind { get; set; }
        public Rain rain { get; set; }
        public Sys sys { get; set; }
        public string dt_txt { get; set; }
    }

    public class Coord
    {
        public double lat { get; set; }
        public double lon { get; set; }
    }

    public class City
    {
        public int id { get; set; }
        public string name { get; set; }
        public Coord coord { get; set; }
        public string country { get; set; }
    }

    public class WeatherData
    {
        public string cod { get; set; }
        public double message { get; set; }
        public int cnt { get; set; }
        public List<List> list { get; set; }
        public City city { get; set; }
    }
}
```

正如您所看到的，有相当多的类。这些直接映射到我们从服务获取的响应。

# 添加特定于应用程序的模型

在这一部分，我们将创建我们的应用程序将天气 API 模型转换为的模型。让我们首先通过以下步骤添加`WeatherData`类（除非您在前一部分手动创建了它）：

1.  在`Weather`项目中创建一个名为`Models`的新文件夹。

1.  添加一个名为`WeatherData`的新文件。

1.  粘贴或编写基于 JSON 的类的代码。如果生成了除属性之外的代码，请忽略它，只使用属性。

1.  将`MainClass`（这是 quicktype 命名的根对象）重命名为`WeatherData`。

现在我们将根据我们感兴趣的数据创建模型。这将使代码的其余部分与数据源更松散地耦合。

# 添加 ForecastItem 模型

我们要添加的第一个模型是`ForecastItem`，它表示特定时间点的具体预报。具体步骤如下：

1.  在`Weather`项目中，创建一个名为`ForecastItem`的新类。

1.  添加以下代码：

```cs
using System;
using System.Collections.Generic;

namespace Weather.Models
{  
    public class ForecastItem
    {
        public DateTime DateTime { get; set; }
        public string TimeAsString => DateTime.ToShortTimeString();
        public double Temperature { get; set; }
        public double WindSpeed { get; set; }
        public string Description { get; set; }
        public string Icon { get; set; }
    }
}     
```

# 添加 Forecast 模型

接下来，我们将创建一个名为`Forecast`的模型，它将跟踪城市的单个预报。`Forecast`保留了多个`ForeCastItem`对象的列表，每个对象代表特定时间点的预报。让我们通过以下步骤设置这个：

1.  在`Weather`项目中，创建一个名为`Forecast`的新类。

1.  添加以下代码：

```cs
using System;
using System.Collections.Generic;

namespace Weather.Models
{ 
    public class Forecast
    {
        public string City { get; set; }
        public List<ForecastItem> Items { get; set; }
    }
}
```

现在我们已经为天气 API 和应用程序创建了模型，我们需要从天气 API 获取数据。

# 创建一个用于获取天气数据的服务

为了更容易地更改外部天气服务并使代码更具可测试性，我们将为服务创建一个接口。具体步骤如下：

1.  在`Weather`项目中，创建一个新文件夹并命名为`Services`。

1.  创建一个新的`public interface`并命名为`IWeatherService`。

1.  添加一个根据用户位置获取数据的方法，如下所示。将方法命名为`GetForecast`：

```cs
 public interface IWeatherService
 {
      Task<Forecast> GetForecast(double latitude, double longitude);
 }
```

当我们有了一个接口，我们可以通过以下步骤为其创建一个实现：

1.  在`Services`文件夹中，创建一个名为`OpenWeatherMapWeatherService`的新类。

1.  实现接口并在`GetForecast`方法中添加`async`关键字。

1.  代码应如下所示：

```cs
using System;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Weather.Models; 

namespace Weather.Services
{ 
    public class OpenWeatherMapWeatherService : IWeatherService
    {
        public async Task<Forecast> GetForecast(double latitude, 
        double longitude)
        { 
        }
    }
}
```

在调用`OpenWeatherMap` API 之前，我们需要为调用天气 API 构建一个 URI。这将是一个`GET`调用，纬度和经度将被添加为查询参数。我们还将添加 API 密钥和我们希望得到响应的语言。让我们通过以下步骤来设置这个：

1.  在`WeatherProject`中，打开`OpenWeatherMapWeatherService`类。

1.  在以下代码片段中添加粗体标记的代码：

```cs
public class OpenWeatherMapWeatherService : IWeatherService
{
    public async Task<Forecast> GetForecast(double latitude, double 
    longitude)
    { 
        var language =  
        CultureInfo.CurrentUICulture.TwoLetterISOLanguageName;
 var apiKey = "{AddYourApiKeyHere}";
 var uri = 
        $"https://api.openweathermap.org/data/2.5/forecast?
        lat={latitude}&lon={longitude}&units=metric&lang=
        {language}&appid={apiKey}";
    }
}
```

为了反序列化我们从外部服务获取的 JSON，我们将使用`Json.NET`，这是.NET 应用程序中最流行的用于序列化和反序列化 JSON 的 NuGet 包。我们可以通过以下步骤安装它：

1.  打开 NuGet 包管理器。

1.  安装`Json.NET`包。包的 ID 是`Newtonsoft.Json`。

为了调用`Weather`服务，我们将使用`HttpClient`类和`GetStringAsync`方法，具体步骤如下：

1.  创建`HttpClient`类的新实例。

1.  调用`GetStringAsync`并将 URL 作为参数传递。

1.  使用`JsonConvert`类和`Json.NET`的`DeserializeObject`方法将 JSON 字符串转换为对象。

1.  将`WeatherData`对象映射到`Forecast`对象。

1.  代码应如下代码片段中的粗体代码所示：

```cs
public async Task<Forecast> GetForecast(double latitude, double  
                                        longitude)
{ 
    var language = 
    CultureInfo.CurrentUICulture.TwoLetterISOLanguageName;
    var apiKey = "{AddYourApiKeyHere}";
    var uri = $"https://api.openweathermap.org/data/2.5/forecast?
    lat={latitude}&lon={longitude}&units=metric&lang=
    {language}&appid={apiKey}";

    var httpClient = new HttpClient();
    var result = await httpClient.GetStringAsync(uri);

    var data = JsonConvert.DeserializeObject<WeatherData>(result);

    var forecast = new Forecast()
    {
        City = data.city.name,
        Items = data.list.Select(x => new ForecastItem()
        {
            DateTime = ToDateTime(x.dt),
            Temperature = x.main.temp,
            WindSpeed = x.wind.speed,
            Description = x.weather.First().description,
            Icon = 
     $"http://openweathermap.org/img/w/{x.weather.First().icon}.png"
     }).ToList()
    };

    return forecast;
}

```

为了优化性能，我们可以将`HttpClient`用作单例，并在应用程序中的所有网络调用中重复使用它。以下信息来自 Microsoft 的文档：*HttpClient**旨在实例化一次并在应用程序的整个生命周期内重复使用。为每个请求实例化 HttpClient 类将在重负载下耗尽可用的套接字数量。这将导致 SocketException 错误。*这可以在以下网址找到：[`docs.microsoft.com/en-gb/dotnet/api/system.net.http.httpclient?view=netstandard-2.0`](https://docs.microsoft.com/en-gb/dotnet/api/system.net.http.httpclient?view=netstandard-2.0)。

在上面的代码中，我们调用了一个`ToDateTime`方法，这是一个我们需要创建的方法。该方法将日期从 Unix 时间戳转换为`DateTime`对象，如下面的代码所示：

```cs
private DateTime ToDateTime(double unixTimeStamp)
{
     DateTime dateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, 
     DateTimeKind.Utc);
     dateTime = dateTime.AddSeconds(unixTimeStamp).ToLocalTime();
     return dateTime;
}
```

默认情况下，`HttpClient`使用`HttpClient`的 Mono 实现（iOS 和 Android）。为了提高性能，我们可以改用特定于平台的实现。对于 iOS，使用`NSUrlSession`。这可以在 iOS 项目的项目设置中的 iOS Build 选项卡下设置。对于 Android，使用 Android。这可以在 Android 项目的项目设置中的 Android Options | Advanced 下设置。

# 配置应用程序以使用位置服务

为了能够使用位置服务，我们需要在每个平台上进行一些配置。我们将使用 Xamarin.Essentials 及其包含的类。在进行以下各节中的步骤之前，请确保已将 Xamarin.Essentials 从 NuGet 安装到解决方案中的所有项目中。

# 配置 iOS 应用程序以使用位置服务

要在 iOS 应用程序中使用位置服务，我们需要在`info.plist`文件中添加描述，以指示为什么要在应用程序中使用位置。在这个应用程序中，我们只需要在使用应用程序时获取位置，因此我们只需要为此添加描述。让我们通过以下步骤设置这一点：

1.  使用 XML（文本）编辑器在`Weather.iOS`中打开`info.plist`。

1.  使用以下代码添加键`NSLocationWhenInUseUsageDescription`：

```cs
<key>NSLocationWhenInUseUsageDescription</key>
<string>We are using your location to find a forecast for you</string>
```

# 配置 Android 应用程序以使用位置服务

对于 Android，我们需要设置应用程序需要以下两个权限：

+   ACCESS_COARSE_LOCATION

+   ACCESS_FINE_LOCATION

我们可以在`Weather.Android`项目的`Properties`文件夹中找到的`AndroidManifest.xml`文件中设置这一点，但我们也可以在项目属性下的 Android 清单选项卡中设置，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/234daa3f-c5a6-471f-8efd-9a1b53904304.png)

当我们在 Android 应用程序中请求权限时，还需要在 Android 项目的`MainActivity.cs`文件中添加以下代码：

```cs
public override void OnRequestPermissionsResult(int requestCode, string[] permissions, 
[GeneratedEnum] Android.Content.PM.Permission[] grantResults)
{
     Xamarin.Essentials.Platform.OnRequestPermissionsResult(requestCode, permissions, grantResults); base.OnRequestPermissionsResult(requestCode, permissions, grantResults);
}
```

对于 Android，我们还需要初始化 Xamarin.Essentials。我们将在`MainActivity`的`OnCreate`方法中执行此操作：

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

# 配置 UWP 应用程序以使用位置服务

由于我们将在 UWP 应用程序中使用位置服务，因此我们需要在`Weather.UWP`项目的`Package.appxmanifest`文件的 Capabilities 下添加 Location capability，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/2a04a344-7e1a-4ee7-9bd3-aa2124362a41.png)

# 创建 ViewModel 类

现在我们有一个负责从外部天气源获取天气数据的服务。是时候创建一个`ViewModel`了。但是，首先，我们将创建一个基本视图模型，在其中可以放置可以在应用程序的所有视图模型之间共享的代码。让我们通过以下步骤设置这一点：

1.  创建一个名为`ViewModels`的新文件夹。

1.  创建一个名为`ViewModel`的新类。

1.  使新类`public`和`abstract`。

1.  添加并实现`INotifiedPropertyChanged`接口。这是必要的，因为我们想要使用数据绑定。

1.  添加一个`Set`方法，它将使得从`INotifiedPropertyChanged`接口中引发`PropertyChanged`事件更容易，如下所示。该方法将检查值是否已更改。如果已更改，它将引发事件：

```cs
public abstract class ViewModel : INotifyPropertyChanged
{
     public event PropertyChangedEventHandler PropertyChanged; 
     protected void Set<T>(ref T field, T newValue, 
     [CallerMemberName] string propertyName = null)
     {
          if (!EqualityComparer<T>.Default.Equals(field, 
          newValue))
          {
               field = newValue;
               PropertyChanged?.Invoke(this, new 
               PropertyChangedEventArgs(propertyName));
          }
     }
} 
```

如果要在方法体中使用`CallerMemberName`属性，可以使用该方法的名称或调用该方法的属性作为参数。但是，我们可以通过简单地向其传递值来始终覆盖这一点。当使用`CallerMember`属性时，参数的默认值是必需的。

现在我们有了一个基本的视图模型。我们可以将其用于我们现在正在创建的视图模型，以及以后将添加的所有其他视图模型。

现在是时候创建`MainViewModel`了，它将是我们应用程序中`MainView`的`ViewModel`。我们通过以下步骤来实现这一点：

1.  在`ViewModels`文件夹中，创建一个名为`MainViewModel`的新类。

1.  将抽象的`ViewModel`类添加为基类。

1.  因为我们将使用构造函数注入，所以我们将添加一个带有`IWeatherService`接口作为参数的构造函数。

1.  创建一个只读的`private`字段，我们将使用它来存储`IWeatherService`实例，使用以下代码：

```cs
public class MainViewModel : ViewModel
{
     private readonly IWeatherService weatherService;

     public MainViewModel(IWeatherService weatherService)
     {
          this.weatherService = weatherService;
     } 
}
```

`MainViewModel`接受任何实现`IWeatherService`的对象，并将对该服务的引用存储在一个字段中。我们将在下一节中添加获取天气数据的功能。

# 获取天气数据

现在我们将创建一个新的加载数据的方法。这将是一个三步过程。首先，我们将获取用户的位置。一旦我们拥有了这个，我们就可以获取与该位置相关的数据。最后一步是准备数据，以便视图可以使用它来为用户创建用户界面。

为了获取用户的位置，我们将使用 Xamarin.Essentials，这是我们之前安装的 NuGet 包，以及`Geolocation`类，该类公开了获取用户位置的方法。我们通过以下步骤来实现这一点：

1.  创建一个名为`LoadData`的新方法。将其设置为异步方法，返回一个`Task`。

1.  使用`Geolocation`类上的`GetLocationAsync`方法获取用户的位置。

1.  从`GetLocationAsync`调用的结果中传递纬度和经度，并将其传递给实现`IWeatherService`的对象上的`GetForecast`方法，使用以下代码：

```cs
public async Task LoadData()
{
     var location = await Geolocation.GetLocationAsync();
     var forecast = await weatherService.GetForecast
     (location.Latitude, location.Longitude); 
}
```

# 对天气数据进行分组

当我们呈现天气数据时，我们将按天分组，以便所有一天的预报都在同一个标题下。为此，我们将创建一个名为`ForecastGroup`的新模型。为了能够将此模型与 Xamarin.Forms 的`ListView`一起使用，它必须具有`IEnumerable`类型作为基类。让我们通过以下步骤来设置这一点：

1.  在`Models`文件夹中创建一个名为`ForecastGroup`的新类。

1.  将`List<ForecastItem>`添加为新模型的基类。

1.  添加一个空构造函数和一个带有`ForecastItem`实例列表作为参数的构造函数。

1.  添加一个`Date`属性。

1.  添加一个名为`DateAsString`的属性，返回`Date`属性的短日期字符串。

1.  添加一个名为`Items`的属性，返回`ForecastItem`实例的列表，如下所示：

```cs
using System;
using System.Collections.Generic;

namespace Weather.Models
{ 
    public class ForecastGroup : List<ForecastItem>
    {
        public ForecastGroup() { }
        public ForecastGroup(IEnumerable<ForecastItem> items)
        {
            AddRange(items);
        }

        public DateTime Date { get; set; }
        public string DateAsString => Date.ToShortDateString();
        public List<ForecastItem> Items => this;
    }
} 
```

完成此操作后，我们可以通过以下步骤更新`MainViewModel`，添加两个新属性：

1.  为我们获取天气数据的城市名称创建一个名为`City`的属性。

1.  创建一个名为`Days`的属性，用于包含分组的天气数据。

1.  `MainViewModel`类应该像以下片段中的粗体代码一样：

```cs
public class MainViewModel : ViewModel
{ 
 private string city;
 public string City
 {
 get => city;
 set => Set(ref city, value);
 }

 private ObservableCollection<ForecastGroup> days;
 public ObservableCollection<ForecastGroup> Days
 {
 get => days;
 set => Set(ref days, value);
 }

    // Rest of the class is omitted for brevity
} 
```

现在我们准备对数据进行实际分组。我们将在`LoadData`方法中执行此操作。我们将通过以下步骤循环遍历来自服务的数据，并通过以下步骤将项目添加到组中：

1.  创建一个`itemGroups`变量，类型为`List<ForecastGroup>`。

1.  创建一个`foreach`循环，循环遍历`forecast`变量中的所有项目。

1.  添加一个`if`语句，检查`itemGroups`属性是否为空。如果为空，向变量中添加一个新的`ForecastGroup`，并继续到项目列表中的下一个项目。

1.  在`itemGroups`变量上使用`SingleOrDefault`方法（这是 System.Linq 中的一个扩展方法），以根据当前`ForecastItem`的日期获取一个组。将结果添加到一个新变量`group`中。

1.  如果 group 属性为 null，则列表中没有当前日期的组。如果是这种情况，应向`itemGroups`变量中添加一个新的`ForecastGroup`，并且代码的执行将继续到`forecast.Items`列表中的下一个`forecast`项目。如果找到一个组，则应将其添加到`itemGroups`变量中的列表中。

1.  在`foreach`循环之后，使用新的`ObservableCollection<ForecastGroup>`设置`Days`属性，并将`itemGroups`变量作为构造函数的参数。

1.  将`City`属性设置为`forecast`变量的`City`属性。

1.  现在，`LoadData`方法应该如下所示：

```cs
public async Task LoadData()
{ 
    var itemGroups = new List<ForecastGroup>();

    foreach (var item in forecast.Items)
    {
        if (!itemGroups.Any())
        {
            itemGroups.Add(new ForecastGroup(
             new List<ForecastItem>() { item }) 
             { Date = item.DateTime.Date});
             continue;
        }

        var group = itemGroups.SingleOrDefault(x => x.Date == 
        item.DateTime.Date);

        if (group == null)
        {
            itemGroups.Add(new ForecastGroup(
            new List<ForecastItem>() { item }) 
            { Date = item.DateTime.Date });

                      continue;
        }

        group.Items.Add(item);
    }

    Days = new ObservableCollection<ForecastGroup>(itemGroups);
    City = forecast.City;
}
```

当您想要添加多个项目时，不要在`ObservableCollection`上使用`Add`方法。最好创建一个新的`ObservableCollection`实例，并将集合传递给构造函数。原因是每次使用`Add`方法时，您都会从视图中进行绑定，并且它将触发视图的渲染。如果我们避免使用`Add`方法，我们将获得更好的性能。

# 创建一个 Resolver

我们将为**Inversion of Control**（**IoC**）创建一个辅助类。这将帮助我们基于配置的 IoC 容器创建类型。在这个项目中，我们将使用 Autofac 作为 IoC 库。让我们通过以下步骤来设置这一点：

1.  在`Weather`项目中安装 NuGet 包 Autofac。

1.  在`Weather`项目中创建一个名为`Resolver`的新类。

1.  添加一个名为`container`的`private static`字段，类型为`IContainer`（来自 Autofac）。

1.  添加一个名为`Initialize`的`public static`方法，带有`IContainer`作为参数。将参数的值设置为`container`字段。

1.  添加一个名为`Resolve<T>`的通用的“public static”方法，它将返回指定类型的对象实例。然后，`Resolve<T>`方法将调用传递给它的`IContainer`实例上的`Resolve<T>`方法。

1.  现在代码应该如下所示：

```cs
using Autofac;

namespace Weather
{ 
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
} 
```

# 创建一个 bootstrapper

在这一部分，我们将创建一个`Bootstrapper`类，用于在应用程序启动阶段设置我们需要的常见配置。通常，每个目标平台都有一个 bootstrapper 的部分，而所有平台都有一个共享的部分。在这个项目中，我们只需要共享部分。让我们通过以下步骤来设置这一点：

1.  在`Weather`项目中，创建一个名为`Bootstrapper`的新类。

1.  添加一个名为`Init`的新的`public static`方法。

1.  创建一个新的`ContainerBuilder`并将类型注册到`container`中。

1.  使用`ContainerBuilder`的`Build`方法创建一个`Container`。创建一个名为`container`的变量，其中包含`Container`的实例。

1.  在`Resolver`上使用`Initialize`方法，并将`container`变量作为参数传递。

1.  现在`Bootstrapper`类应该如下所示：

```cs
using Autofac;
using TinyNavigationHelper.Forms;
using Weather.Services;
using Weather.ViewModels;
using Weather.Views;
using Xamarin.Forms;

namespace Weather
{ 
    public class Bootstrapper
    {
        public static void Init()
        {
            var containerBuilder = new ContainerBuilder();
            containerBuilder.RegisterType
            <OpenWeatherMapWeatherService>().As
            <IWeatherService>();
            containerBuilder.RegisterType<MainViewModel>();

            var container = containerBuilder.Build();

            Resolver.Initialize(container);
        }
    }
}
```

在`App.xaml.cs`文件的构造函数中调用`Bootstrapper`的`Init`方法，该方法在调用`InitializeComponent`方法后调用。另外，将`MainPage`属性设置为`MainView`，如下所示：

```cs
public App()
{
    InitializeComponent();
    Bootstrapper.Init();
    MainPage = new NavigationPage(new MainView());
} 
```

# 基于 FlexLayout 创建一个 RepeaterView

在 Xamarin.Forms 中，如果我们想显示一组数据，可以使用`ListView`。使用`ListView`非常方便，我们稍后会在本章中使用它，但它只能垂直显示数据。在这个应用程序中，我们希望在两个方向上显示数据。在垂直方向上，我们将有天数（根据天数分组预测），而在水平方向上，我们将有特定一天内的预测。我们还希望一天内的预测在一行中没有足够的空间时换行。使用`FlexLayout`，我们可以在两个方向上添加项目。但是，`FlexLayout`是一个布局，这意味着我们无法将项目绑定到它，因此我们必须扩展其功能。我们将命名我们扩展的`FlexLayout`为`RepeaterView`。`RepeaterView`类将基于`DataTemplate`和添加到其中的项目呈现内容，就像使用了`ListView`一样。

按照以下步骤创建`RepeaterView`：

1.  在`Weather`项目中创建一个名为`Controls`的新文件夹。

1.  在`Controls`文件夹中添加一个名为`RepeaterView`的新类。

1.  创建一个名为`Generate`的空方法。我们稍后会向这个方法添加代码。

1.  创建一个名为`itemsTemplate`的`DataTemplate`类型的新私有字段。

1.  创建一个名为`ItemsTemplate`的`DataTemplate`类型的新属性。`get`方法将只返回`itemsTemplate`字段。`set`方法将设置`itemsTemplate`字段为新值。但是，它还将调用`Generate`方法来触发数据的重新生成。生成必须在主线程上进行，如下面的代码所示：

```cs
using System.Collections.Generic;
using Xamarin.Essentials;
using Xamarin.Forms;

namespace Weather.Controls
{ 
    public class ReperaterView : FlexLayout
    {
        private DataTemplate itemsTemplate;
        public DataTemplate ItemsTemplate
        {
            get => itemsTemplate;
            set
            {
                itemsTemplate = value;
                MainThread.BeginInvokeOnMainThread(() => 
                Generate());
            }
        } 

        public void Generate()
        {
        }
    }
}
```

为了绑定到属性，我们需要按照以下步骤添加`BindableProperty`：

1.  添加一个名为`ItemsSourceProperty`的`public static BindableProperty`字段，返回默认值为`null`。

1.  添加一个名为`ItemsSource`的`public`属性。

1.  为`ItemSource`添加一个 setter，设置`ItemsSourceProperty`的值。

1.  添加一个`ItemsSource`属性的 getter，返回`ItemsSourceProperty`的值，如下面的代码所示：

```cs
public static BindableProperty ItemsSourceProperty = BindableProperty.Create(nameof(ItemsSource), typeof(IEnumerable<object>), typeof(RepeaterView), null);

public IEnumerable<object> ItemsSource
{
    get => GetValue(ItemsSourceProperty) as IEnumerable<object>;
    set => SetValue(ItemsSourceProperty, value);
}
```

在前面的代码中的可绑定属性声明中，我们可以对不同的操作采取行动。我们感兴趣的是`propertyChanged`操作。如果我们为此属性分配一个委托，那么每当该属性的值发生变化时，它都会被调用，我们可以对该变化采取行动。在这种情况下，我们将重新生成`RepeaterView`的内容。我们通过以下步骤来实现这一点：

1.  将属性更改委托（如下面的代码所示）作为`BindableProperty`的`Create`方法的参数，以在`ItemsSource`属性更改时重新生成 UI。

1.  在主线程上重新生成 UI 之前，检查`DateTemplate`是否不为`null`，如下面的代码所示：

```cs
public static BindableProperty ItemsSourceProperty = BindableProperty.Create(nameof(ItemsSource), typeof(IEnumerable<object>), typeof(RepeaterView), null, 
             propertyChanged: (bindable, oldValue, newValue) => {

 var repeater = (RepeaterView)bindable;

 if(repeater.ItemsTemplate == null)
 {
 return;
 }

 MainThread.BeginInvokeOnMainThread(() => 
                     repeater.Generate());
                 }); 
```

`RepeaterView`的最后一步是在`Generate`方法中生成内容。

让我们通过以下步骤来实现`Generate`方法：

1.  清除所有子控件，使用`Children.Clear();`。

1.  验证`ItemSource`不为`null`。如果为`null`，则返回空。

1.  循环遍历所有项目，并从`DataTemplate`生成内容。将当前项目设置为`BindingContext`并将其添加为`FlexLayout`的子项，如下面的代码所示：

```cs
private void Generate()
{
    Children.Clear();

    if(ItemsSource == null)
    {
        return;
    }

    foreach(var item in ItemsSource)
    {
        var view = itemsTemplate.CreateContent() as View;

        if(view == null)
        {
            return;
        }

        view.BindingContext = item;

        Children.Add(view);
    }
} 
```

# 为平板电脑和台式电脑创建视图

下一步是创建应用程序在平板电脑或台式电脑上运行时将使用的视图。让我们通过以下步骤设置这一点：

1.  在`Weather`项目中创建一个名为`Views`的新文件夹。

1.  使用 XAML 创建一个名为`MainView`的新内容页。

1.  在视图的构造函数中使用`Resolver`将`BindingContext`设置为`MainViewModel`，如下面的代码所示：

```cs
public MainView ()
{
    InitializeComponent ();
    BindingContext = Resolver.Resolve<MainViewModel>();
} 
```

通过重写`OnAppearing`方法在主线程上调用`LoadData`方法来触发`MainViewModel`中的`LoadData`方法。我们需要确保调用被调度到 UI 线程，因为它将直接与用户界面交互。

要做到这一点，请按照以下步骤进行：

1.  在`Weather`项目中，打开`MainView.xaml.cs`文件。

1.  创建`OnAppearing`方法的重写。

1.  在以下片段中加粗显示的代码：

```cs
protected override void OnAppearing()
{
    base.OnAppearing();

 if (BindingContext is MainViewModel viewModel)
 {
 MainThread.BeginInvokeOnMainThread(async () =>
 {
 await viewModel.LoadData();
 });
 }
} 
```

在 XAML 中，通过以下步骤将`ContentPage`的`Title`属性绑定到`ViewModel`中的`City`属性：

1.  在`Weather`项目中，打开`MainView.xaml`文件。

1.  在以下代码片段中加粗显示的地方将`Title`绑定到`ContentPage`元素。

```cs
<ContentPage xmlns="http://xamarin.com/schemas/2014/forms"
    xmlns:x="http://schemas.microsoft.com/winfx/2009/xaml"
    xmlns:controls="clr-namespace:Weather.Controls" 
    x:Class="Weather.Views.MainView" 
    Title="{Binding City}">
```

# 使用 RepeaterView

要将自定义控件添加到视图中，我们需要将命名空间导入视图。如果视图在另一个程序集中，我们还需要指定程序集，但在这种情况下，视图和控件都在同一个命名空间中，如以下代码所示：

```cs
<ContentPage xmlns="http://xamarin.com/schemas/2014/forms" 
             xmlns:x="http://schemas.microsoft.com/winfx/2009/xaml" 
             xmlns:controls="clr-namespace:Weather.Controls"
             x:Class="Weather.Views.MainView" 
```

按照以下步骤构建视图：

1.  将`Grid`添加为页面的根视图。

1.  将`ScrollView`添加到`Grid`。如果内容高于页面的高度，我们需要这样做才能滚动。

1.  将`RepeaterView`添加到`ScrollView`中，并将方向设置为`Column`，以便内容以垂直方向排列。

1.  在`MainViewModel`中为`Days`属性添加绑定。

1.  将`DataTemplate`设置为`ItemsTemplate`的内容，如以下代码所示：

```cs
<Grid>
    <ScrollView BackgroundColor="Transparent">
        <controls:RepeaterView ItemsSource="{Binding Days}"  
                 Direction="Column">
            <controls:RepeaterView.ItemsTemplate>
                <DataTemplate>
                  <!--Content will be added here -->
                </DataTemplate>
            </controls:RepeaterView.ItemsTemplate>
        </controls:RepeaterView>
    </ScrollView>
</Grid>
```

每个项目的内容将是带有日期的页眉和一行预测的水平`RepeaterView`。通过以下步骤设置这一点：

1.  在`Weather`项目中，打开`MainView.xaml`文件。

1.  添加`StackLayout`，以便将要添加到其中的子元素以垂直方向放置。

1.  将`ContentView`添加到`StackLayout`中，将`Padding`设置为`10`，将`BackgroundColor`设置为`#9F5010`。这将是页眉。我们需要`ContentView`的原因是我们希望文本周围有填充。

1.  将`Label`添加到`ContentView`，将`TextColor`设置为`White`，将`FontAttributes`设置为`Bold`。

1.  为`Label`的`Text`属性添加`DateAsString`的绑定。

1.  代码应该放在`<!-- Content will be added here -->`注释处，并且应该如以下代码所示：

```cs
<StackLayout>
    <ContentView Padding="10" BackgroundColor="#9F5010">
        <Label Text="{Binding DateAsString}" TextColor="White" 
         FontAttributes="Bold" />
    </ContentView> 
</StackLayout>
```

现在我们在用户界面中有了日期，我们需要通过以下步骤添加一个将在`MainViewModel`中的`Items`中重复的`RepeaterView`。`RepeaterView`是我们之前创建的从`FlexLayout`继承的控件：

1.  在`</ContentView>`标记之后但在`</StackLayout>`标记之前添加一个`RepeaterView`。

1.  将`JustifyContent`设置为`Start`，以便从左侧添加`Items`而不是在可用空间上分布它们。

1.  将`AlignItems`设置为`Start`，以将`RepeaterView`基于的`FlexLayout`中的每个项目的内容设置为左侧。

```cs
 <controls:RepeaterView ItemsSource="{Binding Items}" Wrap="Wrap"  
  JustifyContent="Start" AlignItems="Start"> 
```

定义`RepeaterView`后，我们需要提供一个`ItemsTemplate`，定义列表中每个项目的呈现方式。继续通过以下步骤直接在刚刚添加的`<controls:RepeaterView>`标签下添加 XAML：

1.  将`ItemsTemplate`属性设置为`DataTemplate`。

1.  按照以下代码所示填充`DataTemplate`中的元素：

如果我们想要对绑定添加格式，我们可以使用`StringFormat`。在这种情况下，我们希望在温度后添加度符号。我们可以通过使用`{Binding Temperature, StringFormat='{0}° C'}`来实现这一点。通过绑定的`StringFormat`属性，我们可以使用与在 C#中执行相同的参数来格式化数据。这与在 C#中执行`string.Format("{0}° C", Temperature)`相同。我们也可以用它来格式化日期，例如`{Binding Date, StringFormat='yyyy'}`。在 C#中，这看起来像`Date.ToString("yyyy")`。

```cs
<controls:RepeaterView.ItemsTemplate>
    <DataTemplate>
        <StackLayout Margin="10" Padding="20" WidthRequest="150" 
             BackgroundColor="#99FFFFFF">
            <Label FontSize="16" FontAttributes="Bold" Text="{Binding 
              TimeAsString}" HorizontalOptions="Center" />
            <Image WidthRequest="100" HeightRequest="100" 
              Aspect="AspectFit" HorizontalOptions="Center" Source=" 
              {Binding Icon}" />
            <Label FontSize="14" FontAttributes="Bold" Text="{Binding 
              Temperature, StringFormat='{0}° C'}"  
              HorizontalOptions="Center" /> 
            <Label FontSize="14" FontAttributes="Bold" Text="{Binding 
              Description}" HorizontalOptions="Center" />
        </StackLayout>
    </DataTemplate>
</controls:RepeaterView.ItemsTemplate>

```

作为`Image`的`Aspect`属性的值，“AspectFill”短语表示整个图像始终可见，而且不会改变方面。 `AspectFit`短语也会保持图像的方面，但可以对图像进行缩放和裁剪以填充整个`Image`元素。 `Aspect`可以设置的最后一个值，`Fill`，表示图像可以被拉伸或压缩以匹配`Image`视图，而不必确保保持方面。

# 添加一个工具栏项以刷新天气数据

为了能够在不重新启动应用程序的情况下刷新数据，我们将在工具栏中添加一个刷新按钮。`MainViewModel`负责处理我们想要执行的任何逻辑，并且我们必须将任何操作公开为可以绑定的`ICommand`。

让我们首先通过以下步骤在`MainViewModel`上创建`Refresh`命令属性：

1.  在“天气”项目中，打开`MainViewModel`类。

1.  添加一个名为`Refresh`的`ICommand`属性和返回新`Command`的`get`方法

1.  将一个表达式作为`Command`的构造函数中的操作，调用`LoadData`方法，如下所示：

```cs
public ICommand Refresh => new Command(async() => 
{
    await LoadData();
}); 
```

现在我们已经定义了`Command`，我们需要将其绑定到用户界面，以便当用户单击工具栏按钮时，将执行该操作。

为此，请按照以下步骤操作：

1.  在“天气”应用程序中，打开`MainView.xaml`文件。

1.  将新的`ToolbarItem`添加到`ContentPage`的`ToolbarItems`属性中，将`Text`属性设置为`Refresh`，并将`Icon`属性设置为`refresh.png`（可以从 GitHub 下载图标；请参阅[`github.com/PacktPublishing/Xamarin.Forms-Projects/tree/master/Chapter-5`](https://github.com/PacktPublishing/Xamarin.Forms-Projects/tree/master/Chapter-5)）。

1.  将`Command`属性绑定到`MainViewModel`中的`Refresh`属性，如下所示：

```cs
<ContentPage.ToolbarItems>
    <ToolbarItem Icon="refresh.png" Text="Refresh" Command="{Binding 
     Refresh}" />
</ContentPage.ToolbarItems> 
```

刷新数据到此结束。现在我们需要一种数据加载的指示器。

# 添加加载指示器

当我们刷新数据时，我们希望显示一个加载指示器，以便用户知道正在发生某事。为此，我们将添加`ActivityIndicator`，这是 Xamarin.Forms 中称呼此控件的名称。让我们通过以下步骤设置这一点：

1.  在“天气”项目中，打开`MainViewModel`类。

1.  向`MainViewModel`添加名为`IsRefreshing`的布尔属性。

1.  在`LoadData`方法的开头将`IsRefreshing`属性设置为`true`。

1.  在`LoadData`方法的末尾，将`IsRefreshing`属性设置为`false`，如下所示：

```cs
private bool isRefreshing;
public bool IsRefreshing
{
    get => isRefreshing;
    set => Set(ref isRefreshing, value);
} 

public async Task LoadData()
{
    IsRefreshing = true; 
    .... // The rest of the code is omitted for brevity
    IsRefreshing = false;
}
```

现在我们已经在`MainViewModel`中添加了一些代码，我们需要将`IsRefreshing`属性绑定到用户界面元素，当`IsRefreshing`属性为`true`时将显示该元素，如下所示：

1.  在`Grid`的最后一个元素`ScrollView`之后添加一个`Frame`。

1.  将`IsVisible`属性绑定到我们在`MainViewModel`中创建的`IsRefreshing`方法。

1.  将`HeightRequest`和`WidthRequest`设置为`100`。

1.  将`VerticalOptions`和`HorizontalOptions`设置为`Center`，以便`Frame`位于视图的中间。

1.  将`BackgroundColor`设置为“＃99000000”以将背景设置为略带透明的白色。

1.  按照以下代码将`ActivityIndicator`添加到`Frame`中，其中`Color`设置为`Black`，`IsRunning`设置为`True`：

```cs
 <Frame IsVisible="{Binding IsRefreshing}" 
      BackgroundColor="#99FFFFFF" 
      WidthRequest="100" HeightRequest="100" 
      VerticalOptions="Center" 
      HorizontalOptions="Center">
      <ActivityIndicator Color="Black" IsRunning="True" />
</Frame> 
```

这将创建一个旋转器，当数据加载时将可见，这是创建任何用户界面时的一个非常好的实践。现在我们将添加一个背景图片，使应用程序看起来更加美观。

# 设置背景图片

此视图的最后一件事是添加背景图片。我们在此示例中使用的图像是通过 Google 搜索免费使用的图像而获得的。让我们通过以下步骤设置这一点：

1.  在“天气”项目中，打开`MainView.xaml`文件。

1.  将`ScrollView`包装在`Grid`中。如果我们想要将元素分层，使用`Grid`是很好的。

1.  将`ScrollView`的`Background`属性设置为`Transparent`。

1.  在`Grid`中添加一个`Image`元素，将`UriImageSource`作为`Source`属性的值。

1.  将`CachingEnabled`属性设置为`true`，将`CacheValidity`设置为`5`。这意味着图像将在五天内被缓存。

1.  现在 XAML 应该如下所示：

```cs
<ContentPage 

             x:Class="Weather.Views.MainView" Title="{Binding 
                                                       City}">
    <ContentPage.ToolbarItems>
        <ToolbarItem Icon="refresh.png" Text="Refresh" Command="
        {Binding Refresh}" />
    </ContentPage.ToolbarItems>

 <Grid>
 <Image Aspect="AspectFill">
 <Image.Source>
 <UriImageSource 
           Uri="https://upload.wikimedia.org/wikipedia/commons/7/79/
           Solnedg%C3%A5ng_%C3%B6ver_Laholmsbukten_augusti_2011.jpg"            
           CachingEnabled="true" CacheValidity="1" />
 </Image.Source> </Image>
    <ScrollView BackgroundColor="Transparent"> 
        <!-- The rest of the code is omitted for brevity -->
```

我们也可以直接在`Source`属性中设置 URL，使用`<Image Source="https://ourgreatimage.url" />`。但是，如果我们这样做，就无法为图像指定缓存。

# 为手机创建视图

在平板电脑和台式电脑上构建内容在许多方面非常相似。然而，在手机上，我们在可以做的事情上受到了更大的限制。因此，在本节中，我们将通过以下步骤为手机上使用此应用程序创建一个特定的视图：

1.  在`Views`文件夹中创建一个基于 XAML 的新内容页。

1.  将新视图命名为`MainView_Phone`。

1.  在视图的构造函数中使用`Resolver`将`BindingContext`设置为`MainViewModel`，如下所示：

```cs
public MainView_Phone ()
{
    InitializeComponent ();
    BindingContext = Resolver.Resolve<MainViewModel>();
} 
```

通过重写`OnAppearing`方法在主线程上调用`MainViewModel`中的`LoadData`方法来触发`LoadData`方法。通过以下步骤来实现这一点：

1.  在`Weather`项目中，打开`MainView_Phone.xaml.cs`文件。

1.  添加`OnAppearing`方法的重写，如下所示：

```cs
protected override void OnAppearing()
{
    base.OnAppearing();

    if (BindingContext is MainViewModel viewModel)
    {
        MainThread.BeginInvokeOnMainThread(async () =>
        {
            await viewModel.LoadData();
        });
    }
} 
```

在 XAML 中，将`ContentPage`的`Title`属性的绑定添加到`ViewModel`中的`City`属性，如下所示：

1.  在`Weather`项目中，打开`MainView_Phone.xaml`文件。

1.  添加一个绑定到`MainViewModel`的`City`属性的`Title`属性，如下所示：

```cs
<ContentPage xmlns="http://xamarin.com/schemas/2014/forms"
    xmlns:x="http://schemas.microsoft.com/winfx/2009/xaml"
    xmlns:controls="clr-namespace:Weather.Controls" 
    x:Class="Weather.Views.MainView_Phone" 
    Title="{Binding City}">
```

# 使用分组的 ListView

我们可以在手机视图中使用`RepeaterView`，但是因为我们希望用户体验尽可能好，所以我们将使用`ListView`。为了获得每天的标题，我们将在`ListView`中使用分组。对于`RepeaterView`，我们有`ScrollView`，但对于`ListView`，我们不需要，因为`ListView`默认可以处理滚动。

让我们继续通过以下步骤为手机视图创建用户界面：

1.  在`Weather`项目中，打开`MainView_Phone.xaml`文件。

1.  将`ListView`添加到页面的根部。

1.  为`ListView`的`ItemSource`属性设置`MainViewModel`中的`Days`属性的绑定。

1.  将`IsGroupingEnabled`设置为`True`，以在`ListView`中启用分组。

1.  将`HasUnevenRows`设置为`True`，这样`ListView`中每个单元格的高度将为每个项目计算。

1.  将`CachingStrategy`设置为`RecycleElement`，以重用不在屏幕上的单元格。

1.  将`BackgroundColor`设置为`Transparent`，如下所示：

```cs
<ListView ItemsSource="{Binding Days}" IsGroupingEnabled="True" 
          HasUnevenRows="True" CachingStrategy="RecycleElement" 
          BackgroundColor="Transparent">
</ListView>
```

将`CachingStrategy`设置为`RecycleElement`，以从`ListView`中获得更好的性能。这意味着它将重用不显示在屏幕上的单元格，因此它将使用更少的内存，如果`ListView`中有许多项目，我们将获得更流畅的滚动体验。

为了格式化每个标题的外观，我们将通过以下步骤创建一个`DataTemplate`：

1.  将`DataTemplate`添加到`ListView`的`GroupHeaderTemplate`属性中。

1.  将`ViewCell`添加到`DataTemplate`中。

1.  将行的内容添加到`ViewCell`中，如下所示：

```cs
<ListView ItemsSource="{Binding Days}" IsGroupingEnabled="True" 
                   HasUnevenRows="True" 
                   CachingStrategy="RecycleElement" 
                   BackgroundColor="Transparent">
       <ListView.GroupHeaderTemplate>
         <DataTemplate>
             <ViewCell>
                 <ContentView Padding="15,5"  
                  BackgroundColor="#9F5010">
              <Label FontAttributes="Bold" TextColor="White"  
              Text="{Binding DateAsString}"   
              VerticalOptions="Center"/>
                  </ContentView>
             </ViewCell>
         </DataTemplate>
    </ListView.GroupHeaderTemplate> 
</ListView>
```

为了格式化每个预测的外观，我们将创建一个`DataTemplate`，就像我们对分组标题所做的那样。让我们通过以下步骤来设置这个：

1.  将`DataTemplate`添加到`ListView`的`ItemTemplate`属性中。

1.  将`ViewCell`添加到`DataTemplate`中。

1.  在`ViewCell`中，添加一个包含四列的`Grid`。使用`ColumnDefinition`属性来指定列的宽度。第二列应为`50`，其他三列将共享其余的空间。我们将通过将`Width`设置为`*`来实现这一点。

1.  添加内容到`Grid`，如下面的代码所示：

```cs
<ListView.ItemTemplate>
    <DataTemplate>
        <ViewCell>
            <Grid Padding="15,10" ColumnSpacing="10" 
                BackgroundColor="#99FFFFFF">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*" />
                    <ColumnDefinition Width="50" />
                    <ColumnDefinition Width="*" />
                    <ColumnDefinition Width="*" />
                </Grid.ColumnDefinitions>
                <Label FontAttributes="Bold" Text="{Binding 
                  TimeAsString}" VerticalOptions="Center" />
                <Image Grid.Column="1" HeightRequest="50" 
                  WidthRequest="50" Source="{Binding Icon}"   
                  Aspect="AspectFit" VerticalOptions="Center" />
                <Label Grid.Column="2" Text="{Binding Temperature, 
                StringFormat='{0}°  C'}" VerticalOptions="Center" />
                <Label Grid.Column="3" Text="{Binding Description}" 
                 VerticalOptions="Center" />
            </Grid>
        </ViewCell>
    </DataTemplate>
</ListView.ItemTemplate> 
```

# 添加下拉刷新功能

对于视图的平板电脑和台式机版本，我们在工具栏中添加了一个按钮来刷新天气预报。然而，在手机版本的视图中，我们将添加下拉刷新，这是一种常见的刷新数据列表内容的方式。Xamarin.Forms 中的`ListView`内置支持下拉刷新。让我们通过以下步骤来设置这个功能：

1.  转到`MainView_Phone.xaml`。

1.  将`IsPullToRefreshEnabled`属性设置为`True`，以启用`ListView`的下拉刷新。

1.  将`MainViewModel`中的`Refresh`属性绑定到`ListView`的`RefreshCommand`属性，以在用户执行下拉刷新手势时触发刷新。

1.  为了在刷新进行中显示加载图标，将`MainViewModel`中的`IsRefreshing`属性绑定到`ListView`的`IsRefreshing`属性。当我们设置这个属性时，当初始加载正在运行时，我们也会得到一个加载指示器，如下面的代码所示：

```cs
<ListView ItemsSource="{Binding Days}" IsGroupingEnabled="True" 
           HasUnevenRows="True" CachingStrategy="RecycleElement" 
           BackgroundColor="Transparent" 
 IsPullToRefreshEnabled="True" 
           RefreshCommand="{Binding Refresh}" 
 IsRefreshing="{Binding  
           IsRefreshing}"> 
```

# 根据形态因素导航到不同的视图

现在我们有两个不同的视图，应该在应用程序的同一个位置加载。如果应用程序在平板电脑或台式机上运行，应该加载`MainView`，如果应用程序在手机上运行，应该加载`MainView_Phone`。

Xamarin.Forms 中的`Device`类有一个静态的`Idiom`属性，我们可以使用它来检查应用程序运行在哪种形态因素上。`Idiom`的值可以是`Phone`、`Table`、`Desktop`、`Watch`或`TV`。因为我们在这个应用程序中只有一个视图，所以当我们在`App.xaml.cs`中设置`MainPage`时，我们可以使用`if`语句来检查`Idiom`的值。然而，相反地，我们将构建一个解决方案，也可以用于更大的应用程序。

一个解决方案是构建一个导航服务，我们可以使用它根据键导航到不同的视图。哪个视图将根据启动应用程序进行配置。通过这个解决方案，我们可以在不同类型的设备上为相同的键配置不同的视图。我们可以用于此目的的开源导航服务是`TinyNavigationHelper`，可以在[`github.com/TinyStuff/TinyNavigationHelper`](https://github.com/TinyStuff/TinyNavigationHelper)找到，由本书的作者创建。

还有一个名为`TinyMvvm`的 MVVM 库，它包含`TinyNavigationHelper`作为依赖项。`TinyMvvm`库是一个包含辅助类的库，可以让您在 Xamarin.Forms 应用程序中更快地开始使用 MVVM。我们创建了`TinyMvvm`，因为我们希望避免一遍又一遍地编写相同的代码。您可以在[`github.com/TinyStuff/TinyMvvm`](https://github.com/TinyStuff/TinyMvvm)上阅读更多信息。

按照以下步骤将`TinyNavigationHelper`添加到应用程序中：

1.  在`Weather`项目中安装`TinyNavigationHelper.Forms` NuGet 包。

1.  转到`Bootstrapper.cs`。

1.  在`Execute`方法的开头，创建一个`FormsNavigationHelper`并将当前应用程序传递给构造函数。

1.  在`Idiom`为`Phone`时添加一个`if`语句来检查。如果是这样，`MainView_Phone`视图应该被注册为`MainView`键。

1.  添加一个`else`语句，为`MainView`注册`MainView`键。

1.  `Bootstrapper`类现在应该如下面的代码所示，新代码用粗体标记出来：

```cs
public class Bootstrapper
{
    public static void Init()
    {
 var navigation = new 
        FormsNavigationHelper(Application.Current);

 if (Device.Idiom == TargetIdiom.Phone)
 {
 navigation.RegisterView("MainView",  
            typeof(MainView_Phone));
 }
 else
 {
 navigation.RegisterView("MainView", typeof(MainView));
 }

        var containerBuilder = new ContainerBuilder();
        containerBuilder.RegisterType<OpenWeatherMapWeatherService>
        ().As<IWeatherService>();
        containerBuilder.RegisterType<MainViewModel>();

        var container = containerBuilder.Build();

        Resolver.Initialize(container);
    }
}

```

现在，我们可以通过以下步骤在`App`类的构造函数中使用`NavigationHelper`类来设置应用程序的根视图：

1.  在`Weather`应用程序中，打开`App.xaml.cs`文件。

1.  找到`App`类的构造函数。

1.  删除`MainPage`属性的赋值。

1.  添加代码以通过`NavigationHelper`设置根视图。

1.  构造函数现在应该看起来像以下片段中的粗体代码：

```cs
public App()
{
    InitializeComponent();
    Bootstrapper.Execute();
 NavigationHelper.Current.SetRootView("MainView", true);
} 
```

如果我们想在不同的操作系统上加载不同的视图，我们可以使用 Xamarin.Forms 的`Device`类上的静态`RuntimePlatform`方法，例如`if(Device.RuntimePlatform == Device.iOS)`。

# 使用 VisualStateManager 处理状态

`VisualStateManager`在 Xamarin.Forms 3.0 中引入。这是一种从代码中对 UI 进行更改的方法。我们可以定义状态，并为选定的属性设置值，以应用于特定状态。`VisualStateManager`在我们想要在具有不同屏幕分辨率的设备上使用相同视图的情况下非常有用。它最初是在 UWP 中引入的，以便更容易地为多个平台创建 Windows 10 应用程序，因为 Windows 10 可以在 Windows Phone 以及台式机和平板电脑上运行（操作系统被称为 Windows 10 Mobile）。然而，Windows Phone 现在已经被淘汰。对于我们作为 Xamarin.Forms 开发人员来说，`VisualStateManager`非常有趣，特别是当 iOS 和 Android 都可以在手机和平板电脑上运行时。

在这个项目中，我们将使用它在平板电脑或台式机上以横向模式运行应用程序时使预报项目变大。我们还将使天气图标变大。让我们通过以下步骤来设置这个：

1.  在`Weather`项目中，打开`MainView.xaml`文件。

1.  在第一个`RepeaterView`和`DataTemplate`中，在第一个`StackLayout`中插入一个`VisualStateManager.VisualStateGroups`元素：

```cs
<StackLayout Margin="10" Padding="20" WidthRequest="150"  
    BackgroundColor="#99FFFFFF">
    <VisualStateManager.VisualStateGroups>
 <VisualStateGroup> 
 </VisualStateGroup>
 </VisualStateManager.VisualStateGroups> 
</StackLayout>
```

对`VisualStateGroup`添加两个状态，我们将按照以下步骤进行：

1.  向`VisualStateGroup`添加一个名为`Portrait`的新`VisualState`。

1.  在`VisualState`中创建一个 setter，并将`WidthRequest`设置为`150`。

1.  在`VisualStateGroup`中创建另一个名为`Landscape`的`VisualState`。

1.  在`VisualState`中创建一个 setter，并将`WidthRequest`设置为`200`，如下所示：

```cs
 <VisualStateGroup>
     <VisualState Name="Portrait">
 <VisualState.Setters>
 <Setter Property="WidthRequest" Value="150" />
 </VisualState.Setters>
 </VisualState>
 <VisualState Name="Landscape">
 <VisualState.Setters>
 <Setter Property="WidthRequest" Value="200" />
 </VisualState.Setters>
 </VisualState>
</VisualStateGroup> 
```

当项目本身变大时，我们还希望预报项目中的图标变大。为此，我们将再次使用`VisualStateManager`。让我们通过以下步骤来设置这个：

1.  在第二个`RepeaterView`和`DataTemplate`中的`Image`元素中插入一个`VisualStateManager.VisualStateGroups`元素。

1.  为`Portrait`和`Landscape`添加`VisualState`。

1.  向状态添加 setter，设置`WidthRequest`和`HeightRequest`。在`Portrait`状态中，值应为`100`，在`Landscape`状态中，值应为`150`，如下所示：

```cs
<Image WidthRequest="100" HeightRequest="100" Aspect="AspectFit" HorizontalOptions="Center" Source="{Binding Icon}">
    <VisualStateManager.VisualStateGroups>
 <VisualStateGroup>
 <VisualState Name="Portrait">
 <VisualState.Setters>
 <Setter Property="WidthRequest" Value="100" />
 <Setter Property="HeightRequest" Value="100" />
 </VisualState.Setters>
 </VisualState>
 <VisualState Name="Landscape">
 <VisualState.Setters>
 <Setter Property="WidthRequest" Value="150" />
 <Setter Property="HeightRequest" Value="150" />
 </VisualState.Setters>
 </VisualState>
 </VisualStateGroup>
 </VisualStateManager.VisualStateGroups>
</Image> 
```

# 创建一个用于设置状态更改的行为

使用`Behavior`，我们可以为控件添加功能，而无需对它们进行子类化。使用行为，我们还可以创建比对控件进行子类化更可重用的代码。我们创建的`Behavior`越具体，它就越可重用。例如，从`Behavior<View>`继承的`Behavior`可以用于所有控件，但从`Button`继承的`Behavior`只能用于按钮。因此，我们总是希望使用更少特定基类创建行为。

当我们创建一个`Behavior`时，我们需要重写两个方法：`OnAttached`和`OnDetachingFrom`。如果我们在`OnAttached`方法中添加了事件监听器，那么在`OnDeattached`方法中将其移除是非常重要的。这将使应用程序使用更少的内存。在`OnAppearing`方法运行之前，将值设置回它们之前的值也是非常重要的；否则，我们可能会看到一些奇怪的行为，特别是如果行为在重用单元的`ListView`中。

在这个应用程序中，我们将为`RepeaterView`创建一个`Behavior`。这是因为我们无法从代码后台设置`RepeaterView`中项目的状态。我们本可以在`RepeaterView`中添加代码来检查应用程序是在纵向还是横向运行，但如果我们使用`Behavior`，我们可以将该代码与`RepeaterView`分离，使其更具可重用性。相反，我们将在`RepeaterView`中添加一个`Property string`，它将设置`RepeaterView`及其中所有子项的状态。让我们通过以下步骤来设置这一点：

1.  在`Weather`项目中，打开`RepeaterView.cs`文件。

1.  创建一个名为`visualState`的新`private string`字段。

1.  创建一个名为`VisualState`的新`string`属性。

1.  创建一个使用表达式返回`visualState`的 getter。

1.  在 setter 中，设置`RepeaterView`及所有子项的状态，如下所示：

```cs
private string visualState;
public string VisualState
{
    get => visualState;
    set 
    {
        visualState = value;

        foreach(var child in Children)
        {
            VisualStateManager.GoToState(child, visualState);
        }

        VisualStateManager.GoToState(this, visualState);
     }
} 
```

这将遍历每个`child`控件并设置视觉状态。现在让我们按照以下步骤创建将触发状态更改的行为：

1.  在`Weather`项目中，创建一个名为`Behaviors`的新文件夹。

1.  创建一个名为`RepeaterViewBehavior`的新类。

1.  将`Behavior<RepeaterView>`作为基类添加。

1.  创建一个名为`view`的`private`类型为`RepeaterView`的字段。

1.  代码应如下所示：

```cs
using System;
using Weather.Controls;
using Xamarin.Essentials;
using Xamarin.Forms;

namespace Weather.Behaviors
{ 
    public class RepeaterViewBehavior : Behavior<RepeaterView>
    {
        private RepeaterView view;
    }
}
```

`RepeaterViewBehavior`是一个从`Behavior<RepeaterView>`基类继承的类。这将使我们能够重写一些虚拟方法，当我们将行为附加和分离到`RepeaterView`时将被调用。

但首先，我们需要通过以下步骤创建一个处理状态变化的方法：

1.  在`Weather`项目中，打开`RepeaterViewBehavior.cs`文件。

1.  创建一个名为`UpdateState`的`private`方法。

1.  在`MainThread`上运行代码，以检查应用程序是在纵向还是横向模式下运行。

1.  创建一个名为`page`的变量，并将其值设置为`Application.Current.MainPage`。

1.  检查`Width`是否大于`Height`。如果是，则将视图变量的`VisualState`属性设置为`Landscape`。如果不是，则将视图变量的`VisualState`属性设置为`Portrait`，如下所示：

```cs
private void UpdateState()
{
    MainThread.BeginInvokeOnMainThread(() =>
    {
        var page = Application.Current.MainPage;

        if (page.Width > page.Height)
        {
            view.VisualState = "Landscape";
            return;
        }

        view.VisualState = "Portrait";
    });
} 
```

现在添加了`UpdateState`方法。现在我们需要重写`OnAttachedTo`方法，当行为添加到`RepeaterView`时将被调用。当行为添加到`RepeaterView`时，我们希望通过调用此方法来更新状态，并且还要连接到`MainPage`的`SizeChanged`事件，以便在大小更改时再次更新状态。

让我们通过以下步骤设置这一点：

1.  在`Weather`项目中，打开`RepeaterViewBehavior.cs`文件。

1.  重写基类中的`OnAttachedTo`方法。

1.  将`view`属性设置为`OnAttachedTo`方法的参数。

1.  向`Application.Current.MainPage.SizeChanged`添加事件监听器。在事件监听器中，调用`UpdateState`方法，如下所示：

```cs
protected override void OnAttachedTo(RepeaterView view)
{
    this.view = view;

    base.OnAttachedTo(view);

    UpdateState();

    Application.Current.MainPage.SizeChanged += 
    MainPage_SizeChanged;
} 

    void MainPage_SizeChanged(object sender, EventArgs e)
{
    UpdateState();
} 
```

当我们从控件中移除行为时，非常重要的是还要移除任何事件处理程序，以避免内存泄漏，并在最坏的情况下，导致应用程序崩溃。让我们通过以下步骤来做到这一点：

1.  在`Weather`项目中，打开`RepeaterViewBehavior.cs`文件。

1.  重写基类中的`OnDetachingFrom`。

1.  从`Application.Current.MainPage.SizeChanged`中删除事件监听器。

1.  将`view`字段设置为`null`，如下所示：

```cs
protected override void OnDetachingFrom(RepeaterView view)
{
    base.OnDetachingFrom(view);

    Application.Current.MainPage.SizeChanged -= 
    MainPage_SizeChanged;
    this.view = null;
}
```

按照以下步骤将`behavior`添加到视图中：

1.  在`Weather`项目中，打开`MainView.xaml`文件。

1.  导入`Weather.Behaviors`命名空间，如下所示：

```cs
 <ContentPage xmlns="http://xamarin.com/schemas/2014/forms" 
              xmlns:x="http://schemas.microsoft.com/winfx/2009/xaml" 
              xmlns:controls="clr-namespace:Weather.Controls" 
 xmlns:behaviors="clr-                          
 namespace:Weather.Behaviors"
              x:Class="Weather.Views.MainView" Title="{Binding City}"> 
```

我们要做的最后一件事是将`RepeaterViewBehavior`添加到第二个`RepeaterView`中，如下所示：

```cs
 <controls:RepeaterView ItemsSource="{Binding Items}" Wrap="Wrap"  
 JustifyContent="Start" AlignItems="Start">
    <controls:RepeaterView.Behaviors>
 <behaviors:RepeaterViewBehavior />
 </controls:RepeaterView.Behaviors>
    <controls:RepeaterView.ItemsTemplate> 
```

# 总结

我们现在已经成功地为三种不同的操作系统——iOS、Android 和 Windows——以及三种不同的形态因素——手机、平板和台式电脑创建了一个应用。为了在所有平台和形态因素上创造良好的用户体验，我们使用了`FlexLayout`和`VisualStateManager`。我们还学会了如何处理当我们想要为不同的形态因素使用不同的视图，以及如何使用`Behaviors`。

接下来我们要构建的应用是一个具有实时通讯功能的聊天应用。在下一章中，我们将看看如何在 Azure 中使用 SignalR 服务作为聊天应用的后端。


# 第六章：使用 Azure 服务为聊天应用程序设置后端

在本章中，我们将构建一个具有实时通信的聊天应用程序。为此，我们需要一个后端。我们将创建一个后端，可以扩展以处理大量用户，但当用户数量减少时也可以缩小。为了构建该后端，我们将使用基于 Microsoft Azure 服务的无服务器架构。

本章将涵盖以下主题：

+   在 Microsoft Azure 中创建 SignalR 服务

+   使用 Azure 函数作为 API

+   使用 Azure 函数调度作业

+   使用 blob 存储来存储照片

+   使用 Azure 认知服务扫描照片以查找成人内容

# 技术要求

为了能够完成这个项目，您需要安装 Mac 或 PC 上的 Visual Studio。有关如何设置您的环境的更多详细信息，请参阅第一章，*Xamarin 简介*。您还需要一个 Azure 帐户。如果您有 Visual Studio 订阅，每个月都包含特定数量的 Azure 积分。要激活您的 Azure 福利，请转到以下链接：[`my.visualstudio.com`](https://my.visualstudio.com)。

您还可以创建一个免费帐户，在 12 个月内免费使用选定的服务。您将获得价值 200 美元的信用额度，以在 30 天内探索任何 Azure 服务，并且您还可以随时使用免费服务。在以下链接阅读更多信息：[`azure.microsoft.com/en-us/free/`](https://azure.microsoft.com/en-us/free/)。

# Azure 无服务器服务

在我们开始构建具有无服务器架构的后端之前，我们需要定义无服务器实际意味着什么。在无服务器架构中，当然代码将在服务器上运行，但我们不需要担心这一点；我们唯一需要关注的是构建我们的软件。我们让其他人处理与服务器有关的一切。我们不需要考虑服务器需要多少内存或 CPU，甚至我们需要多少服务器。当我们在 Azure 中使用服务时，微软会为我们处理这一切。

# Azure SignalR 服务

**Azure SignalR 服务**是**Microsoft Azure**中用于服务器和客户端之间的实时通信的服务。该服务将向客户端推送内容，而无需他们轮询服务器以获取内容更新。SignalR 可用于多种类型的应用程序，包括移动应用程序、Web 应用程序和桌面应用程序。

如果可用，SignalR 将使用 WebSockets。如果不可用，SignalR 将使用其他通信技术，如**服务器发送事件**（**SSE**）或**长轮询**。SignalR 将检测可用的传输技术并使用它，而开发人员根本不需要考虑这一点。

SignalR 可以在以下示例中使用：

+   **聊天应用程序**：当新消息可用时，应用程序需要立即从服务器获取更新

+   **协作应用程序**：例如，会议应用程序或多个设备上的用户正在使用相同文档时

+   **多人游戏**：所有用户都需要实时更新其他用户的地方

+   **仪表板应用程序**：用户需要实时更新的地方

# Azure 函数

Azure 函数是微软 Azure 的一项服务，允许我们以无服务器的方式运行代码。我们将部署称为**函数**的小代码片段。函数部署在称为**函数应用**的组中。创建函数应用时，我们需要选择是否要在消耗计划或应用服务计划上运行。如果我们希望应用程序完全无服务器化，我们选择消耗计划，而对于应用服务计划，我们必须指定服务器的要求。使用消耗计划，我们支付执行时间和函数使用的内存量。应用服务计划的一个好处是可以配置为始终运行，并且只要不需要扩展到更多实例，就不会有任何冷启动。消耗计划的一个重要好处是它将根据需要的资源进行自动扩展。

函数可以通过多种方式触发运行。两个例子是`HttpTrigger`和`TimeTrigger`。`HttpTrigger`将在调用函数的 HTTP 请求时触发函数运行。使用`TimeTrigger`，函数将按照我们指定的间隔运行。还有其他 Azure 服务的触发器。例如，我们可以配置函数在文件上传到 blob 存储时运行，当新消息发布到事件中心或服务总线时运行，或者在 Azure CosmosDB 中的数据发生变化时运行。

# Azure blob 存储

Azure blob 存储用于存储非结构化数据对象，如图像、视频、音频和文档。对象或 blob 可以组织成容器。Azure 的 Blob 存储可以在多个数据中心进行冗余。这是为了保护数据免受从瞬时硬件故障到网络或电源中断，甚至大规模自然灾害的不可预测事件的影响。Azure 的 Blob 存储可以有不同的层级，取决于我们希望使用存储的对象的频率。这包括存档和冷层，以及热层和高级层，用于需要更频繁访问数据的应用程序。除了 Blob 存储，我们还可以添加**内容交付网络**（**CDN**）以使我们存储的内容更接近我们的用户。如果我们的用户遍布全球，这一点很重要。如果我们可以从更接近用户的地方提供我们的内容，我们可以减少内容的加载时间，并为用户提供更好的体验。

# Azure 认知服务

描述**Azure 认知服务**最简单的方法是它是**机器学习**作为一项服务。只需简单的 API 调用，我们就可以在我们的应用程序中使用机器学习，而无需使用复杂的数据科学技术。当我们使用 API 时，我们正在针对 Microsoft 为我们训练的模型进行预测。

Azure 认知服务的服务已经组织成五个类别：

+   **视觉**：视觉服务涉及图像处理。这包括面部识别、成人内容检测、图像分类和**光学字符识别**（**OCR**）的 API。

+   **知识**：知识服务的一个示例是**问答**（**QnA**）制作者，它允许我们用知识库训练模型。当我们训练了模型，我们可以用它来获取问题的答案。

+   **语言**：语言服务涉及文本理解，如文本分析、语言理解和翻译。

+   **语音**：语音 API 的示例包括说话者识别、语音转文本功能和语音翻译。

+   **搜索**：搜索服务是利用网络搜索引擎的力量来找到问题的答案。这包括从图像中获取知识、搜索查询的自动完成以及相似人员的识别。

# 项目概述

这个项目将是为聊天应用程序设置后端。项目的最大部分将是我们将在 Azure 门户中进行的配置。我们还将为处理 SignalR 连接的 Azure Functions 编写一些代码。将有一个函数返回有关 SignalR 连接的信息，还有一个函数将消息发布到 SignalR 服务。发布消息的函数还将确定消息是否包含图像。如果包含图像，它将被发送到 Azure 认知服务中的 Vision API，以分析是否包含成人内容。如果包含成人内容，它将不会发布到 SignalR 服务，其他用户也不会收到。由于 SignalR 服务有关于消息大小的限制，我们需要将图像存储在 blob 存储中，只需将图像的 URL 发布给用户。因为我们在这个应用程序中不保存任何聊天记录，我们还希望在特定间隔清除 blob 存储。为此，我们将创建一个使用`TimeTrigger`的函数。

以下图显示了此应用程序架构的概述：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/2d439ffb-2128-471c-95c7-422d7b1cda07.png)

完成此项目的估计时间约为两个小时。

# 构建无服务器后端

让我们开始根据前面部分描述的服务来设置后端。

# 创建 SignalR 服务

我们将设置的第一个服务是 SignalR：

1.  转到 Azure 门户：[`portal.azure.com`](https://portal.azure.com)。

1.  创建一个新资源。**SignalR 服务**位于 Web 类别中。

1.  填写表单中的资源名称。

1.  选择要用于此项目的订阅。

1.  我们建议您创建一个新的资源组，并将其用于为此项目创建的所有资源。我们希望使用一个资源组的原因是更容易跟踪与此项目相关的资源，并且更容易一起删除所有资源。

1.  选择一个靠近您的用户的位置。

1.  选择一个定价层。对于这个项目，我们可以使用免费层。我们可以始终在开发中使用免费层，然后扩展到可以处理更多连接的层。参考以下截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/62b6c152-5606-4f37-962b-4a128ffefab8.png)

这就是我们设置 SignalR 服务所需做的一切。我们将在 Azure 门户中返回以获取连接字符串。

# 创建存储帐户

下一步是设置一个存储帐户，我们可以在其中存储用户上传的图像：

1.  创建一个新的存储帐户资源。存储帐户位于存储类别下。

1.  选择订阅和资源组。我们建议您使用与 SignalR 服务相同的订阅和资源组。

1.  给存储帐户命名。

1.  选择一个靠近您的用户的位置。

1.  选择性能选项。如果我们使用高级存储，数据将存储在 SSD 磁盘上。为此项目选择标准存储。

1.  使用 StorageV2 作为帐户类型。

1.  在复制中，我们可以选择我们希望数据在数据中心之间如何复制。

1.  对于访问层，我们将使用热层，因为在这个应用程序中我们需要频繁访问数据。

1.  单击创建+审阅以在创建存储帐户之前审查设置。

1.  单击创建以创建存储帐户：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/f385b548-0a0f-4097-9513-c284754453b3.png)

blob 存储配置的最后一步是转到资源并为聊天图像创建一个容器：

1.  转到资源并选择 Blobs。

1.  创建一个名为`chatimages`的新容器。

1.  将公共访问级别设置为 Blob（仅对 Blob 的匿名读取访问）。这意味着它将具有公共读取访问权限，但您必须获得授权才能上传内容。参考以下截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/f71fdee8-2685-4e61-8b4a-4563de5ea35b.png)

# 创建认知服务

为了能够使用**认知服务**来扫描成人内容的图像，我们需要在 Azure 门户中创建一个资源。这将为我们提供一个在调用 API 时可以使用的密钥：

1.  创建一个新的自定义视觉资源。

1.  给资源命名并选择订阅。

1.  选择一个靠近用户的位置。

1.  为预测和训练选择一个定价层。此应用程序将仅使用预测，因为我们将使用已经训练好的模型。

1.  选择与您为其他资源选择的相同的资源组。

1.  点击“确定”创建新资源。参考以下截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/35760e18-4d2d-4569-93ed-64609451c594.png)

我们现在已经完成了创建认知服务。稍后我们将回来获取一个密钥，我们将用它来调用 API。

# 创建函数

我们将在后端编写的所有代码都将是函数。我们将使用 Azure Functions 的第 2 版，它将在.NET Core 之上运行。第 1 版是在完整的.NET 框架之上运行的。

# 创建用于函数的 Azure 服务

在开始编写任何代码之前，我们将创建 Function App。这将在 Azure 门户中包含函数：

1.  创建一个新的 Function App 资源。Function App 在计算类别下找到。

1.  给 Function App 命名。该名称也将成为函数 URL 的起始部分。

1.  为 Function App 选择一个订阅。

1.  为 Function App 选择一个资源组，应该与本章中创建的其他资源相同。

1.  因为我们将使用.NET Core 作为函数的运行时，所以可以在 Windows 和 Linux 上运行它们。但在这种情况下，我们将在 Windows 上运行它们。

1.  我们将使用**消耗计划**作为我们的托管计划，因此我们只支付我们使用的费用。Function App 将根据我们的要求进行上下缩放，而无需我们考虑任何事情，如果我们选择消耗计划。

1.  选择一个靠近用户的位置。

1.  选择.NET 作为运行时堆栈。

1.  对于存储，我们可以创建一个新的存储帐户，或者使用我们在此项目中早期创建的存储帐户。

1.  将应用程序洞察设置为打开，以便我们可以监视我们的函数。

1.  点击“创建”以创建新资源：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/6c829370-40e8-4cef-b9a3-b4a11a9afec7.png)

# 创建一个函数来返回 SignalR 服务的连接信息

如果愿意，可以在 Azure 门户中创建函数。但我更喜欢使用 Visual Studio，因为代码编辑体验更好，而且可以对源代码进行版本跟踪：

1.  在 Visual Studio 中创建一个 Azure Functions 类型的新项目。这可以在新项目对话框的云选项卡下找到。

1.  将项目命名为`Chat.Functions`。

1.  点击“确定”继续：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/164daf00-aeb7-4a95-af57-836603c096eb.png)

下一步是创建我们的第一个函数：

1.  在对话框顶部选择 Azure Functions v2 (.NET Core)。

1.  选择 Http 触发器作为我们第一个函数的触发器。

1.  将**访问权限**从管理员更改为匿名。

1.  点击“确定”继续，我们的函数项目将被创建：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/eb5a4909-85eb-49dd-9769-cf701904b327.png)

我们的第一个函数将返回 SignalR 服务的连接信息。为此，我们需要通过向 SignalR 服务添加连接字符串来连接函数：

1.  转到 Azure 门户中的 SignalR 服务资源。

1.  转到 Keys 选项卡并复制连接字符串。

1.  转到 Function App 资源并在应用程序设置下添加连接字符串。使用`AzureSignalRConnectionString`作为设置的名称。

1.  将连接字符串添加到 Visual Studio 项目中的`local.settings.json`文件的`Values`数组中，以便能够在开发机器上本地运行函数：

```cs
 {
    "IsEncrypted": false,
    "Values": {
    "AzureWebJobsStorage": "",
    "AzureWebJobsDashboard": ""
    "AzureSignalRConnectionString": "{EnterTheConnectingStringHere}"
   }
 } 
```

现在，我们可以编写将返回连接信息的函数的代码。转到 Visual Studio 并按照以下说明操作：

1.  在函数项目中安装`Microsoft.Azure.WebJobs.Extensions.SignalRService` NuGet 包。该包包含了我们与 SignalR 服务通信所需的类。这是一个预发布包，因此我们必须勾选包含预发布复选框。如果在此过程中出现错误，无法安装该包，请确保您的项目中所有其他包的版本都是最新的，然后重试。

1.  将在创建函数项目时创建的函数重命名为`GetSignalRInfo`。

1.  还要将类重命名为`GetSignalRInfo`。

1.  为了实现与 SignalR 服务的绑定，我们将在函数的方法中添加一个`SignalRConnectionInfo`类型的参数。该参数还将具有`SignalRConnectionInfo`属性，指定`HubName`，如下代码所示。

1.  返回连接信息参数：

```cs
using Microsoft.AspNetCore.Http;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Azure.WebJobs.Extensions.SignalRService;

    [FunctionName("GetSignalRInfo")]
    public static SignalRConnectionInfo GetSignalRInfo(
    [HttpTrigger(AuthorizationLevel.Anonymous)] HttpRequest req,
    [SignalRConnectionInfo(HubName = "chat")] SignalRConnectionInfo   
    connectionInfo)
{
    return connectionInfo;
}
```

# 创建一个消息库

我们现在将定义一些消息类，我们将用它们来发送聊天消息。我们将创建一个基本消息类，其中包含所有类型消息共享的信息。我们还将创建一个消息的独立项目，它将是一个.NET 标准库。我们之所以将它创建为一个独立的.NET 标准库，是因为我们可以在下一章中构建的应用程序中重用它。

1.  创建一个新的.NET 标准 2.0 项目，命名为`Chat.Messages`。

1.  在`Chat.Functions`项目中添加对`Chat.Messages`的引用。

1.  在`Chat.Messages`项目中创建一个新类，命名为`Message`。

1.  向`Message`类添加一个`TypeInfo`属性。我们在第七章中需要这个属性，*构建实时聊天应用程序*，当我们进行消息序列化时。

1.  添加一个名为`Id`的字符串类型的属性。

1.  添加一个`DateTime`类型的`Timestamp`属性。

1.  添加一个`string`类型的`Username`属性。

1.  添加一个空的构造函数。

1.  添加一个以用户名为参数的构造函数。

1.  将所有属性的值设置如下代码所示：

```cs
public class Message
{
    public Type TypeInfo { get; set; }
    public string Id {get;set;}
    public string Username { get; set; }
    public DateTime Timestamp { get; set; }

    public Message(){}
    public Message(string username)
    {
        Id = Guid.NewGuid().ToString();
        TypeInfo = GetType();
        Username = username;
        Timestamp = DateTime.Now;
    }
}
```

当新客户端连接时，将向其他用户发送一条消息，指示他们已连接：

1.  创建一个名为`UserConnectedMessage`的新类。

1.  将`Message`作为基类。

1.  添加一个空的构造函数。

1.  添加一个以用户名为参数的构造函数，并将其发送到基类的构造函数，如下代码所示：

```cs
public class UserConnectedMessage : Message
{
    public UserConnectedMessage() { }
    public UserConnectedMessage(string username) : base(username) { }
} 
```

当客户端发送带有文本的消息时，它将发送一个`SimpleTextMessage`：

1.  创建一个名为`SimpleTextMessage`的新类。

1.  将`Message`作为基类。

1.  添加一个空的构造函数。

1.  添加一个以用户名为参数的构造函数，并将其发送到基类的构造函数。

1.  添加一个名为`Text`的字符串属性。参考以下代码：

```cs
public class SimpleTextMessage : Message
{
    public SimpleTextMessage(){}
    public SimpleTextMessage(string username) : base(username){} 
    public string Text { get; set; }
} 
```

如果用户上传了一张图片，它将作为`base64`字符串发送到函数：

1.  创建一个名为`PhotoMessage`的新类。

1.  将`Message`作为基类。

1.  添加一个空的构造函数。

1.  添加一个以用户名为参数的构造函数，并将其发送到基类的构造函数。

1.  添加一个名为`Base64Photo`的字符串属性。

1.  添加一个名为`FileEnding`的字符串属性，如下代码片段所示：

```cs
public class PhotoMessage : Message
{
    public PhotoMessage() { }
    public PhotoMessage(string username) : base(username) { }

    public string Base64Photo { get; set; }
    public string FileEnding { get; set; }
} 
```

我们将创建的最后一个消息用于向用户发送有关照片的信息：

1.  创建一个名为`PhotoUrlMessage`的新类。

1.  将`Message`作为基类。

1.  添加一个空的构造函数。

1.  添加一个以用户名为参数的构造函数，并将其发送到基类的构造函数。

1.  添加一个名为`Url`的字符串属性。参考以下代码：

```cs
public class PhotoUrlMessage : Message
{
    public PhotoUrlMessage() {}
    public PhotoUrlMessage(string username) : base(username){}

    public string Url { get; set; }
} 
```

# 创建存储助手

我们将创建一个辅助程序，以便在我们将为 Azure Blob Storage 编写的一些代码之间共享发送消息函数和我们将创建的清除照片函数。在 Azure 门户中创建 Function App 时，会创建一个用于连接字符串的设置，因此我们只需将其添加到`local.settings.json`文件中，以便能够在本地运行它。连接字符串的名称将是`StorageConnection`：

```cs
 {
     "IsEncrypted": false,
     "Values": {
     "AzureWebJobsStorage": "",
     "AzureWebJobsDashboard": "",
     "AzureSignalRConnectionString": "{EnterTheConnectingStringHere}"
     "StorageConnection": "{EnterTheConnectingStringHere}"
   }
 } 
```

对于辅助程序，我们将创建一个新的静态类，如下所示：

1.  在`Chat.Functions`项目中安装`WindowsAzure.Storage NuGet`包。这是为了获得我们需要与存储一起使用的类。

1.  在`Chat.Functions`项目中创建一个名为`StorageHelper`的新类。

1.  将类`static`。

1.  创建一个名为`GetContainer`的新静态方法。

1.  使用`Environment`类上的静态`GetEnviromentVariable`方法读取存储的连接字符串。

1.  使用静态`Parse`方法在`CloudStorageAccount`上创建一个`CloudStorageAccount`对象。

1.  使用`CloudStorageAccount`类上的`CreateCloudBlobClient`方法创建一个新的`CloudBlobClient`。

1.  使用`CloudBlobClient`类上的`GetContainerReference`方法获取容器引用，并将我们在本章中早期创建的容器的名称作为参数传递：

```cs
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Blob;
using System;
using System.IO;
using System.Threading.Tasks;

public static class StorageHelper
{

    private static CloudBlobContainer GetContainer()
    {    
        string storageConnectionString =  
        Environment.GetEnvironmentVariable("StorageConnection");
        var storageAccount =   
        CloudStorageAccount.Parse(storageConnectionString);
        var blobClient = storageAccount.CreateCloudBlobClient();

        var container = 
        blobClient.GetContainerReference("chatimages");

        return container;
    } 
}
```

为了将文件上传到 blob 存储，我们将创建一个具有照片的字节和照片类型的方法。照片类型将由其文件结束定义：

1.  创建一个新的`async static`方法，返回`Task<string>`。

1.  向方法添加一个`byte[]`和一个`string`参数。将参数命名为`bytes`和`fileEnding`。

1.  调用`GetContainer`方法获取对容器的引用。

1.  为新的 blob 定义一个文件名，并将其作为参数传递给`CloudBlobContainer`类中的`GetBlockBlobReference`。使用`GUID`作为文件名，以确保其唯一性。

1.  使用字节创建一个`MemoryStream`。

1.  使用`BlockBlobReference`类上的`UploadFromStreamAsync`方法将照片上传到云端。

1.  返回 blob 的`AbsoluteUri`：

```cs
public static async Task<string> Upload(byte[] bytes, string fileEnding)
{
  var container = GetContainer();
  var blob = container.GetBlockBlobReference($"  
  {Guid.NewGuid().ToString()}.{fileEnding}");

  var stream = new MemoryStream(bytes);
  await blob.UploadFromStreamAsync(stream);

  return blob.Uri.AbsoluteUri;
} 
```

我们将添加到辅助程序的第二个公共方法是一个方法，用于删除所有早于一小时的照片：

1.  创建一个名为`Clear`的新的`async static`方法，返回`Task`。

1.  使用`GetContainer`方法获取对容器的引用。

1.  通过调用`ListBlobsSegmentedAsync`方法并使用以下代码中显示的参数获取容器中的所有 blob。

1.  循环遍历所有`CloudBlob`类型的 blob。

1.  添加一个`if`语句来检查照片是否是一个小时前创建的。如果是，则应删除 blob：

```cs
public static async Task Clear()
{
    var container = GetContainer();
    var blobList = await 
    container.ListBlobsSegmentedAsync(string.Empty, false, 
    BlobListingDetails.None, int.MaxValue, null, null, null);

    foreach(var blob in blobList.Results.OfType<CloudBlob>())
    {
        if(blob.Properties.Created.Value.AddHours(1) < DateTime.Now)
        {
            await blob.DeleteAsync();
        }
    }
} 
```

# 创建一个发送消息的函数

为了处理用户发送的消息，我们将创建一个新函数：

1.  创建一个带有`HttpTrigger`和匿名访问权限的函数。

1.  将函数命名为`Messages`。

1.  添加一个`SignalRMessage`集合，如下所示。

1.  使用`SignalR`属性指定 hub 名称：

```cs
[FunctionName("Messages")]
  public async static Task SendMessages(
    [HttpTrigger(AuthorizationLevel.Anonymous, "post")] object 
     message,
    [SignalR(HubName = "chat")] IAsyncCollector<SignalRMessage>    
     signalRMessages)
  { 
```

消息参数将是用户发送的消息。它将是`JObject`类型（来自`Newtonsoft.Json`）。我们需要将其转换为我们之前创建的`Message`类型。为此，我们需要添加对`Chat.Messages`项目的引用。但是，因为参数是对象类型，我们首先需要将其转换为`JObject`。一旦我们做到这一点，我们就可以使用`ToObject`方法获得`Message`：

```cs
var jsonObject = (JObject)message;
var msg = jsonObject.ToObject<Message>();
```

如果消息是`PhotoMessage`，我们将把照片上传到 blob 存储。所有其他消息将直接使用`signalRmessages`参数上的`AddAsync`方法发送到 SignalR 服务：

```cs
if (msg.TypeInfo.Name == nameof(PhotoMessage))
{
    //ToDo: Upload the photo to blob storage.
}

await signalRMessages.AddAsync(new SignalRMessage
  {
    Target = "newMessage",
    Arguments = new[] { message }
 }); 
```

在使用我们创建的辅助程序将照片上传到 blob 存储之前，我们需要将`base64`字符串转换为`byte[]`：

1.  使用`Converter`类上的静态`FromBase64String`方法将`base64`字符串转换为`byte[]`。

1.  使用`StorageHelper`上的静态`Upload`方法将照片上传到 blob 存储。

1.  创建一个新的`PhotoUrlMessage`，将用户名传递给构造函数，并将其设置为`msg`变量的值。

1.  将`Timestamp`属性设置为原始消息的值，因为我们对用户创建消息的时间感兴趣。

1.  将`Id`属性设置为原始消息的值，以便在客户端上将其处理为相同的消息。

1.  将`Url`属性设置为`StorageHelper`上传照片时返回的 URL。

1.  在`signalRMessages`变量上使用`AddAsync`方法向 SignalR 服务发送消息。

1.  添加一个空的返回语句：

```cs
if (msg.TypeInfo.Name == nameof(PhotoMessage))
{
    var photoMessage = jsonObject.ToObject<PhotoMessage>(); 
    var bytes = Convert.FromBase64String(photoMessage.Base64Photo);
    var url = await StorageHelper.Upload(bytes, 
    photoMessage.FileEnding);
 msg = new PhotoUrlMessage(photoMessage.Username)
 {
        Id = photoMessage.Id,
 Timestamp = photoMessage.Timestamp,
 Url = url
 }; await signalRMessages.AddAsync(new SignalRMessage
                                   {
                                    Target = "newMessage",
                                    Arguments = new[] { message }
                                    }); 
    return;
}
```

# 使用计算机视觉 API 扫描成人内容

为了最大程度地减少在我们的聊天中显示冒犯性照片的风险，我们将使用机器学习来尝试查找问题材料并防止其发布到聊天中。为此，我们将在 Azure 中使用**计算机视觉 API**，这是**Azure 认知服务**的一部分。要使用 API，我们需要一个密钥。我们将把它添加到功能应用程序的应用程序设置中：

1.  转到 Azure 门户。

1.  转到我们为 Custom Vision API 创建的资源。

1.  密钥可以在“密钥”选项卡下找到。您可以使用 Key 1 或 Key 2。

1.  转到“功能应用程序”的资源。

1.  将密钥作为名为`ComputerVisionKey`的应用程序设置添加。还要将密钥添加到`local.settings.json`中。

1.  还要将 Endpoint 添加为应用程序设置。使用名称`ComputerVisionEndpoint`。可以在功能应用程序资源的“概述”选项卡下找到 Endpoint。还要将 Endpoint 添加到`local.settings.json`中。

1.  在 Visual Studio 的`Chat.Functions`项目中安装`Microsoft.Azure.CognitiveServices.Vision.ComputerVision` NuGet 包。这是为了获取使用计算机视觉 API 所需的类。

1.  调用计算机视觉 API 的代码将被添加到`Message`函数中。之后，我们将把`base 64`字符串转换为`byte[]`。

1.  基于字节数组创建一个`MemoryStream`。

1.  按照以下代码中所示创建`ComputerVisonClient`并将凭据传递给构造函数。

1.  创建我们在分析照片时将使用的功能列表。在这种情况下，我们将使用`VisualFeatureTypes.Adult`功能。

1.  在`ComputerVisionClient`上使用`AnalyzeImageInStreamAsync`方法，并将流和功能列表传递给构造函数以分析照片。

1.  如果结果是`IsAdultContent`，则使用空的返回语句停止函数的执行：

```cs
var stream = new MemoryStream(bytes); 
  var subscriptionKey =   
  Environment.GetEnvironmentVariable("ComputerVisionKey");
  var computerVision = new ComputerVisionClient(new   
  ApiKeyServiceClientCredentials(subscriptionKey), new 
  DelegatingHandler[] { });

  computerVision.Endpoint =   
  Environment.GetEnvironmentVariable("ComputerVisionEndpoint");

  var features = new List<VisualFeatureTypes>() { 
  VisualFeatureTypes.Adult };

  var result = await   
  computerVision.AnalyzeImageInStreamAsync(stream, features);

if (result.Adult.IsAdultContent)
{
    return;
} 
```

# 创建一个定期清除存储中照片的计划作业

我们要做的最后一件事是定期清理 blob 存储并删除超过一小时的照片。我们将通过创建一个由`TimeTrigger`触发的函数来实现这一点：

1.  要创建新函数，请右键单击`Chat.Functions`项目，然后单击“新的 Azure 函数”，该选项将在“添加”菜单下找到。

1.  将函数命名为`ClearPhotos`。

1.  选择函数将使用时间触发器，因为我们希望它按时间间隔运行。

1.  使用时间表达式将 Schedule 设置为`0 */60 * * * *`，使其每 60 分钟运行一次：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/edc5a51c-8e9e-44e9-b55a-b040ec05de41.png)

在`ClearPhotos`函数中，我们唯一要做的是调用本章前面创建的`StorageHelper`的`Clear`方法：

```cs
[FunctionName("ClearPhotos")]
  public static async Task Run(
    [TimerTrigger("0 */60 * * * *")]TimerInfo myTimer, ILogger log)
{
    await StorageHelper.Clear();
} 
```

# 将函数部署到 Azure

本章的最后一步是将函数部署到 Azure。您可以将其作为 CI/CD 流水线的一部分来完成，例如使用 Azure DevOps。但在这种情况下，将函数直接从 Visual Studio 部署是最简单的方法。按照以下步骤部署函数：

1.  右键单击`Chat.Functions`项目，然后选择发布。

1.  选择“选择现有选项”。还要勾选“从包文件运行”选项。

1.  单击“创建配置文件”按钮。

1.  登录到与我们在创建功能应用程序时在 Azure 门户中使用的相同的 Microsoft 帐户。

1.  选择包含函数应用程序的订阅。我们在订阅中拥有的所有函数应用程序现在将被加载。

1.  选择函数应用程序，然后点击“确定”。

1.  创建配置文件后，点击“发布”按钮。

以下截图显示了最后一步。之后，发布配置文件被创建：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/2fc2606f-d4e0-436b-97ef-d6b867fa5f85.png)

# 总结

在本章中，我们已经学习了如何为实时通信设置无服务器后端，使用 Azure Functions 和 Azure SignalR 服务。我们还学习了如何使用 blob 存储和 Azure 认知服务中的机器学习来扫描照片中的成人内容。

在下一章中，我们将构建一个聊天应用程序，该应用程序将使用我们在本项目中构建的后端。
