# HTML5 iPhone Web 应用开发（三）

> 原文：[`zh.annas-archive.org/md5/C42FBB1BF1A841DF79FD9C30381620A5`](https://zh.annas-archive.org/md5/C42FBB1BF1A841DF79FD9C30381620A5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：位置感知应用程序

地理位置是当今应用程序中广泛请求的功能，为用户提供准确的位置特定信息。在本章中，我们将回顾 HTML5 规范中的地理位置 API。有了这些知识，我们将继续构建一个包装器，使我们能够轻松地利用这一功能。一旦我们彻底了解了如何获取用户的位置，我们将利用一个简单的应用程序来使用我们新发现的知识，该应用程序使用谷歌地图 API。在本章结束时，您应该对地理位置规范有透彻的了解，有一个其实现的简单示例，并且作为奖励，您应该获得了使用谷歌地图 API 的一些经验。因此，让我们开始探索规范。

在本章中，我们将涵盖：

+   地理位置规范

+   检索用户当前位置

+   监视用户的位置

+   处理地理位置错误

+   谷歌地图 API

+   将谷歌地图与地理位置联系起来

+   自定义谷歌地图

# 地理位置规范

基于位置的服务已经存在了相当长的时间，并且随着时间的推移而发展。实质上，这些服务努力提供功能，允许在各种类型的程序中使用时间和位置。然而，直到现在，前端还没有一个有用的工具集。因此，**W3C**（**万维网联盟**）试图标准化从客户端设备检索地理位置的 API，无论是您的台式电脑、手机还是平板电脑。

## 实施

> 地理位置 API 定义了与托管实现的设备相关联的位置信息的高级接口，例如纬度和经度。API 本身对底层位置信息源是不可知的。

（如[`dev.w3.org/geo/api/spec-source.html#introduction`](http://dev.w3.org/geo/api/spec-source.html#introduction)所述。）

浏览器实现地理位置 API 的常见方式涉及**全球定位系统**（**GPS**）、IP 地址、WIFI 和蓝牙 MAC 地址以及基本用户输入。由于这些技术工作的方式各不相同，以及浏览器供应商选择实施规范的程度不同，无法保证此 API 将返回用户或设备的位置。因此，作为开发人员，您需要确保用户也意识到这一限制，并向所有相关方解释合理的期望。

## 范围、安全性和隐私

在实现地理位置到我们的应用程序时，我们唯一需要担心的是脚本。无需提供任何标记，也无需查询或点击某些外部资源或 API。地理位置的实现严格限于脚本方面，并直接与正在使用的设备相关联。还有一点需要知道的是，位置是以世界大地测量系统坐标或纬度和经度的形式提供的。

在暴露用户位置时，还必须考虑安全性和隐私问题。从用于检索和存储此信息的安全方法到如何在其他方之间分发它，每个实施它的设备都必须提供一种保护用户隐私的机制。因此，W3C 规范要求考虑以下问题：

+   需要用户的许可才能发送位置信息。

+   只有在必要时才能请求位置信息。

+   用户必须批准重新传输位置信息。

+   持有此信息的一方必须向用户披露他们正在收集位置数据，包括其目的、安全性、可访问性、共享（如果数据将与其他方共享）以及此类数据将被存储的时间长度。

### 提示

请记住，为移动 Safari 编写的应用程序无法直接访问设备。它们只能查询浏览器代表它们访问设备。因此，您的应用程序正在请求浏览器获取特定信息，浏览器会为您完成工作，但您永远不会与设备本身进行一对一的通信。

总的来说，该规范考虑了与其他方分享个人信息（如地理位置）时出现的问题。然而，这些考虑并未考虑到当用户无意中授予权限或用户决定改变主意时可能出现的复杂性。因此，该规范提出了以下建议：

> 缓解和深入的防御措施是实施责任，而不是由本规范规定。然而，在设计这些措施时，建议实施者启用用户对位置共享的意识，并提供易于访问的接口，以启用撤销权限。

（如在 [`www.w3.org/TR/geolocation-API/#implementation_considerations`](http://www.w3.org/TR/geolocation-API/#implementation_considerations) 中提到的。）

考虑到这些问题和考虑，我们现在简要地描述 API。在接下来的部分中，我们将看看 API 是如何构建的，特别是看看在本章构建的应用程序中将使用的部分。

## API 描述

在本章的这一部分，您可能会想知道为什么我们还没有看代码，尽管这是一个合理的担忧，但我的目标是帮助您彻底理解 Geolocation API，并指导您了解实际的 W3C 规范。因此，在本章中，我们将查看定义 `Geolocation` 规范的四个接口或公开行为，包括 `Geolocation`、`PositionOptions`、`Position`、`Coordinates` 和 `PositionError` 接口。如果您对此提供的任何信息感到困惑，不用担心。请将本节视为可以帮助您增加对该主题的了解的参考资料。

### Geolocation 接口

Geolocation 对象用于确定设备的位置。当我们实例化 Geolocation 对象时，会使用用户代理算法来确定位置，然后创建并填充一个 `position` 对象。如果我们查看 W3C 规范，Geolocation 被定义为：

```html
interface Geolocation { 
    void getCurrentPosition(PositionCallback successCallback,
            optional PositionErrorCallback errorCallback,
            optional PositionOptions options);

    long watchPosition(PositionCallback successCallback,
            optional PositionErrorCallback errorCallback,
            optional PositionOptions options);

    void clearWatch(long watchId);
};
```

（如在 [`www.w3.org/TR/geolocation-API/#geolocation`](http://www.w3.org/TR/geolocation-API/#geolocation) 中所见。）

先前的代码不是 JavaScript，而是 API 或 **接口定义语言** (**IDL**) 的描述。如果它令人困惑，不用担心，当我第一次看规范页面时，我也有同样的感觉。然而，您在这里看到的是 Geolocation 对象的描述。当您阅读先前的代码时，您应该收集以下信息：

有三种方法：

+   `getCurrentPosition`，接受三个参数，其中两个是可选的

+   `watchPosition`，接受三个参数，其中两个是可选的

+   `clearWatch`，接受一个参数

现在您应该知道与 Geolocation 对象关联的有三个方法，每个方法都有一个特定的目的，如函数名称所述。因此，让我们来看看这三种方法，从 `getCurrentPosition` 开始，您可能已经猜到它获取设备的当前位置或尝试获取。

#### getCurrentPosition 方法

如前所述，此方法接受三个参数，其中两个是可选的。第一个参数应该是一个成功请求的 `callback` 方法。第二个和第三个参数是完全可选的。如果定义了第二个参数，那么它是另一个当发生错误时的 `callback` 方法。最后一个参数是由 `PositionsOptions` 接口定义的 `options` 对象。

#### watchPosition 方法

`watchPosition`方法也接受三个参数，与`getCurrentPosition`方法的参数相同。唯一的区别是，这个方法将持续触发`successCallback`，或者第一个参数，直到调用`clearWatch`方法。请记住，只有在位置发生变化时，`successCallback`才会触发，因此不依赖于任何时间选项。此方法还返回一个长值，用于定义观察操作，这是用`clearWatch`方法清除的。

#### clearWatch 方法

正如我们已经讨论过的，`clearWatch`用于停止`watchPosition`设置的过程。要使用这个方法，我们必须使用`watchPosition`返回的长值，并将其作为参数发送给`clearWatch`。

### PositionOptions 接口

我们已经看到`PositionOptions`对象用于向`getCurrentPosition`和`watchPosition`方法传递可选参数。这个对象由 W3C 定义如下：

```html
interface PositionOptions {
    attribute boolean enableHighAccuracy;
    attribute long timeout;
    attribute long maximumAge;
};
```

（见[`www.w3.org/TR/geolocation-API/#position-options`](http://www.w3.org/TR/geolocation-API/#position-options)。）

从中我们应该得出的结论是，我们可以创建一个包含`enableHighAccuracy`、`timeout`和`maximumAge`键/值对的对象。这个对象在我们的 JavaScript 代码中看起来像下面这样：

```html
var positionOptions = {
    'enableHighAccuracy': false,
    'timeout': Infinity,
    'maximumAge': 0
};
```

但是这些值代表什么呢？幸运的是，这一切都在规范中定义了。不过，别担心，这里有每个选项的简单解释。

#### enableHighAccuracy 选项

这个选项基本上是向设备提示应用程序希望接收到最好的可能结果。默认设置为`false`，因为如果设置为`true`，可能会导致响应时间变慢和/或增加功耗。请记住，用户可能会拒绝此功能，设备可能无法提供更准确的结果。

#### 超时选项

超时被定义为等待成功回调被调用的时间，以毫秒为单位。如果获取位置数据的时间超过这个值，那么将调用错误回调，并发送`PositionError`代码`TIMEOUT`。默认情况下，该值设置为`Infinity`。

#### 最大年龄选项

最大年龄选项是指使用缓存位置的年龄不大于此选项设置的时间。默认情况下，此属性设置为`0`，因此每次都会尝试获取新的位置对象。如果此选项设置为`Infinity`，则每次都返回缓存位置。

现在我们了解了这些选项，我们可以将这个对象作为第三个参数传递给`getCurrentPosition`和`watchPosition`方法。API 的一个简单实现看起来可能是这样的：

```html
var positionOptions = {
    'enableHighAccuracy': false,
    'timeout': Infinity,
    'maximumAge': 0
};

function successCallback(position) {}

function errorCallback(positionError) {}

// Get the current position
navigator.geolocation.getCurrentPosition(successCallback, errorCallback, positionOptions);

// Watch for position changes
navigator.geolocation.watchPosition(successCallback, errorCallback, positionOptions);
```

现在我们知道如何自定义对地理位置 API 的调用，但是当成功调用时，数据是什么样子的呢？或者，错误返回是什么样子的？了解这些对于开发地理位置 API 的良好封装非常有用。所以让我们来看一下坐标和位置错误接口。

### 位置接口

位置接口只是设备实现地理位置 API 返回的信息的容器。它返回一个`Coordinates`对象和`Timestamp`。这在 W3C 规范中描述如下：

```html
interface Position {
    readonly attribute Coordinates coords;
    readonly attribute DOMTimeStamp timestamp;
};
```

（见[`www.w3.org/TR/geolocation-API/#position`](http://www.w3.org/TR/geolocation-API/#position)。）

在我们到目前为止讨论的内容中，位置接口在`getCurrentPosition`方法的`successCallback`中发挥作用。如果你还记得，这个方法接受一个名为`options`的参数，它是之前定义的`position`对象。实际上，如果我们想要记录坐标和时间戳，我们可以这样做：

```html
function successCallback(position) {
    console.log(position.coords);
    console.log(position.timestamp);
}
```

返回的时间戳表示为`DOMTimeStamp`，`coords`对象包含地理坐标和其他信息，由`Coordinates`接口定义。

### Coordinates 接口

正如我们之前讨论过的，`getCurrentPosition`和`watchPosition`的`successCallback`返回一个包含`Coordinates`对象的`position`对象。这个`Coordinates`对象包含多个属性，这些属性在下表中描述：

| 属性 | 描述 |
| --- | --- |
| `latitude` | 十进制度的地理坐标。 |
| `longitude` | 十进制度的地理坐标。 |
| `altitude` | 位置的高度，以米为单位。如果不存在则为 null。 |
| `accuracy` | 经度和纬度的精度，以米为单位。如果不存在则为 null。必须是非负实数。 |
| `altitudeAccuracy` | 海拔精度，以米为单位。如果不存在则为 null。必须是非负实数。 |
| `heading` | 行进方向，以度为单位（0° ≤ heading ≤ 360°），顺时针方向。如果不存在则为 null。如果静止则值必须为 NaN。 |
| `speed` | 当前速度的大小，以米/秒为单位。如果不存在则为 null。必须是非负实数。 |

（见[`www.w3.org/TR/geolocation-API/#coordinates`](http://www.w3.org/TR/geolocation-API/#coordinates)。）

既然我们知道了通过`Coordinates`接口可用的属性，我们可以通过以下实现访问这些属性。

```html
function successCallback(position) {
    console.log(position.coords);
    console.log(position.coords.lattitude);
    console.log(position.coords.longitude);
    console.log(position.timestamp);
}
```

正如您所见，我们可以通过`position.coords`对象访问属性。这样，我们可以非常容易地访问用户的当前位置并将其与其他 API 绑定，这正是我们很快将要使用 Google Maps API 做的事情。最后，让我们讨论`PositionError`接口，以便我们知道如何在应用程序中高效处理错误。

### PositionError 接口

当`getCurrentPosition`或`watchPosition`方法出现错误时，`PositionError`接口就会发挥作用。该接口描述了发送到我们的错误处理程序或回调的代码和消息。W3C 将`PositionError`接口解释如下：

```html
interface PositionError {
    const unsigned short PERMISSION_DENIED = 1;
    const unsigned short POSITION_UNAVAILABLE = 2;
    const unsigned short TIMEOUT = 3;
    readonly attribute unsigned short code;
    readonly attribute DOMString message;
};
```

（见[`www.w3.org/TR/geolocation-API/#position-error`](http://www.w3.org/TR/geolocation-API/#position-error)。）

前面的代码描述了作为对象发送到错误处理程序的两个属性，这两个属性分别是`code`和`message`。

`code`属性可以是以下三个常量之一，

+   `PERMISSION_DENIED`（错误代码 1）：用户选择不让浏览器访问位置信息。

+   `POSITION_UNAVAILABLE`（错误代码 2）：浏览器无法确定设备的位置。

+   `TIMEOUT`（错误代码 3）：获取位置信息的总时间已超过 PositionOptions 接口中指定的超时属性。

第二个参数`message`将是一个描述问题的 DOM 字符串或字符串。

在我们的实现中，我们可以这样做：

```html
function errorCallback(positionError) {
    if (positionError.code === 3) {
        console.log("A Timeout has occurred");
        console.log("Additional Details: " + positionError.message);
    }
}
```

正如您所见，我们可以很容易地使用`PositionError`接口确定错误，并根据提供的代码自定义我们的错误消息。在这一点上，您应该已经有了一个坚实的基础，可以在其上构建。现在我们将简要讨论一些将地理位置 API 实现到我们的应用程序中的用例，然后开始构建本书的应用程序。您可以略过下一节，因为它只会给您提供有关地理位置如何实现或已经实现的想法。

## 用例

在我们开始构建应用程序之前，我想回顾一些可以将地理位置信息实现到我们的应用程序中的情况。这将是简短而有用的，但它将帮助您构思如何高效地实现此功能。这些大部分已经在 W3C 规范中，但我希望这将让您更深入地了解规范的用处，以及在探索新功能时为什么一定要查看它。

### 兴趣点

我们一直对我们周围的环境感兴趣，无论是食物、啤酒还是娱乐。所以如果我们能列出与用户正在访问的内容相关的可能的兴趣点，那不是很酷吗？我们可以使用地理位置 API 来实现这一点。通过找到用户的当前位置并利用第三方供应商的开放 API，我们可以轻松地找到用户所在地区的相关信息并呈现相关信息。

### 路由导航

我们以前已经看到这样的情况发生了很多次，手机上的原生应用程序也是如此。甚至可能您的手机预装了这个功能，许多人在之前支付了数百美元。现在，使用 HTML5 地理位置 API，我们可以使用`currentPosition`方法构建这个功能，并将其与 Google Maps 之类的东西绑定在一起，以便我们可以向用户呈现路线。如果我们愿意，甚至可能使用`watchPosition`方法制作一个实时应用程序，尽管在构建应用程序时可能会遇到 API 访问限制，所以请记住这一点。

### 最新信息

该应用程序中的另一个有用功能是向用户提供最新信息。如果我们从后端系统公开 API，这将很容易实现，但如果我们进一步根据用户的当前位置在我们自己的应用程序之外实现信息，会怎么样呢？例如，如果我住在波士顿，去西雅图旅行，我可能想知道西雅图发生了什么，而不是波士顿，所以我的应用程序可能应该处理这种情况。使用 HTML5 地理位置 API，我们可以很容易地实现这一点，而不会有太多复杂性。

我们现在对地理位置 API 有了扎实的理解，从理论理解到简单实现，我们已经了解了关于地理位置和如何使用它的一切。使用案例也已经定义，以帮助我们找到一种将其集成到我们的应用程序中的方法，很可能你会发现在应用程序中使用这项技术的新颖和创新的方式。就目前而言，让我们为指出用户当前位置的简单使用案例场景做好准备，使用 Google Maps API。所以让我们开始吧。

# 谷歌地图 API

在我们开始使用 Google Maps 实现地理位置之前，我们需要做一些相当简单的设置工作。您可能已经知道，Google Maps 提供了一个 API，您可以利用它将他们的地图实现到您的应用程序中，这样您就可以轻松地显示与用户输入相关的信息，甚至更好的是，他们的当前位置。然而，出于几个原因，我们需要使用谷歌的 API 密钥来授权我们的应用程序，并跟踪从您的应用程序发出的请求。在本节中，我们将介绍设置工作，并希望能够快速帮助您。

## API(s)

首先，您需要知道与地图相关的几个 API，包括 JavaScript v3、Places、iOS SDK、Android API、Earth API 等。对于我们的目的，我们将使用 JavaScript API v3；请注意，我们将使用 API 的第 3 版。如果您想了解更多关于几个 API 的信息，您可以访问以下页面：

[`developers.google.com/maps/`](https://developers.google.com/maps/)

## 获取 API 密钥

如果您一直在关注，您会注意到我们的应用程序需要一个 API 密钥。谷歌为此提供了以下理由：

> 使用 API 密钥可以让您监视应用程序的地图 API 使用情况，并确保 Google 在必要时可以联系您的应用程序。如果您的应用程序的地图 API 使用超过使用限制，您必须使用 API 密钥加载地图 API 以购买额外的配额。

（如[`developers.google.com/maps/documentation/javascript/tutorial#api_key`](https://developers.google.com/maps/documentation/javascript/tutorial#api_key)所示。）

### 激活服务

现在让我们开始创建 API 密钥。首先，在以下 URL 登录到您的 Google 账户：

[`code.google.com/apis/console`](https://code.google.com/apis/console)

一旦我们在之前的 URL 登录，我们选择**服务**选项卡。

![激活服务](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024_06_01.jpg)

服务选项卡

在**服务**选项卡中，我们看到了 Google 提供的所有服务。在这个列表中，我们需要激活 Google Maps API v3。它应该看起来像这样：

![激活服务](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024_06_02.jpg)

未激活的 Google Maps API

当您单击**关闭**按钮时，服务将激活，并应该如下所示：

![激活服务](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024_06_03.jpg)

激活 Google Maps API

Google Maps API v3 服务现在已在您的 Google 账户下激活。下一步是检索将在我们的 Geolocation API 实现中使用的密钥。

### 检索密钥

现在，服务已在我们的 Google 账户下激活，让我们获取密钥——最后一步。为此，请切换到左侧导航中的**API 访问**选项卡。

![检索密钥](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024_06_04.jpg)

API 访问选项卡

当我们访问这个页面时，我们将看到一个**简单 API 访问**部分，其中包含我们生成的密钥。这是您要用来授权您的 Google Maps 实现的密钥。除了密钥，您还会注意到它将列出引用者、激活时间以及激活密钥的人（您）。在所有这些信息的右侧，您还会注意到一些选项。这些选项包括生成新密钥、编辑引用者，以及最终删除生成的密钥。

### 提示

请注意，您还可以设置 OAuth 2.0 客户端 ID，这将保护您的应用程序。如果您将处理敏感信息，这绝对是推荐的，因为您将处理用户位置。然而，OAuth 的设置和使用超出了本书的范围，但我建议您花些时间学习这种新的身份验证方法，并在您自己的应用程序中实现它，一旦您在 API 方面有了坚实的基础。

有了 API 密钥，我们现在已经准备好开始使用 Google Maps 实现 Geolocation。接下来的部分将利用我们学到的知识，并使用我们可用的简单方法在页面上放置 Google 地图。在这方面，我希望它能激发您对 Google Maps API 的兴趣，因为它经过时间的发展，是一个几乎可以在任何应用程序中使用的优秀框架。现在让我们开始开发一些很酷的东西。

# Geolocation 和 Google Maps

如果您从本章的开头一直跟随下来，您应该对 Geolocation API 有了全面的了解，并且已经设置好了您的 Google 账户以便利用 Google Maps JavaScript API。如果您一直没有跟随，也没关系，因为本节主要是为了展示如何实现这两种技术。本节将准备我们应用程序中的位置页面，然后快速转移到使用 Google Maps 实现 Geolocation。

## 标记准备

在上一章中，我们做了一些设置工作来启动我们的应用程序；我们将在这里遵循相同的设置工作，以确保我们所有的页面都是一致的。因此，让我们打开与本书附带的源文件中的`location`相关的标记页面`/location/index.html`。当我们在文本编辑器中打开这个页面时，让我们对标记进行以下更新：

+   更新导航以反映选择菜单。

+   包括`location.css`文件，该文件将为此页面提供特定的页面样式。

+   从页面底部删除未使用的脚本。

+   包括`App.Location.js`。

+   在包含`main.js`之后初始化`App.Location`。

一旦我们进行了这些更新，您的标记应该如下所示：

```html
<!DOCTYPE html>
<html class="no-js">
<head>
    <meta charset="utf-8">
    <title></title>
    <meta name="description" content="">
    <meta name="HandheldFriendly" content="True">
    <meta name="MobileOptimized" content="320">
    <meta name="viewport" content="width=device-width">

    <!-- IOS THUMBS -->

    <!-- APPLE META TAGS -->

    <link rel="stylesheet" href="../css/normalize.css">
    <link rel="stylesheet" href="../css/main.css">
    <link rel="stylesheet" href="../css/location.css">
    <script src="img/modernizr-2.6.1.min.js"></script>
</head>
    <body>
        <!-- Add your site or application content here -->
        <div class="site-wrapper">
            <header>
                <hgroup>
                    <h1>iPhone Web Application Development</h1>
                    <h2>Location Aware Apps</h2>
                </hgroup>
                <nav>
                    <select>
                        <!-- OPTIONS HERE -->
                    </select>
                </nav>
            </header>
            <footer>
                <p>iPhone Web Application Development &copy; 2013</p>
            </footer>
        </div>

        <script src="img/zepto.min.js"></script>
        <script src="img/helper.js"></script>
        <!-- BEGIN: Our Framework -->
        <script src="img/App.js"></script>
        <script src="img/App.Nav.js"></script>
        <script src="img/App.Location.js"></script>
        <!-- END: Our Framework -->
        <script src="img/main.js"></script>
        <script> new App.Location({ 'element': document.body }); </script> 
    </body>
</html>
```

### 注意

请注意，在应该存在更多标记的地方添加了注释。与这些部分相关的标记在提供的书籍源代码中。请在那里查找更多关于这些部分应该存在什么的信息。

现在我们已经将标记调整到了先前页面的一致布局，我们准备开始为位置感知定制此应用程序。该过程的下一步是准备标记，以便我们将构建的附加功能。为此，我们需要做以下事情：

+   包括 Google Maps API JavaScript。

+   包括我们将要构建的`Geolocation`包装器。

+   创建一个包含我们地图的`div`。

当我们按照先前的指示进行操作时，我们的标记将如下所示：

```html
<!DOCTYPE html>
<html class="no-js">
<head>
    <meta charset="utf-8">
    <title></title>
    <meta name="description" content="">
    <meta name="HandheldFriendly" content="True">
    <meta name="MobileOptimized" content="320">
    <meta name="viewport" content="width=device-width">

    <!-- IOS THUMBS -->

    <!-- APPLE META TAGS -->

    <link rel="stylesheet" href="../css/normalize.css">
    <link rel="stylesheet" href="../css/main.css">
    <link rel="stylesheet" href="../css/location.css">
    <script src="img/modernizr-2.6.1.min.js"></script>
</head>
    <body>
        <!-- Add your site or application content here -->
        <div class="site-wrapper">
            <header>
                <hgroup>
                    <h1>iPhone Web Application Development</h1>
                    <h2>Location Aware Apps</h2>
                </hgroup>
                <nav>
                    <select>
                        <!-- OPTIONS HERE -->
                    </select>
                </nav>
            </header>
            <div id="map_canvas"></div>
            <footer>
                <p>iPhone Web Application Development &copy; 2013</p>
            </footer>
        </div>

        <script src="img/js?key=YOUR_API_KEY&sensor=SET_TO_TRUE_OR_FALSE"></script>
        <script src="img/zepto.min.js"></script>
        <script src="img/helper.js"></script>
  <script src="img/Geolocation.js"></script>
        <!-- BEGIN: Our Framework -->
        <script src="img/App.js"></script>
        <script src="img/App.Nav.js"></script>
        <script src="img/App.Location.js"></script>
        <!-- END: Our Framework -->
        <script src="img/main.js"></script>
        <script> new App.Location({ 'element': document.body }); </script> 
    </body>
</html>
```

正如您所看到的，这并没有太大的区别。我们在这里所做的是包含一个包含 Google Maps JavaScript 的新脚本。然后我们包含另一个名为`Geolocation.js`的脚本，它将存在于`/js/`中，最后我们创建一个 ID 为`map_canvas`的`div`，它存在于页眉和页脚之间。

### 提示

请注意，您需要将在上一节中创建的 API 密钥包含在 Google Maps JavaScript URL 字符串中，用您之前提供的密钥替换`YOUR_API_KEY`。还要记住，您必须将传感器参数设置为 true 或 false。传感器参数告诉 Google Maps 应用程序使用传感器（例如 GPS）来获取用户位置。

好的，现在我们的标记已经准备好了。我们在这里不需要做任何其他事情，所以现在我们将转向 JavaScript，首先创建我们的`Geolocation`包装器，然后将其实现到我们的`App.Location`类中。让我们看看如何在我们的应用程序中更轻松地利用地理位置。

## 地理位置包装器

在大多数情况下，我们不希望为每种用例反复重写相同的方法。因此，我们创建了包装器，抽象了某些技术的功能，以便我们可以在应用程序中轻松使用它们。这就是我们现在要做的事情，抽象地理位置 API，以便我们可以在 Google Maps API 中使用它。

让我们开始创建一个`Geolocation.js`文件，放在我们的`JavaScript`目录中。您可能已经注意到，这不会存在于`App`命名空间下；这是因为它是任何应用程序都可能使用的抽象类。对于我们的目的，我们只想要获取用户的当前位置，并且希望能够在整个应用程序中使用这些信息，因此我们将其设置为全局对象。

这是我们的`Geolocation`类的基本模板：

```html
(function($){

    var _self, _defaults, _callbacks;

    // Default options
    _defaults = {};

    // Stores custom callbacks
    _callbacks = {};

    /**
        @constructor
    */
    function Geolocation(options) {
        this.options = $.extend({}, _defaults, options);

        _self = this;
    }

    Geolocation.prototype.toString = function() {
        return "[object " + this.constructor.name + "]";
    }

    // Exposess the Geolocation Function
    window.Geolocation = new Geolocation();

}(Zepto));
```

这与我们先前编写的任何代码都没有什么不同，只是我们用以下代码公开了这个类：

```html
window.Geolocation = new Geolocation();
```

我们基本上只是初始化`Geolocation`对象并将其设置为`window`对象，而不是返回`Geolocation`对象，这使其成为全局对象。您还会注意到添加了一个名为`_callbacks`的闭包作用域变量，它将包含用户在扩展地理位置功能时可以覆盖的回调。现在让我们通过包括用于检索当前位置的默认值以及一个将保存地理位置 API 返回的所有数据的一般属性对象来进一步扩展这一点：

```html
    // Default options
    _defaults = {
        'currentPositionOptions': {
            'enableHighAccuracy': false,
            'timeout': 9000,
            'maximumAge': Infinity
        },
        'props': {}
    };
```

当我们检索用户位置时，将使用这些选项。目前，让我们将这些保留为原样，并创建一个回调，用户可以在地理位置 API 发生成功或错误时覆盖：

```html
    // Stores custom callbacks
    _callbacks = {
        'getCurrentPositionCallback': function(){}
    };
```

我们很快将看到如何实现这一点，但现在这将是一个默认方法，用于执行回调。接下来，让我们检查设备/浏览器是否实际支持地理位置 API：

```html
    /**
        @constructor
    */
    function Geolocation(options) {
        this.options = $.extend({}, _defaults, options);

        if(navigator.geolocation) {
            this.geolocation = navigator.geolocation;
        }

        _self = this;
        _self.props = this.options.props;
    }
```

这是一个相当简单的地理位置支持检查，基本上我们只是在 Geolocation 上创建一个叫做`geolocation`的属性，如果存在 API 就会设置它。这样，我们就不必在类内部每次都写`navigator.geolcation`。而且，这样做将更容易在以后检查地理位置功能是否存在。在这一点上，我们准备从 Geolocation API 中公开`getCurrentPosition`方法。

```html
Geolocation.prototype.getCurrentPosition = function(callback) {
    if (typeof callback !== 'undefined') {
        _callbacks.getCurrentPositionCallback = callback;
    }

    if (typeof this.geolocation !== 'undefined') {
    this.geolocation.getCurrentPosition(currentPositionSuccess, currentPositionError, _self.options.currentPositionOptions);

        return this;
    }

    return false;
};
```

之前的方法是公共的并且可访问，因为我们已经将它附加到了 Geolocation 的原型上。这个方法将接受一个参数，一个在 Geolocation API 的`getCurrentPosition`调用成功或失败时将被调用的回调函数。这个方法检查参数是否不是未定义的，然后根据发送的内容重新分配。然后我们检查在构造函数中设置的`geolocation`属性；如果它不是未定义的，我们就调用 Geolocation API 上的`getCurrentPosition`方法并发送适当的参数。然后我们返回我们的`Geolocation`类的实例。如果`geolocation`属性未定义，我们返回一个 false 的布尔值，因此开发人员在使用这个方法时也可以进行错误检查。

### 提示

请注意，我们正在传递两个未定义的方法`currentPositionSuccess`和`currentPositionError`，这些方法将很快被定义。但是，也请注意，我们将之前定义的默认属性作为它的第三个参数发送到这个方法中。通过这样做，我们使开发人员能够轻松地进一步定制地理位置功能的体验。当我们开始开发`App.Location.js`文件时，你会看到定制这些值是多么容易。

在这一点上，唯一剩下的就是创建之前的回调。所以让我们创建以下`successCallback`：

```html
function currentPositionSuccess(position) {
    _self.props.coords = position.coords;
    _self.props.timestamp = position.timestamp;

    _callbacks.getCurrentPositionCallback.call(_self, _self.props);
}
```

最后一个回调被称为，你可能已经猜到了，当我们成功获取用户位置时调用。根据 W3C 规范的定义，这个方法接受一个参数——一个包含坐标和时间戳的`Position`对象。我们使用构造函数中定义的`props`属性来公开返回的信息。一旦所有这些信息都被检索和设置，回调`getCurrentPositionCallback`被调用并传递检索到的属性。

### 提示

请注意，我们还将回调中的`this`的含义更改为 Geolocation 实例的含义，通过将`_self`作为第一个参数传递来调用。

最后，让我们创建我们的错误回调：

```html
    function currentPositionError(positionError) {
        _callbacks.getCurrentPositionCallback.call(_self, positionError);
    }
```

这个回调，根据 W3C 规范的定义，接受一个参数，一个带有错误代码和简短消息的`PositionError`对象。然而，我们所要做的就是使用回调并传递这些信息，类似于`successCallback`中所做的。不同的是，这里我们只是传递`PositionError`对象，以便在这个包装器之外创建自定义消息。

有了这个，我们就完成了对地理位置 API 的简单包装。现在我们可以轻松地从`App.Location.js`中调用 API。所以让我们继续扩展`App.Location`对象，并开始使用带有地理位置的 Google Maps API。

## 使用 Google Maps 的地理位置

所以我们现在准备开始使用`App.Location`来实现使用 Google Maps 的地理位置。我们将使用本书中一直使用的相同样板来将我们的`Geolocation`包装器与 Google Maps API 连接起来。让我们开始打开提供的`App.Location.js`，当你打开它时，它应该看起来类似于以下代码：

```html
var App = window.App || {};

App.Location = (function(window, document, $){
    'use strict';

    var _defaults = {
        'name': 'Location'
    }, _self;

    function Location(options) {
        this.options = $.extend({}, _defaults, options);

        this.$element = $(this.options.element);
    }

    Location.prototype.getDefaults = function() {
        return _defaults;
    };

    Location.prototype.toString = function() {
        return '[ ' + (this.options.name || 'Location') + ' ]';
    };

    Location.prototype.init = function() {
        // Initialization Code

        return this;
    };

    return Location;

}(window, document, Zepto));
```

如果您按顺序阅读本书，这里没有什么新内容。但是作为回顾，我们在`App`对象下声明了一个名为`Location`的新命名空间。这个命名空间将包含我们位置页面的所有功能，因此它非常适合作为 Google 地图和地理位置功能之间的控制器。因此，让我们从缓存地图元素开始，创建一个闭包作用域的`Location`实例引用，然后对其进行初始化。构造函数应该如下所示：

```html
function Location(options) {
    this.options = $.extend({}, _defaults, options);

    this.$element = $(this.options.element);

    // Cache the map element
    this.$cache = {
        'map': this.$element.find('#map_canvas')
    };

    _self = this;

    this.init();
}
```

在这里，我们在`Location`实例上创建了一个`$cache`属性，这个`$cache`属性将包含对`map`元素的引用，因此可以使用这个属性进行访问。然后我们创建了一个闭包作用域的 self 变量，引用了`Location`实例。最后，我们通过调用实例原型上的`init`方法来初始化我们的代码。

在这个过程中的下一步是使用我们的`Geolocation`包装器来获取用户的当前位置。我们将把这段代码添加到`initialize`方法中，如下所示：

```html
Location.prototype.init = function() {
    // Initialization Code
    Geolocation.getCurrentPosition(function(args){
        if(args.toString() !== '[object PositionError]') {
            _self.initGoogleMaps();
        } else {
            console.log("An ERROR has occurred: " + args.message);
        }
    });

    return this;
};
```

在这里，我们最终可以看到我们的`Geolocation`包装器的实现，以及它在应用程序中集成的简易程度，因为`Geolocation`类已经处理了验证和验证设置。这其中的重要部分是我们的回调实际上处理了错误；通过检查`PositionError`的对象类型，我们能够继续集成 Google 地图或记录返回的错误。当然，我们处理错误的方式应该更加详细，但对于这种情况，它有助于确定在我们的应用程序中采用这种方法有多么简单。

现在，让我们看看如何通过查看之前调用的`initGoogleMaps`方法来实现 Google 地图的成功回调：

```html
Location.prototype.initGoogleMaps = function() {
    this.latlng = new google.maps.LatLng(Geolocation.props.coords.latitude, Geolocation.props.coords.longitude);

    this.options.mapOptions.center = this.latlng;

    this.map = new google.maps.Map(this.$cache.map[0], this.options.mapOptions);

    this.marker = new google.maps.Marker({
        'position': this.latlng,
        'map': this.map,
        'title': 'My Location'
    });

    this.infowindow = new google.maps.InfoWindow({
        'map': this.map,
        'position': this.latlng,
        'content': 'My Location!',
        'maxWidth': '140'
    });
```

这里发生了很多事情，但信不信由你，我们几乎已经完成了。所以让我们一步一步地进行。

首先，我们将`latlng`属性设置为 Google Maps API 的`LatLng`类的一个新实例。这个`class`构造函数返回一个表示地理点的对象。尽管我们已经从 Geolocation API 中获得了坐标，但我们需要确保创建一个 Google 地图的`LatLng`实例，因为它将在接下来的方法中使用。

现在，在继续之前，我们需要暂时绕过一下。Google Maps API 非常广泛和可定制，允许我们在几乎每个区域自定义地图的外观和感觉。为了更深入地探索这一点，让我们在默认设置上创建一个`mapOptions`对象，它将为我们的地图定制移动端的外观：

```html
var _defaults = {
    'name': 'Location',
    'mapOptions': {
        'center': '',
        'zoom': 8,
        'mapTypeId': google.maps.MapTypeId.ROADMAP,
        'mapTypeControl': true,
        'mapTypeControlOptions': {
            'style': google.maps.MapTypeControlStyle.DROPDOWN_MENU
        },
        'draggable': true,
        'scaleControl': false,
        'zoomControl': true,
        'zoomControlOptions': {
            'style': google.maps.ZoomControlStyle.SMALL,
            'position': google.maps.ControlPosition.TOP_LEFT
        },
        'streetViewControl': false
    }
}, _self;
```

现在，我们不会深入讨论这一点，但请记住，有许多选项可供您探索和优化，以适用于我们的 iPhone Web 应用程序。我鼓励您访问以下网址并探索这些选项，以便熟悉可用的内容：

[`developers.google.com/maps/documentation/javascript/reference#MapOptions`](https://developers.google.com/maps/documentation/javascript/reference#MapOptions)

让我们回到之前描述的`initGoogleMaps`方法。在初始化`LatLng`类之后，我们现在在刚刚创建的`mapOptions`对象上定义了 center 属性。这个属性设置为`LatLng`的实例：

```html
this.options.mapOptions.center = this.latlng;
```

现在我们已经定义了创建 Google 地图所需的所有属性，我们初始化了 Google Maps API 的`Map`类：

```html
this.map = new google.maps.Map(this.$cache.map[0], this.options.mapOptions);
```

这个方法接受我们在 JavaScript 中创建并缓存的`div`元素作为它的第一个参数。第二个参数将是我们创建的`options`对象。我们在`mapOptions`对象上设置`center`属性的原因是因为地图的初始化将显示用户的位置。我们现在已经完成了地理定位和 Google Maps API 的实现。

# 总结

在本章中，我们回顾了由 W3C 定义的地理定位规范。然后，我们利用这些信息构建了一个包装器，以便我们可以轻松地利用 API。作为一个额外的奖励，我们还回顾了 Google Maps API，创建了一个访问密钥，然后使用我们的地理定位包装器来确定用户的位置并将其显示给用户。现在你应该对确定用户位置并有效使用它有了很好的理解。在下一章中，我们将进入单页应用程序开发，利用我们学到的概念并使用一些额外的开源库进行扩展。


# 第七章：单页面应用程序

到目前为止，我们已经开发了包含相关静态内容的单独页面。在本章中，我们将通过深入研究单页面应用程序开发来提高水平。我们在许多网络应用程序中都见过这种情况，包括 Pandora、Mint 和 NPR。我们将介绍单页面应用程序开发的基础知识，从 MVC、Underscore 和 Backbone 的介绍到使用我们示例应用程序创建架构和利用本章第一部分教授的方法。完成本章后，您应该对单页面应用程序背后的概念有扎实的理解，这将使您能够继续扩展这些知识，并帮助您在构建复杂应用程序的道路上指引您。所以让我们首先学习 MVC。

在本章中，我们将涵盖：

+   MVC 架构

+   介绍`Underscore.js`

+   介绍`Backbone.js`

+   创建单页面应用程序

# 模型-视图-控制器或 MVC

**模型-视图-控制器**（**MVC**）是编程中广泛使用的设计模式。设计模式本质上是解决编程中常见问题的可重用解决方案。例如，**命名空间**和**立即调用函数表达式**是本书中经常使用的模式。MVC 是另一种模式，用于帮助解决分离表示和数据层的问题。它帮助我们将标记和样式保持在 JavaScript 之外；保持我们的代码有组织、清晰和可管理——这些都是创建单页面应用程序的基本要求。因此，让我们简要讨论 MVC 的几个部分，从模型开始。

## 模型

模型是一个对象的描述，包含与之相关的属性和方法。想想构成一首歌的内容，例如曲目的标题、艺术家、专辑、年份、时长等。在本质上，模型是您的数据的蓝图。

## 视图

视图是模型的物理表示。它基本上显示模型的适当属性给用户，页面上使用的标记和样式。因此，我们使用模板来填充我们的视图所提供的数据。

## 控制器

控制器是模型和视图之间的中介。控制器接受操作，并在必要时在模型和视图之间传递信息。例如，用户可以编辑模型上的属性；当这样做时，控制器告诉视图根据用户更新的信息进行更新。

## 关系

在 MVC 应用程序中建立的关系对于遵循设计模式至关重要。在 MVC 中，理论上，模型和视图永远不会直接交流。相反，控制器完成所有工作；它描述一个动作，当该动作被调用时，模型、视图或两者都相应地更新。这种类型的关系在下图中得以建立：

![关系](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_07_01.jpg)

这个图解释了传统的 MVC 结构，特别是控制器和模型之间的通信是双向的；控制器可以向模型发送/接收数据，视图也可以如此。然而，视图和模型永远不会直接交流，这是有充分理由的。我们希望确保我们的逻辑得到适当的包含；因此，如果我们想要为用户操作正确地委派事件，那么这段代码将放入视图中。

然而，如果我们想要有实用方法，比如一个`getName`方法，可以适当地组合用户的名字和姓氏，那么这段代码将包含在用户模型中。最后，任何涉及检索和显示数据的操作都将包含在控制器中。

从理论上讲，这种模式有助于我们保持代码组织良好、清晰和高效。在许多情况下，这种模式可以直接应用，特别是在像 Ruby、PHP 和 Java 这样的许多后端语言中。然而，当我们开始严格将其应用于前端时，我们将面临许多结构性挑战。同时，我们需要这种结构来创建稳固的单页应用程序。接下来的章节将介绍我们将用来解决这些问题以及更多问题的库。

# Underscore.js 简介

我们在示例应用程序中将使用的库之一是`Underscore.js`。由于 Underscore 提供了许多实用方法，而不会扩展内置的 JavaScript 对象，如`String`，`Array`或`Object`，因此 Underscore 在过去几年变得非常流行。虽然它提供了许多有用的方法，但该套件还经过了优化并在许多最受欢迎的 Web 浏览器中进行了测试，包括 Internet Explorer。出于这些原因，社区广泛采用了这个库并不断支持它。

## 实现

在我们的应用程序中实现 Underscore 非常容易。为了让 Underscore 运行，我们只需要在页面上包含它，如下所示：

```html
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
        <title></title>
        <meta name="description" content="">
        <meta name="viewport" content="width=device-width">
    </head>
    <body>
        <script src="img/jquery.min.js"></script>
        <script src="img/underscore-min.js"></script>
    </body>
</html>
```

一旦我们在页面上包含 Underscore，我们就可以使用全局范围内的`_`对象访问库。然后，我们可以通过`_.methodName`访问库提供的任何实用方法。您可以在线查看 Underscore 提供的所有方法（[`underscorejs.org/`](http://underscorejs.org/)），其中所有方法都有文档并包含它们的实现示例。现在，让我们简要回顾一些我们将在应用程序中使用的方法。

### _.extend

Underscore 中的`extend`方法与我们从`Zepto`中使用的`extend`方法非常相似（[`zeptojs.com/#$.extend`](http://zeptojs.com/#$.extend)）。如果我们查看 Underscore 网站上提供的文档（[`underscorejs.org/#extend`](http://underscorejs.org/#extend)），我们可以看到它接受多个对象，第一个参数是目标对象，一旦所有对象组合在一起就会返回。

> 将源对象的所有属性复制到目标对象中，并返回目标对象。它是按顺序的，因此最后一个源将覆盖先前参数中相同名称的属性。

例如，我们可以获取一个`Song`对象并创建一个实例，同时覆盖其默认属性。可以在以下示例中看到：

```html
<script>
    function Song() {
        this.track = "Track Title";
        this.duration = 215;
        this.album = "Track Album";
    };

    var Sample = _.extend(new Song(), {
        'track': 'Sample Title',
        'duration': 0,
        'album': 'Sample Album'
    });
</script>
```

如果我们记录`Sample`对象，我们会注意到它是从`Song`构造函数继承而来，并覆盖了默认属性`track`，`duration`和`album`。虽然我们可以使用传统的 JavaScript 来提高继承的性能，但使用`extend`方法可以帮助我们专注于交付。我们将在本章后面看看如何利用这种方法在我们的示例应用程序中创建基本架构。

### _.each

当我们想要迭代`Array`或`Object`时，`each`方法非常有用。实际上，这是我们可以在`Zepto`和其他流行库如`jQuery`中找到的另一种方法。尽管每个库的实现和性能略有不同，但我们将使用 Underscore 的`_.each`方法，以便我们可以在不引入新依赖项的情况下保持应用程序的架构。根据 Underscore 的文档（[`underscorejs.org/#each`](http://underscorejs.org/#each)），使用`_.each`与其他实现类似：

> 对元素列表进行迭代，依次将每个元素传递给迭代器函数。如果传递了上下文对象，则迭代器绑定到上下文对象。迭代器的每次调用都使用三个参数：（element，index，list）。如果列表是 JavaScript 对象，则迭代器的参数将是（value，key，list）。如果存在本地 forEach 函数，则委托给本地 forEach 函数。

让我们看一个在前一节中创建的代码中使用`_.each`的示例。我们将循环遍历`Sample`的实例，并记录对象的属性，包括曲目、持续时间和专辑。由于 Underscore 的实现允许我们像数组一样轻松地循环遍历`Object`，因此我们可以使用这种方法来迭代我们的`Sample`对象的属性：

```html
<script>
    function Song() {
        this.track = "Track Title";
        this.duration = 215;
        this.album = "Track Album";
    };

    var Sample = _.extend(new Song(), {
        'track': 'Sample Title',
        'duration': 0,
        'album': 'Sample Album'
    });

    _.each(Sample, function(value, key, list){
        console.log(key + ": " + value);
    });

</script>
```

我们的日志输出应该是这样的：

```html
track: Sample Title
duration: 0
album: Sample Album
```

正如你所看到的，使用 Underscore 的`each`方法与数组和对象非常容易。在我们的示例应用程序中，我们将使用这种方法来循环遍历对象数组以填充我们的页面，但现在让我们回顾一下我们将在 Underscore 库中使用的最后一个重要方法。

### _.template

Underscore 已经让我们非常容易地将模板集成到我们的应用程序中。默认情况下，Underscore 带有一个简单的模板引擎，可以根据我们的目的进行定制。实际上，它还可以预编译您的模板以便进行简单的调试。由于 Underscore 的模板化可以插入变量，我们可以利用它来根据需要动态更改页面。Underscore 提供的文档（[`underscorejs.org/#template`](http://underscorejs.org/#template)）有助于解释在使用模板时我们有哪些不同的选项：

> 将 JavaScript 模板编译为可以用于渲染的函数。用于从 JSON 数据源呈现复杂的 HTML 片段。模板函数既可以插入变量，使用<%= ... %>，也可以执行任意的 JavaScript 代码，使用<% ... %>。如果您希望插入一个值，并且它是 HTML 转义的，请使用<%- ... %>。当您评估一个模板函数时，传递一个数据对象，该对象具有与模板的自由变量对应的属性。如果您正在编写一个一次性的模板，可以将数据对象作为模板的第二个参数传递，以便立即呈现，而不是返回一个模板函数。

前端的模板化一开始可能很难理解，毕竟我们习惯于查询后端，使用 AJAX，并检索标记，然后在页面上呈现。如今，最佳实践要求我们使用发送和检索数据的 RESTful API。因此，理论上，您应该使用正确形成的数据并进行插值。但是，如果不是在后端，我们的模板在哪里？很容易，在我们的标记中：

```html
<script type="tmpl/sample" id="sample-song">
    <section>
        <header>
            <h1><%= track %></h1>
            <strong><%= album %></strong>
        </header>
    </section>
</script>
```

因为前面的脚本在浏览器中有一个已识别的类型，所以浏览器避免读取此脚本中的内容。而且因为我们仍然可以使用 ID 来定位它，所以我们可以获取内容，然后使用 Underscore 的`template`方法插入数据：

```html
<script>
    function Song() {
        this.track = "Track Title";
        this.duration = 215;
        this.album = "Track Album";
    };

    var Sample = _.extend(new Song(), {
        'track': 'Sample Title',
        'duration': 0,
        'album': 'Sample Album'
    });

    var template = _.template(Zepto('#sample-song').html(), Sample);

    Zepto(document.body).prepend(template);

</script>
```

运行页面的结果将是以下标记：

```html
<body>
    <section>
        <header>
            <h1>Sample Title</h1>
            <strong>Sample Album</strong>
        </header>
    </section>
    <!-- scripts and template go here -->
</body>
```

正如您所看到的，模板中的内容将被预先放置在主体中，并且数据将被插入，显示我们希望显示的属性；在这种情况下，歌曲的标题和专辑名称。如果这有点难以理解，不要太担心，当行业开始转向运行原始数据（`JSON`）的单页面应用程序时，我自己也很难理解这个概念。

目前，这些是我们将在本章中一直使用的方法。鼓励您尝试使用`Underscore.js`库，以发现一些更高级的功能，使您的生活更轻松，例如`_.map`，`_.reduce`，`_.indexOf`，`_.debounce`和`_.clone`。但是，让我们继续学习`Backbone.js`以及如何使用这个库来创建我们的应用程序。

# 介绍 Backbone.js

为了给我们的单页面应用程序添加结构，我们将使用`Backbone.js`，这是一个轻量级的框架，帮助我们应用 MVC 设计模式。`Backbone.js`是许多 MVC 类型框架之一，它帮助前端开发遵循将数据与视图或特别是 DOM 分离的最佳实践。除此之外，我们的应用程序可能会变得非常复杂。`Backbone.js`有助于缓解这些问题，并让我们快速上手。因此，让我们开始讨论 MVC 如何应用于这个框架。

## MVC 和 Backbone.js

有许多种类型的 JavaScript 框架以不同的方式应用 MVC，Backbone 也不例外。Backbone 实现了`Models`、`Views`、`Collections`和`Routers`；它还包括一个`Event`、`History`和`Sync`系统。正如你所看到的，Backbone 没有传统的 Controller，但我们可以将`Views`解释为控制器。根据 Backbone 的文档（[`backbonejs.org/#FAQ-mvc`](http://backbonejs.org/#FAQ-mvc)）：

> (…)在 Backbone 中，View 类也可以被视为一种控制器，分派源自 UI 的事件，HTML 模板作为真正的视图。

这种 MVC 实现可能有点令人困惑，但我们的示例应用程序将有助于澄清问题。现在让我们深入了解 Backbone 模型、视图和集合。在接下来的部分中，我们将介绍 Backbone 的每个部分是如何实现的，以及我们将用来构建应用程序的部分。

## Backbone 模型

在任何 MVC 模式中，模型都是至关重要的，包含数据和逻辑，包括属性、访问控制、转换、验证等。请记住，我们每天都在编写模型，事实上，我们在本书中创建了许多模型（`MediaElement`、`Video`、`Audio`等）。Backbone 模型类似于样板，它提供了我们否则必须自己构建的实用方法。

让我们以以下代码为例：

```html
function Song() {
    this.track = "Track Title";
    this.duration = 215;
    this.album = "Track Album";
};

Song.prototype.get = function(prop) {
    return this[prop] || undefined;
}

Song.prototype.set = function(prop, value) {
    this[prop] = value;

    return this;
}

var song = new Song();

song.get('album');
// "Track Album"

song.set('album', 'Sample Album');
// Song

song.get('album');
// "Sample Album"
```

在上面的示例中，我们创建了一个`Song`模型，与前一节中一样，它有几个属性（`track`、`duration`和`album`）和方法（`get`和`set`）。然后我们创建了`Song`的一个实例，并使用创建的方法来获取和设置`album`属性。这很棒；然而，我们需要手动创建这些方法。这不是我们想要做的；我们已经知道我们需要这些方法，所以我们只想专注于数据和扩展它。这就是 Backbone 模型发挥作用的地方。

让我们分析以下模型：

```html
var SongModel = Backbone.Model.extend({
    'defaults': {
        'track': 'Track Title',
        'duration': 215,
        'album': 'Track Album'
    }
});

var song = new SongModel();

song.get('album');
// "Track Album"

song.set('album', 'Sample Album');
// SongModel

song.get('album');
// "Sample Album"
```

上面的代码展示了我们快速开始编写应用程序的方式。在幕后，Backbone 是一个命名空间，并且有一个附加到它的模型对象。然后，使用 Underscore 的`extend`方法，我们返回一个`Backbone.Model`的副本，其中附加了默认属性，赋值给变量`SongModel`。然后我们做同样的事情，使用`get`和`set`，期望的输出在注释中。

如你所见，使用 Backbone 很容易入门，尤其是如果你只是想要一种方法来组织你的数据，而不是为每个应用程序构建自定义功能。现在让我们看看 Backbone 中的视图，以及它如何帮助我们将数据与 UI 分离。

## Backbone 视图

Backbone 视图与模型有些不同，它们更多的是为了方便。如果我们查看 Backbone 的文档并比较*Views*和*Models*部分，我们会发现 Views 更加简洁，但在组织我们的应用程序时也很有用。为了看到它们为什么仍然有用，让我们看下面的代码：

```html
var $section = $('section');

$section.on('click', 'a', doSomething);

function doSomething() {
    // we do something here
}
```

通常，这是我们在页面上缓存元素并为特定用户交互委托事件的方式。但是，如果可以减少设置工作呢？在下面的代码中，我们将上面的代码转换为典型的 Backbone 视图设置。

```html
var SongView = Backbone.View.extend({
    'el': document.querySelector('section'),

    'events': {
        'click a': 'doSomething'
    },

    'doSomething': function(e){
        console.log($(e.currentTarget).attr('href'));
    }
});

var view = new SongView();
```

正如您所看到的，Backbone 为您处理了设置工作。它在幕后为您缓存了所选元素并代理了事件。实际上，您在您的端上需要做的只是设置，然后快速进行下一步；现在您会注意到您的开发时间减少了，而您的效率增加了，这只是进入 Backbone 的初步步骤。当我们将模型和视图连接在一起时，魔术就会发生。要看到这一点，请看以下代码：

```html
var SongModel = Backbone.Model.extend({
    'defaults': {
        'track': 'Track Title',
        'duration': 215,
        'album': 'Track Album'
    }
});

var song = new SongModel();

var SongView = Backbone.View.extend({
    'el': document.querySelector('section'),

    'events': {
        'click a': 'doSomething'
    },

    'initialize': function() {
        this.model.on('change:track', this.updateSongTitle, this);

        this.$el.$songTrack = this.$el.find('.song-track');
        this.$el.$songTrack.text(this.model.get('track'));
    },

    'doSomething': function(e){
        console.log($(e.currentTarget).attr('href'));
    },

    'updateSongTitle': function() {
        this.$el.$songTrack.text(this.model.get('track'));
    }
});

var view = new SongView({
    'model': song
});

song.set('track', 'Sample Track');
// The DOM Updates with the right value
```

在这段代码片段中，我们最终将单个模型连接到一个视图。我们这样做的方式是将模型的实例传递给视图的实例：

```html
var view = new SongView({
    'model': song
});
```

当我们这样做时，我们将模型和视图关联起来。但我们还需要对该模型进行一些操作，通常我们希望显示与其关联的数据。因此，在这个例子中，我们创建了一个`initialize`方法，它被调用作为构造函数。在这个方法中，我们使用 Backbone 内置的事件系统来跟踪与模型的`track`属性相关的任何更改，并相应地调用`updateSongTitle`。在此过程中，我们通过将`this`作为第三个参数传递来更改事件处理程序的上下文，然后缓存显示歌曲轨道的元素。

最后，当您更改歌曲的`track`属性的实例时，DOM 会相应地更新。现在我们已经有了构建应用程序所需的基础。但让我们来看看 Backbone 集合，了解如何跟踪数据如何增加应用程序的效率。

## Backbone 集合

到目前为止，我们已经使用了单个模型，这很好，但在大多数情况下，我们使用数据集。这就是 Backbone 集合存在的原因，用于管理有序的模型集。Backbone 集合还与 Underscore 的方法相关联，使我们可以轻松高效地处理这些集合，而无需进行任何设置工作。

让我们看看以下代码：

```html
var SongModel = Backbone.Model.extend({
    'defaults': {
        'track': 'Track Title',
        'duration': 215,
        'album': 'Track Album'
    }
});

var SongCollection = Backbone.Collection.extend({
    'model': SongModel
});

var SongView = Backbone.View.extend({
    'el': document.querySelector('section'),

    'events': {
        'click a': 'doSomething'
    },

    'initialize': function() {
        this.collection.on('change', this.updateDetected, this);
    },

    'doSomething': function(e){
        console.log($(e.currentTarget).attr('href'));
    },

    'updateDetected': function() {
        console.log("Update Detected");
    }
});

var collection = new SongCollection();

for (var i = 0; i < 100; i++) {
    collection.add(new SongModel());
}

var view = new SongView({
    'collection': collection
});
```

这个示例代码与上一节中生成的代码非常相似。不同之处在于我们创建了一个`SongCollection`，它接受`SongModel`类型的模型。然后我们创建了这个集合的一个实例，通过我们的`for`循环向其中添加了 100 个模型，最后将集合附加到我们的视图上。

我们的视图也发生了变化，我们将`change`事件附加到我们的集合上，并创建了一个更通用的监听器，每当集合中的模型更新时都会被调用。因此，当我们执行以下代码时，视图会告诉我们有东西被更新了：

```html
collection.models[0].set('album', 'sample album');
// "Update Detected"
```

## 服务器端交互

看到 Backbone 应用程序如何连接到服务器并不容易，特别是因为前端代码中有很多事情要做。但是，如果您查看 Backbone.js 网站提供的文档（[`backbonejs.org/#Sync`](http://backbonejs.org/#Sync)），我们知道模型包含了操纵数据的所有功能。事实上，模型连接到数据库并可以与之同步。

> Backbone.sync 是 Backbone 每次尝试从服务器读取或保存模型时调用的函数。默认情况下，它使用（jQuery/Zepto）。ajax 来进行 RESTful JSON 请求并返回 jqXHR。您可以覆盖它以使用不同的持久化策略，例如 WebSockets、XML 传输或本地存储。

但是，模型并不是唯一可以连接到服务器的对象。随着文档的继续阅读，模型或集合可以开始同步请求并相应地与之交互。这与传统的 MVC 实现有些不同，特别是因为集合和模型可以与数据库交互。为了更好地显示 Backbone 对 MVC 的实现，提供的图像有助于显示不同类型对象之间的关系：

![服务器端交互](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_07_02.jpg)

这基本上就是我们之前创建的东西；一个视图、模型和控制器。实现略有不同，但我们可以看到演示层和数据之间有明显的分离，因为视图从不直接与数据库交互。如果这有点令人困惑，那是因为它确实如此，这是另一种复杂性的层次，一旦理解，将有助于引导您编写优雅的代码。

您现在已经准备好使用`Underscore`、`Backbone`和`Zepto`创建一个单页应用程序。但是，有一个问题。这些库可以加快我们的开发速度并提高效率，但实际上并没有为我们的应用程序提供一个坚实的结构。这就是我们在示例应用程序中要解决的问题。接下来，我们将讨论单页应用程序所需的架构、实现和优化。

# 我们的示例应用程序

我们现在已经介绍了`Underscore.js`和`Backbone.js`，并且对这些库提供的内容以及它们如何帮助应用程序开发有了很好的理解。然而，我们仍然需要一种结构化应用程序的方式，以便它们可以轻松扩展，最重要的是，可以管理。因此，在本章的这一部分，我们将开始构建一个示例应用程序，将所有内容联系在一起，并帮助您快速构建单页应用程序。

## 应用程序架构

我们的示例应用程序将做两件事。一是允许我们查看用户信息，例如个人资料和仪表板。二是具有可以使用 HTML5 音频媒体元素收听的歌曲播放列表。我们可以将这些要求视为几乎是两个应用程序：一个用于管理用户数据的用户应用程序，另一个用于管理媒体播放的应用程序。但它们将相关联，以便用户将有与他们相关的歌曲播放列表。

### 基本示例架构

让我们开始实现前面的架构。首先，我们知道将有两个应用程序，类似于我们的`App`对象，因此让我们从定义这些开始：

+   `js/Music/`

+   `js/User/`

+   在 JavaScript（`js`）文件夹中，我们应该创建前面提到的两个文件夹：`Music`和`User`。这两个文件夹将分别包含用户和音乐应用程序的代码。为了帮助管理我们的 backbone 文件，我们将为每个创建`models`、`views`和`collections`文件夹。

+   `js/Music/`

+   `views/`

+   `models/`

+   `collections/`

+   `js/User/`

+   `views/`

+   `models/`

+   `collections/`

太棒了！现在我们可以开始创建一个主 JavaScript 文件，其中将包含每个应用程序的命名空间；每个命名空间分别为`User`和`Music`。

+   `js/Music/`

+   `views/`

+   `models/`

+   `collections/`

+   `Music.js`

+   `js/User/`

+   `views/`

+   `models/`

+   `collections/`

+   `User.js`

现在，我们的大多数视图都将具有非常熟悉的功能。例如，将有一个全局导航栏，其中包含三个链接，每个链接将启动每个部分的隐藏/显示，隐藏当前部分并显示下一个部分。我们不一定希望一遍又一遍地编写相同的代码，因此最好有一个基本视图，我们的应用程序可以从中继承。为此，我们将在我们的`App`文件夹中创建一个名为`views`的文件夹：

+   `js/App/`

+   `views/`

+   `BaseView.js`

好的，这基本上是我们这个示例应用程序的 JavaScript 框架。当然，还有其他设置方式，也许它们甚至更好—这很好。对于我们的目的，这符合要求，并有助于展示我们应用程序中的一些结构。现在，让我们开始查看我们的标记。

### 应用标记

让我们打开与本章相关的`index.html`文件；它应该位于`/singlepage/index.html`。现在，如果我们还没有这样做，让我们从更新站点的全局导航开始，这是我们之前为其他章节所做的。如果您需要参考资料，请查看本书提供的上一章的完成源代码，并根据需要更新标记。

更新后，我们的标记应该看起来像这样：

```html
<!DOCTYPE html>
<html class="no-js">
<head>
    <!-- Meta Tags and More Go Here -->

  <link rel="stylesheet" href="../css/normalize.css">
  <link rel="stylesheet" href="../css/main.css">
    <link rel="stylesheet" href="../css/singlepage.css">
  <script src="img/modernizr-2.6.1.min.js"></script>
</head>
  <body>
    <!-- Add your site or application content here -->
        <div class="site-wrapper">
            <header>
                <hgroup>
                    <h1>iPhone Web Application Development</h1>
                    <h2>Single Page Applications</h2>
                </hgroup>
                <nav>
                    <select>
                        <!-- Options Go Here -->
                    </select>
                </nav>
            </header>
            <footer>
                <p>iPhone Web Application Development &copy; 2013</p>
            </footer>
        </div>

        <!-- BEGIN: LIBRARIES / UTILITIES-->
    <script src="img/zepto.min.js"></script>
        <script src="img/underscore-1.4.3.js"></script>
        <script src="img/backbone-0.9.10.js"></script>
    <script src="img/helper.js"></script>
        <!-- END: LIBRARIES / UTILITIES-->
        <!-- BEGIN: FRAMEWORK -->
        <script src="img/App.js"></script>
        <script src="img/App.Nav.js"></script>
        <!-- END: FRAMEWORK -->
  </body>
</html>
```

现在，让我们开始修改这段代码以适应我们的应用程序。首先，让我们在标题后面添加一个`div`，类名为`content`：

```html
 <div class="site-wrapper">
    <header>
        <hgroup>
            <h1>iPhone Web Application Development</h1>
            <h2>Single Page Applications</h2>
        </hgroup>
        <nav>
            <select>
                <!-- Options Go Here -->
            </select>
        </nav>
    </header>
    <div class="content"></div>
    <footer>
        <p>iPhone Web Application Development &copy; 2013</p>
    </footer>
</div>
```

当我们完成这些工作后，让我们修改脚本，包括我们之前创建的整个应用程序。这意味着我们包括了`Music`和`User`应用程序脚本，以及`BaseView`。我们的标记脚本部分应该看起来像这样：

```html
<!-- BEGIN: LIBRARIES / UTILITIES-->
<script src="img/zepto.min.js"></script>
<script src="img/underscore-1.4.3.js"></script>
<script src="img/backbone-0.9.10.js"></script>
<script src="img/helper.js"></script>
<!-- END: LIBRARIES / UTILITIES-->
<!-- BEGIN: FRAMEWORK -->
<script src="img/App.js"></script>
<script src="img/App.Nav.js"></script>
<script src="img/BaseView.js"></script>
<!-- END: FRAMEWORK -->
<!-- BEGIN: MUSIC PLAYLIST APPLICATION -->
<script src="img/Music.js"></script>
<script src="img/SongModel.js"></script>
<script src="img/SongCollection.js"></script>
<script src="img/SongView.js"></script>
<script src="img/PlayListView.js"></script>
<script src="img/AudioPlayerView.js"></script>
<!-- END: MUSIC PLAYLIST APPLICATION -->
<!-- BEGIN: USER APPLICATION -->
<script src="img/User.js"></script>
<script src="img/UserModel.js"></script>
<script src="img/DashboardView.js"></script>
<script src="img/ProfileView.js"></script>
<!-- END: USER APPLICATION -->
<script src="img/main.js"></script>
<script> Backbone.history.start(); </script>
<!-- END: BACKBONE APPLICATION -->
```

### 注意

请注意，我们已经启动了 Backbone 历史 API。虽然我们还没有全面讨论这一点，但这对于保持应用程序状态至关重要。Backbone 中历史 API 的实现细节超出了本书的范围，但对于那些希望利用 Backbone 进行离线存储的人来说，这是非常鼓励的。现在，请记住这对于路由是至关重要的。

#### 创建模板

现在我们的标记接近完成，但我们还剩下应用程序的其余部分将由什么组成；这就是模板化将发挥作用的地方。下一步是包括我们应用程序所需的模板，包括音频播放器视图、播放列表、歌曲、仪表板、个人资料和共享导航视图。那么如何在静态 HTML 页面上指定模板呢？像这样：

```html
<script type="tmpl/Music" id="tmpl-audioplayer-view">
    <section class="view-audioplayer">
        <header>
            <h1>Audio Player</h1>
        </header>
        <div class="audio-container">
            <audio preload controls>
                <source src="img/<%= file %>" type='audio/mpeg; codecs="mp3"'/>
                <p>Audio is not supported in your browser.</p>
            </audio>
        </div>
    </section>
</script>
```

您可能想知道为什么这不会在浏览器中引起任何验证错误或代码执行错误。好吧，为了帮助澄清事情，我们的`script`标签的`type`属性是一个不受支持的 MIME 类型，因此浏览器会忽略`script`块中的所有内容（[`www.whatwg.org/specs/web-apps/current-work/multipage/scripting-1.html#script-processing-prepare`](http://www.whatwg.org/specs/web-apps/current-work/multipage/scripting-1.html#script-processing-prepare)）。因为块内的代码不会被执行，所以我们可以包含我们的 HTML 模板以供以后使用。请记住，我们已经附加了一个 ID，我们可以使用 Zepto 来定位这个元素。还要注意音频元素的来源，特别是`<%= file %>`。这将由 Underscore 的`template`方法用于插入模板本身传递的数据。我们很快就会讨论到这一点，但现在知道这就是我们可以设置模板的方式。

好的，现在我们知道如何创建模板，让我们在包含我们应用程序脚本之前实现以下模板。我们可以包括音频播放器的前一个模板，然后我们可以包括以下模板：

```html
<!-- Playlist View -->
<script type="tmpl/Music" id="tmpl-playlist-view">
    <section class="view-playlist">
        <header>
            <h1><%= name + "'s" %> Playlist</h1>
            <% print(_.template($('#tmpl-user-nav').html(), {})); %>
        </header>
        <ul></ul>
    </div>
</script>
```

在播放列表视图模板中，我们有一些非常有趣的东西。看一下`h1`标签后面的代码。我们在这里看到 Underscore 库的`template`方法；它接受一个参数，这个参数将是模板`#tmpl-user-nav`的 HTML 字符串，我们还没有定义，第二个参数是一个空对象。这个例子展示了在模板中使用模板的用法，有点像潜行，但希望不会太可怕。请记住，我们提到我们的应用程序中将包含全局导航；前面的方法帮助我们编写一次代码，保持我们的代码清洁、可管理和高效。

现在，我们的播放列表仍然不包含歌曲列表。这是因为它将是动态的，基于歌曲数据集；这就是为什么在播放列表视图中有一个空的无序列表。但我们的歌曲会是什么样子呢？传统上，我们只需在 JavaScript 中创建一个列表（`li`）元素，但是使用模板，我们不再需要这样做——我们可以将标记保留在逻辑之外：

```html
<!-- Individual Song View -->
<script type="tmpl/Music" id="tmpl-song-view">
    <li class="view-song">
        <strong><%= track %></strong>
        <em><%= artist %></em>
    </li>
</script>
```

现在看看将标记保留在脚本之外是多么容易？在这个模板中，我们遵循相同的基本原则：定义一个包含标记的脚本块，并创建将插值到其中的标记，以包含我们想要的数据。在这种情况下，我们希望将曲目和艺术家输出到它们自己的元素中。现在让我们创建用户的仪表板：

```html
<script type="tmpl/User" id="tmpl-user-dashboard">
    <section class="view-dashboard">
        <header>
            <h1><%= name + "'s" %> Dashboard</h1>
            <% print(_.template($('#tmpl-user-nav').html(), {})); %>
        </header>
    </section>
</script>
```

再次，和以前一样。实际上，我们正在重复使用在播放列表视图中显示全局导航的相同方法。到目前为止，你已经注意到每个模板都有一个特定的 ID，并且根据约定，我们已经根据其应用程序定义了每个`script`块的类型，例如`tmpl/User`用于用户应用程序，`tmpl/Music`用于音乐应用程序。现在让我们来看一下结合了前面两种方法的个人资料视图。

```html
<script type="tmpl/User" id="tmpl-user-profile">
    <section class="view-profile">
        <header>
            <h1><%= name + "'s" %> Profile</h1>
            <% print(_.template($('#tmpl-user-nav').html(), {})); %>
        </header>
        <dl>
            <dt>Bio</dt>
            <dd><%= bio %></dd>
            <dt>Age</dt>
            <dd><%= age %></dd>
            <dt>Birthdate</dt>
            <dd><%= birthdate.getMonth() + 1 %>/<%= birthdate.getDate() %>/<%= birthdate.getFullYear() %></dd>
        </dl>
    </section>
</script>
```

在这个视图中，全局导航被打印出来，并且数据被插值。正如你所看到的，模板中可以做任何事情。但它也可以是我们应用程序的全局导航这样简单的东西：

```html
<script type="tmpl/User" id="tmpl-user-nav">
    <a href="#dashboard">Dashboard</a>
    <a href="#profile">Profile</a>
    <a href="#playlist">Playlist</a>
</script>
```

在这个最后的例子中，没有发生复杂的事情，实际上就是我们一直期待的全局导航，结果是——它只是标记。现在，你可能会想为什么不在 DOM 中创建所有这些，隐藏它，然后使用`Zepto`或`jQuery`中的内置选择器引擎填充所需的信息。老实说，这是一个很好的问题。但是有一个主要原因，性能。使用这些引擎是昂贵的，甚至是内置方法`querySelector`和`querySelectorAll`。我们不想触及 DOM，因为这是一个繁重的操作，特别是对于处理大数据集的大规模应用程序。最终，仅仅为了数据填充或存储而进行 DOM 操作是混乱的。不要这样做，将 DOM 用于数据而不是最佳实践。

我们的模板已经完成，这就结束了我们应用程序的标记。现在我们转向有趣的部分，我们的脚本。接下来的部分将会相当复杂和相当具有挑战性，但我保证当我们完成时，你将成为一个单页应用程序的专家，并且准备快速创建你自己的应用程序。第一次总是艰难的，但坚持下去，你将会收获回报。

### 应用程序脚本

在本节中，我们将介绍使我们的应用程序工作所需的脚本。我们将从审查`BaseView`开始，这个视图包含了继承视图（`PlayListView`、`ProfileView`和`DashboardView`）中的共享功能。然后我们将创建我们的音乐和用户应用程序，每个应用程序都有它们相对应的模型、视图和集合。

#### BaseView

让我们开始查看我们的脚本，从我们在`App`命名空间下创建的`BaseView`文件开始（`js/App/views/BaseView.js`）。在这个文件中，我们将创建`BaseView`类，它将扩展 Backbone 的通用`View`类。`BaseView`将如下所示：

```html
(function(window, document, $, Backbone, _){

  var BaseView = Backbone.View.extend({

  });

  // Expose the User Object
  window.App.BaseView = BaseView;

}(window, document, Zepto, Backbone, _));
```

这个类遵循了我们在之前章节中编写的其他 JavaScript 的完全相同的模式，这里唯一的区别是包括了`Backbone`和`Undescore`，以及我们如何使用`window.App.BaseView = BaseView`来公开`BaseView`类。

现在，请跟着我。我们将创建几种方法，这些方法将包含在扩展`BaseView`类的任何对象中。这些方法将包括`show`、`hide`、`onProfileClick`、`onPlaylistClick`、`onDashboardClick`和`onEditClick`。正如你可能已经猜到的，其中一些方法将是事件处理程序，用于导航到我们应用程序的某些部分。查看以下代码以了解实现：

```html
(function(window, document, $, Backbone, _){

  var BaseView = Backbone.View.extend({
    'hide': function() {
      this.$template.hide();
    },

    'show': function() {
      this.$template.show();
    },

    'onProfileClick': function(e) {
      e.preventDefault();

      User.navigate('profile/' + this.model.get('username'), { 'trigger': true });
    },

    'onPlaylistClick': function(e) {
      e.preventDefault();

      Music.navigate('playlist', { 'trigger': true });
    },

    'onDashboardClick': function(e) {
      e.preventDefault();

      User.navigate('dashboard', { 'trigger': true });
    },

    'onEditClick': function() {
      console.log('onEditClick');
    }
  });

  // Expose the User Object
  window.App.BaseView = BaseView;

}(window, document, Zepto, Backbone, _));
```

现在，你可能注意到这里写的对象尚未创建，比如`$template`、`User`和`Music`对象。我们将在几个步骤后返回到这一点，但请记住，`this.$template`将指的是扩展`BaseView`的实例，而`User`和`Music`对象将是使用内置的 backbone 方法`navigate`来改变我们应用程序在 URL 中的位置并存储用户交互历史的路由器。为了更好地理解这个类`BaseView`是如何被使用的，让我们开始创建`Music.js`中`Music`对象的代码（`js/Music/Music.js`）。

#### 音乐应用程序

现在让我们开始创建我们应用程序的第一部分，音乐应用程序。音乐和用户应用程序都是分开的，以增加更高级别的可维护性和重用性。从音乐应用程序开始，我们将创建适当的路由器、集合、模型和视图。

##### 路由器

我们的音乐应用程序始于`Music.js`文件中定义的`Music`类，该文件位于`js/Music/`目录下。在这个文件中，我们将扩展 Backbone 的`Router`类，包含我们音乐应用程序的路由、用于模型和集合的示例数据对象，以及当请求播放列表时的事件处理程序。首先，让我们从定义类开始：

```html
(function(window, document, $, Backbone, _){

  var Music = Backbone.Router.extend({
    // Application Routes
    'routes': {
      'playlist': 'setupPlaylist',
      'playlist/:track': 'setupPlaylist'
    }
  });

  // Expose the Music Object
  window.Music = new Music();

}(window, document, Zepto, Backbone, _));
```

按照我们在`BaseView`类中建立的模式，我们在`Backbone`中扩展`Router`类，并定义一些默认路由。这两个路由包括一个常规播放列表路由和一个包含播放列表和曲目编号的替代路由。当调用这两个路由时，都将调用我们接下来将定义的`setupPlaylist`方法：

```html
'setupPlaylist': function(track){
  if (!this.songCollection) {
    // Create song collection on the instance of Music
    this.songCollection = new this.SongCollection(this.songs);
  }

  if (!this.playListView) {
    // Create song list view on the instance of Music
    this.playListView = new this.PlayListView({
      'el': document.querySelector('.content'),
      'collection': this.songCollection,
      'model': new User.UserModel()
    });
  } else {
    this.playListView.show();
    this.playListView.audioPlayerView.show();
  }

  if (track) {
    this.playListView.updateTrack(track);
  }
}
```

如果这段代码让你有点畏首畏尾，那没关系，它实际上非常简单。首先，我们检查是否已经使用`Music`的实例初始化了一个`songCollection`对象。如果没有，我们将使用一组歌曲的示例数据对象来创建一个。接下来，我们做同样的事情，检查`playListView`对象是否已经创建；如果没有，我们继续创建它。否则，我们只是显示播放列表和与之相关的音频播放器。最后，我们检查是否传递了曲目编号（与我们创建的第二个路由相关）；如果有曲目编号，我们将更新`playListView`以反映所选的曲目。

让我们专注于`playListView`的初始化：

```html
this.playListView = new this.PlayListView({
  'el': document.querySelector('.content'),
  'collection': this.songCollection,
  'model': new User.UserModel()
});
```

尽管我们尚未正式创建`PlayListView`类，但我们可以回顾它是如何初始化的。在这种情况下，我们在`Music`的实例上附加了一个`playListView`属性，即`this.playListView`。这个属性将是`PlayListView`的一个实例（`new PlayListView({})`）。这个`PlayListView`的新实例将接受一个普通对象，其中包含三个属性：一个定义为`el`的元素，一个集合，以及一个`UserModel`的实例，这个实例尚未定义。

这里我们需要做的最后一件事是包括一个`initialize`方法，该方法将创建一个示例数据对象（`this.songs`），并监听播放列表路由的调用。当我们调用播放列表路由或导航到它时，我们希望同时隐藏个人资料和仪表板；我们将在`routes`监听器中手动执行这一操作：

```html
'initialize': function() {
  this.songs = [{
      'duration': 251,
      'artist': 'Sample Artist',
      'added': new Date(),
      'track': 'Sample Track Title',
      'album': 'Sample Track Album'
    }, {
      'duration': 110,
      'artist': 'Sample Artist',
      'added': new Date(),
      'track': 'Sample Track Title',
      'album': 'Sample Track Album'
    }, {
      'duration': 228,
      'artist': 'Sample Artist',
      'added': new Date(),
      'track': 'Sample Track Title',
      'album': 'Sample Track Album'
    }
  ];

  this.on('route:setupPlaylist', function() {
    // This should be more dynamic, but fits our needs now
    // ---
    if (User.profileView) {
      User.profileView.hide();
    }

    if (User.dashboardView) {
      User.dashboardView.hide();
    }
    // ---
  });
},
```

好的，我们在这里创建了`initialize`方法，当创建`Music`的实例时会调用这个方法。这很好，因为在这个方法中，我们可以处理任何设置工作，比如创建示例数据对象。示例数据对象是一个对象数组，然后将被`SongCollection`类转换为模型：

```html
'setupPlaylist': function(track){
  if (!this.songCollection) {
    // Create song collection on the instance of Music
    this.songCollection = new this.SongCollection(this.songs);
  }
  // Some code defined after
}
```

看起来很熟悉吧？现在我们正在收尾。我们还没有创建`SongCollection`类，但是 Backbone 的文档中指出，如果将数组传递给集合，它会自动转换为集合中指定的模型（将在未来的步骤中描述）。

这个`initialize`方法做的最后一件事是，在播放列表的路由上定义一个监听器（`this.on('route:setupPlaylist', function() {});`）。事件处理程序然后隐藏了已经创建的个人资料和仪表板。另外，请注意，我们使用`route:setupPlaylist`指定了路由，但我们也可以使用`route`来监听任何路由。

我知道这是很多东西要消化的，但我们现在将从这个`Music`类开始连接这些点，从集合开始，然后转向模型，最后是视图。这个类是其他所有需要构建的东西的基础，以便拥有一个完全功能的音乐应用程序，并提供我们开发的蓝图。

##### 集合

我们音乐应用程序的集合很简单。遵循我们之前所做的基本模板，我们将创建一个包含`SongCollection`类的闭包。然后我们将定义`SongCollection`应该保持的模型类型。最后，我们将把这个类暴露给我们的`Music`对象。

当我们完成了实现这些要求后，我们的类看起来是这样的：

```html
(function(window, document, $, Backbone, _){

  var SongCollection = Backbone.Collection.extend({
    'model': window.Music.SongModel
  });

  window.Music.SongCollection = SongCollection;

}(window, document, Zepto, Backbone, _));
```

看起来多简单啊？现在我们知道这个集合只跟踪`SongModel`类型的模型，并且如果传递一个数组，它将把包含的对象转换为`SongModel`类型。这就是这个类现在要做的全部。当然，您可以扩展它并尝试使用几种方法，比如比较器，这个类可以利用；但现在，这就是我们需要的全部。

##### 模型

我们的`SongModel`将描述我们试图跟踪的数据类型。这个模型还将包含一个单一的方法，该方法将以秒为单位的持续时间作为属性，并将其以分钟返回。当然，我们有选择在模型初始化时准备我们的模型，但现在我们将保持简单。

`SongModel`，当写出来时，将是这样的：

```html
(function(window, document, $, Backbone, _){

  var SongModel = Backbone.Model.extend({
    'defaults': {
      // in seconds
      'duration': 0,
      'artist': '',
      'added': 0,
      'track': '',
      'album': ''
    },

    'initialize': function() {

    },

    'getDurationInMinutes': function() {
      var duration = this.get('duration');

      if (duration === 0) {
        return false;
      }

      return this.get('duration') / 60;
    }
  });

  window.Music.SongModel = SongModel;

}(window, document, Zepto, Backbone, _));
```

从前面的代码中，我们可以推断出`SongModel`将具有属性`duration`、`artist`、`added`、`track`和`album`。每个属性的默认值都是空的`String`或`0`。我们还可以注意到，每个模型都将有一个名为`getDurationInMinutes`的方法，可以被调用，并返回该模型的持续时间（以分钟为单位）。同样，`SongModel`类遵循相同的基本架构和最佳实践，返回给`Music`对象。最后，我们准备好查看这个音乐应用程序的视图。

##### 视图（们）

在这一部分，我们将审查三个单独的视图，包括播放列表、歌曲和音频播放器视图。每个视图呈现音乐应用程序的一个单独部分，除了播放列表，它还呈现音频播放器和每个单独的歌曲。所以，让我们从播放列表视图开始。

###### 播放列表视图

我们希望播放列表视图做一些事情，但我们将一步一步来。首先，让我们创建`PlayListView`类，它将扩展我们已经创建的`BaseView`类。

```html
(function(window, document, $, Backbone, _){

  var PlayListView = App.BaseView.extend({
    // Code goes here
  });

  // Expose the PlayListView Class
  window.Music.PlayListView = PlayListView;

}(window, document, Zepto, Backbone, _));
```

接下来，我们希望`PlayListView`类引用正确的模板。

```html
(function(window, document, $, Backbone, _){

  var PlayListView = App.BaseView.extend({
    'template': _.template($('#tmpl-playlist-view').html())
  });

  // Expose the PlayListView Class
  window.Music.PlayListView = PlayListView;

}(window, document, Zepto, Backbone, _));
```

通过将模板作为属性包含进来，我们可以很容易地使用`this.template`来引用它。请记住，在这个阶段我们还没有处理模板，我们只是简单地使用了 Underscore 的`template`方法来检索标记。接下来，我们想要为用户点击歌曲时定义一个事件监听器。

```html
(function(window, document, $, Backbone, _){

  var PlayListView = App.BaseView.extend({
    'template': _.template($('#tmpl-playlist-view').html()),

    'events': {
      'click .view-song': 'onSongClicked'
    }
  });

  // Expose the PlayListView Class
  window.Music.PlayListView = PlayListView;

}(window, document, Zepto, Backbone, _));
```

在这一步中，我们告诉视图将我们创建的所有事件委托给视图的元素。在这个事件对象中，我们监听一个带有类名`.view-song`的元素上的点击事件。当点击这个元素时，我们想要调用`onSongClicked`事件处理程序。让我们接下来定义这个事件处理程序。

```html
(function(window, document, $, Backbone, _){

  var PlayListView = App.BaseView.extend({
    'template': _.template($('#tmpl-playlist-view').html()),

    'events': {
      'click .view-song': 'onSongClicked'
    },

    'onSongClicked': function(e) {
      var $target = $(e.currentTarget);

      this.$el.find('.active').removeClass('active');

      $target.addClass('active');

      Music.navigate('playlist/' + ($target.index() + 1), { 'trigger': true });
    }
  });

  // Expose the PlayListView Class
  window.Music.PlayListView = PlayListView;

}(window, document, Zepto, Backbone, _));
```

在前面的代码中定义的事件处理程序切换活动类，然后告诉`Music`路由器导航到播放列表路由，告诉它触发路由事件并传递曲目的索引。通过这样做，我们的路由被调用，传递了一个曲目，播放列表更新了。然而，我们仍然没有定义`updateTrack`方法。让我们在我们的类中包含以下方法：

```html
(function(window, document, $, Backbone, _){

  var PlayListView = App.BaseView.extend({
    'template': _.template($('#tmpl-playlist-view').html()),

    'events': {
      'click .view-song': 'onSongClicked'
    },

    'onSongClicked': function(e) {
      var $target = $(e.currentTarget);

      this.$el.find('.active').removeClass('active');

      $target.addClass('active');

      Music.navigate('playlist/' + ($target.index() + 1), { 'trigger': true });
    },

    'updateTrack': function(track) {
      this.audioPlayerView.render(track);

      this.setActiveSong(track || 1);
    }
  });

  // Expose the PlayListView Class
  window.Music.PlayListView = PlayListView;

}(window, document, Zepto, Backbone, _));
```

现在我们有了`updateTrack`方法，这本质上是告诉音频播放器的视图渲染它收到的曲目。不幸的是，我们的代码还没有准备好运行，因为我们还没有创建这个方法。另外，下面的方法`setActiveSong`也没有定义，所以我们现在需要这样做：

```html
(function(window, document, $, Backbone, _){

  var PlayListView = App.BaseView.extend({
    'template': _.template($('#tmpl-playlist-view').html()),

    'events': {
      'click .view-song': 'onSongClicked'
    },

    'onSongClicked': function(e) {
      var $target = $(e.currentTarget);

      this.$el.find('.active').removeClass('active');

      $target.addClass('active');

      Music.navigate('playlist/' + ($target.index() + 1), { 'trigger': true });
    },

    'setActiveSong': function(track) {
      this.$el.find('.active').removeClass('active');

      this.$el.find('.view-song').eq(track - 1).addClass('active');

      return this;
    },

    'updateTrack': function(track) {
      this.audioPlayerView.render(track);

      this.setActiveSong(track || 1);
    }
  });

  // Expose the PlayListView Class
  window.Music.PlayListView = PlayListView;

}(window, document, Zepto, Backbone, _));
```

我们现在创建了`setActiveSong`方法，基本上是根据 URL 的曲目编号切换活动类。我们可能可以推断并在这里为歌曲创建一个通用的切换，但目前这满足了标准。但我们还没有完成，我们仍然需要初始化这个类并适当地渲染它。让我们看看这个类现在需要什么：

```html
(function(window, document, $, Backbone, _){

  var PlayListView = App.BaseView.extend({
    // code before

    'initialize': function() {
      this.render();
    },

    'render': function() {
      var i = 0,
        view,
        that = this;

      // Create the template
      this.$template = $(this.template(this.model.attributes));

      // Append the template
      this.$el.append(this.$template);

      // Create the audio player
      if(!this.audioPlayerView) {
        this.audioPlayerView = new Music.AudioPlayerView({
                      'el': this.el.querySelector('.view-playlist'),
                      'model': new User.UserModel()
                    });
      }

      this.collection.each(function(element, index, list){
        var view  = new Music.SongView({
          'el': that.$template.find('ul'),
          'model': element
        });
      });

      return this;
    },

    // code after 
  });

  // Expose the PlayListView Class
  window.Music.PlayListView = PlayListView;

}(window, document, Zepto, Backbone, _));
```

前面的代码完成了这个类，但在我们继续之前，让我们看看这里发生了什么。首先，我们定义了一个`initialize`方法。这个方法将在创建这个类的实例后被调用，因此`render`方法也将被调用。通常，在 Backbone 中，`render`方法确切地做了函数被调用的事情——渲染视图。

定义的`render`方法做了一些事情；首先，它使用传入的模型编译我们的模板。之前我们看到了以下代码：

```html
// Create song list view on the instance of Music
this.playListView = new this.PlayListView({
  'el': document.querySelector('.content'),
  'collection': this.songCollection,
  'model': new User.UserModel()
});
```

正如我们所看到的，创建了一个新的`UserModel`并将其传递给`PlayListView`，并且这个实例用于填充播放列表的模板。一旦编译完成，我们使用 Zepto 的`append`方法附加编译后的模板。你可能会问，它附加到什么上面？好吧，这个类的上面初始化正在寻找一个类为`content`的元素，我们在页面的标题元素之后定义了它。因此，`PlayListView`将附加到这个类为`content`的`div`上。

当模板附加完成后，我们检查音频播放器视图是否已经创建。如果没有，那么我们就创建它：

```html
if(!this.audioPlayerView) {
  this.audioPlayerView = new Music.AudioPlayerView({
    'el': this.el.querySelector('.view-playlist'),
    'model': new User.UserModel()
  });
}
```

最后，一旦检查音频播放器视图，我们就可以开始有趣的事情了。在最后一部分中，我们循环遍历发送过来的集合，这是`SongCollection`的一个实例，与`Music.js`中创建的相同数据。当我们遍历集合中的每个模型时，我们每次都创建一个`SongView`的实例，将编译模板的无序列表元素传递给它，并传递当前模型。

现在，如果这没有让你大吃一惊，我不知道还有什么能让你大吃一惊。无论如何，我希望你仍然能接受这个挑战，因为我们还有两个视图需要看一看：`AudioPlayerView`和`SongView`。不过不要失去希望，我们已经度过了最大的挑战，准备好迎接新的挑战。

###### 音频播放器视图

接下来我们要构建我们的`AudioPlayerView`。这个视图需要使用我们之前创建的模板，用曲目编号填充它，并在直接访问 URL 时加载它，例如`/#playlist/2`。我们还需要覆盖扩展的`BaseView`上的一个方法，需要被覆盖的方法是`onDashboardClick`。这是因为它要求我们隐藏播放列表，然后导航到仪表板。所以在最基本的层面上，这个类将如下所示：

```html
(function(window, document, $, Backbone, _){

  var AudioPlayerView = App.BaseView.extend({
    'template': _.template($('#tmpl-audioplayer-view').html()),

    'events': {
      'click a[href="#dashboard"]': 'onDashboardClick'
    },

    'initialize': function(){
      this.render();
    },

    'render': function(file){
      // Put our rendering code here
    },

    'onDashboardClick': function() {
      this.hide();
      Music.playListView.hide();

      User.navigate('/dashboard', { 'trigger': true });
    }
  });

  window.Music.AudioPlayerView = AudioPlayerView;

}(window, document, Zepto, Backbone, _));
```

正如我们所看到的，前面段落中列出的所有要求都已经在`AudioPlayerView`的基类中得到满足。然而，我们需要渲染出这个视图，并用 URL 提供的数据填充它。为了做到这一点，我们需要编写我们的`render`方法如下：

```html
'render': function(file){
  var audioElement;

  if (file) {
    audioElement = this.$el.find('audio')[0];

    // Must be made on the audio element itself
    audioElement.src = '../assets/' + 'sample' + (file || 1) + '.mp3';
    audioElement.load();
    audioElement.play();

    return this;
  }

  this.$template = $(this.template({ 'file': 'sample' + (file || 1) + '.mp3', 'name': this.model.get('name') }));
  this.$template.find('audio')[0].volume = 0.5;

  this.$el.find('header').after(this.$template);

  return this;
},
```

与我们为播放列表视图编写的先前的`render`方法类似，`render`方法检查是否传入了文件或数字。如果有，我们将使用传入的内容填充我们的模板中的音频元素。接下来，我们编译我们的模板，然后将音量设置为`0.5`，并将播放器附加到`PlayListView`的标题后面。如果我们回顾一下我们如何初始化这个类，我们会注意到音频播放器视图委托给了播放列表视图元素（在`PlayListView`内部）：

```html
this.audioPlayerView = new Music.AudioPlayerView({
  'el': this.el.querySelector('.view-playlist'),
  'model': new User.UserModel()
});
```

###### 歌曲视图

我们音乐应用程序的最后一部分是`SongView`。让我们快速回顾一下这个视图的要求并看看它的实现。对于这个视图，我们再次想设置我们的模板。当我们初始化这个视图时，我们希望在传入的模型上附加一个事件处理程序，因此如果模型被更新，视图将自动渲染更新。这个视图的`render`方法应该基本上使用模型的属性编译模板，然后将自己附加到为这个视图设置的元素上。

当我们完成了前面的要求实现后，视图应该看起来有点像这样：

```html
(function(window, document, $, Backbone, _){

  var SongView = App.BaseView.extend({
    'template': _.template($('#tmpl-song-view').html()),

    'initialize': function() {
      // Listen to when a change happens on the model assigned this view
      this.listenTo(this.model, 'change', this.render);

      this.render();
    },

    'render': function() {
      this.$el.append(this.template(this.model.attributes));

      return this;
    }
  });

  // Expose the SongView
  window.Music.SongView = SongView;

}(window, document, Zepto, Backbone, _));
```

正如我们所看到的，我们遵循了先前视图实现中设定的标准。唯一的区别是在模型的更改事件上添加了事件侦听器。让我们回顾一下`PlayListView`中这个视图是如何初始化的：

```html
this.collection.each(function(element, index, list){
  var view  = new Music.SongView({
    'el': that.$template.find('ul'),
    'model': element
  });
});
```

现在我们完全理解了音乐应用程序是如何工作的。在这一点上，我们的页面可以仅通过这种实现来运行；但是，我不建议这样做，因为我们还没有创建用户应用程序，错误将会出现。但是我们现在知道，我们的路由定义了应用程序中的操作，视图是实现模型和集合的表示层。模型是我们应用程序的核心，以可管理的方式包含我们需要的所有数据。最后，集合帮助我们管理模型的更大数据集，因为我们可以将这些传递到视图中，视图本身可以管理这些数据的呈现，这对于大型应用程序来说是理想的。

这个过程的下一步是开发用户应用程序，但希望事情会变得更容易一些。就像我们在上一部分中所做的那样，我们将从路由开始，然后逐步进行到集合、模型和视图。

#### 用户应用程序

用户应用程序将遵循我们创建的音乐应用程序相同的流程。同样，我们将涵盖路由、模型和视图的实现。当我们完成这一部分时，我们将拥有各自独立运行的子应用程序，从而增加了我们单页应用程序的可维护性和效率。

##### 路由

我们的用户应用程序的路由将与音乐应用程序非常相似。我们将定义仪表板和个人资料的路由。我们还将抽出时间创建单页应用程序的主页路由。该路由将包含设置仪表板和个人资料的适当方法。它还将包含主页方法，该方法将调用仪表板路由。在路由的`initialize`方法中，我们将监听这些路由并隐藏其他视图。

```html
(function(window, document, $, Backbone, _){

  var User = Backbone.Router.extend({
    // Application Routes
    'routes': {
      '': 'home',
      'dashboard': 'setupDashboard',
      'profile/:user': 'setupProfile'
    },

    'initialize': function() {

    },

    'home': function() {

    },

    'setupDashboard': function() {

    },

    'setupProfile': function(name) {

    }
  });

  // Expose the User Object
  window.User = new User();

}(window, document, Zepto, Backbone, _));
```

在前面的代码中，我们遵循我们的标准，为用户应用程序创建基本模板。接下来，让我们看看`initialize`方法将包含什么：

```html
'initialize': function() {
  var that = this;

  this.on('route:setupDashboard route:setupProfile', function(){
    if(Music.playListView) {
      Music.playListView.hide();
    }
  });

  this.on('route:setupDashboard', function(){
    if (that.profileView) {
      that.profileView.hide();
    }
  });

  this.on('route:setupProfile', function(){
    if (that.dashboardView) {
      that.dashboardView.hide();
    }
  });
},
```

我们路由的`initialize`方法满足了我们列出的要求，通过为我们创建的路由创建事件侦听器。每个侦听器都隐藏了我们不想看到的部分，但是我们如何看到我们想要的应用程序的实际部分呢？这就是`setup`方法发挥作用的地方。

```html
'setupDashboard': function() {
  if (!this.dashboardView) {
    this.dashboardView = new this.DashboardView({
                'model': this.model = new this.UserModel(),
                'el': document.querySelector('.content')
              });
    this.setupDashboard();
    return;
  }

  this.dashboardView.show();
},
'setupProfile': function(name) {
  if (!this.profileView) {
    this.profileView = new this.ProfileView({
                'model': this.model = new this.UserModel(),
                'el': document.querySelector('.content')
              });
    return;
  }

  this.profileView.show();
}
```

这些方法基本上是相同的。它们检查视图是否已经在路由实例上创建（例如`this.dashboardView`和`this.profileView`），如果已经创建，我们只显示该视图。然而，如果视图尚未创建，我们初始化适当的视图，然后再次调用该`setup`方法（递归），以便我们可以显示它，因为现在视图已经存在。

### 提示

你可能已经注意到，我们正在创建一个新的`UserModel`，并将其传递给我们的许多视图。目前这样做是可以的，因为我们想要测试应用程序的核心部分。但从理论上讲，一个`UserModel`将在整个应用程序中被初始化和维护。完成本章后，你可以尝试解决这个问题！

我们需要做的最后一件事是为我们的应用程序包含主页方法：

```html
'home': function() {
  this.navigate('dashboard', { 'trigger': true });
},
```

当你访问`/singlepage/index.html`时，将调用这个路由。根据`Backbone.js`库的文档，空路由指的是应用程序的主页状态。虽然我们可以将`setupDashboard`方法定义为回调，但这是为了说明我们可以在需要时立即从一个路由转到另一个路由。也许我们可以在这里做一些预处理，甚至创建之前提到的单个`UserModel`？

##### 集合

因为我们在这个应用程序中只处理一个用户，所以不需要创建集合。哦！你以为这会变得更加困难吗？好吧，别抱太大希望；我们仍然需要考虑模型和视图。

##### 模型

与 Backbone 中的任何模型一样，我们只是描述了将在整个应用程序中处理的数据。对于我们的`UserModel`来说也是如此，它将包含实例的默认属性，并在初始化时通过组合`first_name`和`last_name`属性来设置人的姓名。

为了满足这些要求，我们的`UserModel`将被定义如下：

```html
(function(window, document, $, Backbone, _){

  var UserModel = Backbone.Model.extend({
    'defaults': {
      // in seconds
      'first_name': 'John',
      'last_name': 'Doe',
      'bio': 'Sample bio data',
      'age': 26,
      'birthdate': new Date(1987, 0, 2),
      'username': 'doe'
    },

    'initialize': function() {
      this.attributes.name = this.get('first_name') + ' ' + this.get('last_name');
    }
  });

  window.User.UserModel = UserModel;

}(window, document, Zepto, Backbone, _));
```

这就是我们模型的全部内容。我们只是为用户定义了默认值，并在创建实例时设置了名称。现在我们将看一下我们的`DashboardView`和`ProfileView`——这个应用程序的最后两个部分。

##### 视图

用户应用程序将包含两个视图，包括`DashboardView`和`ProfileView`。正如我们已经建立的那样，每个视图都扩展了我们之前创建的`BaseView`。为了适应我们的体验，我们需要做一些改变，但总体上这与我们的音乐应用程序视图的实现非常相似。

###### 仪表板视图

与我们之前定义的视图一样，`DashboardView`将包含用于显示我们仪表板的模板，包含与此视图相关的事件，然后渲染模板。你会注意到这里我们的事件将使用在`BaseView`中定义的事件处理程序，因为`BaseView`的事件处理程序满足了导航到另一个视图的基本要求，而路由监听器处理了隐藏功能。

```html
(function(window, document, $, Backbone, _){

  var DashboardView = App.BaseView.extend({
    'template': _.template($('#tmpl-user-dashboard').html()),

    'events': {
      'click a[href="#profile"]': 'onProfileClick',
      'click a[href="#playlist"]': 'onPlaylistClick'
    },

    'initialize': function() {

      this.render();
    },

    'render': function() {
      if (!this.$template) {
        this.$template = $(this.template(this.model.attributes));

        this.$el.prepend(this.$template);
      }

      return this;
    }
  });

  window.User.DashboardView = DashboardView;

}(window, document, Zepto, Backbone, _));
```

这个视图的代码非常简单；我们以前见过这种模式，现在在这里重复。因为我们在`BaseView`中定义了事件处理程序，所以我们不需要在这里重新定义它们。至于`render`方法，它会检查模板的创建，如果存在，就会用用户的数据填充模板，这些数据是在创建`User.js`中的`DashboardView`实例时传递的。

这就是我们为仪表板视图需要做的全部；就像我承诺的那样，一旦一般设置完成，它就相当容易。接下来让我们来看看我们应用程序的最后一部分：个人资料视图。

###### 个人资料视图

我们的个人资料视图将与仪表板视图完全相同，因为我们有一个模板、一些事件和一个`render`方法。就像以前一样，我们不需要定义事件处理程序，因为`BaseView`在这个过程的开始时已经处理了隐藏视图的基本要求。

```html
(function(window, document, $, Backbone, _){

  var ProfileView = App.BaseView.extend({
    'template': _.template($('#tmpl-user-profile').html()),

    'events': {
      'click a[href="#dashboard"]': 'onDashboardClick',
      'click a[href="#edit"]': 'onEditClick'
    },

    'initialize': function() {

      this.render();
    },

    'render': function() {
      if (!this.$template) {
        this.$template = $(this.template(this.model.attributes));

        this.$el.prepend(this.$template);
      }

      return this;
    } 
  });

  window.User.ProfileView = ProfileView;

}(window, document, Zepto, Backbone, _));
```

这就是全部内容。如果我们现在运行页面，我们将得到一个完全可访问的应用程序，其默认视图为仪表板视图。然后，您可以通过导航到个人资料和播放列表视图与应用程序进行交互。当您这样做时，应用程序会更改 URL 并保留您的活动历史记录，让您可以轻松地前进和后退。相当不错，对吧？以下是一些屏幕截图，展示最终应用程序的外观：

### 提示

您可能想知道这个应用程序的样式。幸运的是，本书的源代码已经为您编写了所有这些内容。我们不会讨论样式，因为它实际上并没有涵盖任何移动特定的内容，而是更多地是对我们在这里构建的应用程序进行视觉增强的展示。

![个人资料视图](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_07_03.jpg)

这个应用程序在 iOS 模拟器中运行的屏幕截图展示了我们编写的应用程序的仪表板视图。在这个视图中，我们看到我们的常规页眉和页脚，包括书名和作为导航的选择控件。在内容区域内，我们看到我们的仪表板模板呈现了约翰·多的仪表板和链接到播放列表、个人资料和返回到仪表板。

![个人资料视图](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_07_04.jpg)

在这里，我们展示了播放列表和歌曲视图，展示了音频控件和在曲目之间切换的能力。我们可以看到模板在模板内的呈现（播放列表内的音轨）。通过这个例子，我们可以看到控件（模型、视图和控制器）的分离如何帮助我们区分逻辑和用户界面。

![个人资料视图](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_07_05.jpg)

在这个屏幕截图中，我们看到在**播放列表**页面下选择并播放的音轨。看起来似乎没有太多事情发生，但在幕后，我们已经创建了一个可重复使用的应用程序，允许用户在不刷新页面的情况下进行交互。

![个人资料视图](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_07_06.jpg)

在这最后一个屏幕截图中，我们看到了个人资料视图，显示了约翰·多的简短传记、年龄和出生日期。在播放列表和个人资料的过渡期间，我们没有看到页面刷新，而是内容更新。分析 URL，我们可以看到历史记录已被保留，因此，允许我们使用原生返回按钮在单页应用程序中进行操作。

# 总结

给自己一个鼓励吧；我们终于到达了本章的结尾！这是一次愉快的旅程，希望不会太糟糕。在这一点上，您现在已经准备好着手开发单页应用程序了。从理解 MVC 设计模式到实施，利用 Backbone 和 Underscore 等库，您现在可以扩展这个基础，开发与 API 相结合并为用户创造动态美妙体验的复杂应用程序。
