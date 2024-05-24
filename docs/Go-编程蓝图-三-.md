# Go 编程蓝图（三）

> 原文：[`zh.annas-archive.org/md5/AC9839247134C458206EE3BE6D404A66`](https://zh.annas-archive.org/md5/AC9839247134C458206EE3BE6D404A66)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：随机推荐网络服务

这个项目的概念是简单的：我们希望用户能够根据我们将通过 API 公开的预定义旅行类型，在特定地理位置生成随机推荐的活动。我们将给我们的项目起名为 Meander。

在现实世界的项目中，你通常需要负责整个技术栈；有人建立网站，另一个人可能编写 iOS 应用，也许外包公司建立桌面版本。在更成功的 API 项目中，你甚至可能不知道你的 API 的消费者是谁，特别是如果它是一个公共 API。

在本章中，我们将通过与虚构合作伙伴事先设计和达成最小 API 设计来模拟这一现实，然后再实施 API。一旦我们完成了项目的一部分，我们将下载由我们的队友构建的用户界面，看看它们如何一起工作，产生最终的应用程序。

在本章中，你将：

+   学会使用简短而简单的敏捷用户故事来表达项目的一般目标

+   发现你可以通过达成 API 设计来约定项目的会议点，这样可以让许多人并行工作。

+   看看早期版本的代码实际上可以在代码中编写数据固定装置并编译到程序中，这样我们可以稍后更改实现而不触及接口

+   学习一种策略，允许结构体（和其他类型）代表它们的公共版本，以便在我们想要隐藏或转换内部表示时使用

+   学会使用嵌入结构体来表示嵌套数据，同时保持我们类型的接口简单

+   学会使用`http.Get`来进行外部 API 请求，特别是 Google Places API，而不会有代码膨胀

+   学会在 Go 中有效地实现枚举器，尽管它们实际上不是一种语言特性

+   体验 TDD 的真实例子

+   看看`math/rand`包如何轻松地从切片中随机选择一个项目

+   学会从`http.Request`类型的 URL 参数中轻松获取数据

# 项目概述

遵循敏捷方法，让我们写两个用户故事来描述我们项目的功能。用户故事不应该是描述应用程序整套功能的全面文档；小卡片不仅适合描述用户试图做什么，还适合描述为什么。此外，我们应该在不试图事先设计整个系统或深入实现细节的情况下完成这一点。

首先，我们需要一个关于看到我们的用户可以选择的不同旅行类型的故事：

| **作为** | 旅行者 |
| --- | --- |
| **我想** | 看到我可以获得推荐的不同旅行类型 |
| **以便** | 我可以决定带我的伴侣去哪种类型的晚上 |

其次，我们需要一个关于为选定的旅行类型提供随机推荐的故事：

| **作为** | 旅行者 |
| --- | --- |
| **我想** | 看到我选择的旅行类型的随机推荐 |
| **以便** | 我知道去哪里，晚上会是什么样子 |

这两个故事代表了我们的 API 需要提供的两个核心功能，并最终代表了两个端点。

为了发现指定位置周围的地方，我们将使用 Google Places API，它允许我们搜索具有给定类型的企业列表，比如`酒吧`，`咖啡馆`或`电影院`。然后我们将使用 Go 的`math/rand`包随机选择这些地方，为我们的用户建立完整的旅程。

### 提示

Google Places API 支持许多业务类型；请参阅[`developers.google.com/places/documentation/supported_types`](https://developers.google.com/places/documentation/supported_types)获取完整列表。

## 项目设计细节

为了将我们的故事转化为一个交互式应用程序，我们将提供两个 JSON 端点；一个用于提供用户可以在应用程序中选择的旅程类型，另一个用于实际生成所选旅程类型的随机推荐。

```go
GET /journeys
```

上述调用应返回以下列表：

```go
[
  {
    name: "Romantic",
    journey: "park|bar|movie_theater|restaurant|florist"
  },
  {
    name: "Shopping",
    journey: "department_store|clothing_store|jewelry_store"
  }
]
```

`name`字段是应用程序生成的推荐类型的可读标签，`journey`字段是支持的旅程类型的管道分隔列表。我们将传递旅程值作为 URL 参数到我们的另一个端点，该端点生成实际的推荐：

```go
GET /recommendations?
     lat=1&lng=2&journey=bar|cafe&radius=10&cost=$...$$$$$
```

这个端点负责查询 Google Places API 并在返回地点对象数组之前生成推荐。我们将使用 URL 中的参数来控制查询的类型，根据 HTTP 规范。`lat`和`lng`参数分别表示纬度和经度，告诉我们的 API 我们想要从世界的哪个地方获得推荐，`radius`参数表示我们感兴趣的点周围的米数距离。`cost`值是表示 API 返回的地点价格范围的一种可读方式。它由两个值组成：用三个点分隔的较低和较高范围。美元符号的数量表示价格水平，`$`是最实惠的，`$$$$$`是最昂贵的。使用这种模式，`$...$$`的值将表示非常低成本的推荐，而`$$$$...$$$$$`将表示相当昂贵的体验。

### 提示

一些程序员可能会坚持用数值表示成本范围，但由于我们的 API 将被人们使用，为什么不让事情变得更有趣呢？

对于这个调用的示例负载可能看起来像这样：

```go
[
  {
    icon: "http://maps.gstatic.com/mapfiles/place_api/icons/cafe-71.png",
    lat: 51.519583, lng: -0.146251,
    vicinity: "63 New Cavendish St, London",
    name: "Asia House",
    photos: [{
      url: "https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference=CnRnAAAAyLRN"
     }]
  }, ...
]
```

返回的数组包含代表旅程中每个段的随机推荐的地点对象，按适当的顺序。上面的示例是伦敦的一家咖啡馆。数据字段相当不言自明；`lat`和`lng`字段表示地点的位置（它们是纬度和经度的缩写），`name`和`vicinity`字段告诉我们业务是什么和在哪里，`photos`数组给出了来自 Google 服务器的相关照片列表。`vicinity`和`icon`字段将帮助我们为用户提供更丰富的体验。

# 在代码中表示数据

我们首先要公开用户可以选择的旅程，因此在`GOPATH`中创建一个名为`meander`的新文件夹，并添加以下`journeys.go`代码：

```go
package meander
type j struct {
  Name       string
  PlaceTypes []string
}
var Journeys = []interface{}{
  &j{Name: "Romantic", PlaceTypes: []string{"park", "bar", "movie_theater", "restaurant", "florist", "taxi_stand"}},
  &j{Name: "Shopping", PlaceTypes: []string{"department_store", "cafe", "clothing_store", "jewelry_store", "shoe_store"}},
  &j{Name: "Night Out", PlaceTypes: []string{"bar", "casino", "food", "bar", "night_club", "bar", "bar", "hospital"}},
  &j{Name: "Culture", PlaceTypes: []string{"museum", "cafe", "cemetery", "library", "art_gallery"}},
  &j{Name: "Pamper", PlaceTypes: []string{"hair_care", "beauty_salon", "cafe", "spa"}},
}
```

在这里，我们在`meander`包内定义了一个名为`j`的内部类型，然后我们使用它来通过在`Journeys`切片内创建它们的实例来描述旅程。这种方法是在代码中以一种超简单的方式表示数据，而不会构建对外部数据存储的依赖。

### 提示

作为额外的任务，为什么不看看您是否可以在整个过程中让`golint`保持愉快？每次添加一些代码时，运行`golint`来检查包并满足任何建议。它非常关心没有文档的导出项，因此以正确格式添加简单注释将使其保持愉快。要了解有关`golint`的更多信息，请参阅[`github.com/golang/lint`](https://github.com/golang/lint)。

当然，这可能会在以后演变成这样，甚至可能让用户创建和分享自己的旅程。由于我们通过 API 公开我们的数据，我们可以自由更改内部实现而不影响接口，因此这种方法非常适合 1.0 版本。

### 提示

我们使用`[]interface{}`类型的切片，因为我们将稍后实现一种通用的方式来公开公共数据，而不考虑实际类型。

一次浪漫的旅程包括首先访问公园，然后是酒吧，电影院，然后是餐厅，然后是花店，最后是乘坐出租车回家；你可以得到一个大致的想法。随意发挥创意，并通过查阅 Google Places API 中支持的类型来添加其他类型。

您可能已经注意到，由于我们将代码包含在名为`meander`（而不是`main`）的包中，我们的代码永远无法像我们迄今为止编写的其他 API 一样作为工具运行。在`meander`内创建一个名为`cmd`的新文件夹；这将容纳通过 HTTP 端点公开`meander`包功能的实际命令行工具。

在`cmd`文件夹中，将以下代码添加到`main.go`文件中：

```go
package main
func main() {
  runtime.GOMAXPROCS(runtime.NumCPU())
  //meander.APIKey = "TODO"
  http.HandleFunc("/journeys", func(w http.ResponseWriter, r *http.Request) {
    respond(w, r, meander.Journeys)
  })
  http.ListenAndServe(":8080", http.DefaultServeMux)
}
func respond(w http.ResponseWriter, r *http.Request, data []interface{}) error {
  return json.NewEncoder(w).Encode(data)
}
```

您会认出这是一个简单的 API 端点程序，映射到`/journeys`端点。

### 提示

您将不得不导入`encoding/json`，`net/http`和`runtime`包，以及您之前创建的`meander`包。

`runtime.GOMAXPROCS`调用设置了我们的程序可以使用的 CPU 的最大数量，并告诉它使用所有 CPU。然后我们在`meander`包中设置了`APIKey`的值（目前已注释掉，因为我们还没有实现它），然后在`net/http`包上调用熟悉的`HandleFunc`函数来绑定我们的端点，然后只是响应`meander.Journeys`变量。我们从上一章借用了抽象响应的概念，提供了一个`respond`函数，将指定的数据编码到`http.ResponseWriter`类型中。

让我们通过在终端中导航到`cmd`文件夹并使用`go run`来运行我们的 API 程序。在这个阶段，我们不需要将其构建成可执行文件，因为它只是一个单独的文件：

```go

go run main.go 

```

访问`http://localhost:8080/journeys`端点，注意我们提供的`Journeys`数据负载，它看起来像这样：

```go
[{
  Name: "Romantic",
  PlaceTypes: [
    "park",
    "bar",
    "movie_theater",
    "restaurant",
    "florist",
    "taxi_stand"
  ]
}]
```

这是完全可以接受的，但有一个主要缺陷：它暴露了我们实现的内部信息。如果我们将`PlaceTypes`字段名称更改为`Types`，我们的 API 将发生变化，我们应该避免这种情况。

项目随着时间的推移会不断发展和变化，尤其是成功的项目，作为开发人员，我们应该尽力保护我们的客户免受演变的影响。抽象接口是实现这一点的好方法，以及拥有数据对象的公共视图的所有权。

## Go 结构体的公共视图

为了控制 Go 中结构体的公共视图，我们需要发明一种方法，允许单独的`journey`类型告诉我们它们希望如何暴露。在`meander`文件夹中，创建一个名为`public.go`的新文件，并添加以下代码：

```go
package meander
type Facade interface {
  Public() interface{}
}
func Public(o interface{}) interface{} {
  if p, ok := o.(Facade); ok {
    return p.Public()
  }
  return o
}
```

`Facade`接口公开了一个`Public`方法，该方法将返回结构体的公共视图。`Public`函数接受任何对象并检查它是否实现了`Facade`接口（它是否有一个`Public() interface{}`方法？）；如果实现了，就调用该方法并返回结果，否则就原样返回对象。这允许我们在将结果写入`ResponseWriter`对象之前通过`Public`函数传递任何内容，从而允许单独的结构体控制它们的公共外观。

让我们通过在`journeys.go`中添加以下代码来为我们的`j`类型实现一个`Public`方法：

```go
func (j *j) Public() interface{} {
  return map[string]interface{}{
    "name":    j.Name,
    "journey": strings.Join(j.PlaceTypes, "|"),
  }
}
```

我们的`j`类型的公共视图将`PlaceTypes`字段连接成一个由管道字符分隔的字符串，按照我们的 API 设计。

回到`cmd/main.go`，用使用我们的新`Public`函数替换`respond`方法：

```go
func respond(w http.ResponseWriter, r *http.Request, data []interface{}) error {
  publicData := make([]interface{}, len(data))
  for i, d := range data {
    publicData[i] = meander.Public(d)
  }
  return json.NewEncoder(w).Encode(publicData)
}
```

在这里，我们遍历数据切片，为每个项目调用`meander.Public`函数，将结果构建到一个相同大小的新切片中。对于我们的`j`类型，它的`Public`方法将被调用以提供数据的公共视图，而不是默认视图。在终端中，再次导航到`cmd`文件夹，并在运行`http://localhost:8080/journeys`之前再次运行`go run main.go`。注意，相同的数据现在已更改为新结构：

```go
[{
  journey: "park|bar|movie_theater|restaurant|florist|taxi_stand",
  name: "Romantic"
}, ...]
```

# 生成随机推荐

为了获取我们的代码将随机构建推荐的地点，我们需要查询 Google Places API。在`meander`文件夹中，添加以下`query.go`文件：

```go
package meander
type Place struct {
  *googleGeometry `json:"geometry"`
  Name            string         `json:"name"`
  Icon            string         `json:"icon"`
  Photos          []*googlePhoto `json:"photos"`
  Vicinity        string         `json:"vicinity"`
}
type googleResponse struct {
  Results []*Place `json:"results"`
}
type googleGeometry struct {
  *googleLocation `json:"location"`
}
type googleLocation struct {
  Lat float64 `json:"lat"`
  Lng float64 `json:"lng"`
}
type googlePhoto struct {
  PhotoRef string `json:"photo_reference"`
  URL      string `json:"url"`
}
```

这段代码定义了我们需要解析来自 Google Places API 的 JSON 响应的结构，以便将其转换为可用的对象。

### 提示

转到 Google Places API 文档，查看我们期望的响应示例。请参阅[`developers.google.com/places/documentation/search`](http://developers.google.com/places/documentation/search)。

大部分前面的代码都是显而易见的，但值得注意的是`Place`类型嵌入了`googleGeometry`类型，这允许我们根据 API 表示嵌套数据，同时在我们的代码中实质上将其展平。我们在`googleGeometry`内部也是这样做的，这意味着我们将能够直接在`Place`对象上访问`Lat`和`Lng`值，即使它们在技术上是嵌套在其他结构中的。

因为我们想要控制`Place`对象如何公开显示，让我们给这个类型添加以下`Public`方法：

```go
func (p *Place) Public() interface{} {
  return map[string]interface{}{
    "name":     p.Name,
    "icon":     p.Icon,
    "photos":   p.Photos,
    "vicinity": p.Vicinity,
    "lat":      p.Lat,
    "lng":      p.Lng,
  }
}
```

### 提示

记得在这段代码上运行`golint`，看看哪些注释需要添加到导出的项目中。

## Google Places API 密钥

与大多数 API 一样，我们需要一个 API 密钥才能访问远程服务。转到 Google API 控制台，使用 Google 账户登录，并为 Google Places API 创建一个密钥。有关更详细的说明，请参阅 Google 开发者网站上的文档。

一旦您获得了密钥，让我们在`meander`包中创建一个可以保存它的变量。在`query.go`的顶部，添加以下定义：

```go
var APIKey string
```

现在返回到`main.go`，从`APIKey`行中删除双斜杠`//`，并用 Google API 控制台提供的实际密钥替换`TODO`值。

## Go 中的枚举器

为了处理我们 API 的各种成本范围，使用枚举器（或**enum**）来表示各种值并处理到和从字符串表示的转换是有意义的。Go 并没有明确提供枚举器，但有一种巧妙的实现方法，我们将在本节中探讨。

Go 中编写枚举器的一个简单灵活的检查表是：

+   定义一个基于原始整数类型的新类型

+   在需要用户指定适当值之一时使用该类型

+   使用`iota`关键字在`const`块中设置值，忽略第一个零值

+   实现一个合理的字符串表示到枚举器值的映射

+   在类型上实现一个`String`方法，从映射中返回适当的字符串表示

+   实现一个`ParseType`函数，使用映射从字符串转换为您的类型

现在我们将编写一个枚举器来表示我们 API 中的成本级别。在`meander`文件夹中创建一个名为`cost_level.go`的新文件，并添加以下代码：

```go
package meander
type Cost int8
const (
  _ Cost = iota
  Cost1
  Cost2
  Cost3
  Cost4
  Cost5
)
```

在这里，我们定义了我们的枚举器的类型，我们称之为`Cost`，由于我们只需要表示一些值，所以我们基于`int8`范围进行了定义。对于我们需要更大值的枚举器，您可以自由地使用任何与`iota`一起使用的整数类型。`Cost`类型现在是一个真正的类型，我们可以在需要表示支持的值之一的地方使用它，例如，我们可以在函数的参数中指定`Cost`类型，或者将其用作结构中字段的类型。

然后，我们定义了该类型的常量列表，并使用`iota`关键字指示我们希望为常量获得递增的值。通过忽略第一个`iota`值（始终为零），我们指示必须显式使用指定的常量之一，而不是零值。

为了提供我们的枚举器的字符串表示，我们只需要为`Cost`类型添加一个`String`方法。即使您不需要在代码中使用字符串，这也是一个有用的练习，因为每当您使用 Go 标准库的打印调用（如`fmt.Println`）时，默认情况下将使用数字值。这些值通常是没有意义的，并且需要您查找它们，甚至计算每个项目的数值。

### 注意

有关 Go 中`String()`方法的更多信息，请参阅`fmt`包中的`Stringer`和`GoStringer`接口，网址为[`golang.org/pkg/fmt/#Stringer`](http://golang.org/pkg/fmt/#Stringer)。

### 测试驱动的枚举器

为了确保我们的枚举器代码正常工作，我们将编写单元测试，对预期行为进行一些断言。

在`cost_level.go`旁边，添加一个名为`cost_level_test.go`的新文件，并添加以下单元测试：

```go
package meander_test
import (
  "testing"
  "github.com/cheekybits/is"
  "path/to/meander"
)
func TestCostValues(t *testing.T) {
  is := is.New(t)
  is.Equal(int(meander.Cost1), 1)
  is.Equal(int(meander.Cost2), 2)
  is.Equal(int(meander.Cost3), 3)
  is.Equal(int(meander.Cost4), 4)
  is.Equal(int(meander.Cost5), 5)
}
```

您需要运行`go get`来获取 CheekyBits 的`is`包（从[github.com/cheekybits/is](http://github.com/cheekybits/is)）。

### 提示

`is`包是一个替代测试助手包，但这个包非常简单，故意是最基本的。在编写自己的项目时，您可以选择自己喜欢的包。

通常，我们不会担心枚举中常量的实际整数值，但由于 Google Places API 使用数字值来表示相同的事物，我们需要关心这些值。

### 注意

您可能已经注意到这个测试文件与传统不同之处。虽然它在`meander`文件夹中，但它不是`meander`包的一部分；而是在`meander_test`中。

在 Go 中，这在除了测试之外的每种情况下都是错误的。因为我们将测试代码放入自己的包中，这意味着我们不再可以访问`meander`包的内部-请注意我们必须使用包前缀。这可能看起来像一个缺点，但实际上它允许我们确保我们测试包时就像我们是真正的用户一样。我们只能调用导出的方法，并且只能看到导出的类型；就像我们的用户一样。

通过在终端中运行`go test`来运行测试，并注意它是否通过。

让我们添加另一个测试，对每个`Cost`常量的字符串表示进行断言。在`cost_level_test.go`中，添加以下单元测试：

```go
func TestCostString(t *testing.T) {
  is := is.New(t)
  is.Equal(meander.Cost1.String(), "$")
  is.Equal(meander.Cost2.String(), "$$")
  is.Equal(meander.Cost3.String(), "$$$")
  is.Equal(meander.Cost4.String(), "$$$$")
  is.Equal(meander.Cost5.String(), "$$$$$")
}
```

这个测试断言调用每个常量的`String`方法会产生预期的值。当然，运行这些测试会失败，因为我们还没有实现`String`方法。

在`Cost`常量下面，添加以下映射和`String`方法：

```go
var costStrings = map[string]Cost{
  "$":     Cost1,
  "$$":    Cost2,
  "$$$":   Cost3,
  "$$$$":  Cost4,
  "$$$$$": Cost5,
}
func (l Cost) String() string {
  for s, v := range costStrings {
    if l == v {
      return s
    }
  }
  return "invalid"
}
```

`map[string]Cost`变量将成本值映射到字符串表示形式，`String`方法遍历映射以返回适当的值。

### 提示

在我们的情况下，一个简单的返回`strings.Repeat("$", int(l))`也可以很好地工作（并且因为它是更简单的代码而胜出），但通常不会，因此本节探讨了一般方法。

现在，如果我们要打印`Cost3`的值，我们实际上会看到`$$$`，这比数字值更有用。然而，由于我们确实想在 API 中使用这些字符串，我们还将添加一个`ParseCost`方法。

在`cost_value_test.go`中，添加以下单元测试：

```go
func TestParseCost(t *testing.T) {
  is := is.New(t)
  is.Equal(meander.Cost1, meander.ParseCost("$"))
  is.Equal(meander.Cost2, meander.ParseCost("$$"))
  is.Equal(meander.Cost3, meander.ParseCost("$$$"))
  is.Equal(meander.Cost4, meander.ParseCost("$$$$"))
  is.Equal(meander.Cost5, meander.ParseCost("$$$$$"))
}
```

在这里，我们断言调用`ParseCost`实际上会根据输入字符串产生适当的值。

在`cost_value.go`中，添加以下实现代码：

```go
func ParseCost(s string) Cost {
  return costStrings[s]
}
```

解析`Cost`字符串非常简单，因为这就是我们的映射布局。

由于我们需要表示一系列成本值，让我们想象一个`CostRange`类型，并为我们打算如何使用它编写测试。将以下测试添加到`cost_value_test.go`中：

```go
func TestParseCostRange(t *testing.T) {
  is := is.New(t)
  var l *meander.CostRange
  l = meander.ParseCostRange("$$...$$$")
  is.Equal(l.From, meander.Cost2)
  is.Equal(l.To, meander.Cost3)
  l = meander.ParseCostRange("$...$$$$$")
  is.Equal(l.From, meander.Cost1)
  is.Equal(l.To, meander.Cost5)
}
func TestCostRangeString(t *testing.T) {
  is := is.New(t)
  is.Equal("$$...$$$$", (&meander.CostRange{
    From: meander.Cost2,
    To:   meander.Cost4,
  }).String())
}
```

我们指定传入一个以两个美元符号开头的字符串，然后是三个点，然后是三个美元符号，应该创建一个新的`meander.CostRange`类型，其中`From`设置为`meander.Cost2`，`To`设置为`meander.Cost3`。第二个测试通过测试`CostRange.String`方法返回适当的值来执行相反的操作。

为了使我们的测试通过，添加以下`CostRange`类型和相关的`String`和`ParseString`函数：

```go
type CostRange struct {
  From Cost
  To   Cost
}
func (r CostRange) String() string {
  return r.From.String() + "..." + r.To.String()
}
func ParseCostRange(s string) *CostRange {
  segs := strings.Split(s, "...")
  return &CostRange{
    From: ParseCost(segs[0]),
    To:   ParseCost(segs[1]),
  }
}
```

这使我们能够将诸如`$...$$$$$`之类的字符串转换为包含两个`Cost`值的结构；`From`和`To`设置，反之亦然。

## 查询 Google Places API

现在我们能够表示 API 的结果，我们需要一种方法来表示和初始化实际查询。将以下结构添加到`query.go`中：

```go
type Query struct {
  Lat          float64
  Lng          float64
  Journey      []string
  Radius       int
  CostRangeStr string
}
```

这个结构包含了我们构建查询所需的所有信息，所有这些信息实际上都来自客户端请求的 URL 参数。接下来，添加以下`find`方法，它将负责向 Google 的服务器发出实际请求：

```go
func (q *Query) find(types string) (*googleResponse, error) {
  u := "https://maps.googleapis.com/maps/api/place/nearbysearch/json"
  vals := make(url.Values)
  vals.Set("location", fmt.Sprintf("%g,%g", q.Lat, q.Lng))
  vals.Set("radius", fmt.Sprintf("%d", q.Radius))
  vals.Set("types", types)
  vals.Set("key", APIKey)
  if len(q.CostRangeStr) > 0 {
    r := ParseCostRange(q.CostRangeStr)
    vals.Set("minprice", fmt.Sprintf("%d", int(r.From)-1))
    vals.Set("maxprice", fmt.Sprintf("%d", int(r.To)-1))
  }
  res, err := http.Get(u + "?" + vals.Encode())
  if err != nil {
    return nil, err
  }
  defer res.Body.Close()
  var response googleResponse
  if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
    return nil, err
  }
  return &response, nil
}
```

首先，我们按照 Google Places API 规范构建请求 URL，通过附加`url.Values`编码的`lat`、`lng`、`radius`和`APIKey`值的数据字符串。

### 注意

`url.Values`类型实际上是`map[string][]string`类型，这就是为什么我们使用`make`而不是`new`。

我们指定的`types`值作为参数表示要查找的业务类型。如果有`CostRangeStr`，我们解析它并设置`minprice`和`maxprice`值，最后调用`http.Get`来实际发出请求。如果请求成功，我们推迟关闭响应主体，并使用`json.Decoder`方法将从 API 返回的 JSON 解码为我们的`googleResponse`类型。

## 建立推荐

接下来，我们需要编写一个方法，允许我们对不同旅程步骤进行多次调用。在`find`方法下面，添加以下`Run`方法到`Query`结构：

```go
// Run runs the query concurrently, and returns the results.
func (q *Query) Run() []interface{} {
  rand.Seed(time.Now().UnixNano())
  var w sync.WaitGroup
  var l sync.Mutex
  places := make([]interface{}, len(q.Journey))
  for i, r := range q.Journey {
    w.Add(1)
    go func(types string, i int) {
      defer w.Done()
      response, err := q.find(types)
      if err != nil {
        log.Println("Failed to find places:", err)
        return
      }
      if len(response.Results) == 0 {
        log.Println("No places found for", types)
        return
      }
      for _, result := range response.Results {
        for _, photo := range result.Photos {
          photo.URL = "https://maps.googleapis.com/maps/api/place/photo?" +
            "maxwidth=1000&photoreference=" + photo.PhotoRef + "&key=" + APIKey
        }
      }
      randI := rand.Intn(len(response.Results))
      l.Lock()
      places[i] = response.Results[randI]
      l.Unlock()
    }(r, i)
  }
  w.Wait() // wait for everything to finish
  return places
}
```

我们首先将随机种子设置为自 1970 年 1 月 1 日 UTC 以来的纳秒时间。这确保每次我们调用`Run`方法并使用`rand`包时，结果都会不同。如果我们不这样做，我们的代码将每次都建议相同的推荐，这就失去了意义。

由于我们需要向 Google 发出许多请求，并且希望尽快完成，我们将通过并发调用我们的`Query.find`方法同时运行所有查询。因此，我们接下来创建一个`sync.WaitGroup`方法，并创建一个地图来保存选定的地点以及一个`sync.Mutex`方法，以允许许多 go 例程同时访问地图。

然后，我们迭代`Journey`切片中的每个项目，可能是`bar`、`cafe`、`movie_theater`。对于每个项目，我们向`WaitGroup`对象添加`1`，并调用一个 goroutine。在例程内部，我们首先推迟`w.Done`调用，通知`WaitGroup`对象该请求已完成，然后调用我们的`find`方法进行实际请求。假设没有发生错误，并且确实能够找到一些地方，我们会遍历结果并构建出可用于任何可能存在的照片的 URL。根据 Google Places API，我们会得到一个`photoreference`键，我们可以在另一个 API 调用中使用它来获取实际的图像。为了使我们的客户不必完全了解 Google Places API，我们为他们构建完整的 URL。

然后我们锁定地图锁，并通过调用`rand.Intn`随机选择其中一个选项，并将其插入到`places`切片的正确位置，然后解锁`sync.Mutex`方法。

最后，我们等待所有 goroutine 完成，通过调用`w.Wait`，然后返回地点。

## 使用查询参数的处理程序

现在我们需要连接我们的`/recommendations`调用，因此返回`cmd`文件夹中的`main.go`，并在`main`函数内添加以下代码：

```go
http.HandleFunc("/recommendations", func(w http.ResponseWriter, r *http.Request) {
  q := &meander.Query{
    Journey: strings.Split(r.URL.Query().Get("journey"), "|"),
  }
  q.Lat, _ = strconv.ParseFloat(r.URL.Query().Get("lat"), 64)
  q.Lng, _ = strconv.ParseFloat(r.URL.Query().Get("lng"), 64)
  q.Radius, _ = strconv.Atoi(r.URL.Query().Get("radius"))
  q.CostRangeStr = r.URL.Query().Get("cost")
  places := q.Run()
  respond(w, r, places)
})
```

这个处理程序负责准备`meander.Query`对象并调用其`Run`方法，然后用结果进行响应。`http.Request`类型的 URL 值公开了提供`Get`方法的`Query`数据，该方法反过来查找给定键的值。

旅程字符串是从`bar|cafe|movie_theater`格式转换为字符串切片，通过在管道字符上进行分割。然后，对`strconv`包中的函数进行几次调用，将字符串纬度、经度和半径值转换为数值类型。

## CORS

我们的 API 第一个版本的最后一部分将是实现 CORS，就像我们在上一章中所做的那样。在阅读下一节中的解决方案之前，看看你能否自己解决这个问题。

### 提示

如果您要自己解决这个问题，请记住，您的目标是将`Access-Control-Allow-Origin`响应标头设置为`*`。还考虑我们在上一章中所做的`http.HandlerFunc`包装。这段代码的最佳位置可能是在`cmd`程序中，因为它通过 HTTP 端点公开了功能。

在`main.go`中，添加以下`cors`函数：

```go
func cors(f http.HandlerFunc) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    f(w, r)
  }
}
```

这种熟悉的模式接受一个`http.HandlerFunc`类型，并返回一个在调用传入的函数之前设置适当标头的新函数。现在我们可以修改我们的代码，以确保`cors`函数被调用我们的两个端点。更新`main`函数中的适当行：

```go
func main() {
  runtime.GOMAXPROCS(runtime.NumCPU())
  meander.APIKey = "YOUR_API_KEY"
  http.HandleFunc("/journeys", cors(func(w http.ResponseWriter, r *http.Request) {
    respond(w, r, meander.Journeys)
  }))
  http.HandleFunc("/recommendations", cors(func(w http.ResponseWriter, r *http.Request) {
    q := &meander.Query{
      Journey: strings.Split(r.URL.Query().Get("journey"), "|"),
    }
    q.Lat, _ = strconv.ParseFloat(r.URL.Query().Get("lat"), 64)
    q.Lng, _ = strconv.ParseFloat(r.URL.Query().Get("lng"), 64)
    q.Radius, _ = strconv.Atoi(r.URL.Query().Get("radius"))
    q.CostRangeStr = r.URL.Query().Get("cost")
    places := q.Run()
    respond(w, r, places)
  }))
  http.ListenAndServe(":8080", http.DefaultServeMux)
}
```

现在对我们的 API 的调用将允许来自任何域的调用，而不会发生跨域错误。

## 测试我们的 API

现在我们准备测试我们的 API，前往控制台并导航到`cmd`文件夹。因为我们的程序导入了`meander`包，构建程序将自动构建我们的`meander`包。

构建并运行程序：

```go

go build –o meanderapi

./meanderapi

```

为了从我们的 API 中看到有意义的结果，让我们花一分钟找到您实际的纬度和经度。转到[`mygeoposition.com/`](http://mygeoposition.com/)并使用 Web 工具获取您熟悉的位置的`x,y`值。

或者从这些热门城市中选择：

+   英格兰伦敦：`51.520707 x 0.153809`

+   美国纽约：`40.7127840 x -74.0059410`

+   日本东京：`35.6894870 x 139.6917060`

+   美国旧金山：`37.7749290 x -122.4194160`

现在打开一个 Web 浏览器，并使用一些适当的值访问`/recommendations`端点：

```go
http://localhost:8080/recommendations?
  lat=51.520707&lng=-0.153809&radius=5000&
  journey=cafe|bar|casino|restaurant&
  cost=$...$$$
```

以下屏幕截图显示了伦敦周围的一个示例推荐的样子：

![测试我们的 API](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-prog-bp/img/Image00013.jpg)

随意在 URL 中玩弄值，尝试不同的旅程字符串，调整位置，并尝试不同的成本范围值字符串，以查看简单 API 的强大之处。

### Web 应用程序

我们将下载一个完整的 Web 应用程序，该应用程序构建到相同的 API 规范，并将其指向我们的实现，以便在我们眼前看到它变得生动。转到[`github.com/matryer/goblueprints/tree/master/chapter7/meanderweb`](https://github.com/matryer/goblueprints/tree/master/chapter7/meanderweb)并将`meanderweb`项目下载到您的`GOPATH`中。

在终端中，导航到`meanderweb`文件夹，并构建和运行它：

```go

go build –o meanderweb

./meanderweb

```

这将启动一个在`localhost:8081`上运行的网站，它被硬编码为查找在`localhost:8080`上运行的 API。因为我们添加了 CORS 支持，尽管它们在不同的域上运行，这不会成为问题。

打开浏览器，访问`http://localhost:8081/`并与应用程序交互，虽然其他人构建了 UI，但没有我们构建的 API 支持它将会非常无用。

# 摘要

在本章中，我们构建了一个 API，它消耗和抽象了 Google Places API，以提供一个有趣而有趣的方式让用户规划他们的白天和夜晚。

我们开始写一些简单而简短的用户故事，以高层次描述我们想要实现的目标，而不是试图提前设计实现。为了并行化项目，我们同意将项目的会议点作为 API 设计，并朝着这个目标构建（就像我们的合作伙伴一样）。

我们直接在代码中嵌入数据，避免在项目的早期阶段进行数据存储的调查、设计和实施。我们关心的是数据如何被访问（通过 API 端点），这样我们就可以完全改变数据存储的方式和位置，而不会影响到已经编写为我们的 API 的应用程序。

我们实现了`Facade`接口，允许我们的结构体和其他类型提供它们的公共表示，而不会透露关于我们实现的混乱或敏感细节。

我们对枚举器的探索为我们提供了一个有用的起点，用于构建枚举类型，尽管语言中没有官方支持。我们使用的`iota`关键字让我们能够指定我们自己的数值类型的常量，并递增值。我们实现的常见`String`方法向我们展示了如何确保我们的枚举类型不会成为日志中的晦涩数字。与此同时，我们还看到了 TDD 的一个现实例子，以及红/绿编程，我们首先编写会失败的单元测试，然后通过编写实现代码使其通过。

# 读累了记得休息一会哦~

**公众号：古德猫宁李**

+   电子书搜索下载

+   书单分享

+   书友学习交流

**网站：**[沉金书屋 https://www.chenjin5.com](https://www.chenjin5.com)

+   电子书搜索下载

+   电子书打包资源分享

+   学习资源分享


# 第八章：文件系统备份

有许多解决方案提供文件系统备份功能。这些包括从应用程序（如 Dropbox、Box、Carbonite）到硬件解决方案（如苹果的 Time Machine、希捷或网络附加存储产品）等各种解决方案。大多数消费者工具提供一些关键的自动功能，以及一个应用程序或网站供您管理您的策略和内容。通常，特别是对于开发人员来说，这些工具并不能完全满足我们的需求。然而，由于 Go 的标准库（其中包括`ioutil`和`os`等包），我们有了构建备份解决方案所需的一切。

对于我们的最终项目，我们将为我们的源代码项目构建一个简单的文件系统备份，该备份将存档指定的文件夹并在每次更改时保存它们的快照。更改可能是当我们调整文件并保存它时，或者如果我们添加新文件和文件夹，甚至如果我们删除文件。我们希望能够回到任何时间点以检索旧文件。

具体来说，在本章中，您将学到：

+   如何构建由包和命令行工具组成的项目

+   在工具执行之间持久化简单数据的务实方法

+   `os`包如何允许您与文件系统交互

+   如何在无限定时循环中运行代码，同时尊重*Ctrl* + *C*

+   如何使用`filepath.Walk`来迭代文件和文件夹

+   如何快速确定目录的内容是否已更改

+   如何使用`archive/zip`包来压缩文件

+   如何构建关心命令行标志和普通参数组合的工具

# 解决方案设计

我们将首先列出一些高层次的解决方案验收标准以及我们想要采取的方法：

+   解决方案应该在我们对源代码项目进行更改时定期创建我们文件的快照

+   我们希望控制检查目录更改的间隔

+   代码项目主要是基于文本的，因此将目录压缩以生成存档将节省大量空间

+   我们将快速构建这个项目，同时密切关注我们可能希望以后进行改进的地方

+   如果我们决定将来更改我们的实现，我们所做的任何实现决策都应该很容易修改

+   我们将构建两个命令行工具，后台守护进程执行工作，用户交互工具让我们列出、添加和删除备份服务中的路径

## 项目结构

在 Go 解决方案中，通常在单个项目中，既有一个允许其他 Go 程序员使用您的功能的包，也有一个允许最终用户使用您的代码的命令行工具。

一种约定正在兴起，即通过在主项目文件夹中放置包，并在名为`cmd`或`cmds`的子文件夹中放置命令行工具。由于在 Go 中所有包（无论目录树如何）都是平等的，您可以从子包中导入主包，知道您永远不需要从主包中导入命令。这可能看起来像是一个不必要的抽象，但实际上是一个非常常见的模式，并且可以在标准的 Go 工具链中看到，例如`gofmt`和`goimports`。

例如，对于我们的项目，我们将编写一个名为`backup`的包，以及两个命令行工具：守护进程和用户交互工具。我们将按以下方式构建我们的项目：

```go
/backup - package
/backup/cmds/backup – user interaction tool
/backup/cmds/backupd – worker daemon
```

# 备份包

我们首先将编写`backup`包，我们将成为编写相关工具时的第一个客户。该包将负责决定目录是否已更改并需要备份，以及实际执行备份过程。

## 明显的接口？

在着手编写新的 Go 程序时，首先要考虑的是是否有任何接口吸引了你的注意。我们不希望在一开始就过度抽象或浪费太多时间设计我们知道在编码开始时会发生变化的东西，但这并不意味着我们不应该寻找值得提取的明显概念。由于我们的代码将对文件进行归档，`Archiver`接口显然是一个候选者。

在`GOPATH`中创建一个名为`backup`的新文件夹，并添加以下`archiver.go`代码：

```go
package backup

type Archiver interface {
  Archive(src, dest string) error
}
```

`Archiver`接口将指定一个名为`Archive`的方法，该方法接受源和目标路径，并返回一个错误。该接口的实现将负责对源文件夹进行归档，并将其存储在目标路径中。

### 注意

提前定义一个接口是将一些概念从我们的头脑中转移到代码中的好方法；这并不意味着随着我们解决方案的演变，这个接口就不能改变，只要我们记住简单接口的力量。还要记住，`io`包中的大多数 I/O 接口只公开一个方法。

从一开始，我们就已经说明了，虽然我们将实现 ZIP 文件作为我们的存档格式，但以后我们可以很容易地用其他类型的`Archiver`格式来替换它。

## 实现 ZIP

现在我们有了`Archiver`类型的接口，我们将实现一个使用 ZIP 文件格式的接口。

将以下`struct`定义添加到`archiver.go`：

```go
type zipper struct{}
```

我们不打算导出这种类型，这可能会让你得出结论，包外的用户将无法使用它。实际上，我们将为他们提供该类型的一个实例供他们使用，以免他们担心创建和管理自己的类型。

添加以下导出的实现：

```go
// Zip is an Archiver that zips and unzips files.
var ZIP Archiver = (*zipper)(nil)
```

这段有趣的 Go 代码实际上是一种非常有趣的方式，可以向编译器暴露意图，而不使用任何内存（确切地说是 0 字节）。我们定义了一个名为`ZIP`的变量，类型为`Archiver`，因此从包外部很清楚，我们可以在需要`Archiver`的任何地方使用该变量——如果你想要压缩文件。然后我们将其赋值为`nil`，转换为`*zipper`类型。我们知道`nil`不占用内存，但由于它被转换为`zipper`指针，并且考虑到我们的`zipper`结构没有字段，这是解决问题的一种合适方式，它隐藏了代码的复杂性（实际实现）对外部用户。包外部没有任何理由需要知道我们的`zipper`类型，这使我们可以随时更改内部而不触及外部；这就是接口的真正力量。

这个技巧的另一个方便之处是，编译器现在将检查我们的`zipper`类型是否正确实现了`Archiver`接口，如果你尝试构建这段代码，你将会得到一个编译器错误：

```go

./archiver.go:10: cannot use (*zipper)(nil) (type *zipper) as type Archiver in assignment:

 *zipper does not implement Archiver (missing Archive method)

```

我们看到我们的`zipper`类型没有实现接口中规定的`Archive`方法。

### 注意

你也可以在测试代码中使用`Archive`方法来确保你的类型实现了它们应该实现的接口。如果你不需要使用这个变量，你可以使用下划线将其丢弃，你仍然会得到编译器的帮助：

```go
var _ Interface = (*Implementation)(nil)
```

为了让编译器满意，我们将为我们的`zipper`类型添加`Archive`方法的实现。

将以下代码添加到`archiver.go`：

```go
func (z *zipper) Archive(src, dest string) error {
  if err := os.MkdirAll(filepath.Dir(dest), 0777); err != nil {
    return err
  }
  out, err := os.Create(dest)
  if err != nil {
    return err
  }
  defer out.Close()
  w := zip.NewWriter(out)
  defer w.Close()
  return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
    if info.IsDir() {
      return nil // skip
    }
    if err != nil {
      return err
    }
    in, err := os.Open(path)
    if err != nil {
      return err
    }
    defer in.Close()
    f, err := w.Create(path)
    if err != nil {
      return err
    }
    io.Copy(f, in)
    return nil
  })
}
```

你还需要从 Go 标准库中导入`archive/zip`包。在我们的`Archive`方法中，我们采取以下步骤来准备写入 ZIP 文件：

+   使用`os.MkdirAll`确保目标目录存在。`0777`代码表示用于创建任何缺失目录的文件权限。

+   使用`os.Create`根据`dest`路径创建一个新文件。

+   如果文件创建没有错误，使用`defer out.Close()`延迟关闭文件。

+   使用`zip.NewWriter`创建一个新的`zip.Writer`类型，它将写入我们刚刚创建的文件，并延迟关闭写入器。

一旦我们准备好一个`zip.Writer`类型，我们使用`filepath.Walk`函数来迭代源目录`src`。

`filepath.Walk`函数接受两个参数：根路径和回调函数`func`，用于在遍历文件系统时遇到的每个项目（文件和文件夹）进行调用。`filepath.Walk`函数是递归的，因此它也会深入到子文件夹中。回调函数本身接受三个参数：文件的完整路径，描述文件或文件夹本身的`os.FileInfo`对象，以及错误（如果发生错误，它也会返回错误）。如果对回调函数的任何调用导致返回错误，则操作将被中止，并且`filepath.Walk`将返回该错误。我们只需将其传递给`Archive`的调用者，并让他们担心，因为我们无法做更多事情。

对于树中的每个项目，我们的代码采取以下步骤：

+   如果`info.IsDir`方法告诉我们该项目是一个文件夹，我们只需返回`nil`，有效地跳过它。没有理由将文件夹添加到 ZIP 存档中，因为文件的路径将为我们编码该信息。

+   如果传入错误（通过第三个参数），这意味着在尝试访问有关文件的信息时出现了问题。这是不常见的，所以我们只需返回错误，最终将其传递给`Archive`的调用者。

+   使用`os.Open`打开源文件进行读取，如果成功则延迟关闭。

+   在`ZipWriter`对象上调用`Create`，表示我们要创建一个新的压缩文件，并给出文件的完整路径，其中包括它所嵌套的目录。

+   使用`io.Copy`从源文件读取所有字节，并通过`ZipWriter`对象将它们写入我们之前打开的 ZIP 文件。

+   返回`nil`表示没有错误。

本章不涉及单元测试或**测试驱动开发**（**TDD**）实践，但请随意编写一个测试来确保我们的实现达到预期的效果。

### 提示

由于我们正在编写一个包，花一些时间注释到目前为止导出的部分。您可以使用`golint`来帮助您找到可能遗漏的任何导出部分。

## 文件系统是否发生了更改？

我们的备份系统面临的最大问题之一是如何以跨平台、可预测和可靠的方式确定文件夹是否发生了更改。当我们考虑这个问题时，有几件事情值得一提：我们应该只检查顶层文件夹的上次修改日期吗？我们应该使用系统通知来通知我们关心的文件何时发生更改吗？这两种方法都存在问题，事实证明这并不是一个微不足道的问题。

相反，我们将生成一个由我们关心的所有信息组成的 MD5 哈希，以确定某些内容是否发生了更改。

查看`os.FileInfo`类型，我们可以看到关于文件的许多信息：

```go
type FileInfo interface {
  Name() string       // base name of the file
  Size() int64        // length in bytes for regular files; 
                         system-dependent for others
  Mode() FileMode     // file mode bits
  ModTime() time.Time // modification time
  IsDir() bool        // abbreviation for Mode().IsDir()
  Sys() interface{}   // underlying data source (can return nil)
}
```

为了确保我们能够意识到文件夹中任何文件的各种更改，哈希将由文件名和路径（因此如果它们重命名文件，哈希将不同）、大小（如果文件大小发生变化，显然是不同的）、上次修改日期、项目是文件还是文件夹以及文件模式位组成。尽管我们不会存档文件夹，但我们仍然关心它们的名称和文件夹的树结构。

创建一个名为`dirhash.go`的新文件，并添加以下函数：

```go
package backup
import (
  "crypto/md5"
  "fmt"
  "io"
  "os"
  "path/filepath"
)
func DirHash(path string) (string, error) {
  hash := md5.New()
  err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
    if err != nil {
      return err
    }
    io.WriteString(hash, path)
    fmt.Fprintf(hash, "%v", info.IsDir())
    fmt.Fprintf(hash, "%v", info.ModTime())
    fmt.Fprintf(hash, "%v", info.Mode())
    fmt.Fprintf(hash, "%v", info.Name())
    fmt.Fprintf(hash, "%v", info.Size())
    return nil
  })
  if err != nil {
    return "", err
  }
  return fmt.Sprintf("%x", hash.Sum(nil)), nil
}
```

我们首先创建一个知道如何计算 MD5 的新`hash.Hash`，然后使用`filepath.Walk`来遍历指定路径目录中的所有文件和文件夹。对于每个项目，假设没有错误，我们使用`io.WriteString`将差异信息写入哈希生成器，这让我们可以将字符串写入`io.Writer`，以及`fmt.Fprintf`，它同时暴露了格式化功能，允许我们使用`%v`格式动词生成每个项目的默认值格式。

一旦每个文件都被处理，假设没有发生错误，我们就使用`fmt.Sprintf`生成结果字符串。`hash.Hash`上的`Sum`方法计算具有附加指定值的最终哈希值。在我们的情况下，我们不想附加任何东西，因为我们已经添加了所有我们关心的信息，所以我们只传递`nil`。`%x`格式动词表示我们希望该值以十六进制（基数 16）的小写字母表示。这是表示 MD5 哈希的通常方式。

## 检查更改并启动备份

现在我们有了哈希文件夹的能力，并且可以执行备份，我们将把这两者放在一个名为`Monitor`的新类型中。`Monitor`类型将具有一个路径映射及其关联的哈希值，任何`Archiver`类型的引用（当然，我们现在将使用`backup.ZIP`），以及一个表示存档位置的目标字符串。

创建一个名为`monitor.go`的新文件，并添加以下定义：

```go
type Monitor struct {
  Paths       map[string]string
  Archiver    Archiver
  Destination string
}
```

为了触发更改检查，我们将添加以下`Now`方法：

```go
func (m *Monitor) Now() (int, error) {
  var counter int
  for path, lastHash := range m.Paths {
    newHash, err := DirHash(path)
    if err != nil {
      return 0, err
    }
    if newHash != lastHash {
      err := m.act(path)
      if err != nil {
        return counter, err
      }
      m.Paths[path] = newHash // update the hash
      counter++
    }
  }
  return counter, nil
}
```

`Now`方法遍历映射中的每个路径，并生成该文件夹的最新哈希值。如果哈希值与映射中的哈希值不匹配（上次检查时生成的哈希值），则认为它已更改，并需要再次备份。在调用尚未编写的`act`方法之前，我们会这样做，然后使用这个新的哈希值更新映射中的哈希值。

为了给我们的用户一个高层次的指示，当他们调用`Now`时发生了什么，我们还维护一个计数器，每次备份一个文件夹时我们会增加这个计数器。我们稍后将使用这个计数器来让我们的最终用户了解系统正在做什么，而不是用信息轰炸他们。

```go
m.act undefined (type *Monitor has no field or method act)
```

编译器再次帮助我们，并提醒我们还没有添加`act`方法：

```go
func (m *Monitor) act(path string) error {
  dirname := filepath.Base(path)
  filename := fmt.Sprintf("%d.zip", time.Now().UnixNano())
  return m.Archiver.Archive(path, filepath.Join(m.Destination, dirname, filename))
}
```

因为我们在我们的 ZIP `Archiver`类型中已经做了大部分工作，所以我们在这里所要做的就是生成一个文件名，决定存档的位置，并调用`Archive`方法。

### 提示

如果`Archive`方法返回一个错误，`act`方法和`Now`方法将分别返回它。在 Go 中，这种将错误传递到链条上的机制非常常见，它允许你处理你可以做一些有用的恢复的情况，或者将问题推迟给其他人。

上述代码中的`act`方法使用`time.Now().UnixNano()`生成时间戳文件名，并硬编码`.zip`扩展名。

### 硬编码在短时间内是可以的

像我们这样硬编码文件扩展名在开始时是可以的，但是如果你仔细想想，我们在这里混合了一些关注点。如果我们改变`Archiver`的实现以使用 RAR 或我们自己制作的压缩格式，`.zip`扩展名将不再合适。

### 提示

在继续阅读之前，想想你可能会采取哪些步骤来避免硬编码。文件扩展名决策在哪里？为了正确避免硬编码，你需要做哪些改变？

文件扩展名决定的正确位置可能在`Archiver`接口中，因为它知道将要进行的归档类型。所以我们可以添加一个`Ext()`字符串方法，并从我们的`act`方法中访问它。但是我们可以通过允许`Archiver`作者指定整个文件名格式，而不仅仅是扩展名，来增加一点额外的功能而不需要太多额外的工作。

回到`archiver.go`，更新`Archiver`接口定义：

```go
type Archiver interface {

DestFmt() string

  Archive(src, dest string) error
}
```

我们的`zipper`类型现在需要实现这个：

```go
func (z *zipper) DestFmt() string {
  return "%d.zip"
}
```

现在我们可以要求我们的`act`方法从`Archiver`接口获取整个格式字符串，更新`act`方法：

```go
func (m *Monitor) act(path string) error {
  dirname := filepath.Base(path)
  filename := fmt.Sprintf(m.Archiver.DestFmt(), time.Now().UnixNano())
  return m.Archiver.Archive(path, filepath.Join(m.Destination, dirname, filename))
}
```

# 用户命令行工具

我们将构建的两个工具中的第一个允许用户为备份守护程序工具（稍后我们将编写）添加、列出和删除路径。你可以暴露一个 web 界面，或者甚至使用桌面用户界面集成的绑定包，但我们将保持简单，构建一个命令行工具。

在`backup`文件夹内创建一个名为`cmds`的新文件夹，并在其中创建另一个`backup`文件夹。

### 提示

将命令的文件夹和命令二进制本身命名为相同的名称是一个好的做法。

在我们的新`backup`文件夹中，将以下代码添加到`main.go`：

```go
func main() {
  var fatalErr error
  defer func() {
    if fatalErr != nil {
      flag.PrintDefaults()
      log.Fatalln(fatalErr)
    }
  }()
  var (
    dbpath = flag.String("db", "./backupdata", "path to database directory")
  )
  flag.Parse()
  args := flag.Args()
  if len(args) < 1 {
    fatalErr = errors.New("invalid usage; must specify command")
    return
  }
}
```

我们首先定义我们的`fatalErr`变量，并推迟检查该值是否为`nil`的函数。如果不是，它将打印错误以及标志默认值，并以非零状态代码退出。然后我们定义一个名为`db`的标志，它期望`filedb`数据库目录的路径，然后解析标志并获取剩余的参数，并确保至少有一个。

## 持久化小数据

为了跟踪路径和我们生成的哈希，我们需要一种数据存储机制，最好是在我们停止和启动程序时仍然有效。我们在这里有很多选择：从文本文件到完全水平可扩展的数据库解决方案。Go 的简单原则告诉我们，将数据库依赖性构建到我们的小型备份程序中并不是一个好主意；相反，我们应该问问我们如何能以最简单的方式解决这个问题？

`github.com/matryer/filedb`包是这种问题的实验性解决方案。它允许您与文件系统交互，就好像它是一个非常简单的无模式数据库。它从`mgo`等包中获取设计灵感，并且可以在数据查询需求非常简单的情况下使用。在`filedb`中，数据库是一个文件夹，集合是一个文件，其中每一行代表不同的记录。当然，随着`filedb`项目的发展，这一切都可能会发生变化，但接口希望不会变。

将以下代码添加到`main`函数的末尾：

```go
db, err := filedb.Dial(*dbpath)
if err != nil {
  fatalErr = err
  return
}
defer db.Close()
col, err := db.C("paths")
if err != nil {
  fatalErr = err
  return
}
```

在这里，我们使用`filedb.Dial`函数连接到`filedb`数据库。实际上，在这里并没有发生太多事情，除了指定数据库的位置，因为没有真正的数据库服务器可以连接（尽管这可能会在未来发生变化，这就是接口中存在这些规定的原因）。如果成功，我们推迟关闭数据库。关闭数据库确实会做一些事情，因为可能需要清理的文件可能是打开的。

按照`mgo`模式，接下来我们使用`C`方法指定一个集合，并将其引用保存在`col`变量中。如果在任何时候发生错误，我们将把它赋给`fatalErr`变量并返回。

为了存储数据，我们将定义一个名为`path`的类型，它将存储完整路径和最后一个哈希值，并使用 JSON 编码将其存储在我们的`filedb`数据库中。在`main`函数之前添加以下`struct`定义：

```go
type path struct {
  Path string
  Hash string
}
```

## 解析参数

当我们调用`flag.Args`（而不是`os.Args`）时，我们会收到一个不包括标志的参数切片。这允许我们在同一个工具中混合标志参数和非标志参数。

我们希望我们的工具能够以以下方式使用：

+   添加路径：

```go

backup -db=/path/to/db add {path} [paths...]

```

+   删除路径：

```go

backup -db=/path/to/db remove {path} [paths...]

```

+   列出所有路径：

```go

backup -db=/path/to/db list

```

为了实现这一点，因为我们已经处理了标志，我们必须检查第一个（非标志）参数。

将以下代码添加到`main`函数：

```go
switch strings.ToLower(args[0]) {
case "list":
case "add":
case "remove":
}
```

在这里，我们只需切换到第一个参数，然后将其设置为小写（如果用户输入`backup LIST`，我们仍希望它能正常工作）。

### 列出路径

要列出数据库中的路径，我们将在路径的`col`变量上使用`ForEach`方法。在列表情况下添加以下代码：

```go
var path path
col.ForEach(func(i int, data []byte) bool {
  err := json.Unmarshal(data, &path)
  if err != nil {
    fatalErr = err
    return false
  }
  fmt.Printf("= %s\n", path)
  return false
})
```

我们向`ForEach`传递一个回调函数，该函数将为该集合中的每个项目调用。然后我们将其从 JSON 解封到我们的`path`类型，并使用`fmt.Printf`将其打印出来。我们根据`filedb`接口返回`false`，这告诉我们返回`true`将停止迭代，我们要确保列出它们所有。

#### 自定义类型的字符串表示

如果以这种方式在 Go 中打印结构体，使用`%s`格式动词，你可能会得到一些混乱的结果，这些结果对用户来说很难阅读。但是，如果该类型实现了`String()`字符串方法，那么将使用该方法，我们可以使用它来控制打印的内容。在路径结构体下面，添加以下方法：

```go
func (p path) String() string {
  return fmt.Sprintf("%s [%s]", p.Path, p.Hash)
}
```

这告诉`path`类型应该如何表示自己。

### 添加路径

要添加一个或多个路径，我们将遍历剩余的参数并为每个参数调用`InsertJSON`方法。在`add`情况下添加以下代码：

```go
if len(args[1:]) == 0 {
  fatalErr = errors.New("must specify path to add")
  return
}
for _, p := range args[1:] {
  path := &path{Path: p, Hash: "Not yet archived"}
  if err := col.InsertJSON(path); err != nil {
    fatalErr = err
    return
  }
  fmt.Printf("+ %s\n", path)
}
```

如果用户没有指定任何其他参数，比如他们只是调用`backup add`而没有输入任何路径，我们将返回一个致命错误。否则，我们将完成工作并打印出路径字符串（前缀为`+`符号）以指示成功添加。默认情况下，我们将哈希设置为`Not yet archived`字符串字面量-这是一个无效的哈希，但它具有双重目的，既让用户知道它尚未被归档，又向我们的代码指示这一点（因为文件夹的哈希永远不会等于该字符串）。

### 删除路径

要删除一个或多个路径，我们使用路径的集合的`RemoveEach`方法。在`remove`情况下添加以下代码：

```go
var path path
col.RemoveEach(func(i int, data []byte) (bool, bool) {
  err := json.Unmarshal(data, &path)
  if err != nil {
    fatalErr = err
    return false, true
  }
  for _, p := range args[1:] {
    if path.Path == p {
      fmt.Printf("- %s\n", path)
      return true, false
    }
  }
  return false, false
})
```

我们提供给`RemoveEach`的回调函数期望我们返回两个布尔类型：第一个指示是否应删除该项，第二个指示我们是否应停止迭代。

## 使用我们的新工具

我们已经完成了我们简单的`backup`命令行工具。让我们看看它的运行情况。在`backup/cmds/backup`内创建一个名为`backupdata`的文件夹；这将成为`filedb`数据库。

通过导航到`main.go`文件并运行终端中的以下命令来构建工具：

```go

go build -o backup

```

如果一切顺利，我们现在可以添加一个路径：

```go

./backup -db=./backupdata add ./test ./test2

```

你应该看到预期的输出：

```go

+ ./test [Not yet archived]

+ ./test2 [Not yet archived]

```

现在让我们添加另一个路径：

```go

./backup -db=./backupdata add ./test3

```

现在你应该看到完整的列表：

```go

./backup -db=./backupdata list

```

我们的程序应该产生：

```go

= ./test [Not yet archived]

= ./test2 [Not yet archived]

= ./test3 [Not yet archived]

```

让我们删除`test3`以确保删除功能正常：

```go

./backup -db=./backupdata remove ./test3

./backup -db=./backupdata list

```

这将把我们带回到：

```go

+ ./test [Not yet archived]

+ ./test2 [Not yet archived]

```

我们现在能够以符合我们用例的方式与`filedb`数据库进行交互。接下来，我们构建将实际使用我们的`backup`包执行工作的守护程序。

# 守护进程备份工具

`backup`工具，我们将其称为`backupd`，将负责定期检查`filedb`数据库中列出的路径，对文件夹进行哈希处理以查看是否有任何更改，并使用`backup`包来执行需要的文件夹的归档。

在`backup/cmds/backup`文件夹旁边创建一个名为`backupd`的新文件夹，让我们立即处理致命错误和标志：

```go
func main() {
  var fatalErr error
  defer func() {
    if fatalErr != nil {
      log.Fatalln(fatalErr)
    }
  }()
  var (
    interval = flag.Int("interval", 10, "interval between checks (seconds)")
    archive  = flag.String("archive", "archive", "path to archive location")
    dbpath   = flag.String("db", "./db", "path to filedb database")
  )
  flag.Parse()
}
```

你现在一定很习惯看到这种代码了。在指定三个标志之前，我们推迟处理致命错误：`interval`，`archive`和`db`。`interval`标志表示检查文件夹是否更改之间的秒数，`archive`标志是 ZIP 文件将存储的存档位置的路径，`db`标志是与`backup`命令交互的相同`filedb`数据库的路径。通常调用`flag.Parse`设置变量并验证我们是否准备好继续。

为了检查文件夹的哈希值，我们将需要我们之前编写的`Monitor`的一个实例。将以下代码附加到`main`函数：

```go
m := &backup.Monitor{
  Destination: *archive,
  Archiver:    backup.ZIP,
  Paths:       make(map[string]string),
}
```

在这里，我们使用`archive`值作为`Destination`类型创建了一个`backup.Monitor`方法。我们将使用`backup.ZIP`归档程序，并创建一个准备好在其中存储路径和哈希的映射。在守护程序开始时，我们希望从数据库加载路径，以便在停止和启动时不会不必要地进行归档。

将以下代码添加到`main`函数中：

```go
db, err := filedb.Dial(*dbpath)
if err != nil {
  fatalErr = err
  return
}
defer db.Close()
col, err := db.C("paths")
if err != nil {
  fatalErr = err
  return
}
```

你以前也见过这段代码；它拨号数据库并创建一个允许我们与`paths`集合交互的对象。如果出现任何问题，我们设置`fatalErr`并返回。

## 重复的结构

由于我们将使用与用户命令行工具程序中相同的路径结构，因此我们也需要为该程序包含一个定义。在`main`函数之前插入以下结构：

```go
type path struct {
  Path string
  Hash string
}
```

面向对象的程序员们毫无疑问现在正在对页面尖叫，要求这个共享的片段只存在于一个地方，而不是在两个程序中重复。我敦促你抵制这种早期抽象的冲动。这四行代码几乎不能证明我们的代码需要一个新的包和依赖，因此它们可以在两个程序中很容易地存在，而几乎没有额外开销。还要考虑到我们可能想要在我们的`backupd`程序中添加一个`LastChecked`字段，这样我们就可以添加规则，每个文件夹最多每小时归档一次。我们的`backup`程序不关心这一点，它将继续快乐地查看哪些字段构成了一个路径。

## 缓存数据

我们现在可以查询所有现有的路径并更新`Paths`映射，这是一种增加程序速度的有用技术，特别是在数据存储缓慢或断开连接的情况下。通过将数据加载到缓存中（在我们的情况下是`Paths`映射），我们可以以闪电般的速度访问它，而无需每次需要信息时都要查阅文件。

将以下代码添加到`main`函数的主体中：

```go
var path path
col.ForEach(func(_ int, data []byte) bool {
  if err := json.Unmarshal(data, &path); err != nil {
    fatalErr = err
    return true
  }
  m.Paths[path.Path] = path.Hash
  return false // carry on
})
if fatalErr != nil {
  return
}
if len(m.Paths) < 1 {
  fatalErr = errors.New("no paths - use backup tool to add at least one")
  return
}
```

再次使用`ForEach`方法使我们能够遍历数据库中的所有路径。我们将 JSON 字节解组成与我们在其他程序中使用的相同路径结构，并在`Paths`映射中设置值。假设没有出现问题，我们最后检查以确保至少有一个路径，如果没有，则返回错误。

### 注意

我们程序的一个限制是一旦启动，它将无法动态添加路径。守护程序需要重新启动。如果这让你烦恼，你可以随时构建一个定期更新`Paths`映射的机制。

## 无限循环

接下来，我们需要立即对哈希进行检查，看看是否需要进行归档，然后进入一个无限定时循环，在其中以指定的间隔定期进行检查。

无限循环听起来像一个坏主意；实际上，对于一些人来说，它听起来像一个 bug。然而，由于我们正在谈论这个程序内部的一个无限循环，并且由于无限循环可以很容易地通过简单的`break`命令打破，它们并不像听起来那么戏剧性。

在 Go 中，编写无限循环就像这样简单：

```go
for {}
```

大括号内的指令会一遍又一遍地执行，尽可能快地运行代码的机器。再次听起来像一个坏计划，除非你仔细考虑你要求它做什么。在我们的情况下，我们立即启动了一个`select` case，它会安全地阻塞，直到其中一个通道有有趣的事情要说。

添加以下代码：

```go
check(m, col)
signalChan := make(chan os.Signal, 1)
signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
for {
  select {
  case <-time.After(time.Duration(*interval) * time.Second):
    check(m, col)
  case <-signalChan:
    // stop
    fmt.Println()
    log.Printf("Stopping...")
    goto stop
  }
}
stop:
```

当然，作为负责任的程序员，我们关心用户终止我们的程序时会发生什么。因此，在调用尚不存在的`check`方法之后，我们创建一个信号通道，并使用`signal.Notify`要求将终止信号发送到通道，而不是自动处理。在我们无限的`for`循环中，我们选择两种可能性：要么`timer`通道发送消息，要么终止信号通道发送消息。如果是`timer`通道消息，我们再次调用`check`，否则我们终止程序。

`time.After`函数返回一个通道，在指定的时间过去后发送一个信号（实际上是当前时间）。有些令人困惑的`time.Duration(*interval) * time.Second`代码只是指示在发送信号之前要等待的时间量；第一个`*`字符是解引用运算符，因为`flag.Int`方法表示指向 int 的指针，而不是 int 本身。第二个`*`字符将间隔值乘以`time.Second`，从而得到与指定间隔相等的值（以秒为单位）。将`*interval int`转换为`time.Duration`是必需的，以便编译器知道我们正在处理数字。

在前面的代码片段中，我们通过使用`goto`语句来回顾一下内存中的短暂旅程，以跳出 switch 并阻止循环。我们可以完全不使用`goto`语句，只需在接收到终止信号时返回，但是这里讨论的模式允许我们在`for`循环之后运行非延迟代码，如果我们希望的话。

## 更新 filedb 记录

现在剩下的就是实现`check`函数，该函数应该调用`Monitor`类型的`Now`方法，并在有任何新的哈希值时更新数据库。

在`main`函数下面，添加以下代码：

```go
func check(m *backup.Monitor, col *filedb.C) {
  log.Println("Checking...")
  counter, err := m.Now()
  if err != nil {
    log.Fatalln("failed to backup:", err)
  }
  if counter > 0 {
    log.Printf("  Archived %d directories\n", counter)
    // update hashes
    var path path
    col.SelectEach(func(_ int, data []byte) (bool, []byte, bool) {
      if err := json.Unmarshal(data, &path); err != nil {
        log.Println("failed to unmarshal data (skipping):", err)
        return true, data, false
      }
      path.Hash, _ = m.Paths[path.Path]
      newdata, err := json.Marshal(&path)
      if err != nil {
        log.Println("failed to marshal data (skipping):", err)
        return true, data, false
      }
      return true, newdata, false
    })
  } else {
    log.Println("  No changes")
  }
}
```

`check`函数首先告诉用户正在进行检查，然后立即调用`Now`。如果`Monitor`类型为我们做了任何工作，即询问它是否归档了任何文件，我们将输出它们给用户，并继续使用新值更新数据库。`SelectEach`方法允许我们更改集合中的每个记录，如果我们愿意的话，通过返回替换的字节。因此，我们`Unmarshal`字节以获取路径结构，更新哈希值并返回编组的字节。这确保下次我们启动`backupd`进程时，它将使用正确的哈希值进行操作。

# 测试我们的解决方案

让我们看看我们的两个程序是否能很好地配合，以及它们对我们的`backup`包内部代码产生了什么影响。您可能希望为此打开两个终端窗口，因为我们将运行两个程序。

我们已经向数据库中添加了一些路径，所以让我们使用`backup`来查看它们：

```go

./backup -db="./backupdata" list

```

你应该看到这两个测试文件夹；如果没有，可以参考*添加路径*部分。

```go

= ./test [Not yet archived]

= ./test2 [Not yet archived]

```

在另一个窗口中，导航到`backupd`文件夹并创建我们的两个测试文件夹，名为`test`和`test2`。

使用通常的方法构建`backupd`：

```go

go build -o backupd

```

假设一切顺利，我们现在可以开始备份过程，确保将`db`路径指向与`backup`程序相同的路径，并指定我们要使用一个名为`archive`的新文件夹来存储 ZIP 文件。为了测试目的，让我们指定一个间隔为`5`秒以节省时间：

```go

./backupd -db="../backup/backupdata/" -archive="./archive" -interval=5

```

立即，`backupd`应该检查文件夹，计算哈希值，注意到它们是不同的（`尚未归档`），并启动两个文件夹的归档过程。它将打印输出告诉我们这一点：

```go

Checking...

Archived 2 directories

```

打开`backup/cmds/backupd`内新创建的`archive`文件夹，并注意它已经创建了两个子文件夹：`test`和`test2`。在这些文件夹中是空文件夹的压缩归档版本。随意解压一个并查看；到目前为止并不是很令人兴奋。

与此同时，在终端窗口中，`backupd`一直在检查文件夹是否有变化：

```go

Checking...

 No changes

Checking...

 No changes

```

在您喜欢的文本编辑器中，在`test2`文件夹中创建一个包含单词`test`的新文本文件，并将其保存为`one.txt`。几秒钟后，您会发现`backupd`已经注意到了新文件，并在`archive/test2`文件夹中创建了另一个快照。

当然，它的文件名不同，因为时间不同，但是如果您解压缩它，您会注意到它确实创建了文件夹的压缩存档版本。

通过执行以下操作来尝试解决方案：

+   更改`one.txt`文件的内容

+   将文件添加到`test`文件夹中

+   删除文件

# 摘要

在本章中，我们成功地为您的代码项目构建了一个非常强大和灵活的备份系统。您可以看到扩展或修改这些程序行为有多么简单。您可以解决的潜在问题范围是无限的。

与上一节不同，我们不是将本地存档目标文件夹，而是想象挂载网络存储设备并使用该设备。突然间，您就可以对这些重要文件进行离站（或至少是离机）备份。您可以轻松地将 Dropbox 文件夹设置为存档目标，这意味着不仅您自己可以访问快照，而且副本存储在云中，甚至可以与其他用户共享。

扩展`Archiver`接口以支持`Restore`操作（只需使用`encoding/zip`包解压文件）允许您构建可以查看存档内部并访问单个文件更改的工具，就像 Time Machine 允许您做的那样。索引文件使您可以在整个代码历史记录中进行全面搜索，就像 GitHub 一样。

由于文件名是时间戳，您可以将旧存档备份到不太活跃的存储介质，或者将更改总结为每日转储。

显然，备份软件已经存在，经过充分测试，并且在全球范围内得到使用，专注于解决尚未解决的问题可能是一个明智的举措。但是，当写小程序几乎不费吹灰之力时，通常值得去做，因为它给予您控制权。当您编写代码时，您可以得到完全符合您要求的结果，而不需要妥协，这取决于每个人做出的决定。

具体来说，在本章中，我们探讨了 Go 标准库如何轻松地与文件系统交互：打开文件进行读取，创建新文件和创建目录。与`io`包中的强大类型混合在一起的`os`包，再加上像`encoding/zip`等功能，清楚地展示了极其简单的 Go 接口如何组合以产生非常强大的结果。


# 附录 A：稳定的 Go 环境的良好实践

编写 Go 代码是一种有趣且愉快的体验，其中编译时错误——而不是痛苦——实际上会指导您编写健壮、高质量的代码。然而，偶尔会遇到环境问题，开始妨碍并打断您的工作流程。虽然通常可以在一些搜索和一些微调后解决这些问题，但正确设置开发环境可以大大减少问题，使您能够专注于构建有用的应用程序。

在本章中，我们将在新机器上从头开始安装 Go，并讨论我们拥有的一些环境选项以及它们可能在未来产生的影响。我们还将考虑协作如何影响我们的一些决定，以及开源我们的软件包可能会产生什么影响。

具体来说，我们将：

+   获取 Go 源代码并在开发机器上本地构建它

+   了解`GOPATH`环境变量的用途，并讨论其合理的使用方法

+   了解 Go 工具以及如何使用它们来保持我们代码的质量

+   学习如何使用工具自动管理我们的导入

+   考虑我们的`.go`文件的“保存时”操作，以及我们如何将 Go 工具集成为我们日常开发的一部分。

# 安装 Go

Go 是一个最初用 C 编写的开源项目，这意味着我们可以轻松地从代码中编译我们自己的版本；这仍然是安装 Go 的最佳选项，出于各种原因。它允许我们在需要稍后查找某些内容时浏览源代码，无论是在标准库 Go 代码中还是在工具的 C 代码中。它还允许我们轻松地更新到 Go 的新版本，或者在发布候选版本出现时进行实验，只需从代码存储库中拉取不同的标签或分支并重新构建。当然，如果需要，我们也可以轻松地回滚到早期版本，甚至修复错误并生成拉取请求发送给 Go 核心团队，以便他们考虑对项目的贡献。

### 注意

可以在[`golang.org/doc/install/source`](http://golang.org/doc/install/source)上找到一个不断更新的资源，用于在各种平台上从源代码安装 Go，或者通过搜索`Install Golang from source`。本章将涵盖相同的内容，但如果遇到问题，互联网将成为帮助解决问题的最佳途径。

## 安装 C 工具

由于 Go 工具链是用 C 编写的，因此在构建 Go 安装时实际上会编译 C 代码。这可能看起来有点反直觉；使用一种不同的编程语言编写了一种编程语言，但当然，当 Go 核心团队开始编写 Go 时，Go 并不存在，但 C 存在。更准确地说，用于构建和链接 Go 程序的工具是用 C 编写的。无论如何，现在我们需要能够编译 C 源代码。

### 注意

在 2014 年的丹佛科罗拉多州举行的首届 Gophercon 上，Rob Pike 和他的团队表示，他们的目标之一将是用 Go 编写的程序替换 C 工具链，以便整个堆栈都变成 Go。在撰写本文时，这还没有发生，因此我们将需要 C 工具。

要确定是否需要安装 C 工具，请打开终端并尝试使用`gcc`命令：

```go

gcc -v

```

如果收到`command not found`错误或类似错误，则可能需要安装 C 工具。但是，如果您看到`gcc`的输出给出版本信息（这就是`-v`标志的作用），则可能可以跳过此部分。

安装 C 工具因各种平台而异，并且随时间可能会发生变化，因此本节应该只被视为帮助您获取所需工具的粗略指南。

在运行 OS X 的 Mac 上，工具随 Xcode 一起提供，可在 App Store 免费获取。安装 Xcode 后，您打开**首选项**并导航到**下载**部分。从那里，您可以找到包含构建 Go 所需的 C 工具的命令行工具。

在 Ubuntu 和 Debian 系统上，您可以使用`apt-get`安装工具：

```go

sudo apt-get install gcc libc6-dev

```

对于 RedHat 和 Centos 6 系统，您可以使用`yum`安装工具：

```go

sudo yum install gcc glibc-devel

```

对于 Windows，MinGW 项目提供了一个 Windows 安装程序，可以为您安装工具。转到[`www.mingw.org/`](http://www.mingw.org/)并按照那里的说明开始。

一旦您成功安装了工具，并确保适当的二进制文件包含在您的`PATH`环境变量中，当运行`gcc -v`时，您应该能够看到一些合理的输出：

```go

Apple LLVM version 5.1 (clang-503.0.40) (based on LLVM 3.4svn)

Target: x86_64-apple-darwin13.2.0

Thread model: posix

```

上述片段是在 Apple Mac 计算机上的输出，最重要的是要查看是否缺少`command not found`错误。

## 从源代码下载和构建 Go

Go 源代码托管在 Google Code 的 Mercurial 存储库中，因此我们将使用`hg`命令克隆它以准备构建。

### 注意

如果您没有`hg`命令，您可以从[`mercurial.selenic.com/downloads`](http://mercurial.selenic.com/downloads)下载页面获取 Mercurial。

在终端中，要安装 Go，请转到适当的位置，例如 Unix 系统上的`/opt`，或 Windows 上的`C:\`。

通过输入以下命令获取 Go 的最新版本：

```go

hg clone -u release https://code.google.com/p/go

```

过一会儿，最新的 Go 源代码将下载到一个新的`go`文件夹中。

转到刚刚创建的`go/src`文件夹并运行`all`脚本，这将从源代码构建 Go 的实例。在 Unix 系统上，这是`all.bash`，在 Windows 上是`all.bat`。

一旦所有构建步骤完成，您应该注意到所有测试都已成功通过。

# 配置 Go

现在 Go 已安装，但为了使用工具，我们必须确保它已正确配置。为了更容易调用工具，我们需要将我们的`go/bin`路径添加到`PATH`环境变量中。

### 注意

在 Unix 系统上，您应该将 export `PATH=$PATH:/opt/go/bin`（确保这是您下载源代码时选择的路径）添加到您的`.bashrc`文件中。

在 Windows 上，打开**系统属性**（尝试右键单击**我的电脑**），在**高级**下，单击**环境变量**按钮，并使用 UI 确保`PATH`变量包含到您的`go/bin`文件夹的路径。

在终端中（您可能需要重新启动它以使更改生效），您可以通过打印`PATH`变量的值来确保这一点：

```go

echo $PATH

```

确保打印的值包含正确的路径到您的`go/bin`文件夹，例如，在我的机器上打印为：

```go

/usr/local/bin:/usr/bin:/bin:/opt/go/bin

```

### 注意

路径之间的冒号（在 Windows 上是分号）表明`PATH`变量实际上是一个文件夹列表，而不仅仅是一个文件夹。这表明在输入终端命令时，将搜索每个包含的文件夹。

现在我们可以确保我们刚刚构建的 Go 构建成功运行：

```go

go version

```

执行`go`命令（可以在您的`go/bin`位置找到）如下将为我们打印出当前版本。例如，对于 Go 1.3，您应该看到类似于：

```go

go version go1.3 darwin/amd64

```

## 获取正确的 GOPATH

`GOPATH`是另一个环境变量，用于指定 Go 源代码和已编译二进制包的位置（就像前一节中的`PATH`一样）。在您的 Go 程序中使用`import`命令将导致编译器在`GOPATH`位置查找您所引用的包。使用`go get`和其他命令时，项目将下载到`GOPATH`文件夹中。

虽然`GOPATH`位置可以包含一系列以冒号分隔的文件夹，例如`PATH`，并且您甚至可以根据您正在工作的项目来使用不同的`GOPATH`值，但强烈建议您为所有内容使用单个`GOPATH`位置，这是我们假设您将为本书中的项目所做的。

在您的`Users`文件夹中的某个地方，也许是`Work`子文件夹中，创建一个名为`go`的新文件夹。这将是我们的`GOPATH`目标，也是所有第三方代码和二进制文件的存放地，以及我们将编写 Go 程序和包的地方。使用在上一节设置`PATH`环境变量时使用的相同技术，将`GOPATH`变量设置为新的`go`文件夹。让我们打开一个终端并使用新安装的命令之一来获取一个我们要使用的第三方包：

```go

go get github.com/stretchr/powerwalk 

```

从`Stretchr`获取`powerwalk`库实际上会创建以下文件夹结构；`$GOPATH/src/github.com/stretchr/powerwalk`。您可以看到路径段在 Go 组织事物方面很重要，这有助于命名空间项目并使它们保持唯一。例如，如果您创建了自己的名为`powerwalk`的包，您不会将其保存在`Stretchr`的 GitHub 存储库中，因此路径将不同。

当我们在本书中创建项目时，您应该为它们考虑一个合理的`GOPATH`根目录。例如，我使用了`github.com/matryer/goblueprints`，如果您要`go get`它，实际上会在您的`GOPATH`文件夹中获得本书的所有源代码的完整副本！

# Go 工具

Go 核心团队早期做出的决定是，所有 Go 代码应该对每个说 Go 语言的人看起来熟悉和明显，而不是每个代码库都需要额外的学习才能让新程序员理解或处理它。当考虑到开源项目时，这是一个特别明智的做法，其中一些项目有数百名贡献者不断涌入和离开。

有一系列工具可以帮助我们达到 Go 核心团队设定的高标准，我们将在本节中看到其中一些工具的实际应用。

在您的`GOPATH`位置，创建一个名为`tooling`的新文件夹，并创建一个包含以下代码的新`main.go`文件：

```go
package main
import (
"fmt"
)
func main() {
return
var name string
name = "Mat"
fmt.Println("Hello ", name)
}
```

紧凑的空间和缺乏缩进是故意的，因为我们将要看一个随 Go 一起提供的非常酷的实用工具。

在终端中，导航到您的新文件夹并运行：

```go

go fmt

```

### 注意

在 2014 年的 Gophercon 在科罗拉多州丹佛市，大多数人都了解到，与其将这个小三合一发音为“格式”或“f, m, t”，实际上它是作为一个单词发音的。现在试着对自己说：“fhumt”；似乎计算机程序员没有说一个外星语言的话，他们就不够怪异！

您会注意到，这个小工具实际上已经调整了我们的代码文件，以确保我们的程序布局（或格式）符合 Go 标准。新版本要容易阅读得多：

```go
package main

import (
  "fmt"
)

func main() {
  return
  var name string
  name = "Mat"
  fmt.Println("Hello ", name)
}
```

`go fmt`命令关心缩进、代码块、不必要的空格、不必要的额外换行等。以这种方式格式化代码是一个很好的实践，可以确保您的 Go 代码看起来像所有其他 Go 代码。

接下来，我们将对我们的程序进行审查，以确保我们没有犯任何可能令用户困惑的错误或决定；我们可以使用另一个很棒的免费工具来自动完成这个过程：

```go

go vet

```

我们的小程序的输出指出了一个明显而显眼的错误：

```go

main.go:10: unreachable code

exit status 1

```

我们在函数顶部调用`return`，然后尝试在此之后做其他事情。`go vet`工具已经注意到了这一点，并指出我们的文件中有无法访问的代码。

### 提示

如果您在运行任何 Go 工具时遇到错误，通常意味着您必须获取该命令才能使用它。但是，在 vet 工具的情况下，您只需打开终端并运行：

```go
go get code.google.com/p/go.tools/cmd/vet
```

`go vet`不仅会捕捉到这样的愚蠢错误，它还会寻找程序的更微妙的方面，这将指导您编写尽可能好的 Go 代码。有关 vet 工具将报告的最新列表，请查看[`godoc.org/code.google.com/p/go.tools/cmd/vet`](https://godoc.org/code.google.com/p/go.tools/cmd/vet)上的文档。

我们将要使用的最后一个工具叫做`goimports`，由 Brad Fitzpatrick 编写，用于自动修复（添加或删除）Go 文件的`import`语句。在 Go 中导入一个包而不使用它是一个错误，显然尝试使用一个未导入的包也不会起作用。`goimports`工具将根据我们代码文件的内容自动重写我们的`import`语句。首先，让我们使用熟悉的命令安装`goimports`：

```go

go get code.google.com/p/go.tools/cmd/goimports

```

更新您的程序以导入一些我们不打算使用的包，并删除`fmt`包：

```go
import (
  "net/http"
  "sync"
)
```

当我们尝试通过调用`go run main.go`来运行我们的程序时，我们会看到我们得到了一些错误：

```go

./main.go:4: imported and not used: "net/http"

./main.go:5: imported and not used: "sync"

./main.go:13: undefined: fmt

```

这些错误告诉我们，我们已经导入了我们不使用的包，并且缺少了`fmt`包，为了继续，我们需要进行更正。这就是`goimports`发挥作用的地方：

```go

goimports -w *.go

```

我们正在使用`goimports`命令和`-w`写入标志，这将节省我们对所有以`.go`结尾的文件进行更正的任务。

现在看看您的`main.go`文件，注意`net/http`和`sync`包已被移除，而`fmt`包已被重新放回。

您可以争论切换到终端运行这些命令比手动操作需要更多时间，而在大多数情况下您可能是正确的，这就是为什么强烈建议您将 Go 工具与您的文本编辑器集成。

# 在保存时进行清理、构建和运行测试

由于 Go 核心团队为我们提供了`fmt`、`vet`、`test`和`goimports`等优秀的工具，我们将看一下一个被证明非常有用的开发实践。每当我们保存一个`.go`文件时，我们希望自动执行以下任务：

1.  使用`goimports`和`fmt`来修复我们的导入并格式化代码。

1.  检查代码是否有任何错误，并立即告诉我们。

1.  尝试构建当前包并输出任何构建错误。

1.  如果构建成功，请运行包的测试并输出任何失败。

因为 Go 代码编译速度如此之快（Rob Pike 曾经说过它并不快速构建，但它只是不像其他一切那样慢），所以我们可以在每次保存文件时轻松地构建整个包。对于运行测试也是如此，这有助于我们如果我们以 TDD 风格进行开发，体验非常好。每当我们对代码进行更改时，我们可以立即看到我们是否破坏了某些东西，或者对项目的其他部分产生了意外的影响。我们再也不会看到包导入错误了，因为我们的`import`语句已经被自动修复了，我们的代码也会在我们眼前被正确格式化。

一些编辑器可能不支持响应特定事件运行代码，比如保存文件，这给您留下了两个选择；您可以切换到更好的编辑器，或者编写自己的脚本文件以响应文件系统的更改。后一种解决方案不在本书的范围之内，相反，我们将专注于如何在流行的文本编辑器中实现这个功能。

## Sublime Text 3

Sublime Text 3 是一个在 OS X、Linux 和 Windows 上运行的编写 Go 代码的优秀编辑器，并且具有非常强大的扩展模型，这使得它易于定制和扩展。您可以从[`www.sublimetext.com/`](http://www.sublimetext.com/)下载 Sublime Text，并在决定是否购买之前免费试用。

感谢**DisposaBoy**（参见[`github.com/DisposaBoy`](https://github.com/DisposaBoy)），已经为 Go 创建了一个 Sublime 扩展包，实际上为我们提供了许多 Go 程序员实际上错过的功能和功能。我们将安装这个`GoSublime`包，然后在此基础上添加我们想要的保存功能。

在安装`GoSublime`之前，我们需要将 Package Control 安装到 Sublime Text 中。前往[`sublime.wbond.net/`](https://sublime.wbond.net/)，点击**Installation**链接，获取有关如何安装 Package Control 的说明。在撰写本文时，只需复制单行命令，并将其粘贴到 Sublime 控制台中即可，控制台可以通过从菜单中导航到**View** | **Show Console**来打开。

完成后，按*shift* + *command* + *P*，然后键入`Package Control: Install Package`，选择该选项后按*return*。稍等片刻（Package Control 正在更新其列表），将出现一个框，允许您通过输入并选择 GoSublime 来搜索并安装 GoSublime，然后按*return*。如果一切顺利，GoSublime 将被安装，编写 Go 代码将变得更加容易。

### 提示

现在您已经安装了 GoSublime，您可以按*command* + *.*，*command* + *2*（同时按下*command*键和句点，然后按下*command*键和数字*2*）打开一个包含该包详细信息的简短帮助文件。

Tyler Bunnell 是 Go 开源社区中另一个知名人物（参见[`github.com/tylerb`](https://github.com/tylerb)），我们将使用他的自定义来实现我们的保存功能。

按*command* + *.*，*command* + *5*打开 GoSublime 设置，并向对象添加以下条目：

```go
"on_save": [
  {
    "cmd": "gs9o_open", 
    "args": {
      "run": ["sh", "go build . errors && go test -i && go test && go vet && golint"],
      "focus_view": false
    }
  }
]
```

### 提示

注意，设置文件实际上是一个 JSON 对象，因此在添加`on_save`属性时，请确保不要损坏文件。例如，如果在之前和之后有属性，请确保逗号放置在适当的位置。

上述设置将告诉 Sublime Text 在保存文件时构建代码以查找错误，安装测试依赖项，运行测试并检查代码。保存设置文件（暂时不要关闭它），让我们看看它的效果。

从菜单中导航到**选择文件** | **打开…**并选择要打开的文件夹-现在让我们打开我们的`tooling`文件夹。Sublime Text 的简单用户界面清楚地表明，我们目前项目中只有一个文件，`main.go`。单击文件，添加一些额外的换行符，并添加和删除一些缩进。然后从菜单中导航到**文件** | **保存**，或按*command* + *S*。注意代码立即被清理了，只要你没有删除`main.go`中奇怪放置的`return`语句，你会注意到控制台已经出现，并且由于`go vet`的原因报告了问题：

```go

main.go:8: unreachable code

```

按住*command* + *shift*，双击控制台中无法到达的代码行将打开文件并将光标跳转到相关行。随着您继续编写 Go 代码，您会看到这个功能有多么有用。

如果您向文件添加了不需要的导入，您会注意到在使用`on_save`时会收到有关问题的通知，但它不会自动修复。这是因为我们还需要进行另一个调整。在与您添加`on_save`属性的相同设置文件中，添加以下属性：

```go
"fmt_cmd": ["goimports"]
```

这告诉 GoSublime 使用`goimports`命令而不是`go fmt`。再次保存此文件并返回到`main.go`。再次将`net/http`添加到导入中，删除`fmt`导入，并保存文件。注意未使用的包已被移除，`fmt`再次被放回。

# 摘要

在这个附录中，我们从源代码安装了自己的 Go 构建，这意味着我们可以轻松使用`hg`命令来保持我们的安装最新，或者在发布之前测试我们的测试功能。在孤独的夜晚，有整个 Go 语言代码供我们浏览也是很不错的。

你了解了`GOPATH`环境变量，并发现了将一个值用于所有项目的常见做法。这种方法极大地简化了在 Go 项目上的工作，否则你可能会继续遇到棘手的失败。

我们发现了 Go 工具集如何真正帮助我们生成高质量、符合社区标准的代码，任何其他程序员都可以轻松上手并进行开发，几乎不需要额外学习。更重要的是，我们看到了如何自动化使用这些工具意味着我们可以真正专注于编写应用程序和解决问题，这正是开发人员真正想要做的事情。

# 读累了记得休息一会哦~

公众号：古德猫宁李

+   电子书搜索下载

+   书单分享

+   书友学习交流

网站：沉金书屋 https://www.chenjin5.com

+   电子书搜索下载

+   电子书打包资源分享

+   学习资源分享
