# 精通 Go Web 服务（四）

> 原文：[`zh.annas-archive.org/md5/2D0D1F51B3626D3F3DD6A0D48080FBC1`](https://zh.annas-archive.org/md5/2D0D1F51B3626D3F3DD6A0D48080FBC1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：最大化性能

在讨论部署和启动应用程序的概念之后，我们将在本章中锁定 Go 和相关第三方包中的高性能策略。

随着您的网络服务或 API 的增长，性能问题可能会凸显出来。成功的网络服务的一个标志是需要更多的硬件支持；然而，通过编程最佳实践来减少这种需求比简单地为应用程序提供更多处理能力更好。

在本章中，我们将探讨：

+   引入中间件来减少代码中的冗余，并为一些性能特性铺平道路

+   设计缓存策略以保持内容新鲜并尽快提供

+   使用基于磁盘的缓存

+   使用内存缓存

+   通过中间件对我们的 API 进行速率限制

+   谷歌的 SPDY 协议倡议

在本章结束时，您应该知道如何将自己的中间件构建到您的社交网络（或任何其他网络服务）中，以引入额外的功能，从而提高性能。

# 使用中间件来减少冗余

在 Go 中处理 Web 时，内置的路由和处理程序的方法并不总是很适合直接使用中间件的清晰方法。

例如，尽管我们有一个非常简单的`UsersRetrieve()`方法，但如果我们想要阻止消费者到达那一点或在那之前运行一些东西，我们将需要在我们的代码中多次包含这些调用或参数：

```go
func UsersRetrieve(w http.ResponseWriter, r *http.Request) {
  CheckRateLimit()
```

还有一个调用是：

```go
func UsersUpdate( w http.ResponseWriter, r *http.Request) {
  CheckRateLimit()
  CheckAuthentication()
}
```

中间件允许我们更清晰地指导应用程序的内部模式，因为我们可以对速率限制和身份验证进行检查，就像前面的代码中所示的那样。如果有一些外部信号告诉我们应用程序应该暂时离线，而不是完全停止应用程序，我们也可以绕过调用。

考虑到可能性，让我们想一想如何在应用程序中有效地利用中间件。

最好的方法是找到我们通过重复插入了大量不必要代码的地方。一个容易开始的地方是我们的身份验证步骤，它存在于我们的`api.go`文件的许多代码部分中。

```go
func UserLogin(w http.ResponseWriter, r *http.Request) {

  CheckLogin(w,r)
```

我们在整个应用程序中多次调用`CheckLogin()`函数，因此我们可以将其卸载到中间件中，以减少冗余和重复的代码。

另一种方法是访问控制头设置，允许或拒绝基于允许的域的请求。我们特别用于服务器端请求，这些请求受到 CORS 规则的约束：

```go
func UserCreate(w http.ResponseWriter, r *http.Request) {

 w.Header().Set("Access-Control-Allow-Origin", "*")
 for _, domain := range PermittedDomains {
 fmt.Println("allowing", domain)
 w.Header().Set("Access-Control-Allow-Origin", domain)
  }
```

这也可以由中间件处理，因为它不需要基于请求类型的任何自定义。在我们希望设置允许的域的任何请求中，我们可以将这段代码移到中间件中。

总的来说，这代表了良好的代码设计，但有时候没有自定义中间件处理程序可能会有些棘手。

中间件的一种流行方法是链接，工作原理如下：

```go
firstFunction().then(nextFunction()).then(thirdFunction())
```

这在 Node.js 世界中非常常见，`next()`、`then()`和`use()`函数在代码中广泛使用。在 Go 中也可以做到这一点。

有两种主要方法。第一种是在处理程序中包装处理程序。这通常被认为是丑陋的，不被推荐。

处理返回到其父级的包装处理程序函数可能会很难解析。

因此，让我们来看看第二种方法：链接。有许多框架包括中间件链接，但引入一个重型框架仅仅是为了中间件链接是不必要的。让我们看看如何在 Go 服务器中直接实现这一点：

```go
package main

import
(
  "fmt"
  "net/http"
)

func PrimaryHandler(w http.ResponseWriter, r *http.Request) {
  fmt.Fprintln(w, "I am the final response")
}

func MiddlewareHandler(h http.HandlerFunc) http.HandlerFunc {
  fmt.Println("I am middleware")
  return func(w http.ResponseWriter, r *http.Request) {
    h.ServeHTTP(w, r)
  }
}

func middleware(ph http.HandlerFunc, middleHandlers ..func(http.HandlerFunc) (http.HandlerFunc) ) http.HandlerFunc {
  var next http.HandlerFunc = ph
  for _, mw := range middleHandlers {
    next = mw(ph)
  }
  return next
}

func main() {
  http.HandleFunc("/middleware", middleware(PrimaryHandler,MiddlewareHandler))
  http.ListenAndServe(":9000",nil)
}
```

正如前面提到的，在我们的代码和大多数基于服务器的应用程序中，中间件将非常有帮助。在本章后面，我们将看看如何将我们的认证模型移入中间件，以减少我们在处理程序中进行的重复调用。

然而，出于性能考虑，这种类型的中间件的另一个功能可以用作缓存查找的阻塞机制。如果我们想要避免`GET`请求中的潜在瓶颈，我们可以在请求和响应之间放置一个缓存层。

我们正在使用关系数据库，这是网络瓶颈最常见的来源之一；因此，在接受过时或不经常更改的内容是可以接受的情况下，将查询结果放在这样的屏障后面可以大大提高我们 API 的整体性能。

鉴于我们有两种主要类型的请求可以以不同的方式从中间件中受益，我们应该规定我们将如何处理各种请求的中间件策略。

以下图表是我们如何设计中间件的模型。它可以作为一个基本指南，指导我们在哪里为特定类型的 API 调用实现特定的中间件处理程序：

使用中间件减少冗余

所有请求都应该受到一定程度的速率限制，即使某些请求的限制比其他请求高得多。因此，`GET`、`PUT`、`POST`和`DELETE`请求将在每个请求上至少通过一个中间件。

任何其他动词的请求（例如`OPTIONS`）应该绕过这一点。

`GET`请求应该受到缓存的影响，我们也将其描述为使它们返回的数据在一定程度上可以过时。

另一方面，显然不能对 PUT、POST 和 DELETE 请求进行缓存，因为这要么会导致我们的响应不准确，要么会导致重复尝试创建或删除数据。

让我们从`GET`请求开始，看看我们可以绕过瓶颈的两种相关方式，当可能提供服务器缓存的结果而不是访问我们的关系数据库时。

## 缓存请求

当然，有不止一种或两种方法可以在任何给定请求的生命周期内引入缓存。我们将在本节中探讨其中一些方法，以引入最高级别的非冗余缓存。

在脚本或浏览器级别有客户端缓存，它明显受到从服务器端发送给它的规则的约束。我们指的是遵守 HTTP 响应头，比如`Cache-Control`、`Expires`、`If-None-Match`、`If-Modified-Since`等等。

这些是您可以强制执行的最简单的缓存控制形式，它们也是作为 RESTful 设计的重要部分。然而，它们也有点脆弱，因为它们不允许对这些指令进行任何强制执行，并且客户端可以轻易地忽略它们。

接下来是基于代理的缓存——通常是第三方应用程序，它们要么提供任何给定请求的缓存版本，要么通过到原始服务器应用程序。我们在谈论在 API 前面使用 Apache 或 Nginx 时，已经提到了这个的前身。

最后，在应用程序级别有服务器级别的缓存。这通常是代理缓存的替代，因为两者往往遵循相同的规则集。在大多数情况下，诉诸于独立的代理缓存是最明智的选择，但有时这些解决方案无法适应特定的边缘情况。

从头开始设计这些也有一定的价值，以更好地理解代理缓存的缓存策略。让我们简要地看一下如何在基于磁盘和基于内存的方式上为我们的社交网络构建服务器端应用程序缓存，并看看我们如何利用这一经验来更好地定义代理级别的缓存规则。

## 简单的基于磁盘的缓存

不久以前，大多数开发人员处理缓存请求的方式通常是通过应用程序级别的磁盘缓存。

在这种方法中，围绕任何给定请求的缓存机制和限定条件设置了一些参数。然后，请求的结果被保存到一个字符串，然后保存到一个锁文件中。最后，锁文件被重命名。这个过程相当稳定，尽管有些过时，但足够可靠。

在 Web 早期，有一些不可逾越的缺点。

请注意，磁盘，特别是机械磁盘，一直以来都以存储和访问速度慢而著称，并且在查找、发现和排序方面很可能会导致文件系统和操作系统操作出现许多问题。

分布式系统也带来了一个明显的挑战，即需要共享缓存以确保平衡请求的一致性。如果服务器 A 更新其本地缓存，并且下一个请求从服务器 B 返回了缓存命中，您会看到根据服务器的不同而产生不同的结果。使用网络文件服务器可能会减少这种情况，但它会引入一些权限和网络延迟的问题。

另一方面，没有什么比将请求的版本保存到文件更简单。这个特点，再加上磁盘缓存在编程的其他领域中有着悠久的历史，使它成为一个自然的早期选择。

此外，完全公平地说磁盘缓存的时代已经结束也并不合适。更快的驱动器，通常是固态硬盘，重新打开了使用非短暂存储进行快速访问的潜力。

让我们快速看一下如何为我们的 API 设计一个基于磁盘的缓存中间件解决方案，以减少高流量中的负载和瓶颈。

首先要考虑的是要缓存什么。出于明显的原因，我们绝不希望允许`PUT`、`POST`和`DELETE`请求进行缓存，因为我们既不希望数据重复，也不希望`DELETE`或`POST`请求出现错误响应，表明资源已经被创建或删除，而实际上并没有。

因此，我们知道我们只缓存`GET`请求或数据列表。这是我们唯一的数据，可以在某种程度上过时，而不会对应用程序的运行方式产生重大变化。

让我们从我们最基本的请求`/api/users`开始，它返回我们系统中用户的列表，并引入一些用于将数据缓存到磁盘的中间件。让我们将其设置为一个框架，以解释我们如何评估：

```go
package diskcache

import
(
)

type CacheItem struct {

}
```

我们的`CacheItem`结构是包中唯一真正的元素。它包括一个有效的缓存命中（以及关于缓存元素的最后修改时间、内容等信息）或一个缓存未命中。缓存未命中将返回给我们的 API，要么该项不存在，要么已经超过了生存时间（TTL）。在这种情况下，`diskcache`包将把缓存设置为文件：

```go
func SetCache() {

}
```

这就是我们将要做的。如果一个请求没有缓存的响应，或者缓存无效，我们需要获取结果，以便保存它。这使得中间件部分有点棘手，但我们很快会向您展示如何处理这个问题。以下的`GetCache()`函数查找我们的缓存目录，找到并返回一个缓存项（无论是否有效），或者产生一个 false 值：

```go
func GetCache() (bool, CacheItem) {

}
```

以下的`Evaluate()`函数将是我们的主要入口点，传递给`GetCache()`，可能稍后还会传递给`SetCache()`，如果我们需要创建或重新创建缓存条目的话：

```go
func Evaluate(context string, value string, in ...[]string) (bool, CacheItem) {

}
```

在这个结构中，我们将利用上下文（以便我们可以区分请求类型）、结果值（用于保存）和一个开放的字符串可变参数，我们可以用作缓存条目的限定符。我们指的是强制生成唯一缓存文件的参数。比如，我们指定`page`和`search`作为这样的限定符。第 1 页的请求将与第 2 页的请求不同，并且它们将被分别缓存。搜索 Nathan 的第 1 页请求将与搜索 Bob 的第 1 页请求不同，依此类推。

这一点对硬文件来说非常严格，因为我们需要以一种可靠和一致的方式命名（和查找）我们的缓存文件，但当我们将缓存保存在数据存储中时，这也很重要。

考虑到所有这些，让我们来看看我们如何区分可缓存的条目

### 启用过滤

目前我们的 API 不接受任何特定参数来对我们的`GET`请求进行过滤，这些请求返回实体列表或实体的特定详细信息。例如，用户列表、状态更新列表或关系列表。

您可能会注意到我们的`UsersRetrieve()`处理程序目前根据`start`值和`limit`值返回下一页。目前这是在`start`值为`0`和`limit`值为`10`的情况下硬编码的。

此外，我们设置了一个`Pragma: no-cache`头。显然我们不希望这样。因此，为了进行缓存准备，让我们添加一些额外的字段，客户端可以使用这些字段来查找他们想要的特定用户。

第一个是起始值和限制值，它决定了一种分页。我们现在有的是这样的：

```go
  start := 0
  limit := 10

  next := start + limit
```

首先让我们通过接受一个起始值来使其对请求做出响应：

```go
  start := 0
  if len(r.URL.Query()["start"]) > 0 {
    start = r.URL.Query()["start"][0]
  }
  limit := 10
  if len(r.URL.Query()["limit"]) > 0 {
    start = r.URL.Query()["limit"][0]
  }
  if limit > 50 {
    limit = 50
  }
```

现在，我们可以接受一个起始值和一个限制值。请注意，我们还对我们将返回的结果数量进行了限制。任何超过 50 的结果都将被忽略，最多返回 50 个结果。

### 将磁盘缓存转换为中间件

现在我们将把`diskcache`的框架转换为中间件调用，并开始加速我们的`GET`请求：

```go
package diskcache

import
(
  "errors"
  "io/ioutil"
  "log"
  "os"
  "strings"
  "sync"
  "time"
)

const(
 CACHEDIR = "/var/www/cache/"
)
```

这显然代表了缓存文件的严格位置，但它也可以分成基于上下文的子目录，例如，在这种情况下，我们的 API 端点。因此，`/api/users`在`GET`请求中将映射到`/var/www/cache/users/get/.`这样可以减少单个目录中的数据量：

```go
var MaxAge int64  = 60
var(
  ErrMissingFile = errors.New("File Does Not Exist")
  ErrMissingStats = errors.New("Unable To Get File Stats")
  ErrCannotWrite = errors.New("Cannot Write Cache File")
  ErrCannotRead = errors.New("Cannot Read Cache File")
)

type CacheItem struct {
  Name string
  Location string
  Cached bool
  Contents string
  Age int64
}
```

我们通用的`CacheItem`结构由文件名、物理位置、以秒为单位的年龄和内容组成，如下面的代码中所述：

```go
func (ci *CacheItem) IsValid(fn string) bool {
  lo := CACHEDIR + fn
  ci.Location = lo

  f, err := os.Open(lo)
  defer f.Close()
  if err != nil {
    log.Println(ErrMissingFile)
    return false
  }

  st, err := f.Stat()
  if err != nil {
    log.Println(ErrMissingStats)
    return false
  }

  ci.Age := int64(time.Since(st.ModTime()).Seconds())
  return (ci.Age <= MaxAge)
}
```

我们的`IsValid()`方法首先确定文件是否存在且可读，如果它的年龄超过`MaxAge`变量。如果无法读取或者它太旧，那么我们返回 false，这告诉我们的`Evaluate()`入口创建文件。否则，我们返回 true，这将指示`Evaluate()`函数执行对现有缓存文件的读取。

```go
func (ci *CacheItem) SetCache() {
  f, err := os.Create(ci.Location)
  defer f.Close()
  if err != nil {
    log.Println(err.Error())
  } else {
    FileLock.Lock()
    defer FileLock.Unlock()
    _, err := f.WriteString(ci.Contents)
    if err != nil {
      log.Println(ErrCannotWrite)
    } else {
      ci.Age = 0
    }
  }
  log.Println(f)
}
```

在我们的导入部分，您可能会注意到调用了`sync`包；`SetCache()`应该在生产中至少利用互斥锁来对文件操作进行加锁。我们使用`Lock()`和`Unlock()`（在延迟中）来处理这个问题。

```go
func (ci *CacheItem) GetCache() error {
  var e error
  d, err := ioutil.ReadFile(ci.Location)
  if err == nil {
    ci.Contents = string(d)
  }
  return err
}

func Evaluate(context string, value string, expireAge int64, qu ...string) (error, CacheItem) {

  var err error
  var ci CacheItem
  ci.Contents = value
  ci.Name = context + strings.Join(qu,"-")
  valid := ci.IsValid(ci.Name)
```

请注意，这里的文件名是通过连接`qu`可变参数中的参数生成的。如果我们想要对此进行微调，我们需要按字母顺序对参数进行排序，这将防止缓存丢失，如果参数以不同的顺序提供。

由于我们控制了起始调用，所以风险较低。然而，由于这是作为一个共享库构建的，因此行为应该是相当一致的。

```go
  if !valid {
    ci.SetCache()
    ci.Cached = false
  } else {
    err = ci.GetCache()
    ci.Cached = true
  }

  return err, ci
}
```

我们可以使用一个简单的示例来测试这一点，该示例只是按值写文件：

```go
package main

import
(
  "fmt"
  "github.com/nkozyra/api/diskcache"
)

func main() {
  err,c := diskcache.Evaluate("test","Here is a value that will only live for 1 minute",60)
  fmt.Println(c)
  if err != nil {
    fmt.Println(err)
  }
  fmt.Println("Returned value is",c.Age,"seconds old")
  fmt.Println(c.Contents)
}
```

如果我们运行这个，然后改变`这里是一个值...`的值，并在 60 秒内再次运行它，我们将得到我们的缓存值。这表明我们的 diskcache 包保存并返回值，而不会触及可能成为后端瓶颈的内容。

因此，现在让我们在`UsersRetrieve()`处理程序前面加上一些可选参数。通过将我们的缓存设置为`page`和`search`作为可缓存的参数，我们将减轻对数据库的基于负载的影响。

## 分布式内存中的缓存

与基于磁盘的缓存类似，尽管这仍然是磁盘缓存的一个有用替代，但我们在简单的内存缓存中仍然受限于单个实体键。

用类似 Memcache(d)的东西替换磁盘将使我们能够非常快速地检索，但在键方面不会给我们带来任何好处。此外，大量重复的潜力意味着我们的内存存储通常比物理存储小，可能会成为一个问题。

然而，有许多方法可以潜入内存或分布式内存缓存。我们不会向您展示这种可替换的方法，但是通过与 NoSQL 解决方案的衔接，您可以轻松地将两种类型的缓存转换为严格的仅内存缓存选项。

## 使用 NoSQL 作为缓存存储

与 Memcache(d)不同，使用数据存储或数据库，我们可以根据非链接参数进行更复杂的查找。

例如，在我们的`diskcache`包中，我们将参数（如`page`和`search`）链接在一起，这样我们的键（在这种情况下是文件名）就变成了`getusers_1_nathan.cache`。

这些键以一种一致可靠的方式生成以进行查找是至关重要的，因为任何更改都会导致缓存未命中而不是预期的命中，我们将需要重建我们的缓存请求，这将完全消除预期的好处。

对于数据库，我们可以对缓存请求进行非常详细的列查找，但是，考虑到关系数据库的性质，这并不是一个好的解决方案。毕竟，我们构建缓存层是非常具体的，以避免命中常见瓶颈，如关系数据库管理系统。

为了举例，我们将再次利用 MongoDB 来编译和查找我们的缓存文件，以实现高吞吐量和可用性，并具有参数相关查询所提供的额外灵活性。

在这种情况下，我们将添加一个基本文档，其中只有一个页面、搜索、内容和一个修改字段。最后一个字段将作为我们的时间戳进行分析。

尽管`page`看起来是一个明显的整数字段，但我们将其在 MongoDB 中创建为字符串，以避免在进行查询时进行类型转换。

```go
package memorycache
```

出于明显的原因，我们将其称为`memorycache`，而不是 memcache，以避免任何潜在的混淆。

```go
import
(
  "errors"
  "log"
  mgo "gopkg.in/mgo.v2"
  bson "gopkg.in/mgo.v2/bson"
  _ "strings"
  "sync"
  "time"
)
```

我们用 MongoDB 的包替换了任何基于操作系统和磁盘的包。BSON 包也包含在内，作为进行特定的`Find()`请求的一部分。

### 提示

在生产环境中，当寻找一个键值存储或内存存储用于这样的意图时，应该注意解决方案的锁定机制及其对读/写操作的影响。

```go
const(
  MONGOLOC = "localhost"
)

var MaxAge int64  = 60
var Session mgo.Session
var Collection *mgo.Collection

var(
  ErrMissingFile = errors.New("File Does Not Exist")
  ErrMissingStats = errors.New("Unable To Get File Stats")
  ErrCannotWrite = errors.New("Cannot Write Cache File")
  ErrCannotRead = errors.New("Cannot Read Cache File")

  FileLock sync.RWMutex
)

type CacheItem struct {
  Name string
  Location string
  Contents string
  Age int64
  Parameters map[string] string
}
```

值得注意的是，MongoDB 具有数据过期的生存时间概念。这可能消除了手动过期内容的必要性，但在替代存储平台上可能无法使用。

```go
type CacheRecord struct {
  Id bson.ObjectId `json:"id,omitempty" bson:"_id,omitempty"`
  Page string
  Search string
  Contents string
  Modified int64
}
```

请注意`CacheRecord`结构中的文字标识符；这些允许我们自动生成 MongoDB ID。如果没有这个，MongoDB 将抱怨`_id_`上的重复索引。以下的`IsValid()`函数实际上返回了有关我们的`diskcache`包中文件的信息。在`memorycache`版本中，我们只会返回一个信息，即请求的年龄内是否存在记录。

```go
func (ci *CacheItem) IsValid(fn string) bool {
  now := time.Now().Unix()
  old := now - MaxAge

  var cr CacheRecord
  err := Collection.Find(bson.M{"page":"1", "modified": bson.M{"$gt":old} }).One(&cr)
  if err != nil {
    return false
  } else {
    ci.Contents = cr.Contents
    return true
  }

  return false
}
```

还要注意，我们没有删除旧记录。这可能是保持缓存记录敏捷的逻辑下一步。

```go
func (ci *CacheItem) SetCache() {
  err := Collection.Insert(&CacheRecord{Id: bson.NewObjectId(), Page:ci.Parameters["page"],Search:ci.Parameters["search"],Contents:ci.Contents,Modified:time.Now().Unix()})
  if err != nil {
    log.Println(err.Error())
  }
}
```

无论我们是否找到记录，我们都会在前面的代码中插入一个新记录。这使我们在查找时获得最新的记录，也使我们在某种程度上具有修订控制的意识。您还可以更新记录以避免修订控制。

```go
func init() {
  Session, err := mgo.Dial(MONGOLOC)
  if err != nil {
    log.Println(err.Error())
  }
  Session.SetMode(mgo.Monotonic, true)
  Collection = Session.DB("local").C("cache")
  defer Session.Ping()
}

func Evaluate(context string, value string, expireAge int64, param map[string]string) (error, CacheItem) {

  MaxAge = expireAge
  defer Session.Close()

  var ci CacheItem
  ci.Parameters = param
  ci.Contents = value
  valid := ci.IsValid("bah:")
  if !valid {
    ci.SetCache()
  }

  var err error

  return err, ci
}
```

这与`diskcache`的操作方式基本相同，只是我们在`param`哈希映射中提供键/值对，而不是无结构的参数名称列表。

因此，使用方法会有一些变化。这里有一个例子：

```go
package main

import
(
  "fmt"
  "github.com/nkozyra/api/memorycache"
)

func main() {
  parameters := make( map[string]string )
  parameters["page"] = "1"
  parameters["search"] = "nathan"
  err,c := memorycache.Evaluate("test","Here is a value that will only live for 1 minute",60,parameters)
  fmt.Println(c)
  if err != nil {
    fmt.Println(err)
  }
  fmt.Println("Returned value is",c.Age,"seconds old")
  fmt.Println(c.Contents)
}
```

当我们运行这个时，我们将在数据存储中设置我们的内容，这将持续 60 秒，然后变为无效，并在第二行重新创建缓存内容。

## 实施缓存作为中间件

为了将此缓存放置在我们所有`GET`请求的中间件链中，我们可以实现我们上面概述的策略并添加一个缓存中间件元素。

使用我们之前的示例，我们可以使用我们的`middleware()`函数在链的前面实现这一点：

```go
  Routes.HandleFunc("/api/users", middleware(DiskCache, UsersRetrieve, DiskCacheSave) ).Methods("GET")
```

这使我们能够在`UsersRetrieve()`函数之前执行`DiskCache()`处理程序。但是，如果我们没有有效的缓存，我们还希望保存我们的响应，因此我们还将在最后调用`DiskCacheSave()`。如果`DiskCache()`中间件处理程序接收到有效的缓存，它将阻止链。它的工作原理如下：

```go
func DiskCache(h http.HandlerFunc) http.HandlerFunc {
  start := 0
  q := r.URL.Query()
  if len(r.URL.Query()["start"]) > 0 {
    start = r.URL.Query()["start"][0]
  }
  limit := 10
  if len(r.URL.Query()["limit"]) > 0 {
    limit = q["limit"][0]
  }
  valid, check := diskcache.Evaluate("GetUsers", "", MaxAge, start, limit)
  fmt.Println("Cache valid",valid)
  if check.Cached  {
    return func(w http.ResponseWriter, r *http.Request) {
      fmt.Fprintln(w, check.Contents)
    }
  } else {
    return func(w http.ResponseWriter, r *http.Request) {
      h.ServeHTTP(w, r)
    }
  }
}
```

如果我们得到`check.Cached`为 true，我们只需提供内容。否则，我们继续。

在将内容传输到下一个函数之前，我们的主要函数需要进行一些小的修改：

```go
  r.CacheContents = string(output)
  fmt.Fprintln(w, string(output))
}
```

然后，`DiskCacheSave()`基本上可以是`DiskCache`的副本，只是它将从`http.Request`函数设置实际内容：

```go
func DiskCacheSave(h http.HandlerFunc) http.HandlerFunc {
  start := 0
  if len(r.URL.Query()["start"]) > 0 {
    start = r.URL.Query()["start"][0]
  }
  limit := 10
  if len(r.URL.Query()["limit"]) > 0 {
    start = r.URL.Query()["limit"][0]
  }
  valid, check := diskcache.Evaluate("GetUsers", r.CacheContents, MaxAge, start, limit)
  fmt.Println("Cache valid",valid)
  return func(w http.ResponseWriter, r *http.Request) {
    h.ServeHTTP(w, r)
  }

}
```

## 在 Go 前面使用前端缓存代理

我们工具箱中的另一个工具是利用前端缓存代理（就像我们在第七章中所做的那样，*使用其他 Web 技术*）作为我们面向请求的缓存层。

除了传统的 Web 服务器，如 Apache 和 Nginx，我们还可以使用专门用于缓存的服务，这些服务可以替代、放在前面或与上述服务器并行使用。

在不深入研究这种方法的情况下，我们可以从应用程序外部复制一些功能，以获得更好的性能。如果我们至少不提及这一点，那就不够完整。像 Nginx、Varnish、Squid 和 Apache 这样的工具都具有反向代理服务器的内置缓存。

对于生产级部署，这些工具可能更成熟，更适合处理这种级别的缓存。

### 提示

您可以在[`nginx.com/resources/admin-guide/caching/`](http://nginx.com/resources/admin-guide/caching/)找到有关 Nginx 和反向代理缓存的更多信息。

Varnish 和 Squid 都主要用于在这个级别进行缓存。有关 Varnish 和 Squid 的更多详细信息，可以在[`www.varnish-cache.org/`](https://www.varnish-cache.org/)和[`www.squid-cache.org/`](http://www.squid-cache.org/)找到。

# 在 Go 中进行速率限制

向我们的 API 引入缓存可能是展示有效中间件策略的最简单方法。我们现在能够减轻重负流量的风险，并朝着

在 Web 服务中，这种中间件功能特别有用的地方是速率限制。

在具有高流量的 API 中存在速率限制，以允许消费者使用应用程序而不会滥用它。在这种情况下，滥用可能只是指可能影响性能的过度访问，或者可能意味着为大规模数据获取创建障碍。

通常，人们会利用 API 来创建整个数据集的本地索引，通过 API 有效地爬取网站。对于大多数应用程序，您将希望阻止这种访问。

在任何一种情况下，对我们应用程序中的某些请求施加一些速率限制是有意义的。并且，重要的是，我们希望这足够灵活，以便我们可以根据请求时间使用不同的限制。

我们可以使用许多因素来实现这一点，但最常见的两种方法如下：

+   通过相应的 API 用户凭据

+   通过请求的 IP 地址

理论上，我们也可以通过每个代理发出请求来对底层用户引入速率限制。在现实世界的情况下，这将减少第三方应用因其用户使用而受到惩罚的风险。

重要的因素是，在深入研究更复杂的调用之前，我们发现速率限制已超出标记，因为我们希望在速率限制已超出的那一点精确地打破中间件链。

对于这个速率限制中间件示例，我们将再次使用 MongoDB 作为请求存储，并基于从午夜到午夜的日历日进行限制。换句话说，我们每个用户的限制每天在凌晨 12:01 重置。

存储实际请求只是一种方法。我们也可以从 Web 服务器日志中读取或将它们存储在内存中。然而，最轻量级的方法是将它们保存在数据存储中。

```go
package ratelimit

import
(
  "errors"
  "log"
  mgo "gopkg.in/mgo.v2"
  bson "gopkg.in/mgo.v2/bson"
  _ "strings"
  "time"
)

const(
  MONGOLOC = "localhost"
)
```

这只是我们的 MongoDB 主机或主机。在这里，我们有一个结构，用于定义日历日的开始和结束的边界：

```go
type Requester struct {
  Id bson.ObjectId `json:"id,omitempty" bson:"_id,omitempty"`
  IP string
  APIKey string
  Requests int
  Timestamp int64
  Valid bool
}

type DateBounds struct {
  Start int64
  End int64
}
```

以下的`CreateDateBounds()`函数计算今天的日期，然后将`86400`秒添加到返回的`Unix()`值（实际上是 1 天）。

```go
var (
  MaxDailyRequests = 15
  TooManyRequests = errors.New("You have exceeded your daily limit of requests.")
  Bounds DateBounds
  Session mgo.Session
  Collection *mgo.Collection
)

func createDateBounds() {
  today := time.Now()
  Bounds.Start = time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, time.UTC).Unix()
  Bounds.End = Bounds.Start + 86400
}
```

通过以下的`RegisterRequest()`函数，我们只是简单地记录了对 API 的另一个请求。同样，我们只是将请求绑定到 IP，添加认证密钥、用户 ID 或

```go
func (r *Requester) CheckDaily() {

  count, err := Collection.Find(bson.M{"ip": r.IP, "timestamp": bson.M{"$gt":Bounds.Start, "$lt":Bounds.End } }).Count()
  if err != nil {
    log.Println(err.Error())
  }
  r.Valid = (count <= MaxDailyRequrests)
}

func (r Requester) RegisterRequest() {
  err := Collection.Insert(&Requester{Id: bson.NewObjectId(), IP: r.IP, Timestamp: time.Now().Unix()})
  if err != nil {
    log.Println(err.Error())
  }

}
```

以下代码是一个简单的标准初始化设置，除了`createDateBounds()`函数，它只是设置了我们查找的开始和结束：

```go
func init() {
  Session, err := mgo.Dial(MONGOLOC)
  if err != nil {
    log.Println(err.Error())
  }
  Session.SetMode(mgo.Monotonic, true)
  Collection = Session.DB("local").C("requests")
  defer Session.Ping()
  createDateBounds()
}
```

以下的`CheckRequest()`函数充当整个过程的协调函数；它确定任何给定请求是否超过了每日限制，并返回`Valid`状态属性：

```go
func CheckRequest(ip string) (bool) {
  req := Requester{ IP: ip }
  req.CheckDaily()
  req.RegisterRequest()

  return req.Valid
}
```

## 实施速率限制作为中间件

与缓存系统不同，将速率限制器转换为中间件要容易得多。要么 IP 地址受到速率限制，要么没有，我们继续进行。

以下是更新用户的示例：

```go
  Routes.HandleFunc("/api/users/{id:[0-9]+}", middleware(RateLimit,UsersUpdate)).Methods("PUT")
```

然后，我们可以引入一个`RateLimit()`中间件调用：

```go
func RateLimit(h http.HandlerFunc) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    if (ratelimit.CheckRequest(r.RemoteAddr) == false {
      fmt.Fprintln(w,"Rate limit exceeded")
    } else {
      h.ServeHTTP(w,r)
    }
  }
}
```

这使我们能够在我们的`ratelimit.CheckRequest()`调用失败时阻止中间件链，并防止调用 API 的更多处理密集型部分。

# 实施 SPDY

如果有一件事你可以说谷歌庞大的产品、平台和语言生态系统，那就是它们都有一个永恒的、一致的关注点——对速度的需求。

### 注意

我们在第七章中简要提到了 SPDY 伪协议，*使用其他 Web 技术*。您可以从其白皮书[`www.chromium.org/spdy/spdy-whitepaper`](http://www.chromium.org/spdy/spdy-whitepaper)中了解更多关于 SPDY 的信息。

随着谷歌（搜索引擎）从一个学生项目迅速发展成为地球上最受欢迎的网站，成为人们发现任何事物的事实方式，产品及其基础设施的扩展变得至关重要。

而且，如果你仔细想想，这个搜索引擎非常依赖于网站的可用性；如果网站速度快，谷歌的蜘蛛和索引器将更快，结果也将更加及时。

其中很多都是谷歌的*让网络更快*活动背后的原因，该活动旨在通过认识到速度是主要考虑因素并朝着速度推进，来帮助后端和前端开发人员。

谷歌也是 SPDY 伪协议的背后推手，它增强了 HTTP 并作为一组改进的临时措施，其中许多改进正在被纳入 HTTP/2 的标准化。

有很多为 Go 编写的 SPDY 实现，SPDY 似乎是一个特别受欢迎的项目，因为它尚未直接在 Go 中支持。大多数实现都可以替换`net/http`中的`http`，在大多数实际情况下，你可以通过简单地将 SPDY 留给 HAProxy 或 Nginx 等反向代理来获得这些好处。

### 注意

以下是一些实现了安全和非安全连接的 SPDY 实现，值得一看并进行比较：

Solomon Hykes 的`spdy.go`文件：[`github.com/shykes/spdy-go`](https://github.com/shykes/spdy-go)

Jamie Hall 的`spdy`文件：[`github.com/SlyMarbo`](https://github.com/SlyMarbo)

我们首先来看一下前面列表中的`spdy.go`。切换我们的`ListenAndServe`函数是最简单的第一步，这种实现 SPDY 的方法是相当常见的。

以下是如何在我们的`api.go`文件中使用`spdy.go`作为一个可替换的方法：

```go
  wg.Add(1)
  go func() {
    //http.ListenAndServeTLS(SSLport, "cert.pem", "key.pem", Routes)
    spdy.ListenAndServeTLS(SSLport, "cert.pem", "key.pem", Routes)
    wg.Done()
  }()
```

相当简单，是吧？一些 SPDY 实现通过 SPDY 协议提供页面，而不是`HTTP/HTTPS`，在语义上是无法区分的。

对于一些 Go 开发者来说，这被视为一种惯用的方法。对于其他人来说，这些协议的差异足够大，以至于有单独的语义是合乎逻辑的。在这里的选择取决于您的偏好。

然而，还有一些其他考虑因素需要考虑。首先，SPDY 引入了一些我们可以利用的附加功能。其中一些是内置的，比如头部压缩。

## 检测 SPDY 支持

对于大多数客户端来说，检测 SPDY 并不是需要过多担心的事情，因为 SPDY 支持依赖于 TLS/SSL 支持。

# 总结

在本章中，我们讨论了一些对高性能 API 非常重要的概念。这些主要包括通过自定义中间件执行的速率限制和磁盘和内存缓存。

利用本章中的示例，您可以实现任意数量的依赖中间件的服务，以保持代码清晰，并引入更好的安全性、更快的响应时间和更多功能。

在接下来的最后一章中，我们将专注于安全特定的概念，这些概念应该锁定额外的关注点，包括速率限制、拒绝服务检测，以及减轻和预防代码和 SQL 注入的尝试。


# 第十一章：安全

在我们开始本章之前，绝对必要指出一件事——尽管安全是本书最后一章的主题，但它不应该是应用程序开发的最终步骤。在开发任何 Web 服务时，安全性应该在每一步骤中得到重视。通过在设计时考虑安全性，您可以限制应用程序启动后进行自上而下的安全审计的影响。

话虽如此，这里的意图是指出一些更大更猖獗的安全漏洞，并探讨我们如何使用标准的 Go 和一般安全实践来减轻它们对我们的 Web 服务的影响。

当然，Go 提供了一些出色的安全功能，它们被伪装成纯粹的良好编程实践。使用所有包和处理所有错误不仅有助于养成良好的习惯，而且还有助于确保应用程序的安全。

然而，没有一种语言可以提供完美的安全性，也无法阻止你自己给自己惹麻烦。事实上，最具表现力和实用性的语言往往使这变得尽可能容易。

在开发自己的设计与使用现有包（就像我们在整本书中所做的那样）之间也存在很大的权衡，无论是用于身份验证、数据库接口还是 HTTP 路由或中间件。前者可以提供快速解决方案，并减少错误和安全漏洞的曝光。

通过构建自己的应用程序，还可以提供一些安全性，但对安全更新的迅速响应以及整个社区的目光都胜过一个较小的闭源项目。

在本章中，我们将看到：

+   处理安全目的的错误日志记录

+   防止暴力尝试

+   记录身份验证尝试

+   输入验证和注入缓解

+   输出验证

最后，我们将看一些生产就绪的框架，以了解它们处理 API 和 Web 服务集成以及相关安全性的方式。

# 处理安全目的的错误日志记录

在通往安全应用程序的道路上，关键的一步是使用全面的日志记录。您拥有的数据越多，就越能分析潜在的安全漏洞，并了解应用程序的使用方式。

即使如此，“记录所有”方法可能有些难以利用。毕竟，如果你有所有的干草，找到其中的针可能会特别困难。

理想情况下，我们希望将所有错误记录到文件，并具有将其他类型的一般信息（例如与用户和/或 IP 地址相关的 SQL 查询）分隔的能力。

在下一节中，我们将看一下记录身份验证尝试，但仅在内存/应用程序的生命周期中，以便检测暴力尝试。更广泛地使用日志包可以让我们保持对这些尝试的更持久的记录。

创建日志输出的标准方法是简单地设置一般日志`Logger`的输出，就像这样：

```go
dbl, err := os.OpenFile("errors.log", os.O_CREATE | os.RDWR | os.O_APPEND, 0666)
  if err != nil {
    log.Println("Error opening/creating database log file")
  }
defer dbl.Close()

log.SetOutput(dbl)
```

这使我们能够指定一个新文件，而不是我们默认的`stdout`类，用于记录我们的数据库错误，以便以后分析。

然而，如果我们想要为不同的错误（例如数据库错误和身份验证错误）创建多个日志文件，我们可以将它们分成单独的记录器：

```go
package main

import (
  "log"
  "os"
)

var (
  Database       *log.Logger
  Authentication *log.Logger
  Errors         *log.Logger
)

func LogPrepare() {
  dblog, err := os.OpenFile("database.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
  if err != nil {
    log.Println(err)
  }
  authlog, err := os.OpenFile("auth.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
  if err != nil {
    log.Println(err)
  }
  errlog, err := os.OpenFile("errors.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
  if err != nil {
    log.Println(err)
  }

  Database = log.New(dblog, "DB:", log.Ldate|log.Ltime)
  Authentication = log.New(authlog, "AUTH:", log.Ldate|log.Ltime)
  Errors = log.New(errlog, "ERROR:", log.Ldate|log.Ltime|log.Lshortfile)
}
```

在这里，我们使用特定格式为我们的日志文件实例化单独的记录器：

```go
func main() {
  LogPrepare()

  Database.Println("Logging a database item")
  Authentication.Println("Logging an auth attempt item")
  Errors.Println("Logging an error")

}
```

通过以这种方式为应用程序的各个元素构建单独的日志，我们可以分而治之地进行调试过程。

关于记录 SQL，我们可以利用`sql.Prepare()`函数，而不是使用`sql.Exec()`或`sql.Query()`在执行之前保留对查询的引用。

`sql.Prepare()`函数返回一个`sql.Stmt`结构，而查询本身，由变量 query 表示，不会被导出。但是，您可以在日志文件中使用结构的值本身：

```go
  d, _ := db.Prepare("SELECT fields FROM table where column=?")
  Database.Println(d)
```

这将在日志文件中留下查询的详细账户。为了获得更多细节，IP 地址可以附加到`Stmt`类以获取更多信息。

将每个交易查询存储到文件中可能会对性能产生影响。将其限制为修改数据的查询和/或短时间内将允许您识别安全性潜在问题。

### 注意

有一些第三方库可以进行更强大和/或更漂亮的记录。我们最喜欢的是 go-logging，它实现了多种输出格式、分区调试桶和具有吸引人的格式的可扩展错误。您可以在[`github.com/op/go-logging`](https://github.com/op/go-logging)上阅读更多信息，或通过`go get github.com/op/go-logging`命令下载文档。

# 防止暴力破解尝试

也许是绕过任何给定系统安全性的最常见、最低级别的尝试是暴力破解方法。

从攻击者的角度来看，这是有道理的。如果应用程序设计者允许无限次数的登录尝试而不受惩罚，那么这个应用程序执行良好的密码创建策略的可能性就很低。

这使得它成为一个特别容易受攻击的应用程序。即使密码规则已经制定，仍然有可能使用字典攻击来获取登录权限。

一些攻击者会查看彩虹表以确定哈希策略，但这至少在某种程度上被每个帐户使用唯一的盐所缓解。

实际上，在线下时代，暴力登录攻击通常更容易，因为大多数应用程序没有流程来自动检测和锁定使用无效凭据的帐户访问尝试。他们本来可以这样做，但那么也需要有一个检索权限流程——类似于“给我发邮件我的密码”。

对于像我们的社交网络这样的服务，锁定帐户或在一定程度后暂时禁用登录是非常有意义的。

第一个是一种更激进的方法，需要直接用户操作来恢复帐户；通常，这也需要更大的支持系统。

后者是有益的，因为它通过大大减慢尝试的速度来阻止暴力破解尝试，并使大多数攻击在实际目的上变得无用，而不一定需要用户操作或支持来恢复访问。

## 知道要记录什么

在记录日志时最难的事情之一是决定你需要知道什么。有几种方法可以做到这一点，从记录所有内容到仅记录致命错误。所有这些方法都伴随着自己的潜在问题，这在很大程度上取决于错过一些数据和浏览不可能的数据之间的权衡。

我们需要考虑的第一个问题是我们应该在内存中记录什么——只有失败的身份验证或针对 API 密钥和其他凭据的尝试。

记录针对不存在用户的登录尝试也可能是明智的。这将告诉我们，有人很可能在对我们的网络服务进行不正当的操作。

接下来，我们将希望设置一个较低的阈值或登录尝试的最大次数，然后再采取行动。

让我们首先介绍一个`bruteforcedetect`包：

```go
package bruteforcedetect

import
(
)

var MaxAttempts = 3
```

我们可以直接将其设置为一个包变量，并在必要时从调用应用程序中进行修改。三次尝试可能比我们希望的一般无效登录阈值要低，特别是自动禁止 IP 的情况：

```go
type Requester struct {
  IP string
  LoginAttempts int
  FailedAttempts int
  FailedInvalidUserAttempts int
}
```

我们的`Requester`结构将维护与任何给定 IP 或主机名相关的所有增量值，包括一般的登录尝试、失败的尝试以及请求的用户实际上并不存在于我们的数据库中的失败尝试：

```go
func Init() {

}

func (r Requester) Check() {

}
```

我们不需要将其作为中间件，因为它只需要对一件事情做出反应——认证尝试。因此，关于认证尝试的存储，我们有选择。在现实环境中，我们可能希望给这个过程更长的寿命。我们可以直接将这些尝试存储到内存中、数据存储中，甚至存储到磁盘中。

然而，在这种情况下，我们将通过创建`bruteforce.Requester`结构的映射，让这些数据仅存在于应用程序的内存空间中。这意味着如果我们的服务器重新启动，我们将丢失这些尝试。同样，这意味着多个服务器设置不一定会知道其他服务器上的尝试。

这两个问题都可以通过在记录错误尝试的背后放置更少的短暂存储来轻松解决，但是为了演示的简单性，我们将保持简单。

在我们的`api.go`文件中，我们将引入`bruteforce`并在启动应用程序时创建我们的`Requesters`映射：

```go
package main

import (
…
    "github.com/nkozyra/api/bruteforce"
)

var Database *sql.DB
var Routes *mux.Router
var Format string
var Logins map[string] bruteforce.Requester
```

然后，当我们的服务器启动时，当然要将这个从空映射变成一个初始化的映射：

```go
func StartServer() {

  LoginAttempts = make(map[string] bruteforce.Requester)
OauthServices.InitServices()
```

我们现在准备开始记录我们的尝试。

如果您决定为登录尝试实现中间件，在这里进行调整，只需将这些更改放入中间件处理程序中，而不是最初调用的名为`CheckLogin()`的单独函数。

无论我们的认证发生了什么——无论是有效的用户、有效的认证；有效的用户、无效的认证；还是无效的用户——我们都希望将其添加到相应的`Requester`结构的`LoginAttempts`函数中。

我们将每个`Requester`映射绑定到我们的 IP 或主机名。在这种情况下，我们将使用 IP 地址。

### 注意

`net`包有一个名为`SplitHostPort`的函数，可以正确地从`http.Request`处理程序中的`RemoteAddr`值中分解出来，如下所示：

```go
ip,_,_ := net.SplitHostPort(r.RemoteAddr)
```

您也可以只使用整个`r.RemoteAddr`值，这可能更全面：

```go
func CheckLogin(w http.ResponseWriter, r *http.Request) bool {
  if val, ok := Logins[r.RemoteAddr]; ok {
    fmt.Println("Previous login exists",val)
  } else {
    Logins[r.RemoteAddr] = bruteforce.Requester{IP: r.RemoteAddr, LoginAttempts:0, FailedAttempts: 0, FailedValidUserAttempts: 0, }
  }

  Logins[r.RemoteAddr].LoginAttempts += 1
```

这意味着无论如何，我们都会对总数进行另一次尝试。

由于`CheckLogin()`总是会在不存在时创建映射的键，我们可以在认证流程的后面安全地对这个键进行评估。例如，在我们的`UserLogin()`处理程序中，首先调用`UserLogin()`，然后再检查提交的值：

```go
func UserLogin(w http.ResponseWriter, r *http.Request) {

  w.Header().Set("Access-Control-Allow-Origin", "*")
  fmt.Println("Attempting User Login")

  Response := UpdateResponse{}
 CheckLogin(w,r)
```

如果我们在`CheckLogin()`调用之后检查最大的登录尝试次数，我们将永远不会在某一点之后允许数据库查找。

在`UserLogin()`函数的以下代码中，我们将提交的密码的哈希与数据库中存储的密码哈希进行比较，并在不成功匹配时返回错误。让我们使用它来增加`FailedAttempts`值：

```go
  if (dbPassword == expectedPassword) {
    // ...
  } else {
    fmt.Println("Incorrect password!")
    _, httpCode, msg := ErrorMessages(401)
    Response.Error = msg
    Response.ErrorCode = httpCode
    Logins[r.RemoteAddr].FailedAttempts = Logins[r.RemoteAddr].FailedAttempts + 1
    http.Error(w, msg, httpCode)
  }
```

这只是增加了我们的一般`FailedAttempts`整数值，每个 IP 的无效登录都会增加这个值。

然而，我们还没有对此做任何处理。为了将其作为一个阻塞元素注入，我们需要在`CheckLogin()`调用之后对其进行评估，以初始化映射的哈希（如果尚不存在）：

### 提示

在前面的代码中，您可能会注意到由`RemoteAddr`绑定的可变`FailedAttempts`值在理论上可能会受到竞争条件的影响，导致不自然的增加和过早的阻塞。可以使用互斥锁或类似的锁定机制来防止这种行为。

```go
func UserLogin(w http.ResponseWriter, r *http.Request) {

  w.Header().Set("Access-Control-Allow-Origin", "*")
  fmt.Println("Attempting User Login")

if Logins[r.RemoteAddr].Check() == false {
  return
}
```

这个对`Check()`的调用可以防止被禁止的 IP 地址甚至在登录端点访问我们的数据库，这仍然可能导致额外的压力、瓶颈和潜在的服务中断：

```go
  Response := UpdateResponse{}
  CheckLogin(w,r)
  if Logins[r.RemoteAddr].Check() == false {
    _, httpCode, msg := ErrorMessages(403)
    Response.Error = msg
    Response.ErrorCode = httpCode
    http.Error(w, msg, httpCode)
    return
  }
```

为了更新我们的`Check()`方法，以防止暴力攻击，我们将使用以下代码：

```go
func (r Requester) Check() bool {
  return r.FailedAttempts <= MaxAttempts
}
```

这为我们提供了一种短暂的方式来存储有关登录尝试的信息，但是如果我们想找出某人是否只是在测试帐户名和密码，比如“guest”或“admin”，该怎么办呢？

为此，我们只需在`UserLogin()`中添加额外的检查，以查看所请求的电子邮件帐户是否存在。如果存在，我们将继续。如果不存在，我们将增加`FailedInvalidUserAttempts`。然后我们可以决定是否应该在`UserLogin()`的登录部分下降到更低的阈值：

```go
  var dbPassword string
  var dbSalt string
  var dbUID int
  var dbUserCount int
  uexerr := Database.QueryRow("SELECT count(*) from users where user_email=?",email).Scan(&dbUserCount)
  if uexerr != nil {

  }
  if dbUserCount > 0 {
    Logins[r.RemoteAddr].FailedInvalidUserAttempts = Logins[r.RemoteAddr].FailedInvalidUserAttempts + 1
  }
```

如果我们决定流量由完全失败的身份验证尝试（例如，无效用户）表示，我们还可以将该信息传递给 IP 表或我们的前端代理，以阻止流量甚至到达我们的应用程序。

# 在 Go 中处理基本身份验证

在第七章中，我们没有深入研究身份验证部分，*与其他 Web 技术合作*，基本身份验证。这是值得讨论的安全问题，特别是它可以是一种非常简单的方式，允许身份验证代替 OAuth、直接登录（带会话）或密钥。即使在后者中，完全可以利用 API 密钥作为基本身份验证的一部分。

基本身份验证最关键的方面是一个显而易见的一点——**TLS**。与涉及传递密钥的方法不同，在基本身份验证标头方法中几乎没有混淆，除了 Base64 编码之外，一切基本上都是明文。

当然，这为恶意方提供了一些非常简单的中间人机会。

在第七章中，*与其他 Web 技术合作*，我们探讨了使用共享密钥创建交易密钥并通过会话存储有效身份验证的概念。

我们可以直接从“授权”标头中获取用户名和密码或 API 密钥，并通过在我们的`CheckLogin()`调用顶部包含对该标头的检查来测量对 API 的尝试：

```go
func CheckLogin(w http.ResponseWriter, r *http.Request) {
  bauth := strings.SplitN(r.Header["Authorization"][0], " ", 2)
  if bauth[0] == "Basic" {
    authdata, err := base64.StdEncoding.DecodeString(bauth[1])
    if err != nil {
      http.Error(w, "Could not parse basic auth", http.StatusUnauthorized)
      return
    }
      authparts := strings.SplitN(string(authdata),":",2)
      username := authparts[0]
      password := authparts[1]
    }else {
      // No basic auth header
    }
```

在这个例子中，我们可以允许我们的`CheckLogin()`函数利用要么从我们的 API 发布的数据来获取用户名和密码组合、API 密钥或身份验证令牌，要么我们也可以直接从标头中摄取这些数据。

# 处理输入验证和注入缓解

如果暴力攻击是一种相当不雅的坚持练习，攻击者没有访问、输入或注入攻击则相反。在这一点上，攻击者对应用程序有一定程度的信任，即使它很小。

SQL 注入攻击可以发生在应用程序管道的任何级别，但跨站点脚本和跨站点请求伪造更多地针对其他用户，而不是应用程序，针对漏洞暴露其数据或直接将其他安全威胁带到应用程序或浏览器。

在接下来的部分中，我们将通过输入验证来检查如何保持我们的 SQL 查询安全，然后转向其他形式的输入验证以及输出验证和净化。

## 使用 SQL 的最佳实践

在使用关系数据库时存在一些非常大的安全漏洞，其中大部分都适用于其他数据存储方法。我们已经看过一些这些漏洞，比如正确和唯一地加盐密码以及使用安全会话。即使在后者中，也总是存在一些会话固定攻击的风险，这允许共享或持久共享会话被劫持。

其中一个更普遍的攻击向量，现代数据库适配器 tend to 消除的是注入攻击。

注入攻击，特别是 SQL 注入，是最常见的，但也是最可避免的漏洞之一，可以暴露敏感数据，损害问责制，甚至使您失去对整个服务器的控制。

敏锐的眼睛可能已经注意到了，但在本书的前面，我们故意在我们的`api.go`文件中构建了一个不安全的查询，可以允许 SQL 注入。

这是我们原始的`CreateUser()`处理程序中的一行：

```go
  sql := "INSERT INTO users set user_nickname='" + NewUser.Name + "', user_first='" + NewUser.First + "', user_last='" + NewUser.Last + "', user_email='" + NewUser.Email + "'"
  q, err := database.Exec(sql)
```

不言而喻，但是在几乎所有语言中，直接构造查询作为直接的 SQL 命令是不受欢迎的。

一个很好的经验法则是将所有外部生成的数据，包括用户输入、内部或管理员用户输入和外部 API 视为恶意。通过尽可能怀疑用户提供的数据，我们提高了捕捉潜在有害注入的几率。

我们的其他大部分查询都使用了参数化的`Query()`函数，该函数允许您添加与`?`标记对应的可变参数。

请记住，由于我们在数据库中存储用户的唯一盐（至少在我们的示例中），失去对 MySQL 数据库的访问权限意味着我们也失去了首次使用密码盐的安全好处。

这并不意味着在这种情况下所有账户的密码都会被暴露，但在这一点上，如果用户保持个人密码标准低劣，那么直接获取用户的登录凭据只有在利用其他服务方面才有用，也就是说，在服务之间共享密码。

# 验证输出

通常情况下，输出验证的概念似乎很陌生，特别是当数据在输入端进行了消毒时。

保留值的发送方式，并且仅在输出时对其进行消毒可能是有道理的，但这增加了这些值在传递给 API 消费者时可能未经消毒的几率。

有两种主要方式可以将有效负载传递给最终用户，一种是存储攻击，我们作为应用程序在服务器上保留向量，另一种是反射攻击，其中一些代码通过其他方法附加，例如包含有效负载的电子邮件消息。

API 和 Web 服务有时特别容易受到不仅**XSS**（**跨站脚本攻击**的缩写）的影响，还有**CSRF**（**跨站请求伪造**的缩写）。

我们将简要讨论这两种情况以及我们可以在 Web 服务中限制它们的有效性的方法。

## 防止 XSS 攻击

每当我们处理用户输入，以便稍后将其转换为其他用户消费的输出时，我们都需要警惕跨站脚本攻击或跨站请求伪造在生成的数据有效负载中的问题。

这不仅仅是输出验证的问题。这也应该在输入阶段进行处理。然而，我们的输出是我们在一个用户的任意文本和另一个用户消费该文本之间的最后防线。

传统上，最好通过以下假设性的恶意代码片段来说明这一点。用户通过`POST`请求击中我们的`/api/statuses`端点，经过选择的任何方法进行身份验证，并发布以下状态：

```go
url -X POST -H "Authorization: Basic dGVzdDp0ZXN0" -H "Cache-Control: no-cache" -H "Postman-Token: c2b24964-c12d-c183-dd7f-5c1365f5ae81" -H "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW" -F "status=Having a great day! <iframe src='somebadsite/somebadscript'></iframe>" https://localhost/api/statuses
```

如果像我们的界面示例一样呈现在模板中，那么使用 Go 的模板引擎将自动减轻这个问题。

让我们看看前面的示例数据在我们界面的用户配置文件页面上是什么样子：

![防止 XSS 攻击](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_11_01.jpg)

`html/template`包会自动转义 HTML 输出，以防止代码注入，并且需要覆盖以允许任何 HTML 标签原样输入。

然而，作为 API 提供者，我们对消费应用程序语言的类型以及对输入的消毒的支持或关注是中立的。

转义数据的责任是需要考虑的问题，也就是说，您的应用程序提供给客户端的数据是否应该预先经过消毒，或者是否应该附带有关消毒数据的使用说明？在几乎所有情况下，答案都是第一种选择，但根据您的角色和数据类型，情况可能有所不同。另一方面，在某些情况下（例如 API），在前端取消消毒数据意味着可能需要以多种方式重新格式化数据。

在本章的前面部分，我们向您展示了一些输入验证技术，用于允许或禁止某些类型的数据（如字符、标签等），您可以将这些技术应用到诸如`/statuses`之类的端点。

然而，更合理的做法是允许这些数据；但是，在将其保存到数据库/数据存储或通过 API 端点返回之前对其进行清理。以下是我们可以使用`http/template`包来执行这两种操作的方法。

首先，当我们通过`/api/statuses`端点接受数据时，我们可以利用`html/template`中的一个或多个函数来防止某些类型的数据被存储。这些函数如下：

+   `template.HTMLEscapeString`: 这将对 HTML 标签进行编码，并将生成的字符串呈现为非 HTML 内容

+   `template.JSEscapeString()`: 这将对字符串的 JavaScript 特定部分进行编码，以防止正确呈现

为了简化通过 HTML 输出的目的，我们可以只需对我们的数据应用`HTMLEscapeString()`，这将禁用任何 JavaScript 调用的执行：

```go
func StatusCreate(w http.ResponseWriter, r *http.Request) {

  Response := CreateResponse{}
  UserID := r.FormValue("user")
  Status := r.FormValue("status")
  Token := r.FormValue("token")
  ConsumerKey := r.FormValue("consumer_key")

  Status = template.HTMLEscapeString(Status)
```

这使得数据在输入（`StatusCreate`）端进行转义。如果我们想要添加 JavaScript 转义（正如前面所述，可能并不需要），它应该在 HTML 转义之前进行，如下所示：

```go
  Status = template.JSEscapeString(Status)
  Status = template.HTMLEscapeString(Status)
```

如果我们希望在输入端不进行转义，而是在输出端进行转义，那么可以在相应的状态请求 API 调用中进行相同的模板转义调用，比如`/api/statuses`：

```go
func StatusRetrieve(w http.ResponseWriter, r *http.Request) {
  var Response StatusResponse
  w.Header().Set("Access-Control-Allow-Origin", "*")
  loggedIn := CheckLogin(w, r)
  if loggedIn {

  } else {
    statuses,_ := Database.Query("select * from user_status where user_id=? order by user_status_timestamp desc",Session.UID)
    for statuses.Next() {

      status := Status{}
      statuses.Scan(&status.ID, &status.UID, &status.Time, &status.Text)
      status.Text = template.JSEscapeString(status.Text)
      status.Text = template.HTMLEscapeString(status.Text)
      Response.Statuses = append(Response.Statuses, status)
  }
```

如果我们想要尝试检测并记录尝试将特定 HTML 元素传递到输入元素中，我们可以为 XSS 尝试创建一个新的日志记录器，并捕获与`<script>`元素、`<iframe>`元素或其他任何元素匹配的任何文本。

这可以是一个像标记器或更高级的安全包一样复杂，也可以是一个像正则表达式匹配一样简单，我们将在接下来的示例中看到。首先，我们将查看我们日志设置中的代码：

```go
var (
  Database       *log.Logger
  Authentication *log.Logger
  Errors         *log.Logger
  Questionable *log.Logger
)
```

我们初始化代码中的更改如下：

```go
  questlog, err := os.OpenFile("injections.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
  if err != nil {
    log.Println(err)
  }
  Questionable = log.New(questlog, "XSS:", log.Ldate|log.Ltime)

```

然后，在我们应用程序的`StatusCreate`处理程序中进行以下更改：

```go
  isinject, _ := regexp.MatchString("<(script|iframe).*",Status)
  if isinject  {

  }
```

通过正则表达式以这种方式检测标签既不是绝对可靠的，也不是本意。请记住，我们将在输入端或输出端对数据进行清理，因此如果我们可以通过这种方法捕捉到尝试，它将为我们提供一些关于对我们应用程序的潜在恶意尝试的见解。

如果我们想要更符合 Go 语言的习惯和更全面，我们可以简单地对文本进行清理并将其与原始文本进行比较。如果两个值不匹配，我们可以推断出 HTML 已被包含。

这意味着我们将对无害的 HTML 标签（如粗体标签或表格标签）进行转义。

# 在 Go 中使用服务器端框架

在详细介绍如何从头开始构建 Web 服务时，如果我们不至少触及集成或专门使用一些现有框架，那就不够周全了。

虽然通过插入这样一个框架来获得与从头开始设计一个框架相同的体验是不可能的，但出于实际目的，当您想要启动一个项目时，通常没有理由重新发明轮子。

Go 语言有一些现成的、成熟的 Web/HTML 框架，但也有一些特别为 Web 服务设计的值得注意的框架，其中一些提供了你可能期望看到的一些交付方法和额外的钩子。

根据某些标准，可以将 Gorilla 描述为一个框架；然而，正如其名称所暗示的那样，它有点基础。

无论您使用现有框架还是选择构建自己的框架（无论是出于经验还是出于完全定制业务需求），您都应该考虑做一些

我们将简要地看一下这些框架中的一些，以及它们如何简化小型基于 Web 的项目的开发。

## Tiger Tonic

Tiger Tonic 是一个专门面向 API 的框架，因此我们将在本节中首先提到它。它采用了一种非常符合 Go 语言习惯的方式来开发 JSON Web 服务。

响应主要是以 JSON 格式为主，多路复用应该与 Gorilla 引入的风格非常相似。

Tiger Tonic 还提供了一些高质量的日志记录功能，允许您将日志直接导入 Apache 格式进行更详细的分析。最重要的是，它以一种方式处理中间件，允许根据中间件本身的结果进行一些条件操作。

### 注意

您可以在[`github.com/rcrowley/go-tigertonic`](https://github.com/rcrowley/go-tigertonic)了解更多关于 Tiger Tonic 的信息，或使用`go get github.com/rcrowley/go-tigertonic`命令下载文档。

## Martini

Web 框架 Martini 是相对年轻的 Go 语言中较受欢迎的 Web 框架之一，这在很大程度上是因为它在设计上与`Node.js`框架 Express 和流行的 Ruby-on-Rails 框架 Sinatra 相似。

Martini 还与中间件非常搭配，以至于它经常被专门用于这个目的。它还带有一些标准的中间件处理程序，比如`Logger()`用于处理登录和退出的日志记录，`Recovery()`用于从 panic 中恢复并返回 HTTP 错误。

Martini 是为大量网络项目构建的，可能包括比简单的网络服务更多的内容；然而，它是一个非常全面的框架，值得一试。

### 注意

您可以在[`github.com/go-martini/martini`](https://github.com/go-martini/martini)了解更多关于 Martini 的信息，或使用`go get github.com/go-martini/martini`命令下载文档。

## Goji

与 Martini 相比，Goji 框架是非常简约和精简的。Goji 的主要优势在于其非常快速的路由系统，额外垃圾收集的开销低，以及强大的中间件集成。

Goji 使用 Alice 作为中间件，我们在前面的章节中简要提到过。

### 注意

您可以在[`goji.io/`](https://goji.io/)了解更多关于 Goji 微框架的信息，并使用`go get github.com/zenazn/goji`和`go get github.com/zenazn/goji/web`命令下载它。

## Beego

Beego 是一种更复杂的框架类型，已经迅速成为 Go 项目中较受欢迎的 Web 框架之一。

Beego 有许多功能，可以为网络服务提供便利，尽管其附加功能主要用于渲染网页。该框架配备了自己的会话、路由和缓存模块，并包括一个实时监控过程，允许您动态分析项目。

### 注意

您可以在[`beego.me/`](http://beego.me/)了解更多关于 Beego 的信息，或使用`go get github.com/astaxie/beego`命令下载它。

# 总结

在本章的最后，我们看了如何尽可能地使我们的网络服务免受常见的安全问题，并研究了如何在发生违规时减轻问题的解决方案。

随着 API 在受欢迎程度和范围上的扩展，确保用户及其数据的安全至关重要。

我们希望您已经（并将能够）利用这些安全最佳实践和工具来提高应用程序的整体可靠性和速度。

虽然我们的主要项目——社交网络——绝不是一个完整或全面的项目，但我们已经分解了这样一个项目的各个方面，以演示路由、缓存、身份验证、显示、性能和安全性。

如果您希望继续扩展项目，请随意增加、分叉或克隆[`github.com/nkozyra/masteringwebservices`](https://github.com/nkozyra/masteringwebservices)上的示例。我们很乐意看到该项目继续作为演示 Go 中与网络服务和 API 相关的功能和最佳实践。
