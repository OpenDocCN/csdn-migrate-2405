# Go 依赖注入实用指南（三）

> 原文：[`zh.annas-archive.org/md5/87633C3DBA89BFAAFD7E5238CC73EA73`](https://zh.annas-archive.org/md5/87633C3DBA89BFAAFD7E5238CC73EA73)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：方法注入的依赖注入

在上一章中，我们使用构造函数来注入我们的依赖项。这样做简化了我们的对象和其依赖项的生命周期。但是当我们的依赖项对于每个请求都不同的时候会发生什么？这就是方法注入发挥作用的地方。

本章将涵盖以下主题：

+   方法注入

+   方法注入的优势

+   应用方法注入

+   方法注入的缺点

# 技术要求

熟悉我们服务的代码可能会很有益，就像第四章中介绍的那样，*ACME 注册服务简介*。

你可能还会发现阅读并运行本章的完整代码版本很有用，可在[`github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/tree/master/ch07`](https://github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/tree/master/ch07)找到。

有关如何获取代码和配置示例服务的说明，请参阅 README 文件，位于[`github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/`](https://github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/)。

您可以在`ch07/acme`中找到我们的服务代码，并已应用了本章的更改。

# 方法注入

方法注入随处可见。你可能每天都在使用它，甚至都没有意识到。你有没有写过这样的代码？：

```go
fmt.Fprint(os.Stdout, "Hello World")
```

这样怎么样？：

```go
req, err := http.NewRequest("POST", "/login", body)
```

这就是方法注入——将依赖项作为参数传递给请求。

让我们更详细地检查之前的例子。`Fprint()`的函数签名如下：

```go
// Fprint formats using the default formats for its operands and writes 
// to w. It returns the number of bytes written and any write error 
// encountered.
func Fprint(w io.Writer, a ...interface{}) (n int, err error)
```

正如你所看到的，第一个参数`io.Writer`是这个函数的一个依赖项。这与任何其他函数调用不同的是，依赖项为函数调用提供了调用上下文或数据。

在第一个例子中，依赖是必需的，因为它被用作输出目的地。然而，在方法注入中使用的依赖项并不总是必需的。有时，依赖是可选的，就像我们在下面的例子中看到的那样：

```go
func NewRequest(method, url string, body io.Reader) (*http.Request, error) {
   // validate method
   m, err := validateMethod(method)
   if err != nil {
      return nil, err
   }

   // validate URL
   u, err := validateURL(url)
   if err != nil {
      return nil, err
   }

   // process body (if exists)
   var b io.ReadCloser
   if body != nil {
      // read body
      b = ioutil.NopCloser(body)
   }

   // build Request and return
   req := &http.Request{
      URL:    u,
      Method: m,
      Body:   b,
   }

   return req, nil
}
```

这不是标准库中的实际实现；我已经简化了它以突出关键部分。在前面的例子中，`io.Reader`是可选的，因此受到守卫条款的保护。

在应用方法注入时，依赖项是特定于当前调用的，并且我们经常会发现自己需要守卫条款。为了帮助我们决定是否包含守卫条款，让我们深入研究一下我们的例子。

在`fmt.Fprint()`标准库实现中，对`io.Writer`没有守卫条款，这意味着提供`nil`将导致函数发生 panic。这是因为没有`io.Writer`，输出就无处可去。

然而，在`http.NewRequest()`的实现中，有一个守卫条款，因为可能发出不包含请求体的 HTTP 请求。

那么，对于我们编写的函数来说意味着什么呢？在大多数情况下，我们应该避免编写可能导致崩溃的代码。让我们实现一个类似于`Fprint()`的函数，并看看是否可以避免崩溃。这是第一个粗糙的实现（带有 panic）：

```go
// TimeStampWriterV1 will output the supplied message to 
//writer preceded with a timestamp
func TimeStampWriterV1(writer io.Writer, message string) {
   timestamp := time.Now().Format(time.RFC3339)
   fmt.Fprintf(writer, "%s -> %s", timestamp, message)
}
```

避免`nil`写入器引起的 panic 的第一件事是什么？

我们可以添加一个守卫条款，并在未提供`io.Writer`时返回错误，如下面的代码所示：

```go
// TimeStampWriterV2 will output the supplied message to 
//writer preceded with a timestamp
func TimeStampWriterV2(writer io.Writer, message string) error {
   if writer == nil {
      return errors.New("writer cannot be nil")
   }

   timestamp := time.Now().Format(time.RFC3339)
   fmt.Fprintf(writer,"%s -> %s", timestamp, message)

   return nil
}
```

虽然这看起来和感觉起来仍然像是常规的有效的 Go 代码，但我们现在有一个只有在我们程序员犯错时才会发生的错误。一个更好的选择是*合理的默认值*，如下面的代码所示：

```go
// TimeStampWriterV3 will output the supplied message to 
//writer preceded with a timestamp
func TimeStampWriterV3(writer io.Writer, message string) {
   if writer == nil {
      // default to Standard Out
      writer = os.Stdout
   }

   timestamp := time.Now().Format(time.RFC3339)
   fmt.Fprintf(writer,"%s -> %s", timestamp, message)
}
```

这种技术称为**防御性编码**。其核心概念是*即使体验降级，也比崩溃更好*。

尽管这些示例都是函数，但方法注入可以以完全相同的方式与结构体一起使用。有一个警告——不要将注入的依赖保存为成员变量。我们使用方法注入是因为依赖项提供函数调用上下文或数据。将依赖项保存为成员变量会导致它在调用之间共享，从而在请求之间泄漏此上下文。

# 方法注入的优势

正如我们在前一节中看到的，方法注入在标准库中被广泛使用。当您想要编写自己的共享库或框架时，它也非常有用。它的用途并不止于此。

**它在函数中表现出色**——每个人都喜欢一个好函数，特别是那些遵循*单一责任原则*部分的函数，如第二章中所讨论的*Go 的 SOLID 设计原则*。它们简单、无状态，并且可以被高度重用。将方法注入到函数中将通过将依赖项转换为抽象来增加其可重用性。考虑以下 HTTP 处理程序：

```go
func HandlerV1(response http.ResponseWriter, request *http.Request) {
   garfield := &Animal{
      Type: "Cat",
      Name: "Garfield",
   }

   // encode as JSON and output
   encoder := json.NewEncoder(response)
   err := encoder.Encode(garfield)
   if err != nil {
      response.WriteHeader(http.StatusInternalServerError)
      return
   }

   response.WriteHeader(http.StatusOK)
}
```

简单明了。它构建一个 Go 对象，然后将对象的内容作为 JSON 写入响应。很容易想象，我们接下来编写的下一个 HTTP 处理程序也将具有相同的最终九行。因此，让我们将它们提取到一个函数中，而不是复制和粘贴：

```go
func outputAnimal(response http.ResponseWriter, animal *Animal) {
   encoder := json.NewEncoder(response)
   err := encoder.Encode(animal)
   if err != nil {
      response.WriteHeader(http.StatusInternalServerError)
      return
   }

   // Happy Path
   response.WriteHeader(http.StatusOK)
}
```

现在让我们检查函数的输入；我们如何使这些更通用或抽象？

虽然 JSON 编码器只需要`io.Writer`而不是完整的`http.ResponseWriter`，但我们也输出 HTTP 状态码。因此，除了定义我们自己的接口之外，这是我们能做的最好的了。第二个参数是`*Animal`。在我们的函数中，我们实际上需要的最少是什么？

我们只使用`*Animal`作为 JSON 编码器的输入，其函数签名为

`Encode(v interface{}) error`。因此，我们可以减少我们的参数以匹配，得到以下结果：

```go
func outputJSON(response http.ResponseWriter, data interface{}) {
   encoder := json.NewEncoder(response)
   err := encoder.Encode(data)
   if err != nil {
      response.WriteHeader(http.StatusInternalServerError)
      return
   }

   // Happy Path
   response.WriteHeader(http.StatusOK)
}
```

通常，我避免使用`interface{}`，因为它的使用会导致代码中充斥着类型转换和使代码更难阅读的语句。然而，在这种情况下，这是最好（也是唯一）的选择。

与其他章节中基于*接口隔离原则*的示例类似，最好是在函数或方法旁边定义最小可能的接口；或者如果可能的话，使用标准库中适当的最小接口（如`io.Writer`）。

**依赖项充当数据**——因为方法注入要求用户在每次调用时传入依赖项，这对依赖项和使用之间的关系产生了一些有趣的副作用。依赖项成为请求中的数据的一部分，并且可以极大地改变调用的结果。考虑以下代码：

```go
func WriteLog(writer io.Writer, message string) error {
   _, err := writer.Write([]byte(message))
   return err
}
```

一个非常无害和直接的函数，但是看看当我们提供一些不同的依赖项时会发生什么：

```go
// Write to console
WriteLog(os.Stdout, "Hello World!")

// Write to file
file, _ := os.Create("my-log.log")
WriteLog(file, "Hello World!")

// Write to TCP connection
tcpPipe, _ := net.Dial("tcp", "127.0.0.1:1234")
WriteLog(tcpPipe, "Hello World!")
```

**依赖项是请求范围的**——这些依赖项根据定义一直在被创建和销毁。因此，它们不适合构造函数注入甚至猴子补丁。当然，我们可以在每个请求中创建使用依赖项的对象，但这既不高效也不总是必要的。

让我们看一个 HTTP 请求处理程序：

```go
// LoadOrderHandler is a HTTP handler that loads orders based on the current user and supplied user ID
type LoadOrderHandler struct {
   loader OrderLoader
}

// ServeHTTP implements http.Handler
func (l *LoadOrderHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
   // extract user from supplied authentication credentials
   currentUser, err := l.authenticateUser(request)
   if err != nil {
      response.WriteHeader(http.StatusUnauthorized)
      return
   }

   // extract order ID from request
   orderID, err := l.extractOrderID(request)
   if err != nil {
      response.WriteHeader(http.StatusBadRequest)
      return
   }

   // load order using the current user as a request-scoped dependency
   // (with method injection)
   order, err := l.loader.loadOrder(currentUser, orderID)
   if err != nil {
      response.WriteHeader(http.StatusInternalServerError)
      return
   }

   // output order
   encoder := json.NewEncoder(response)
   err = encoder.Encode(order)
   if err != nil {
      response.WriteHeader(http.StatusInternalServerError)
      return
   }

   response.WriteHeader(http.StatusOK)
}
```

作为 HTTP 处理程序，`ServeHTTP()`方法将针对每个传入的 HTTP 请求调用一次。`LoadOrderHandler`依赖于`OrderLoader`，我们将使用构造函数注入我们的实现`AuthenticatedLoader`。

`AuthenticatedLoader`的实现可以在以下代码中看到：

```go
// AuthenticatedLoader will load orders for based on the supplied owner
type AuthenticatedLoader struct {
   // This pool is expensive to create.  
   // We will want to create it once and then reuse it.
   db *sql.DB
}

// load the order from the database based on owner and order ID
func (a *AuthenticatedLoader) loadByOwner(owner Owner, orderID int) (*Order, error) {
   order, err := a.load(orderID)
   if err != nil {
      return nil, err
   }

   if order.OwnerID != owner.ID() {
      // Return not found so we do not leak information to hackers
      return nil, errNotFound
   }

   // happy path
   return order, nil
}
```

正如您所看到的，`AuthenticatedLoader`依赖于数据库连接池；这很昂贵，所以我们不希望在每个请求中重新创建它。

`loadByOwner()`函数接受使用方法注入的`Owner`。我们在这里使用方法注入，因为我们期望`Owner`会随着每个请求而变化。

这个例子使用构造函数注入长期依赖项和方法注入请求范围的依赖项。这样，我们就不会不必要地创建和销毁对象。

**协助不可变性、无状态性和并发性**—你可能会指责我有点夸大其词，但在编写一些非常并发的 Go 系统之后，我发现无状态和/或不可变的对象不太容易出现与并发相关的问题。方法注入本身并不赋予这些特性，但确实使其更容易实现。通过传递依赖项，所有权和使用范围更加清晰。此外，我们不需要担心对依赖项的并发访问，就像它是成员变量一样。

# 应用方法注入

在本节中，我们将通过应用方法注入来改进我们的 ACME 注册服务，也许会用到我最喜欢的 Go 标准库中的包，上下文包。该包的核心是`Context`接口，它自述如下：

**上下文在 API 边界跨越期限、取消信号和请求范围值。它的方法可以同时被多个 goroutine 安全使用**

那么，为什么我这么喜欢它呢？通过应用方法注入，以上下文作为依赖项，我能够构建我的处理逻辑，以便可以自动取消和清理所有内容。

# 快速回顾

在我们深入改变之前，让我们更深入地看一下我们示例服务提供的注册函数及其与外部资源的交互。以下图表概述了在调用注册端点时执行的步骤：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/5f9cb019-ed60-4dc7-9616-0e5080a68a76.png)

这些交互如下：

1.  用户调用注册端点。

1.  我们的服务调用**汇率服务**。

1.  我们的服务将注册信息保存到数据库中。

现在让我们考虑这些交互可能出现的问题。问问自己以下问题：

+   可能会失败或变慢的是什么？

+   我希望如何对失败做出反应或恢复？

+   我的用户会如何对我的失败做出反应？

考虑到我们函数中的交互，立即想到两个问题：

+   **对数据库的调用可能会失败或变慢：**我们如何从中恢复？我们可以进行重试，但这一点我们必须非常小心。数据库往往更像是有限资源而不是 web 服务。因此，重试请求实际上可能会进一步降低数据库的性能。

+   **对汇率服务的调用可能会失败或变慢：**我们如何从中恢复？我们可以自动重试失败的请求。这将减少我们无法加载汇率的情况。假设业务批准，我们可以设置一些默认汇率来使用，而不是完全失败注册。

我们可以做出的最好的改变来提高系统的稳定性可能会让你感到意外。

我们可以根本不发出请求。如果我们能够改变注册流程，使得在处理的这一部分不需要汇率，那么它就永远不会给我们带来问题。

假设在我们（刻意制造的）例子中，前面提到的解决方案都不可用。我们唯一剩下的选择就是失败。如果加载汇率花费的时间太长，用户放弃并取消他们的请求会发生什么？他们很可能会认为注册失败，希望再次尝试。

考虑到这一点，我们最好的做法是放弃等待汇率，不再进一步处理注册。这个过程被称为**提前停止**。

# 提前停止

提前停止是基于外部信号中止处理请求的过程（在本应完成之前）。

在我们的情况下，外部信号将是用户 HTTP 请求的取消。在 Go 中，`http.Request`对象包括一个`Context()`方法；以下是该方法文档的摘录：

对于传入的服务器请求，当客户端的连接关闭时，请求被取消（使用 HTTP/2），或者当 ServeHTTP 方法返回时，上下文被取消。

当请求被取消时意味着什么？对我们来说最重要的是，这意味着没有人在等待响应。

如果用户放弃等待响应，他们很可能会认为请求失败，并希望再次尝试。

我们应该如何对这种情况做出反应取决于我们正在实现的功能，但在许多情况下，主要是与加载或获取数据相关的功能，最有效的响应是停止处理请求。

对于我们服务的注册端点，这是我们选择的选项。我们将通过方法注入从请求中传递`Context`到我们代码的所有层。如果用户取消他们的请求，我们将立即停止处理请求。

既然我们清楚我们要达到什么目标，让我们从内部开始将方法注入到我们服务的层中。我们需要从内部开始，以确保我们的代码和测试在重构过程中保持运行。

# 将方法注入应用到数据包

快速提醒，`data`包是一个提供对底层 MySQL 数据库的简化和抽象访问的**数据访问层**（**DAL**）。

以下是`Save()`函数的当前代码：

```go
// Save will save the supplied person and return the ID of the newly 
// created person or an error.
// Errors returned are caused by the underlying database or our 
// connection to it.
func Save(in *Person) (int, error) {
   db, err := getDB()
   if err != nil {
      logging.L.Error("failed to get DB connection. err: %s", err)
      return defaultPersonID, err
   }

   // perform DB insert
   result, err := db.Exec(sqlInsert, in.FullName, in.Phone, in.Currency, in.Price)
   if err != nil {
      logging.L.Error("failed to save person into DB. err: %s", err)
      return defaultPersonID, err
   }

   // retrieve and return the ID of the person created
   id, err := result.LastInsertId()
   if err != nil {
      logging.L.Error("failed to retrieve id of last saved person. err: %s", err)
      return defaultPersonID, err
   }

   return int(id), nil
}
```

通过应用方法注入，我们得到了以下结果：

```go
// Save will save the supplied person and return the ID of the newly 
// created person or an error.
// Errors returned are caused by the underlying database or our 
// connection to it.
func Save(ctx context.Context, in *Person) (int, error) {
   db, err := getDB()
   if err != nil {
      logging.L.Error("failed to get DB connection. err: %s", err)
      return defaultPersonID, err
   }

   // perform DB insert
   result, err := db.ExecContext(ctx, sqlInsert, in.FullName, in.Phone, in.Currency, in.Price)
   if err != nil {
      logging.L.Error("failed to save person into DB. err: %s", err)
      return defaultPersonID, err
   }

   // retrieve and return the ID of the person created
   id, err := result.LastInsertId()
   if err != nil {
      logging.L.Error("failed to retrieve id of last saved person. err: %s", err)
      return defaultPersonID, err
   }

   return int(id), nil
}
```

如您所见，我们将`Exec()`调用替换为`ExecContext()`，但其他方面没有改变。因为我们已经改变了函数签名，我们还需要更新对该包的使用如下：

```go
// save the registration
func (r *Registerer) save(in *data.Person, price float64) (int, error) {
   person := &data.Person{
      FullName: in.FullName,
      Phone:    in.Phone,
      Currency: in.Currency,
      Price:    price,
   }
   return saver(context.TODO(), person)
}

// this function as a variable allows us to Monkey Patch during testing
var saver = data.Save

```

您会注意到我们使用了`context.TODO()`；它在这里被用作占位符，直到我们可以将`save()`方法重构为使用方法注入为止。在更新了我们在重构过程中破坏的测试之后，我们可以继续进行下一个包。

# 将方法注入应用到 exchange 包

`exchange`包负责从上游服务加载当前的货币兑换率（例如，马来西亚林吉特兑澳大利亚元），与数据包类似，它提供了对这些数据的简化和抽象访问。

以下是当前代码的相关部分：

```go
// Converter will convert the base price to the currency supplied
type Converter struct{}

// Do will perform the load
func (c *Converter) Do(basePrice float64, currency string) (float64, error) {
   // load rate from the external API
   response, err := c.loadRateFromServer(currency)
   if err != nil {
      return defaultPrice, err
   }

   // extract rate from response
   rate, err := c.extractRate(response, currency)
   if err != nil {
      return defaultPrice, err
   }

   // apply rate and round to 2 decimal places
   return math.Floor((basePrice/rate)*100) / 100, nil
}

// load rate from the external API
func (c *Converter) loadRateFromServer(currency string) (*http.Response, error) {
   // build the request
   url := fmt.Sprintf(urlFormat,
      config.App.ExchangeRateBaseURL,
      config.App.ExchangeRateAPIKey,
      currency)

   // perform request
   response, err := http.Get(url)
   if err != nil {
      logging.L.Warn("[exchange] failed to load. err: %s", err)
      return nil, err
   }

   if response.StatusCode != http.StatusOK {
      err = fmt.Errorf("request failed with code %d", response.StatusCode)
      logging.L.Warn("[exchange] %s", err)
      return nil, err
   }

   return response, nil
}
```

第一个变化与之前的相同。在`Do()`和`loadRateFromServer()`方法上进行简单的方法注入，将这些方法签名更改为以下内容：

```go
// Converter will convert the base price to the currency supplied
type Converter struct{}

// Do will perform the load
func (c *Converter) Do(ctx context.Context, basePrice float64, currency string) (float64, error) {

}

// load rate from the external API
func (c *Converter) loadRateFromServer(ctx context.Context, currency string) (*http.Response, error) {

}
```

不幸的是，没有`http.GetWithContext()`方法，所以我们需要以稍微冗长的方式构建请求并设置上下文，得到以下结果：

```go
// load rate from the external API
func (c *Converter) loadRateFromServer(ctx context.Context, currency string) (*http.Response, error) {
   // build the request
   url := fmt.Sprintf(urlFormat,
      config.App.ExchangeRateBaseURL,
      config.App.ExchangeRateAPIKey,
      currency)

   // perform request
   req, err := http.NewRequest("GET", url, nil)
   if err != nil {
      logging.L.Warn("[exchange] failed to create request. err: %s", err)
      return nil, err
   }

   // replace the default context with our custom one
   req = req.WithContext(ctx)

   // perform the HTTP request
   response, err := http.DefaultClient.Do(req)
   if err != nil {
      logging.L.Warn("[exchange] failed to load. err: %s", err)
      return nil, err
   }

   if response.StatusCode != http.StatusOK {
      err = fmt.Errorf("request failed with code %d", response.StatusCode)
      logging.L.Warn("[exchange] %s", err)
      return nil, err
   }

   return response, nil
}
```

与之前一样，我们还需要在调用`exchange`包的模型层中使用`context.TODO()`，直到我们有机会将它们改为方法注入。完成了两个*底层*软件层（`data`和`exchange`包）后，我们可以继续进行下一个软件层、业务层或模型层。

# 将方法注入应用到模型层（Get、List 和 Register 包）

以前，在我们调用`data`或`exchange`包的地方，我们使用`context.TODO()`来确保代码仍然可以编译，并且我们的测试继续发挥作用。现在是时候将方法注入应用到模型层，并用注入的上下文替换`context.TODO()`的调用。首先，我们将`getPrice()`和`save()`方法更改为接受上下文：

```go
// get price in the requested currency
func (r *Registerer) getPrice(ctx context.Context, currency string) (float64, error) {
   converter := &exchange.Converter{}
   price, err := converter.Do(ctx, config.App.BasePrice, currency)
   if err != nil {
      logging.L.Warn("failed to convert the price. err: %s", err)
      return defaultPersonID, err
   }

   return price, nil
}

// save the registration
func (r *Registerer) save(ctx context.Context, in *data.Person, price float64) (int, error) {
   person := &data.Person{
      FullName: in.FullName,
      Phone:    in.Phone,
      Currency: in.Currency,
      Price:    price,
   }
   return saver(ctx, person)
}
```

然后我们可以更新包的公共 API 函数`Do()`：

```go
type Registerer struct {}

func (r *Registerer) Do(ctx context.Context, in *data.Person) (int, error) {
   // validate the request
   err := r.validateInput(in)
   if err != nil {
      logging.L.Warn("input validation failed with err: %s", err)
      return defaultPersonID, err
   }

   // get price in the requested currency
   price, err := r.getPrice(ctx, in.Currency)
   if err != nil {
      return defaultPersonID, err
   }

   // save registration
   id, err := r.save(ctx, in, price)
   if err != nil {
      // no need to log here as we expect the data layer to do so
      return defaultPersonID, err
   }

   return id, nil
}

```

我们已经将传递给数据和`exchange`包的`Context`对象合并为一个单一的注入依赖项；这是一个我们可以从 REST 包中的`http.Request`中提取的依赖项。

# 将上下文的方法注入到 REST 包中

最后，现在是关键的更改。首先，我们从请求中提取上下文：

```go
// ServeHTTP implements http.Handler
func (h *RegisterHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
   // extract payload from request
   requestPayload, err := h.extractPayload(request)
   if err != nil {
      // output error
      response.WriteHeader(http.StatusBadRequest)
      return
   }

   // call the business logic using the request data and context
   id, err := h.register(request.Context(), requestPayload)
   if err != nil {
      // not need to log here as we can expect other layers to do so
      response.WriteHeader(http.StatusBadRequest)
      return
   }

   // happy path
   response.Header().Add("Location", fmt.Sprintf("/person/%d/", id))
   response.WriteHeader(http.StatusCreated)
}
```

然后我们将其传递给模型：

```go

// call the logic layer
func (h *RegisterHandler) register(ctx context.Context, requestPayload *registerRequest) (int, error) {
   person := &data.Person{
      FullName: requestPayload.FullName,
      Phone:    requestPayload.Phone,
      Currency: requestPayload.Currency,
   }

   return h.registerer.Do(ctx, person)
}
```

经过了许多*太简单*的更改之后，我们已经将方法注入应用到了注册端点的所有层。

让我们来看看我们取得了什么成就。我们的处理现在与请求的执行上下文相关联。因此，当请求被取消时，我们将立即停止处理该请求。

但这为什么重要呢？有两个原因；第一个和最重要的是用户期望。如果用户取消了请求，无论是手动还是通过超时，他们将看到一个错误。他们会得出结论，处理已失败。如果我们继续处理请求并设法完成它，这将违背他们的期望。

第二个原因更加务实；当我们停止处理请求时，我们减少了服务器和上游的负载。这种释放的容量随后可以用于处理其他请求。

当涉及满足用户期望时，上下文包实际上可以做更多的事情。我们可以添加延迟预算。

# 延迟预算

与许多 IT 术语一样，延迟预算可以以多种方式使用。在这种情况下，我们指的是调用允许的最长时间。

将这些转化为我们当前的重构，它涉及两件事：

+   允许上游（数据库或汇率服务）调用完成的最长时间

+   我们的注册 API 允许的最长完成时间

你可以看到这两件事情是如何相关的。让我们看看我们的 API 响应时间是如何组成的：

*API 响应时间 =（汇率服务调用+数据库调用+我们的代码）*

假设*我们的代码*的性能主要是一致的，那么我们的服务质量直接取决于上游调用的速度。这不是一个非常舒适的位置，那么我们能做什么呢？

在前一节中，我们检查了这些失败和一些选项，并决定暂时要失败请求。我们能为用户提供的最好的失败是什么？一个及时而有信息的失败。

为了实现这一点，我们将使用`context.Context`接口的另一个特性：

`WithTimeout(parent Context, timeout time.Duration) (Context, CancelFunc)`

你可能已经猜到了，这种方法在上下文中设置了一个超时。这个超时将作为一个计时器，如果超过了延迟预算（超时），上下文将被取消。然后，因为我们已经设置了停止短路，我们的请求将停止处理并退出。

首先，让我们将其应用到我们的数据库调用中。在下一个示例中，我们将从原始上下文中创建一个*子上下文*并为其设置一个超时。由于上下文是分层的，我们应用的超时只适用于子上下文和我们从中创建的任何上下文。

在我们的情况下，我们已经决定对数据库的调用的延迟预算为 1 秒，如下所示：

```go
// Save will save the supplied person and return the ID of the newly 
// created person or an error.
// Errors returned are caused by the underlying database or our 
// connection to it.
func Save(ctx context.Context, in *Person) (int, error) {
   db, err := getDB()
   if err != nil {
      logging.L.Error("failed to get DB connection. err: %s", err)
      return defaultPersonID, err
   }

   // set latency budget for the database call
   subCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
   defer cancel()

   // perform DB insert
   result, err := db.ExecContext(subCtx, sqlInsert, in.FullName, in.Phone, in.Currency, in.Price)
   if err != nil {
      logging.L.Error("failed to save person into DB. err: %s", err)
      return defaultPersonID, err
   }

   // retrieve and return the ID of the person created
   id, err := result.LastInsertId()
   if err != nil {
      logging.L.Error("failed to retrieve id of last saved person. err: %s", err)
      return defaultPersonID, err
   }

   return int(id), nil
}
```

现在，让我们将延迟预算应用到交换服务调用中。为此，我们将使用`http.Request`的另一个特性，`Context()`方法，文档如下：

**对于出站客户端请求，上下文控制取消**

为了在我们的出站 HTTP 请求上设置延迟预算，我们将创建另一个子上下文，就像我们为数据库做的那样，然后使用`WithRequest()`方法将该上下文设置到请求中。在这些更改之后，我们的代码看起来像这样：

```go
// load rate from the external API
func (c *Converter) loadRateFromServer(ctx context.Context, currency string) (*http.Response, error) {
   // build the request
   url := fmt.Sprintf(urlFormat,
      config.App.ExchangeRateBaseURL,
      config.App.ExchangeRateAPIKey,
      currency)

   // perform request
   req, err := http.NewRequest("GET", url, nil)
   if err != nil {
      logging.L.Warn("[exchange] failed to create request. err: %s", err)
      return nil, err
   }

   // set latency budget for the upstream call
   subCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
   defer cancel()

   // replace the default context with our custom one
   req = req.WithContext(subCtx)

   // perform the HTTP request
   response, err := http.DefaultClient.Do(req)
   if err != nil {
      logging.L.Warn("[exchange] failed to load. err: %s", err)
      return nil, err
   }

   if response.StatusCode != http.StatusOK {
      err = fmt.Errorf("request failed with code %d", response.StatusCode)
      logging.L.Warn("[exchange] %s", err)
      return nil, err
   }

   return response, nil
}
```

有了这些更改，让我们重新审视我们的 API 响应时间公式，并考虑最坏的情况-两个调用都花了不到 1 秒的时间但成功完成，给我们这个：

*API 响应时间 =（~1 秒+ ~1 秒+我们的代码）*

这给我们一个大约 2 秒的最大执行时间。但是如果我们决定允许自己的最大响应时间是 1.5 秒呢？

幸运的是，我们也可以轻松做到这一点。早些时候，我提到过上下文是分层的。我们所有的上下文当前都是从请求中的上下文派生出来的。虽然我们无法更改作为请求一部分的上下文，但我们可以从中派生出一个具有我们 API 的延迟预算的上下文，然后将其传递给数据和交换包。处理程序的更新部分如下所示：

```go
// ServeHTTP implements http.Handler
func (h *RegisterHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
   // set latency budget for this API
   subCtx, cancel := context.WithTimeout(request.Context(), 1500 *time.Millisecond)
   defer cancel()

   // extract payload from request
   requestPayload, err := h.extractPayload(request)
   if err != nil {
      // output error
      response.WriteHeader(http.StatusBadRequest)
      return
   }

   // register person
   id, err := h.register(subCtx, requestPayload)
   if err != nil {
      // not need to log here as we can expect other layers to do so
      response.WriteHeader(http.StatusBadRequest)
      return
   }

   // happy path
   response.Header().Add("Location", fmt.Sprintf("/person/%d/", id))
   response.WriteHeader(http.StatusCreated)
}
```

经过一些简单的更改，我们可以更好地控制我们的 API 的性能，这要归功于上下文包和一点点方法注入。

# 方法注入的缺点

我没有为您列出很长的缺点；事实上，我只有两个。

**添加参数会降低用户体验** - 这是一个相当大的问题。向方法或函数添加参数会降低函数的用户体验。正如我们在第三章中所看到的，*为用户体验编码*，函数的糟糕用户体验会对其可用性产生负面影响。

考虑以下结构：

```go
// Load people from the database
type PersonLoader struct {
}

func (d *PersonLoader) Load(db *sql.DB, ID int) (*Person, error) {
   return nil, errors.New("not implemented")
}

func (d *PersonLoader) LoadAll(db *sql.DB) ([]*Person, error) {
   return nil, errors.New("not implemented")
}
```

这段代码有效，完成了任务。但是每次都必须传入数据库很烦人。除此之外，没有保证调用`Load()`的代码也会维护数据库池。

另一个要考虑的方面是封装。这些函数的用户是否需要知道它们依赖于数据库？请试着站在一会儿`Load()`函数的用户的角度。你想做什么，你知道什么？

你想加载一个人，你知道那个人的 ID。你不知道（或者不关心）数据来自哪里。如果你为自己设计这个函数，它会是什么样子：

```go
type MyPersonLoader interface {
   Load(ID int) (*Person, error)
}
```

它简洁易用，没有泄漏任何实现细节。

让我们看另一个例子：

```go
type Generator struct{}

func (g *Generator) Generate(storage Storage, template io.Reader, destination io.Writer, renderer Renderer, formatter Formatter, params ...interface{}) {

}
```

在这种情况下，我们有很多参数，很难将数据与非请求范围的依赖项分开。如果我们提取这些依赖项，我们会得到以下结果：

```go
func NewGeneratorV2(storage Storage, renderer Renderer, formatter Formatter) *GeneratorV2 {
   return &GeneratorV2{
      storage:   storage,
      renderer:  renderer,
      formatter: formatter,
   }
}

type GeneratorV2 struct {
   storage   Storage
   renderer  Renderer
   formatter Formatter
}

func (g *GeneratorV2) Generate(template io.Reader, destination io.Writer, params ...interface{}) {

}
```

虽然第二个例子中的用户体验更好，但仍然相当繁琐。代码可以从不同的角度受益，比如组合。

**适用性有限** - 正如我们在本章中所看到的，方法注入在函数和请求范围的依赖项中表现出色。虽然这种用例确实经常出现，但方法注入并不适用于非请求范围的依赖项，而这是我们想要使用**依赖注入**（**DI**）的大部分用例。

# 总结

在本章中，我们研究了方法注入的 DI，这可能是所有形式的 DI 中最普遍的。

当涉及从现有代码中提取依赖项以进行测试时，可能会首先想到的就是方法。请小心，我们不想引入*测试引起的损害*。

为了测试的唯一目的向导出的 API 函数添加参数无疑会损害 UX 代码。幸运的是，我们有一些技巧可用来避免损害我们的 API。我们可以定义仅存在于测试代码中的成员函数。我们还可以使用**即时**（**JIT**）依赖注入，我们将在第九章中进行探讨，*即时依赖注入*。

在本章中，我们已经研究了出色而强大的`context`包。您可能会惊讶地发现，我们可以从这个包中提取更多的价值。我鼓励您查看 Go 博客（[`blog.golang.org/context`](https://blog.golang.org/context)）并自行调查这个包。

在下一章中，我们将应用一种特定形式的构造函数注入和方法注入，称为**DI by config**。通过它，我们最终将`config`包从我们服务中几乎每个其他包都依赖的状态中解脱出来，使我们的包更加解耦，并显著提高它们的可重用性。

# 问题

1.  方法注入的理想用例是什么？

1.  为什么不保存使用方法注入注入的依赖关系很重要？

1.  如果我们过度使用方法注入会发生什么？

1.  为什么“停止短”对整个系统有用？

1.  延迟预算如何改善用户体验？


# 第八章：通过配置进行依赖注入

在本章中，我们将通过配置来看**依赖注入**（**DI**）。配置注入不是一种完全不同的方法，而是构造函数注入和方法注入的扩展。

它旨在解决这些方法可能存在的问题，比如过多或重复注入的依赖项，而不牺牲我们代码的用户体验。

本章将涵盖以下主题：

+   配置注入

+   配置注入的优点

+   应用配置注入

+   配置注入的缺点

# 技术要求

熟悉我们在第四章中介绍的服务代码将是有益的，*ACME 注册服务简介*。本章还假设您已经阅读了第六章，*构造函数注入的依赖注入*，和第七章，*方法注入的依赖注入*。

您可能还会发现阅读和运行本章的完整代码版本很有用，可在[`github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/tree/master/ch08`](https://github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/tree/master/ch08)找到。

获取代码并配置示例服务的说明可在此处的 README 中找到：[`github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/`](https://github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/)

您可以在`ch08/acme`中找到我们的服务代码，并已应用了本章的更改。

# 配置注入

配置注入是方法和参数注入的特定实现。通过配置注入，我们将多个依赖项和系统级配置合并到一个`config`接口中。

考虑以下构造函数：

```go
// NewLongConstructor is the constructor for MyStruct
func NewLongConstructor(logger Logger, stats Instrumentation, limiter RateLimiter, cache Cache, timeout time.Duration, workers int) *MyStruct {
 return &MyStruct{
 // code removed
 }
}
```

正如你所看到的，我们正在注入多个依赖项，包括记录器、仪器、速率限制器、缓存和一些配置。

可以肯定地假设我们很可能会将记录器和仪器注入到这个项目中的大多数对象中。这导致每个构造函数至少有两个参数。在整个系统中，这将增加大量额外的输入。它还通过使构造函数更难阅读来减少了我们的构造函数的用户体验，并且可能会隐藏重要参数。

考虑一下——超时和工作人数的值可能定义在哪里？它们可能是从某个中央来源定义的，比如一个`config`文件。

通过应用配置注入，我们的示例变成了以下内容：

```go
// NewByConfigConstructor is the constructor for MyStruct
func NewByConfigConstructor(cfg MyConfig, limiter RateLimiter, cache Cache) *MyStruct {
   return &MyStruct{
      // code removed
   }
}
```

我们已将常见问题和配置合并到配置定义中，但保留了重要参数。这样，函数参数仍然具有信息性，而无需阅读`config`接口定义。在某种程度上，我们隐藏或封装了常见问题。

考虑的另一个可用性方面是配置现在是一个接口。我们应该考虑哪种对象会实现这样的接口。这样的对象是否已经存在？它的责任是什么？

通常，配置来自单一来源，其责任是加载配置并提供对其的访问。即使我们引入配置接口以解耦实际的配置管理，利用它是单一来源仍然很方便。

考虑以下代码：

```go
myFetcher := NewFetcher(cfg, cfg.URL(), cfg.Timeout())
```

这段代码表明所有参数都来自同一位置。这表明它们可以合并。

如果你来自面向对象的背景，你可能熟悉服务定位器的概念。配置注入故意非常相似。然而，与典型的服务定位器用法不同，我们只提取配置和一些共享的依赖项。

配置注入采用这种方法来避免服务定位器的*上帝对象*和使用与上帝对象之间的耦合。

# 配置注入的优势

鉴于配置注入是构造函数和方法注入的扩展形式，其他方法的优点在这里也适用。在本节中，我们将仅讨论特定于此方法的附加优点。

**它非常适合与配置包解耦**-当我们有一个从单一位置加载的`config`包时，比如一个文件，那么这个包往往会成为系统中许多其他包的依赖项。考虑到第二章中的*单一职责原则*部分，我们意识到一个包或对象的用户越多，它就越难以改变。

通过配置注入，我们还在本地接口中定义我们的需求，并利用 Go 的隐式接口和**依赖反转原则**（**DIP**）来保持包的解耦。

这些步骤还使得测试我们的结构体变得更加容易。考虑以下代码：

```go
func TestInjectedConfig(t *testing.T) {
   // load test config
   cfg, err := config.LoadFromFile(testConfigLocation)
   require.NoError(t, err)

   // build and use object
   obj := NewMyObject(cfg)
   result, resultErr := obj.Do()

   // validate
   assert.NotNil(t, result)
   assert.NoError(t, resultErr)
}
```

现在，看一下使用配置注入的相同代码：

```go
func TestConfigInjection(t *testing.T) {
   // build test config
   cfg := &TestConfig{}

   // build and use object
   obj := NewMyObject(cfg)
   result, resultErr := obj.Do()

   // validate
   assert.NotNil(t, result)
   assert.NoError(t, resultErr)
}

// Simple implementation of the Config interface
type TestConfig struct {
   logger *logging.Logger
   stats  *stats.Collector
}

func (t *TestConfig) Logger() *logging.Logger {
   return t.logger
}

func (t *TestConfig) Stats() *stats.Collector {
   return t.stats
}
```

是的，代码量更大了。然而，我们不再需要管理测试配置文件，这通常会很麻烦。我们的测试是完全自包含的，不应该出现并发问题，就像全局配置对象可能出现的那样。

**减轻注入常见关注的负担**-在前面的例子中，我们使用配置注入来注入日志记录和仪表对象。这类常见关注是配置注入的一个很好的用例，因为它们经常需要，但并不涉及函数本身的目的。它们可以被视为环境依赖项。由于它们的共享性质，另一种方法是将它们转换为全局单例，而不是注入它们。个人而言，我更喜欢注入它们，因为这给了我验证它们使用的机会。这本身可能感觉奇怪，但在许多情况下，我们从仪表数据的存在或缺失构建系统监控和警报，从而使仪表成为我们代码的特性或契约的一部分，并且可能希望通过测试来防止它们的退化。

**通过减少参数来提高可用性**-与前面的优点类似，应用配置注入可以增强方法的可用性，特别是构造函数，同时减少参数的数量。考虑以下构造函数：

```go
func NewLongConstructor(logger Logger, stats Instrumentation, limiter RateLimiter, cache Cache, url string, credentials string) *MyStruct {
   return &MyStruct{
      // code removed
   }
}
```

现在，看一下使用配置注入的相同构造函数：

```go
func NewByConfigConstructor(cfg MyConfig, url string, credentials string) *MyStruct {
   return &MyStruct{
      // code removed
   }
}
```

通过从构造函数定义中移除环境依赖项，我们剩下的参数大大减少了。更重要的是，**唯一**剩下的参数是与目的相关的，因此使得方法更容易理解和使用。

**依赖项的创建可以推迟到使用时**-你是否曾经尝试注入一个依赖项，却发现它不存在或尚未准备好？你是否曾经有一个非常昂贵的依赖项，你只想在绝对必要的时候才创建它？

通过配置注入，依赖项的创建和访问只需要在使用时解决，而不是在注入时。

# 应用配置注入

之前，我提到我们的 ACME 注册服务有一些问题，我真的希望我们能解决。在这一部分，我们将使用配置注入来处理其中的两个问题。

第一个是我们的许多包都依赖于`config`和`logging`包，除了是一个重大的单一责任原则违反，这种耦合可能会导致循环依赖问题。

第二个问题是我们无法在不实际调用上游服务的情况下测试我们对汇率的调用。到目前为止，我们已经避免在这个包中添加任何测试，因为我们担心我们的测试会受到该服务的影响（在速度和稳定性方面）。

首先，让我们看看我们现在的情况。我们的依赖图目前如下图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/d30373a7-5e67-4c58-bb09-275f904f343b.png)

正如你所看到的，我们有四个包（`data`，`register`，`exchange`和`main`）依赖于`config`包，还有五个（`data`，`register`，`exchange`，`rest`和`config`）依赖于`logging`包。也许更糟糕的是这些包如何依赖于`config`和`logging`包。目前，它们直接访问公共单例。这意味着当我们想要测试我们的记录器使用或在测试期间替换一些配置时，我们将不得不进行猴子补丁，这将导致测试中的数据竞争不稳定性。

为了解决这个问题，我们将为我们的每个对象定义一个配置。每个配置将包括记录器和任何其他需要的配置。然后，我们将任何直接链接到全局变量的内容替换为对注入配置的引用。

这将导致一些大刀阔斧的手术（许多小的改变），但代码将因此变得更好。

我们只会在这里进行一组更改；如果您希望查看所有更改，请查看本章的源代码。

# 将配置注入应用到模型层

重新审视我们的`register`包，我们看到它引用了`config`和`logging`：

```go
// Registerer validates the supplied person, calculates the price in 
// the requested currency and saves the result.
// It will return an error when:
// -the person object does not include all the fields
// -the currency is invalid
// -the exchange rate cannot be loaded
// -the data layer throws an error.
type Registerer struct {
}

// get price in the requested currency
func (r *Registerer) getPrice(ctx context.Context, currency string) (float64, error) {
  converter := &exchange.Converter{}
  price, err := converter.Do(ctx, config.App.BasePrice, currency)
  if err != nil {
    logging.L.Warn("failed to convert the price. err: %s", err)
    return defaultPersonID, err
  }

  return price, nil
}
```

我们的第一步是定义一个接口，它将提供我们需要的依赖项：

```go
// Config is the configuration for the Registerer
type Config interface {
   Logger() *logging.LoggerStdOut
   BasePrice() float64
}
```

你有没有发现什么问题？首先显而易见的是我们的`Logger()`方法返回一个记录器实现的指针。这样可以工作，但不够具有未来性或可测试性。我们可以在本地定义一个`logging`接口，并完全与`logging`包解耦。然而，这意味着我们将不得不在大多数包中定义一个`logging`接口。从理论上讲，这是最好的选择，但实际上并不太实用。相反，我们可以定义一个`logging`接口，并让所有的包都依赖于它。虽然这意味着我们仍然与`logging`包保持耦合，但我们将依赖于一个很少改变的接口，而不是一个更有可能改变的实现。

第二个潜在问题是另一个方法`BasePrice()`的命名，因为它有点通用，并且可能会在以后造成混淆。它也是`Config`结构体中的字段名称，但 Go 不允许我们拥有相同名称的成员变量和方法，所以我们需要更改它。

更新我们的`config`接口后，我们有以下内容：

```go
// Config is the configuration for the Registerer
type Config interface {
  Logger() logging.Logger
  RegistrationBasePrice() float64
}
```

我们现在可以将配置注入应用到我们的`Registerer`，得到以下结果：

```go
// NewRegisterer creates and initializes a Registerer
func NewRegisterer(cfg Config) *Registerer {
   return &Registerer{
      cfg: cfg,
   }
}

// Config is the configuration for the Registerer
type Config interface {
   Logger() logging.Logger
   RegistrationBasePrice() float64
}

// Registerer validates the supplied person, calculates the price in 
// the requested currency and saves the result.
// It will return an error when:
// -the person object does not include all the fields
// -the currency is invalid
// -the exchange rate cannot be loaded
// -the data layer throws an error.
type Registerer struct {
   cfg Config
}

// get price in the requested currency
func (r *Registerer) getPrice(ctx context.Context, currency string) (float64, error) {
   converter := &exchange.Converter{}
   price, err := converter.Do(ctx, r.cfg.RegistrationBasePrice(), currency)
   if err != nil {
      r.logger().Warn("failed to convert the price. err: %s", err)
      return defaultPersonID, err
   }

   return price, nil
}

func (r *Registerer) logger() logging.Logger {
   return r.cfg.Logger()
}
```

我还添加了一个方便的方法`logger()`，以减少代码从`r.cfg.Logger()`到`r.logger()`。我们的服务和测试目前已经损坏，所以我们还需要做更多的改变。

为了再次进行测试，我们需要定义一个测试配置并更新我们的测试。对于我们的测试配置，我们可以使用 mockery 并创建一个模拟实现，但我们不感兴趣验证我们的配置使用或在所有测试中添加额外的代码来配置模拟。相反，我们将使用一个返回可预测值的存根实现。这是我们的存根测试配置：

```go
// Stub implementation of Config
type testConfig struct{}

// Logger implement Config
func (t *testConfig) Logger() logging.Logger {
   return &logging.LoggerStdOut{}
}

// RegistrationBasePrice implement Config
func (t *testConfig) RegistrationBasePrice() float64 {
   return 12.34
}
```

并将这个测试配置添加到我们所有的`Registerer`测试中，如下面的代码所示：

```go
registerer := &Registerer{
   cfg: &testConfig{},
}
```

我们的测试又可以运行了，但奇怪的是，虽然我们的服务编译通过了，但如果我们运行它，它会崩溃并出现`nil`指针异常。我们需要更新我们的`Registerer`的创建方式，从以下方式：

```go
registerModel := &register.Registerer{}
```

我们将其更改为：

```go
registerModel := register.NewRegisterer(config.App)
```

这导致了下一个问题。`config.App`结构体没有实现我们需要的方法。将这些方法添加到`config`，我们得到了以下结果：

```go
// Logger returns a reference to the singleton logger
func (c *Config) Logger() logging.Logger {
   if c.logger == nil {
      c.logger = &logging.LoggerStdOut{}
   }

   return c.logger
}

// RegistrationBasePrice returns the base price for registrations
func (c *Config) RegistrationBasePrice() float64 {
   return c.BasePrice
}
```

通过这些改变，我们已经切断了`registration`包和`config`包之间的依赖链接。在我们之前展示的`Logger()`方法中，你可以看到我们仍然将日志记录器作为单例使用，但它不再是一个全局公共变量，这样就不容易出现数据竞争，而是现在在`config`对象内部。表面上，这可能看起来没有任何区别；然而，我们主要关心的数据竞争是在测试期间。我们的对象现在依赖于注入版本的日志记录器，并且不需要使用全局公共变量。

在这里，我们检查了我们更新后的依赖图，看看接下来该怎么做：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/73430c51-07d8-429f-b4bb-5284a9955b5b.png)

我们只剩下三个连接到`config`包的链接，即来自`main`、`data`和`exchange`包。来自`main`包的链接无法移除，因此我们可以忽略它。所以，让我们看看`data`包。

# 将配置注入应用到数据包

我们的`data`包目前是基于函数的，因此与之前的改变相比，这些改变会有所不同。这是`data`包中的一个典型函数：

```go
// Load will attempt to load and return a person.
// It will return ErrNotFound when the requested person does not exist.
// Any other errors returned are caused by the underlying database 
// or our connection to it.
func Load(ctx context.Context, ID int) (*Person, error) {
   db, err := getDB()
   if err != nil {
      logging.L.Error("failed to get DB connection. err: %s", err)
      return nil, err
   }

   // set latency budget for the database call
   subCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
   defer cancel()

   // perform DB select
   row := db.QueryRowContext(subCtx, sqlLoadByID, ID)

   // retrieve columns and populate the person object
   out, err := populatePerson(row.Scan)
   if err != nil {
      if err == sql.ErrNoRows {
         logging.L.Warn("failed to load requested person '%d'. err: %s", ID, err)
         return nil, ErrNotFound
      }

      logging.L.Error("failed to convert query result. err: %s", err)
      return nil, err
   }
   return out, nil
}
```

在这个函数中，我们引用了我们想要移除的日志记录器，以及我们真正需要提取的一个配置。这个配置是前面代码中函数的第一行需要的。这是`getDB()`函数：

```go
var getDB = func() (*sql.DB, error) {
   if db == nil {
      if config.App == nil {
         return nil, errors.New("config is not initialized")
      }

      var err error
      db, err = sql.Open("mysql", config.App.DSN)
      if err != nil {
         // if the DB cannot be accessed we are dead
         panic(err.Error())
      }
   }

   return db, nil
}
```

我们有一个引用`DSN`来创建数据库池。那么，你认为我们的第一步应该是什么？

和之前的改变一样，让我们首先定义一个包括我们想要注入的所有依赖和配置的接口：

```go
// Config is the configuration for the data package
type Config interface {
   // Logger returns a reference to the logger
   Logger() logging.Logger

   // DataDSN returns the data source name
   DataDSN() string
}
```

现在，让我们更新我们的函数以注入`config`接口：

```go
// Load will attempt to load and return a person.
// It will return ErrNotFound when the requested person does not exist.
// Any other errors returned are caused by the underlying database 
// or our connection to it.
func Load(ctx context.Context, cfg Config, ID int) (*Person, error) {
   db, err := getDB(cfg)
   if err != nil {
      cfg.Logger().Error("failed to get DB connection. err: %s", err)
      return nil, err
   }

   // set latency budget for the database call
   subCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
   defer cancel()

   // perform DB select
   row := db.QueryRowContext(subCtx, sqlLoadByID, ID)

   // retrieve columns and populate the person object
   out, err := populatePerson(row.Scan)
   if err != nil {
      if err == sql.ErrNoRows {
         cfg.Logger().Warn("failed to load requested person '%d'. err: %s", ID, err)
         return nil, ErrNotFound
      }

      cfg.Logger().Error("failed to convert query result. err: %s", err)
      return nil, err
   }
   return out, nil
}

var getDB = func(cfg Config) (*sql.DB, error) {
   if db == nil {
      var err error
      db, err = sql.Open("mysql", cfg.DataDSN())
      if err != nil {
         // if the DB cannot be accessed we are dead
         panic(err.Error())
      }
   }

   return db, nil
}
```

不幸的是，这个改变会导致很多问题，因为`getDB()`被`data`包中所有公共函数调用，而这些函数又被模型层包调用。幸运的是，我们有足够的单元测试来帮助防止在修改过程中出现回归。

我想请你停下来思考一下：我们试图做的是一个微不足道的改变，但它导致了一大堆小改变。此外，我们被迫在这个包的每个公共函数中添加一个参数。这让你对基于函数构建这个包的决定有什么感觉？从函数中重构不是一件小事，但你认为这样做值得吗？

模型层的改变很小，但有趣的是，由于我们已经使用了配置注入，所以这些改变是有意义的。

只需要做两个小改变：

+   我们将`DataDSN()`方法添加到我们的 config

+   我们需要通过`loader()`调用将配置传递到数据包

这是应用了改变的代码：

```go
// Config is the configuration for Getter
type Config interface {
   Logger() logging.Logger
   DataDSN() string
}

// Getter will attempt to load a person.
// It can return an error caused by the data layer or when the 
// requested person is not found
type Getter struct {
   cfg Config
}

// Do will perform the get
func (g *Getter) Do(ID int) (*data.Person, error) {
   // load person from the data layer
   person, err := loader(context.TODO(), g.cfg, ID)
   if err != nil {
      if err == data.ErrNotFound {
         // By converting the error we are hiding the implementation 
         // details from our users.
         return nil, errPersonNotFound
      }
      return nil, err
   }

   return person, err
}

// this function as a variable allows us to Monkey Patch during testing
var loader = data.Load
```

遗憾的是，我们需要在所有模型层包中进行这些小改变。完成后，我们的依赖图现在如下图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/25ae83b5-f5b4-4769-8d43-c4541008f54b.png)

太棒了。只剩下一个不必要的连接到`config`包，它来自`exchange`包。

# 将配置注入应用到 exchange 包

我们可以像对其他包一样，对`exchange`包应用配置注入，使用以下步骤：

1.  定义一个包括我们想要注入的依赖和配置的接口

1.  定义/更新构造函数以接受`config`接口

1.  将注入的配置保存为成员变量

1.  更改引用（例如指向`config`和`logger`）以指向成员变量

1.  更新其他层的`config`接口以包含任何新内容

在我们对`exchange`包应用配置注入后，出现了一种不寻常的情况。我们的依赖图显示，我们已经从`exchange`到`config`包的链接，如下图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/408cc23b-7cbb-43f5-8ec6-a07ba2ffd63f.png)

然而，为了使我们的测试继续工作，我们仍然需要引用配置，如下面的代码所示：

```go
type testConfig struct{}

// ExchangeBaseURL implements Config
func (t *testConfig) ExchangeBaseURL() string {
   return config.App.ExchangeRateBaseURL
}

// ExchangeAPIKey implements Config
func (t *testConfig) ExchangeAPIKey() string {
   return config.App.ExchangeRateAPIKey
}
```

退一步看，我们注意到我们所指的测试并不是针对`exchange`包的测试，而是针对其用户`register`包的测试。这是一个很大的警示。我们可以通过在这两个包之间的关系上应用构造函数注入来快速解决这个问题的第一部分。然后我们可以对对外部服务的调用进行模拟或存根。

我们还可以撤消对`Config`接口的一些早期更改，删除与`exchange`包相关的方法，并将其还原为以下内容：

```go
// Config is the configuration for the Registerer
type Config interface {
   Logger() logging.Logger
   RegistrationBasePrice() float64
   DataDSN() string
}
```

这最终使我们能够从我们的`register`测试到`config`包的链接，并且更重要的是，使我们能够将我们的测试与外部汇率服务解耦。

当我们开始这一部分时，我们定义了两个目标。首先，从`config`包和`logging`包中解耦，并且其次，能够在不调用外部服务的情况下进行测试。到目前为止，我们已经完全解耦了`config`包。我们已经从除`config`包以外的所有包中删除了对全局公共记录器的使用，并且我们还删除了对外部汇率服务的依赖。

然而，我们的服务仍然依赖于该外部服务，但我们绝对没有测试来验证我们是否正确调用它，或者证明服务是否按我们期望的方式响应。这些测试被称为**边界测试**。

# 边界测试

边界测试有两种形式，各自有自己的目标——内部边界和外部边界。

内部边界测试旨在验证两件事：

+   我们的代码是否按我们期望的方式调用外部服务

+   我们的代码对来自外部服务的所有响应（包括正常路径和错误）都做出了我们期望的反应

因此，内部边界测试不与外部服务交互，而是与外部服务的模拟或存根实现交互。

外部边界测试则相反。它们与外部服务进行交互，并验证外部服务是否按我们需要的方式执行。请注意，它们不验证外部服务的 API 合同，也不会按照其所有者的期望进行操作。然而，它们只关注我们的需求。外部边界测试通常会比单元测试更慢、更不可靠。因此，我们可能不希望始终运行它们。我们可以使用 Go 的构建标志来实现这一点。

让我们首先向我们的服务添加外部边界测试。我们可以编写一个测试，其中包含按照服务文档建议的格式对外部服务进行 HTTP 调用，然后验证响应。如果我们对这项服务不熟悉，并且尚未构建调用该服务的代码，这也是了解外部服务的绝佳方式。

然而，在我们的情况下，我们已经编写了代码，因此更快的选择是使用*live*配置调用该代码。这样做会返回一个类似于以下内容的 JSON 负载：

```go
{
   "success":true,
   "historical":true,
   "date":"2010-11-09",
   "timestamp":1289347199,
   "source":"USD",
   "quotes":{
      "USDAUD":0.989981
   }
}
```

虽然响应的格式是可预测的，但`timestamp`和`quotes`的值会改变。那么，我们可以测试什么？也许更重要的是，我们依赖响应的哪些部分？在仔细检查我们的代码后，我们意识到在响应中的所有字段中，我们唯一使用的是`quotes`映射。此外，我们从外部服务需要的唯一东西是我们请求的货币存在于该映射中，并且该值是`float64`类型。因此，通过仅测试这些特定属性，我们的测试将尽可能地对更改具有弹性。

这给我们一个看起来像以下代码的测试：

```go
func TestExternalBoundaryTest(t *testing.T) {
   // define the config
   cfg := &testConfig{
      baseURL: config.App.ExchangeRateBaseURL,
      apiKey:  config.App.ExchangeRateAPIKey,
   }

   // create a converter to test
   converter := NewConverter(cfg)

   // fetch from the server
   response, err := converter.loadRateFromServer(context.Background(), "AUD")
   require.NotNil(t, response)
   require.NoError(t, err)

   // parse the response
   resultRate, err := converter.extractRate(response, "AUD")
   require.NoError(t, err)

   // validate the result
   assert.True(t, resultRate > 0)
}
```

为了确保这个测试只在我们想要的时候运行，我们在文件顶部放置了以下构建标签：

```go
// +build external
```

现在，让我们看看内部边界测试。第一步是制作外部服务的模拟实现。我们有先前提到的结果有效负载。为此，我们将使用`httptest`包创建一个返回我们的测试有效负载的 HTTP 服务器，如下所示：

```go
type happyExchangeRateService struct{}

// ServeHTTP implements http.Handler
func (*happyExchangeRateService) ServeHTTP(response http.ResponseWriter, request *http.Request) {
  payload := []byte(`
{
   "success":true,
   "historical":true,
   "date":"2010-11-09",
   "timestamp":1289347199,
   "source":"USD",
   "quotes":{
      "USDAUD":0.989981
   }
}`)
  response.Write(payload)
}
```

现在，它返回一个固定的响应，并且不对请求进行验证。我们现在可以构建我们的内部边界测试。与外部边界测试不同，结果现在完全由我们控制，因此是可预测的。因此，我们可以测试确切的结果，如下面的代码所示：

```go
func TestInternalBoundaryTest(t *testing.T) {
   // start our test server
   server := httptest.NewServer(&happyExchangeRateService{})
   defer server.Close()

   // define the config
   cfg := &testConfig{
      baseURL: server.URL,
      apiKey:  "",
   }

   // create a converter to test
   converter := NewConverter(cfg)
   resultRate, resultErr := converter.Exchange(context.Background(), 100.00, "AUD")

   // validate the result
   assert.Equal(t, 101.01, resultRate)
   assert.NoError(t, resultErr)
}
```

现在我们有了一个基本的内部边界测试。我们能够验证，而不依赖外部服务，外部服务返回我们期望的有效负载，并且我们能够正确提取和使用结果。我们可以进一步扩展我们的测试，包括以下内容：

+   验证我们的代码，并在外部服务宕机或缓慢时返回合理的错误

+   证明我们的代码在外部服务返回空或无效响应时返回合理的错误

+   验证我们的代码执行的 HTTP 请求的测试

在我们的内部边界测试就位后，我们最终对我们的汇率代码进行了测试。我们已经确保我们的代码按预期工作，并且我们的测试是可靠的，并且完全由我们控制。此外，我们还有外部边界测试，我们可以偶尔运行以通知我们外部服务的任何更改将会破坏我们的服务。

# 配置注入的缺点

正如我们所看到的，配置注入可以与构造函数和函数一起使用，因此可以构建一个只使用配置注入的系统。不幸的是，配置注入也有一些缺点。

**传递配置而不是抽象依赖项泄漏实现细节** - 考虑以下代码：

```go
type PeopleFilterConfig interface {
   DSN() string
}

func PeopleFilter(cfg PeopleFilterConfig, filter string) ([]Person, error) {
   // load people
   loader := &PersonLoader{}
   people, err := loader.LoadAll(cfg)
   if err != nil {
      return nil, err
   }

   // filter people
   out := []Person{}
   for _, person := range people {
      if strings.Contains(person.Name, filter) {
         out = append(out, person)
      }
   }

   return out, nil
}

type PersonLoaderConfig interface {
   DSN() string
}

type PersonLoader struct{}

func (p *PersonLoader) LoadAll(cfg PersonLoaderConfig) ([]Person, error) {
   return nil, errors.New("not implemented")
}
```

在这个例子中，`PeopleFilter`函数知道`PersonLoader`是一个数据库。这可能看起来不是什么大不了的事，如果实现策略永远不改变，它就不会产生不利影响。然而，如果我们从数据库转移到外部服务或其他任何地方，我们将不得不同时更改我们的`PersonLoader`数据库。一个更具未来性的实现如下：

```go
type Loader interface {
   LoadAll() ([]Person, error)
}

func PeopleFilter(loader Loader, filter string) ([]Person, error) {
   // load people
   people, err := loader.LoadAll()
   if err != nil {
      return nil, err
   }

   // filter people
   out := []Person{}
   for _, person := range people {
      if strings.Contains(person.Name, filter) {
         out = append(out, person)
      }
   }

   return out, nil
}
```

如果我们改变数据加载的位置，这种实现不太可能需要更改。

**依赖生命周期不太可预测** - 在优势中，我们说过依赖项的创建可以推迟到使用时。你内心的批评者可能反对这种说法，而且有充分的理由。这是一个优势，但它也使得依赖项的生命周期不太可预测。当使用构造函数注入或方法注入时，依赖项必须在注入之前存在。因此，依赖项的创建或初始化的任何问题都会在此较早的时间出现。当依赖项在某个未知的时间点初始化时，可能会出现一些问题。

首先，如果问题是无法恢复的或导致系统崩溃，这意味着系统最初看起来健康，然后变得不健康或崩溃不可预测。这种不可预测性可能导致极其难以调试的问题。

其次，如果依赖项的初始化包括延迟的可能性，我们必须意识到并考虑任何这样的延迟。考虑以下代码：

```go
func DoJob(pool WorkerPool, job Job) error {
   // wait for pool
   ready := pool.IsReady()

   select {
   case <-ready:
      // happy path

   case <-time.After(1 * time.Second):
      return errors.New("timeout waiting for worker pool")
   }

   worker := pool.GetWorker()
   return worker.Do(job)
}
```

现在将其与假设池在注入之前已准备就绪的实现进行比较：

```go
func DoJobUpdated(pool WorkerPool, job Job) error {
   worker := pool.GetWorker()
   return worker.Do(job)
}
```

如果这个函数是端点的一部分，并且具有延迟预算，会发生什么？如果启动延迟大于延迟预算，那么第一个请求将总是失败。

**过度使用会降低用户体验** - 虽然我强烈建议您只在配置和环境依赖项（如仪器）中使用这种模式，但也可以在许多其他地方应用这种模式。但是，通过将依赖项推入`config`接口，它们变得不太明显，并且我们有一个更大的接口要实现。让我们重新审视一个早期的例子：

```go
// NewByConfigConstructor is the constructor for MyStruct
func NewByConfigConstructor(cfg MyConfig, limiter RateLimiter, cache Cache) *MyStruct {
   return &MyStruct{
   // code removed
   }
}
```

考虑速率限制器依赖。如果我们将其合并到`Config`接口中会发生什么？这个对象使用和依赖速率限制器的事实就不太明显了。如果每个类似的函数都有速率限制，那么随着使用变得更加环境化，这将不再是一个问题。

另一个不太显而易见的方面是配置。速率限制器的配置可能在所有用法中并不一致。当所有其他依赖项和配置都来自共享对象时，这是一个问题。我们可以组合配置对象并自定义返回的速率限制器，但这感觉像是过度设计。

**更改可能会在软件层中传播** - 当配置通过层传递时，这个问题才会出现。考虑以下例子：

```go
func NewLayer1Object(config Layer1Config) *Layer1Object {
   return &Layer1Object{
      MyConfig:     config,
      MyDependency: NewLayer2Object(config),
   }
}

// Configuration for the Layer 1 Object
type Layer1Config interface {
   Logger() Logger
}

// Layer 1 Object
type Layer1Object struct {
   MyConfig     Layer1Config
   MyDependency *Layer2Object
}

// Configuration for the Layer 2 Object
type Layer2Config interface {
   Logger() Logger
}

// Layer 2 Object
type Layer2Object struct {
   MyConfig Layer2Config
}

func NewLayer2Object(config Layer2Config) *Layer2Object {
   return &Layer2Object{
      MyConfig: config,
   }
}
```

有了这种结构，当我们需要向`Layer2Config`接口添加新的配置或依赖时，我们也会被迫将其添加到`Layer1Config`接口中。`Layer1Config`将违反接口隔离原则，正如第二章中讨论的*SOLID 设计原则 for Go*，这表明我们可能会有问题。此外，根据代码的分层和重用级别，更改的数量可能会很大。在这种情况下，更好的选择是应用构造函数注入，将`Layer2Object`注入`Layer1Object`。这将完全解耦对象并消除对分层更改的需求。

# 总结

在本章中，我们利用了配置注入，这是构造函数和方法注入的扩展版本，以改善我们的代码的用户体验，主要是通过将环境依赖和配置与上下文相关的依赖分开处理。

在对我们的示例服务应用配置注入时，我们已经将所有可能的包与`config`包解耦，使其有更多的自由发展。我们还将大部分日志记录器的使用从全局公共变量切换为注入的抽象依赖，从而消除了与日志记录器实例相关的任何数据竞争的可能性，并使我们能够在没有任何混乱的猴子补丁的情况下测试日志记录器的使用。

在下一章中，我们将研究另一种不寻常的依赖注入形式，称为**即时**（**JIT**）**依赖注入**。通过这种技术，我们将减少与层之间的依赖创建和注入相关的负担，同时不会牺牲使用模拟和存根进行测试的能力。

# 问题

1.  配置注入与方法或构造函数注入有何不同？

1.  我们如何决定将哪些参数移动到配置注入？

1.  为什么我们不通过配置注入注入所有依赖项？

1.  为什么我们想要注入环境依赖（如日志记录器），而不是使用全局公共变量？

1.  边界测试为什么重要？

1.  配置注入的理想使用案例是什么？


# 第九章：刚性依赖注入

使用*传统* **依赖注入**（**DI**）方法，父对象或调用对象向子类提供依赖项。然而，有许多情况下，依赖项只有一个实现。在这些情况下，一个务实的方法是问自己，为什么要注入依赖项？在本章中，我们将研究**just-in-time**（**JIT**）依赖注入，这是一种策略，它给我们带来了 DI 的许多好处，如解耦和可测试性，而不需要向我们的构造函数或方法添加参数。

本章将涵盖以下主题：

+   JIT 注入

+   JIT 注入的优势

+   应用 JIT 注入

+   JIT 注入的缺点

# 技术要求

熟悉我们在第四章中介绍的服务代码可能会有所帮助，*ACME 注册服务简介*。本章还假定您已经阅读了第六章，*构造函数注入的依赖注入*，以及在较小程度上，第五章，*使用 Monkey Patching 进行依赖注入*。

您可能还会发现阅读和运行本章的完整代码版本很有用，该代码版本可在[`github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/tree/master/ch09`](https://github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/tree/master/ch09)上找到。

获取代码并配置示例服务的说明可在此处的 README 部分找到：[`github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/`](https://github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/)。

您可以在`ch09/acme`中找到我们的服务代码，其中已经应用了本章的更改。

在本章中，我们将使用 mockery（[`github.com/vektra/mockery`](https://github.com/vektra/mockery)）生成我们接口的模拟实现，并介绍一个名为**package coverage**（[`github.com/corsc/go-tools/tree/master/package-coverage)`](https://github.com/corsc/go-tools/tree/master/package-coverage)）的新工具。

# JIT 注入

您是否曾经编写过一个对象，并注入了一个您知道只会有一个实现的依赖项？也许您已经将数据库处理代码注入到业务逻辑层中，如下面的代码所示：

```go
func NewMyLoadPersonLogic(ds DataSource) *MyLoadPersonLogic {
   return &MyLoadPersonLogic{
      dataSource: ds,
   }
}

type MyLoadPersonLogic struct {
   dataSource DataSource
}

// Load person by supplied ID
func (m *MyLoadPersonLogic) Load(ID int) (Person, error) {
   return m.dataSource.Load(ID)
}
```

您是否曾经为了在测试期间将其模拟而将依赖项添加到构造函数中？这在以下代码中显示：

```go
func NewLoadPersonHandler(logic LoadPersonLogic) *LoadPersonHandler {
   return &LoadPersonHandler{
      businessLogic: logic,
   }
}

type LoadPersonHandler struct {
   businessLogic LoadPersonLogic
}

func (h *LoadPersonHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
   requestedID, err := h.extractInputFromRequest(request)

   output, err := h.businessLogic.Load(requestedID)
   if err != nil {
      response.WriteHeader(http.StatusInternalServerError)
      return
   }

   h.writeOutput(response, output)
}
```

这些事情可能会感觉像是不必要的额外工作，它们确实会降低代码的用户体验。 JIT 注入为我们提供了一个舒适的中间地带。 JIT 注入可能最好通过一些示例来解释。让我们看看我们第一个应用了 JIT 注入的示例：

```go
type MyLoadPersonLogicJIT struct {
   dataSource DataSourceJIT
}

// Load person by supplied ID
func (m *MyLoadPersonLogicJIT) Load(ID int) (Person, error) {
   return m.getDataSource().Load(ID)
}

func (m *MyLoadPersonLogicJIT) getDataSource() DataSourceJIT {
   if m.dataSource == nil {
      m.dataSource = NewMyDataSourceJIT()
   }

   return m.dataSource
}
```

如您所见，我们已经通过添加一个`getter`函数`getDataSource()`，将直接引用从`m.dataSource`更改为`m.getDataSource()`。在`getDataSource()`中，我们执行了一个简单而高效的检查，以查看依赖项是否已经存在，当它不存在时，我们创建它。这就是我们得到*just-in-time 注入*名称的地方。

因此，如果我们不打算注入依赖项，那么为什么需要注入？简单的答案是测试。

在我们的原始示例中，我们能够在测试期间使用模拟实现*替换*我们的依赖项，如下面的代码所示：

```go
func TestMyLoadPersonLogic(t *testing.T) {
   // setup the mock db
   mockDB := &mockDB{
      out: Person{Name: "Fred"},
   }

   // call the object we are testing
   testObj := NewMyLoadPersonLogic(mockDB)
   result, resultErr := testObj.Load(123)

   // validate expectations
   assert.Equal(t, Person{Name: "Fred"}, result)
   assert.Nil(t, resultErr)
}
```

使用 JIT 注入，我们仍然可以提供一个模拟实现，但是不是通过构造函数提供，而是直接将其注入到私有成员变量中，就像这样：

```go
func TestMyLoadPersonLogicJIT(t *testing.T) {
   // setup the mock db
   mockDB := &mockDB{
      out: Person{Name: "Fred"},
   }

   // call the object we are testing
   testObj := MyLoadPersonLogicJIT{
      dataSource: mockDB,
   }
   result, resultErr := testObj.Load(123)

   // validate expectations
   assert.Equal(t, Person{Name: "Fred"}, result)
   assert.Nil(t, resultErr)
}
```

您可能还注意到，在这个例子中，我们放弃了使用构造函数。这并不是必要的，也不会总是这种情况。应用 JIT 注入通过减少参数的数量来提高对象的可用性。在我们的例子中，没有剩下的参数，所以放弃构造函数似乎也是合适的。

JIT 注入使我们能够打破 DI 的传统规则，使对象能够在需要时创建自己的依赖关系。虽然严格来说这是违反了*单一责任原则*部分，正如在第二章中讨论的那样，*Go 的 SOLID 设计原则*，但可用性的改进是显著的。

# JIT 注入的优势

这种方法旨在解决传统 DI 的一些痛点。这里列出的优势是特定于这种方法的，与其他形式的依赖注入形成对比。这种方法的特定优势包括以下内容。

更好的用户体验（UX）由于更少的输入 - 我知道我已经提到了这一点很多次，但是更容易理解的代码也更容易维护和扩展。当一个函数的参数更少时，它本质上更容易理解。比较构造函数：

```go
func NewGenerator(storage Storage, renderer Renderer, template io.Reader) *Generator {
   return &Generator{
      storage:  storage,
      renderer: renderer,
      template: template,
   }
}
```

与这个：

```go
func NewGenerator(template io.Reader) *Generator {
   return &Generator{
      template: template,
   }
}
```

在这个例子中，我们删除了所有只有一个活动实现的依赖项，并用 JIT 注入替换了它们。现在，这个函数的用户只需要提供一个可能会改变的依赖项。

**它非常适合可选依赖项** - 与前面关于 UX 的观点类似，可选依赖项可能会使函数的参数列表膨胀。此外，依赖项是否是可选的并不是立即显而易见的。将依赖项移动到公共成员变量允许用户仅在需要时提供它。然后应用 JIT 注入允许对象实例化默认依赖项的副本。这显著简化了对象内部的代码。

考虑以下不使用 JIT 注入的代码：

```go
func (l *LoaderWithoutJIT) Load(ID int) (*Animal, error) {
   var output *Animal
   var err error

   // attempt to load from cache
   if l.OptionalCache != nil {
      output = l.OptionalCache.Get(ID)
      if output != nil {
         // return cached value
         return output, nil
      }
   }

   // load from data store
   output, err = l.datastore.Load(ID)
   if err != nil {
      return nil, err
   }

   // cache the loaded value
   if l.OptionalCache != nil {
      l.OptionalCache.Put(ID, output)
   }

   // output the result
   return output, nil
}
```

应用 JIT 注入，这变成了以下形式：

```go
func (l *LoaderWithJIT) Load(ID int) (*Animal, error) {
   // attempt to load from cache
   output := l.cache().Get(ID)
   if output != nil {
      // return cached value
      return output, nil
   }

   // load from data store
   output, err := l.datastore.Load(ID)
   if err != nil {
      return nil, err
   }

   // cache the loaded value
   l.cache().Put(ID, output)

   // output the result
   return output, nil
}
```

这个函数现在更加简洁，更容易阅读。我们将在下一节中更详细地讨论使用 JIT 注入处理可选依赖项。

**更好地封装实现细节** - 对典型 DI（即构造函数或参数注入）的反驳之一是，通过暴露一个对象对另一个对象的依赖，你泄漏了实现细节。考虑以下构造函数：

```go
func NewLoader(ds Datastore, cache Cache) *MyLoader {
   return &MyLoader{
      ds:    ds,
      cache: cache,
   }
}
```

现在，把自己放在`MyLoader`的用户的位置上，不知道它的实现。对你来说，`MyLoader`使用数据库还是缓存重要吗？如果你没有多个实现或配置可供使用，让`MyLoader`的作者为你处理会更容易吗？

**减少测试引起的损害** - 反对 DI 的人经常抱怨的另一个问题是，依赖项被添加到构造函数中，唯一目的是在测试期间替换它们。这个观点是有根据的；你会经常看到这种情况，也是测试引起的损害的更常见形式之一。JIT 注入通过将关系更改为私有成员变量并将其从公共 API 中移除来缓解了这一问题。这仍然允许我们在测试期间替换依赖项，但不会造成公共损害。

如果你在想，选择私有成员变量而不是公共的是有意的，也是有意限制的。私有的话，我们只能在同一个包内的测试期间访问和替换依赖项。包外的测试故意没有访问权限。这样做的第一个原因是封装。我们希望隐藏实现细节，使其他包不与我们的包耦合。任何这样的耦合都会使对我们实现的更改变得更加困难。

第二个原因是 API 污染。如果我们将成员变量设为公共的，那么不仅测试可以访问，而且所有人都可以访问，从而打开了意外、无效或危险使用我们内部的可能性。

**这是一个很好的替代方法**——正如你可能还记得第五章中所说的，*使用猴子补丁进行依赖注入*，猴子补丁的最大问题之一是测试期间的并发性。通过调整单个全局变量以适应当前测试，任何使用该变量的其他测试都会受到影响，很可能会出错。可以使用 JIT 注入来避免这个问题。考虑以下代码：

```go
// Global singleton of connections to our data store
var storage UserStorage

type Saver struct {
}

func (s *Saver) Do(in *User) error {
   err := s.validate(in)
   if err != nil {
      return err
   }

   return storage.Save(in)
}
```

目前，全局变量存储在测试期间需要进行猴子补丁。但是当我们应用 JIT 注入时会发生什么呢？

```go
// Global singleton of connections to our data store
var storage UserStorage

type Saver struct {
   storage UserStorage
}

func (s *Saver) Do(in *User) error {
   err := s.validate(in)
   if err != nil {
      return err
   }

   return s.getStorage().Save(in)
}

// Just-in-time DI
func (s *Saver) getStorage() UserStorage {
   if s.storage == nil {
      s.storage = storage
   }

   return s.storage
}
```

现在所有对全局变量的访问都通过`getStorage()`进行，我们能够使用 JIT 注入来*替换*`storage`成员变量，而不是对全局（和共享）变量进行猴子补丁，就像这个例子中所示的那样：

```go
func TestSaver_Do(t *testing.T) {
   // input
   carol := &User{
      Name:     "Carol",
      Password: "IamKing",
   }

   // mocks/stubs
   stubStorage := &StubUserStorage{}

   // do call
   saver := &Saver{
      storage: stubStorage,
   }
   resultErr := saver.Do(carol)

   // validate
   assert.NotEqual(t, resultErr, "unexpected error")
}
```

在上述测试中，全局变量上不再存在数据竞争。

**对于分层代码来说非常好**——当将依赖注入应用于整个项目时，很常见的是在应用程序执行的早期看到大量对象被创建。例如，我们的最小示例服务已经在`main()`中创建了四个对象。四个听起来可能不多，但我们还没有将 DI 应用到所有的包，到目前为止我们只有三个端点。

对于我们的服务，我们有三层代码，REST、业务逻辑和数据。层之间的关系很简单。REST 层中的一个对象调用其业务逻辑层的合作对象，然后调用数据层。除了测试之外，我们总是注入相同的依赖项。应用 JIT 注入将允许我们从构造函数中删除这些依赖项，并使代码更易于使用。

**实现成本低**——正如我们在之前的猴子补丁示例中看到的，应用 JIT 注入非常容易。此外，更改范围很小。

同样，对于原本没有任何形式的 DI 的代码应用 JIT 注入也很便宜。考虑以下代码：

```go
type Car struct {
   engine Engine
}

func (c *Car) Drive() {
   c.engine.Start()
   defer c.engine.Stop()

   c.engine.Drive()
}
```

如果我们决定将`Car`与`Engine`解耦，那么我们只需要将抽象交互定义为接口，然后将所有对`c.engine`的直接访问更改为使用`getter`函数，如下面的代码所示：

```go
type Car struct {
   engine Engine
}

func (c *Car) Drive() {
   engine := c.getEngine()

   engine.Start()
   defer engine.Stop()

   engine.Drive()
}

func (c *Car) getEngine() Engine {
   if c.engine == nil {
      c.engine = newEngine()
   }

   return c.engine
}
```

考虑一下应用构造函数注入的过程。我们需要在哪些地方进行更改？

# 应用 JIT 注入

在之前的章节中，我提到了 JIT 注入可以用于私有和公共依赖项，这是两种非常不同的用例。在本节中，我们将应用这两种选项以实现非常不同的结果。

# 单元测试覆盖率

在 Go 中，测试覆盖率是通过在调用 go test 时添加`-cover`标志来计算的。由于这只适用于一个包，我觉得这很不方便。因此，我们将使用一个工具，该工具可以递归计算目录树中所有包的测试覆盖率。这个工具叫做**package-coverage**，可以从 GitHub ([`github.com/corsc/go-tools/tree/master/package-coverage`](https://github.com/corsc/go-tools/tree/master/package-coverage)) 获取。

使用`package-coverage`计算覆盖率时，我们使用以下命令：

```go
$ cd $GOPATH/src/github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/ch08/

$ export ACME_CONFIG=$GOPATH/src/github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/config.json

$ package-coverage -a -prefix $(go list)/ ./acme/
```

注意：我故意使用了第八章中的代码，*通过配置进行依赖注入*，所以覆盖率数字是在我们在本章可能进行的任何更改之前。

这给我们带来了以下结果：

```go
-------------------------------------------------------------------------
|      Branch     |       Dir       |                                   |
|   Cov% |  Stmts |   Cov% |  Stmts | Package                           |
-------------------------------------------------------------------------
|  65.66 |    265 |   0.00 |      7 | acme/                             |
|  47.83 |     23 |  47.83 |     23 | acme/internal/config/             |
|   0.00 |      4 |   0.00 |      4 | acme/internal/logging/            |
|  73.77 |     61 |  73.77 |     61 | acme/internal/modules/data/       |
|  61.70 |     47 |  61.70 |     47 | acme/internal/modules/exchange/   |
|  85.71 |      7 |  85.71 |      7 | acme/internal/modules/get/        |
|  46.15 |     13 |  46.15 |     13 | acme/internal/modules/list/       |
|  62.07 |     29 |  62.07 |     29 | acme/internal/modules/register/   |
|  79.73 |     74 |  79.73 |     74 | acme/internal/rest/               |
-------------------------------------------------------------------------
```

所以，我们可以从这些数字中推断出什么呢？

1.  代码覆盖率是合理的。它可能会更好，但除了`logging`包上的 0 之外，几乎所有包都有 50%以上。

1.  语句（`stmts`）计数很有趣。语句大致相当于*代码行*，因此这些数字表明哪些包有更多或更少的代码。我们可以看到`rest`、`data`和`exchange`包是最大的。

1.  我们可以从包中的代码量推断出，包含的代码越多，责任和复杂性就越大。因此，这个包带来的风险也就越大。

考虑到两个最大的、最具风险的包`rest`和`data`都有很好的测试覆盖率，我们仍然没有任何迫切需要关注的迹象。但是如果我们将测试覆盖率和依赖图结合起来会发生什么呢？

# 私有依赖

我们可以通过应用 JIT 注入来改进我们的服务的许多地方。那么我们该如何决定呢？让我们看看我们的依赖图有什么说法：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/aeec3c06-de6a-41e5-89e3-56c80332a557.png)

有很多连接进入日志包。但是我们在第八章中已经相当程度地解耦了它，*通过配置进行依赖注入*。

下一个用户最多的包是`data`包。我们在第五章中曾经讨论过它，*使用 Monkey Patching 进行依赖注入*，但也许现在是时候重新审视它，看看我们是否可以进一步改进它。

在我们做出决定之前，我将向你介绍另一种了解代码健康状况和我们最好花费精力的方法：单元测试覆盖率。与依赖图一样，它不能提供明确的指标，只能给你一些暗示。

# 覆盖率和依赖图

依赖图告诉我们，`data`包有很多用户。测试覆盖率告诉我们，它也是我们拥有的最大的包之一。因此，我们可以推断，如果我们想要做改进，这可能是开始的合适地方。

你可能还记得之前章节提到的，`data`包使用了函数和全局单例池，这两者都给我们带来了不便。因此，让我们看看是否可以使用 JIT 注入来摆脱这些痛点。

# 赶走猴子

以下是`get`包目前如何使用`data`包的方式：

```go
// Do will perform the get
func (g *Getter) Do(ID int) (*data.Person, error) {
   // load person from the data layer
   person, err := loader(context.TODO(), g.cfg, ID)
   if err != nil {
      if err == data.ErrNotFound {
         // By converting the error we are hiding the implementation 
         // details from our users.
         return nil, errPersonNotFound
      }
      return nil, err
   }

   return person, err
}

// this function as a variable allows us to Monkey Patch during testing
var loader = data.Load

```

我们的第一个改变将是定义一个接口，用它来替换我们的`loader`函数：

```go
//go:generate mockery -name=myLoader -case underscore -testonly -inpkg
type myLoader interface {
   Load(ctx context.Context, ID int) (*data.Person, error)
}
```

你可能已经注意到我们删除了配置参数。等我们完成后，我们将不必在每次调用时传递这个参数。我还添加了一个`go generate`注释，它将创建一个我们以后会使用的模拟。

接下来，我们将将这个依赖作为私有成员变量添加，并更新我们的`Do()`方法以使用 JIT 注入：

```go
// Do will perform the get
func (g *Getter) Do(ID int) (*data.Person, error) {
   // load person from the data layer
   person, err := g.getLoader().Load(context.TODO(), ID)
   if err != nil {
      if err == data.ErrNotFound {
         // By converting the error we are hiding the implementation 
         // details from our users.
         return nil, errPersonNotFound
      }
      return nil, err
   }

   return person, err
}
```

但是我们的 JIT 注入`getter`方法会是什么样子呢？基本结构将是标准的，如下面的代码所示：

```go
func (g *Getter) getLoader() myLoader {
   if g.data == nil {
      // To be determined
   }

   return g.data
}
```

因为`data`包是以函数实现的，我们目前没有任何实现我们的`loader`接口的东西。我们的代码和单元测试现在都出问题了，所以在我们让它们再次工作之前，我们将不得不盲目行事一段时间。

让我们首先定义一个**数据访问对象**（**DAO**），这是让我们的代码再次工作的最短路径。这将用一个结构体替换`data`包中的函数，并给我们一个实现`myLoader`接口的东西。为了尽量减少更改，我们将让 DAO 方法调用现有的函数，如下面的代码所示：

```go
// NewDAO will initialize the database connection pool (if not already 
// done) and return a data access object which can be used to interact 
// with the database
func NewDAO(cfg Config) *DAO {
   // initialize the db connection pool
   _, _ = getDB(cfg)

   return &DAO{
      cfg: cfg,
   }
}

type DAO struct {
   cfg Config
}

// Load will attempt to load and return a person.
func (d *DAO) Load(ctx context.Context, ID int) (*Person, error) {
   return Load(ctx, d.cfg, ID)
}
```

即使在我们将 DAO 添加到`getLoader()`函数中后，我们的测试仍然没有恢复。我们的测试仍然使用了 Monkey Patching，因此我们需要删除该代码并用一个模拟替换它，得到以下结果：

```go
func TestGetter_Do_happyPath(t *testing.T) {
   // inputs
   ID := 1234

   // configure the mock loader
   mockResult := &data.Person{
      ID:       1234,
      FullName: "Doug",
   }
   mockLoader := &mockMyLoader{}
   mockLoader.On("Load", mock.Anything, ID).Return(mockResult, nil).Once()

   // call method
   getter := &Getter{
      data: mockLoader,
   }
   person, err := getter.Do(ID)

   // validate expectations
   require.NoError(t, err)
   assert.Equal(t, ID, person.ID)
   assert.Equal(t, "Doug", person.FullName)
   assert.True(t, mockLoader.AssertExpectations(t))
}
```

最后，我们的测试又可以工作了。通过这些重构，我们还实现了一些其他的改进：

+   我们的`get`包的测试不再使用 Monkey Patching；这意味着我们可以确定没有与 Monkey Patching 相关的并发问题

+   除了数据结构（`data.Person`）之外，`get`包的测试不再使用`data`包

+   也许最重要的是，`get`包的测试不再需要配置数据库

完成`get`包的计划更改后，我们可以转移到`data`包。

早些时候，我们定义了一个 DAO，其中我们的`Load()`方法调用了现有的`Load()`函数。由于`Load()`函数没有更多的用户，我们可以简单地复制代码并更新相应的测试。

在为`data`包及其用户重复这个简单的过程之后，我们成功地迁移到了基于对象的包，而不是基于函数的包。

# 可选的公共依赖项

到目前为止，我们已经将 JIT 依赖注入应用于私有依赖项，目标是减少参数，并使我们的`data`包更加简单易用。

还有另一种使用 JIT 注入的方式——可选的公共依赖项。这些依赖项是公共的，因为我们希望用户能够更改它们，但我们不将它们作为构造函数的一部分，因为它们是可选的。这样做会影响用户体验，特别是在可选依赖项很少使用的情况下。

假设我们在服务的*加载所有注册*端点遇到性能问题，并且我们怀疑问题与数据库的响应速度有关。

面对这样的问题，我们决定需要通过添加一些仪器来跟踪这些查询花费了多长时间。为了确保我们能够轻松地打开和关闭这个跟踪器，我们可以将其作为可选依赖项。

我们的第一步将是定义我们的`tracker`接口：

```go
// QueryTracker is an interface to track query timing
type QueryTracker interface {
   // Track will record/out the time a query took by calculating 
   // time.Now().Sub(start)
   Track(key string, start time.Time)
}
```

我们需要做出决定。使用`QueryTracker`是可选的，这意味着用户不能保证已注入依赖项。

为了避免在使用`QueryTracker`时出现守卫子句，我们将引入一个 NO-OP 实现，当用户没有提供时可以使用。NO-OP 实现，有时被称为**空对象**，是一个实现接口但所有方法都故意不执行任何操作的对象。

这是`QueryTracker`的 NO-OP 实现：

```go
// NO-OP implementation of QueryTracker
type noopTracker struct{}

// Track implements QueryTracker
func (_ *noopTracker) Track(_ string, _ time.Time) {
   // intentionally does nothing
}
```

现在，我们可以将其引入到我们的 DAO 作为一个公共成员变量：

```go
// DAO is a data access object that provides an abstraction over 
// our database interactions.
type DAO struct {
   cfg Config

   // Tracker is an optional query timer
   Tracker QueryTracker
}
```

我们可以使用 JIT 注入来访问默认为 NO-OP 版本的跟踪器：

```go
func (d *DAO) getTracker() QueryTracker {
   if d.Tracker == nil {
      d.Tracker = &noopTracker{}
   }

   return d.Tracker
}
```

现在一切就绪，我们可以在想要跟踪的任何方法的开头添加以下行：

```go
// track processing time
defer d.getTracker().Track("LoadAll", time.Now())
```

这里值得注意的是`defer`的使用。基本上，`defer`在这里有两个重要的特性。首先，它将在函数退出时被调用，这样我们可以一次添加跟踪器，而不是在每个返回语句旁边添加。其次，`defer`的参数是在遇到该行时确定的，而不是在执行时确定的。这意味着`time.Now()`的值将在我们跟踪的函数开始时调用，而不是在`Track()`函数返回时调用。

为了使我们的跟踪器有用，我们需要提供除了 NO-OP 之外的实现。我们可以将这些值推送到像 StatsD 或 Graphite 这样的外部系统，但为了简单起见，我们将结果输出到日志。代码如下：

```go
// NewLogTracker returns a Tracker that outputs tracking data to log
func NewLogTracker(logger logging.Logger) *LogTracker {
   return &LogTracker{
      logger: logger,
   }
}

// LogTracker implements QueryTracker and outputs to the supplied logger
type LogTracker struct {
   logger logging.Logger
}

// Track implements QueryTracker
func (l *LogTracker) Track(key string, start time.Time) {
   l.logger.Info("[%s] Timing: %s\n", key, time.Now().Sub(start).String())
}
```

现在，我们可以暂时将我们的 DAO 使用从这个更新为：

```go
func (l *Lister) getLoader() myLoader {
   if l.data == nil {
      l.data = data.NewDAO(l.cfg)
   }

   return l.data
}
```

现在更新为：

```go
func (l *Lister) getLoader() myLoader {
   if l.data == nil {
      l.data = data.NewDAO(l.cfg)

      // temporarily add a log tracker
      l.data.(*data.DAO).Tracker = data.NewLogTracker(l.cfg.Logger())
   }

   return l.data
}
```

是的，这行有点丑，但幸运的是它只是临时的。如果我们决定让我们的 QueryTracker 永久存在，或者发现自己大部分时间都在使用它，那么我们可以很容易地切换到构造函数注入。

# JIT 注入的缺点

虽然 JIT 注入可能很方便，但并非在所有情况下都可以使用，而且有一些需要注意的地方。其中包括以下内容：

**只能应用于静态依赖项**-第一个，也许是最重要的缺点是，这种方法只能应用于在测试期间只发生变化的依赖项。我们不能用它来替代参数注入或配置注入。这是因为依赖项的实例化发生在私有方法内部，只在第一次尝试访问变量时发生。

**依赖和用户生命周期没有分开**-当使用构造函数注入或参数注入时，通常可以假定被注入的依赖已经完全初始化并准备就绪。任何成本或延迟，比如与创建资源池或预加载数据相关的成本，都已经支付。使用 JIT 注入时，依赖项会在第一次使用之前立即创建。因此，任何初始化成本都必须由第一个请求支付。下图显示了三个对象之间的典型交互（调用者、被调用者和数据存储）：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/8535fb3c-c845-4c66-bace-3e0bd77e620c.png)

现在，将其与在调用期间创建数据存储对象时的交互进行比较：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/e1e57d5a-3105-447a-bbb5-04443b79754d.png)

您可以看到第二个图中产生的额外时间（成本）。在大多数情况下，这些成本并不会发生，因为在 Go 中创建对象很快。但是，当它们存在时，它们可能会在应用程序启动期间导致一些意外或不便的行为。

在像前面提到的那种情况下，依赖项的状态不确定，导致生成的代码存在另一个缺点。考虑以下代码：

```go
func (l *Sender) Send(ctx context.Context, payload []byte) error {
   pool := l.getConnectionPool()

   // ensure pool is ready
   select {
   case <-pool.IsReady():
      // happy path

   case <-ctx.Done():
      // context timed out or was cancelled
      return errors.New("failed to get connection")
   }

   // get connection from pool and return afterwards
   conn := pool.Get()
   defer l.connectionPool.Release(conn)

   // send and return
   _, err := conn.Write(payload)

   return err
}
```

将前面的代码与保证依赖项处于*就绪*状态的相同代码进行比较：

```go
func (l *Sender) Send(payload []byte) error {
   pool := l.getConnectionPool()

   // get connection from pool and return afterwards
   conn := pool.Get()
   defer l.connectionPool.Release(conn)

   // send and return
   _, err := conn.Write(payload)

   return err
}
```

这只是几行代码，当然，它要简单得多，因此更易于阅读和维护。它也更容易实现和测试。

**潜在的数据和初始化竞争**-与前一点类似，这一点也围绕着依赖项的初始化。然而，在这种情况下，问题与访问依赖项本身有关。让我们回到前面关于连接池的例子，但改变实例化的方式：

```go
func newConnectionPool() ConnectionPool {
   pool := &myConnectionPool{}

   // initialize the pool
   pool.init()

   // return a "ready to use pool"
   return pool
}
```

正如您所看到的，连接池的构造函数在池完全初始化之前不会返回。那么，在初始化正在进行时再次调用`getConnectionPool()`会发生什么？

我们可能会创建两个连接池。这张图显示了这种交互：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/3e44b2f3-dba6-4ff4-9b04-6ab877ba0f3e.png)

那么，另一个连接池会发生什么？它将被遗弃。用于创建它的所有 CPU 都是浪费的，甚至可能无法被垃圾收集器正确清理；因此，任何资源，如内存、文件句柄或网络端口，都可能丢失。

有一种简单的方法可以确保避免这个问题，但它会带来非常小的成本。我们可以使用`standard`库中的 sync 包。这个包有几个不错的选项，但在这种情况下，我建议使用`Once()`。通过将`Once()`添加到我们的`getConnectionPool()`方法中，我们得到了这个：

```go
func (l *Sender) getConnection() ConnectionPool {
   l.initPoolOnce.Do(func() {
      l.connectionPool = newConnectionPool()
   })

   return l.connectionPool
}
```

这种方法有两个小成本。第一个是代码的复杂性增加；这很小，但确实存在。

第二个成本是对`getConnectionPool()`的每次调用，可能有很多次，都会检查`Once()`，看它是否是第一次调用。这是一个非常小的成本，但根据您的性能要求，可能会不方便。

**对象并非完全解耦**-在整本书中，我们使用依赖图来识别潜在问题，特别是关于包之间的关系，以及在某些情况下对特定包的过度依赖。虽然我们仍然可以并且应该使用第二章中的*依赖反转原则*部分，*Go 的 SOLID 设计原则*，并将我们的依赖定义为本地接口，但通过在我们的代码中包含依赖的创建，依赖图仍将显示我们的包与依赖之间的关系。在某种程度上，我们的对象仍然与我们的依赖有些耦合。

# 摘要

在本章中，我们使用了 JIT 注入，这是一种不太常见的 DI 方法，以消除前几章中的一些猴子补丁。

我们还使用了不同形式的 JIT 注入来添加可选依赖项，而不会影响我们代码的用户体验。

此外，我们还研究了 JIT 注入如何用于减少测试引起的损害，而不牺牲我们在测试中使用模拟和存根的能力。

在下一章中，我们将研究本书中的最后一个 DI 方法，即现成的注入。我们将讨论采用 DI 框架的一般优缺点，并且在我们的示例中，我们将使用 Google 的 Wire 框架。

# 问题

1.  JIT 注入与构造函数注入有何不同？

1.  在处理可选依赖关系时，为什么使用 NO-OP 实现很重要？

1.  JIT 注入的理想用例是什么？
