# Go 依赖注入实用指南（四）

> 原文：[`zh.annas-archive.org/md5/87633C3DBA89BFAAFD7E5238CC73EA73`](https://zh.annas-archive.org/md5/87633C3DBA89BFAAFD7E5238CC73EA73)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：现成注入

在本节的最后一章中，我们将使用框架来进行**依赖注入**（**DI**）。选择与您首选风格相匹配的 DI 框架可以显著地简化您的生活。即使您不喜欢使用框架，研究它的实现方式和方法也可能会有所帮助，并帮助您找到改进您首选实现的方法。

虽然有许多可用的框架，包括 Facebook 的 Inject（[`github.com/facebookgo/inject`](https://github.com/facebookgo/inject)）和 Uber 的 Dig（[`godoc.org/go.uber.org/dig`](https://godoc.org/go.uber.org/dig)），但对于我们的示例服务，我们将使用 Google 的 Go Cloud Wire（[`github.com/google/go-cloud/tree/master/wire`](https://github.com/google/go-cloud/tree/master/wire)）。

本章将涵盖以下主题：

+   使用 Wire 进行现成的注入

+   现成注入的优点

+   应用现成的注入

+   现成注入的缺点

# 技术要求

熟悉我们在第四章中介绍的服务代码将是有益的，*ACME 注册服务简介*。本章还假设您已经阅读了第六章，*构造函数注入的依赖注入*。

您可能还会发现阅读和运行本章的完整代码版本对您有用，该代码版本可在[`github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/tree/master/ch10`](https://github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/tree/master/ch10)上找到。

获取代码并配置示例服务的说明在此处的 README 中可用：[`github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/`](https://github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/)。

您可以在`ch10/acme`中找到我们的服务代码，并已应用本章的更改。

# 使用 Wire 进行现成的注入

Go Cloud 项目是一个旨在使应用程序开发人员能够轻松在任何组合的云提供商上部署云应用程序的倡议。该项目的重要部分是基于代码生成的依赖注入工具**Wire**。

Wire 非常适合我们的示例服务，因为它提倡显式实例化，并且不鼓励使用全局变量；正如我们在之前的章节中尝试实现的那样。此外，Wire 使用代码生成来避免由于运行时反射而导致的性能损失或代码复杂性。

对我们来说，Wire 最有用的方面可能是其简单性。一旦我们理解了一些简单的概念，我们需要编写的代码和生成的代码就会相当简单。

# 引入提供者

文档将提供者定义如下：

“*可以生成值的函数*。”

对于我们的目的，我们可以换一种方式说，提供者返回一个依赖项的实例。

提供者可以采用的最简单形式是*简单的无参数函数*，如下面的代码所示：

```go
// Provider
func ProvideFetcher() *Fetcher {
   return &Fetcher{}
}

// Object being "provided"
type Fetcher struct {
}

func (f *Fetcher) GoFetch() (string, error) {
```

```go
return "", errors.New("not implemented yet")
}
```

提供者还可以通过具有以下参数的方式指示它们需要注入依赖项：

```go
func ProvideFetcher(cache *Cache) *Fetcher {
   return &Fetcher{
      cache: cache,
   }
}
```

此提供者的依赖项（参数）必须由其他提供者提供。

提供者还可以通过返回错误来指示可能无法初始化，如下面的代码所示：

```go
func ProvideCache() (*Cache, error) {
   cache := &Cache{}

   err := cache.Start()
   if err != nil {
      return nil, err
   }

   return cache, nil
}
```

重要的是要注意，当提供者返回错误时，使用提供的依赖项的任何注入器也必须返回错误。

# 理解注入器

Wire 中的第二个概念是注入器。注入器是魔术发生的地方。它们是我们（开发人员）定义的函数，Wire 将其用作代码生成的基础。

例如，如果我们想要一个函数，可以创建我们服务的 REST 服务器的实例，包括初始化和注入所有必需的依赖关系，我们可以通过以下函数实现：

```go
func initializeServer() (*rest.Server, error) {
 wire.Build(wireSet)
 return nil, nil
}
```

这可能对于这样一个简单的函数来说感觉很大，尤其是因为它似乎没有做任何事情（即 `返回 nil, nil`）。但这就是我们需要写的全部；代码生成器将把它转换成以下内容：

```go
func initializeServer() (*rest.Server, error) {
   configConfig, err := config.Load()
   if err != nil {
      return nil, err
   }
   getter := get.NewGetter(configConfig)
   lister := list.NewLister(configConfig)
   converter := exchange.NewConverter(configConfig)
   registerer := register.NewRegisterer(configConfig, converter)
   server := rest.New(configConfig, getter, lister, registerer)
   return server, nil
}
```

我们将在 *应用* 部分更详细地讨论这一点，但现在有三个上述函数的特点要记住。首先，生成器不关心函数的实现，除了函数必须包含一个 `wire.Build(wireSet)` 调用。其次，函数必须返回我们计划使用的具体类型。最后，如果我们依赖于任何返回错误的提供者，那么注入器也必须返回一个错误。

# 采用提供者集

在使用 Wire 时，我们需要了解的最后一个概念是提供者集。提供者集提供了一种将提供者分组的方法，在编写注入器时可以很有帮助。它们的使用是可选的；例如，之前我们使用了一个名为 `wireSet` 的提供者集，如下面的代码所示：

```go
func initializeServer() (*rest.Server, error) {
   wire.Build(wireSet)
   return nil, nil
}
```

然而，我们可以像下面的代码所示，单独传递所有的提供者：

```go
func initializeServer() (*rest.Server, error) {
   wire.Build(
      // *config.Config
      config.Load,

      // *exchange.Converter
      wire.Bind(new(exchange.Config), &config.Config{}),
      exchange.NewConverter,

      // *get.Getter
      wire.Bind(new(get.Config), &config.Config{}),
      get.NewGetter,

      // *list.Lister
      wire.Bind(new(list.Config), &config.Config{}),
      list.NewLister,

      // *register.Registerer
      wire.Bind(new(register.Config), &config.Config{}),
      wire.Bind(new(register.Exchanger), &exchange.Converter{}),
      register.NewRegisterer,

      // *rest.Server
      wire.Bind(new(rest.Config), &config.Config{}),
      wire.Bind(new(rest.GetModel), &get.Getter{}),
      wire.Bind(new(rest.ListModel), &list.Lister{}),
      wire.Bind(new(rest.RegisterModel), &register.Registerer{}),
      rest.New,
   )

   return nil, nil
}
```

遗憾的是，前面的例子并不是虚构的。它来自我们的小例子服务。

正如你所期望的，Wire 中还有很多更多的功能，但在这一点上，我们已经涵盖了足够让我们开始的内容。

# 现成注入的优势

虽然到目前为止在本章中我们一直在讨论 Wire，但我想花点时间讨论现成注入的优势。在评估工具或框架时，审视它可能具有的优势、劣势和对代码的影响是至关重要的。

现成注入的一些可能优势包括以下。

**减少样板代码**—将构造函数注入应用到程序后，`main()` 函数通常会因对象的实例化而变得臃肿。随着项目的增长，`main()` 也会增长。虽然这不会影响程序的性能，但维护起来会变得不方便。

许多依赖注入框架的目标要么是删除这些代码，要么是将其移动到其他地方。正如我们将看到的，这是在采用 Google Wire 之前我们示例服务的 `main()`：

```go
func main() {
   // bind stop channel to context
   ctx := context.Background()

   // build the exchanger
   exchanger := exchange.NewConverter(config.App)

   // build model layer
   getModel := get.NewGetter(config.App)
   listModel := list.NewLister(config.App)
   registerModel := register.NewRegisterer(config.App, exchanger)

   // start REST server
   server := rest.New(config.App, getModel, listModel, registerModel)
   server.Listen(ctx.Done())
}
```

这是在采用 Google Wire 之后的 `main()`：

```go
func main() {
   // bind stop channel to context
   ctx := context.Background()

   // start REST server
   server, err := initializeServer()
   if err != nil {
      os.Exit(-1)
   }

   server.Listen(ctx.Done())
}

```

所有相关的对象创建都被简化为这样：

```go
func initializeServer() (*rest.Server, error) {
   wire.Build(wireSet)
   return nil, nil
}
```

因为 Wire 是一个代码生成器，实际上我们最终会得到更多的代码，但其中更少的代码是由我们编写或维护的。同样，如果我们使用另一个名为 **Dig** 的流行 DI 框架，`main()` 将变成这样：

```go
func main() {
   // bind stop channel to context
   ctx := context.Background()

   // build DIG container
   container := BuildContainer()

   // start REST server
   err := container.Invoke(func(server *rest.Server) {
      server.Listen(ctx.Done())
   })

   if err != nil {
      os.Exit(-1)
   }
}
```

正如你所看到的，我们在代码上获得了类似的减少。

**自动实例化顺序**—与前面的观点类似，随着项目的增长，依赖项必须创建的顺序复杂性也会增加。因此，现成注入框架提供的许多 *魔法* 都集中在消除这种复杂性上。在 Wire 和 Dig 的两种情况下，提供者明确定义它们的直接依赖关系，并忽略它们的依赖项的任何要求。

考虑以下示例。假设我们有一个像这样的 HTTP 处理程序：

```go
func NewGetPersonHandler(model *GetPersonModel) *GetPersonHandler {
   return &GetPersonHandler{
      model: model,
   }
}

type GetPersonHandler struct {
   model *GetPersonModel
}

func (g *GetPersonHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
   response.WriteHeader(http.StatusInternalServerError)
   response.Write([]byte(`not implemented yet`))
}
```

正如你所看到的，处理程序依赖于一个模型，看起来像下面的代码所示：

```go
func NewGetPersonModel(db *sql.DB) *GetPersonModel {
   return &GetPersonModel{
      db: db,
   }
}

type GetPersonModel struct {
   db *sql.DB
}

func (g *GetPersonModel) LoadByID(ID int) (*Person, error) {
   return nil, errors.New("not implemented yet")
}

type Person struct {
   Name string
}
```

这个模型依赖于 `*sql.DB`。然而，当我们为我们的处理程序定义提供者时，它只定义了它需要 `*GetPersonModel`，并不知道 `*sql.DB`，就像这样：

```go
func ProvideHandler(model *GetPersonModel) *GetPersonHandler {
   return &GetPersonHandler{
      model: model,
   }
}
```

与创建数据库、将其注入模型，然后将模型注入处理程序的替代方案相比，这样做更简单，无论是在编写还是在维护上。

**有人已经为你考虑过了**——也许一个好的 DI 框架可以提供的最不明显但最重要的优势是其创建者的知识。创建和维护一个框架的行为绝对不是一个微不足道的练习，它教给了它的作者比大多数程序员需要知道的更多关于 DI 的知识。这种知识通常会导致框架中出现微妙但有用的特性。例如，在 Dig 框架中，默认情况下，所有依赖关系都是单例的。这种设计选择导致了性能和资源使用的改进，以及更可预测的依赖关系生命周期。

# 应用现成的注入

正如我在前一节中提到的，通过采用 Wire，我们希望在`main()`中看到代码和复杂性显著减少。我们也希望能够基本上忘记依赖关系的实例化顺序，让框架来为我们处理。

# 采用 Google Wire

然而，我们需要做的第一件事是整理好我们的房子。大多数，如果不是全部，我们要让 Wire 处理的对象都使用我们的`*config.Config`对象，目前它存在为全局单例，如下面的代码所示：

```go
// App is the application config
var App *Config

// Load returns the config loaded from environment
func init() {
   filename, found := os.LookupEnv(DefaultEnvVar)
   if !found {
      logging.L.Error("failed to locate file specified by %s", DefaultEnvVar)
      return
   }

   _ = load(filename)
}

func load(filename string) error {
   App = &Config{}
   bytes, err := ioutil.ReadFile(filename)
   if err != nil {
      logging.L.Error("failed to read config file. err: %s", err)
      return err
   }

   err = json.Unmarshal(bytes, App)
   if err != nil {
      logging.L.Error("failed to parse config file. err : %s", err)
      return err
   }

   return nil
}
```

为了将其改为 Wire 可以使用的形式，我们需要删除全局实例，并将配置加载更改为一个函数，而不是由`init()`触发。

快速查看我们的全局单例的用法后，可以看到只有`main()`和`config`包中的一些测试引用了这个单例。由于我们之前的所有工作，这个改变将会非常简单。重构后的配置加载器如下：

```go
// Load returns the config loaded from environment
func Load() (*Config, error) {
   filename, found := os.LookupEnv(DefaultEnvVar)
   if !found {
      err := fmt.Errorf("failed to locate file specified by %s", DefaultEnvVar)
      logging.L.Error(err.Error())
      return nil, err
   }

   cfg, err := load(filename)
   if err != nil {
      logging.L.Error("failed to load config with err %s", err)
      return nil, err
   }

   return cfg, nil
}
```

这是我们更新后的`main()`：

```go
func main() {
   // bind stop channel to context
   ctx := context.Background()

   // load config
   cfg, err := config.Load(config.DefaultEnvVar)
   if err != nil {
      os.Exit(-1)
   }

   // build the exchanger
   exchanger := exchange.NewConverter(cfg)

   // build model layer
   getModel := get.NewGetter(cfg)
   listModel := list.NewLister(cfg)
   registerModel := register.NewRegisterer(cfg, exchanger)

   // start REST server
   server := rest.New(cfg, getModel, listModel, registerModel)
   server.Listen(ctx.Done())
}
```

现在我们已经移除了配置全局变量，我们准备开始采用 Google Wire。

我们将首先添加一个新文件；我们将其命名为`wire.go`。它可以被称为任何东西，但我们需要一个单独的文件，因为我们将使用 Go 构建标签来将我们在这个文件中编写的代码与 Wire 生成的版本分开。

如果你不熟悉构建标签，在 Go 中它们是文件顶部的注释，在`package`语句之前，形式如下：

```go
//+build myTag

package main

```

这些标签告诉编译器何时包含或不包含文件在编译期间。例如，前面提到的标签告诉编译器仅在触发构建时包含此文件，就像这样：

```go
$ go build -tags myTag
```

我们还可以使用构建标签来做相反的事情，使一个文件只在未指定标签时包含，就像这样：

```go
//+build !myTag

package main

```

回到`wire.go`，在这个文件中，我们将定义一个用于配置的注入器，它使用我们的配置加载器作为提供者，如下所示：

```go
//+build wireinject

package main

import (
   "github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/ch10/acme/internal/config"
   "github.com/google/go-cloud/wire"
)

// The build tag makes sure the stub is not built in the final build.

func initializeConfig() (*config.Config, error) {
   wire.Build(config.Load)
   return nil, nil
}
```

让我们更详细地解释一下注入器。函数签名定义了一个返回`*config.Config`实例或错误的函数，这与之前的`config.Load()`是一样的。

函数的第一行调用了`wire.Build()`并提供了我们的提供者，第二行返回了`nil, nil`。事实上，它返回什么并不重要，只要它是有效的 Go 代码。Wire 中的代码生成器将读取函数签名和`wire.Build()`调用。

接下来，我们打开一个终端，并在包含我们的`wire.go`文件的目录中运行`wire`。Wire 将为我们创建一个名为`wire_gen.go`的新文件，其内容如下所示：

```go
// Code generated by Wire. DO NOT EDIT.

//go:generate wire
//+build !wireinject

package main

import (
   "github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/ch10/acme/internal/config"
)

// Injectors from wire.go:

func initializeConfig() (*config.Config, error) {
   configConfig, err := config.Load()
   if err != nil {
      return nil, err
   }
   return configConfig, nil
}
```

你会注意到这个文件也有一个构建标签，但它与我们之前写的相反。Wire 已经复制了我们的`initializeConfig()`方法，并为我们*填写了所有的细节*。

到目前为止，代码非常简单，很可能与我们自己编写的代码非常相似。你可能会觉得到目前为止我们并没有真正获得太多。我同意。当我们将其余的对象转换过来时，Wire 将为我们处理的代码和复杂性将会显著增加。

为了完成这一系列的更改，我们更新`main()`以使用我们的`initializeConfig()`函数，如下所示：

```go
func main() {
   // bind stop channel to context
   ctx := context.Background()

   // load config
   cfg, err := initializeConfig()
   if err != nil {
      os.Exit(-1)
   }

   // build the exchanger
   exchanger := exchange.NewConverter(cfg)

   // build model layer
   getModel := get.NewGetter(cfg)
   listModel := list.NewLister(cfg)
   registerModel := register.NewRegisterer(cfg, exchanger)

   // start REST server
   server := rest.New(cfg, getModel, listModel, registerModel)
   server.Listen(ctx.Done())
}
```

处理配置后，我们可以继续下一个对象，`*exchange.Converter`。在先前的示例中，我们没有使用提供程序集，而是直接将我们的提供程序传递给`wire.Build()`调用。我们即将添加另一个提供程序，所以现在是时候更加有条理了。因此，我们将在`main.go`中添加一个私有全局变量，并将我们的`Config`和`Converter`提供程序添加到其中，如下所示：

```go
// List of wire enabled objects
var wireSet = wire.NewSet(
   // *config.Config
   config.Load,

   // *exchange.Converter
   wire.Bind(new(exchange.Config), &config.Config{}),
   exchange.NewConverter,
)
```

正如您所看到的，我还添加了一个`wire.Bind()`调用。Wire 要求我们定义或映射满足接口的具体类型，以便在注入期间满足它们。`*exchange.Converter`的构造函数如下所示：

```go
// NewConverter creates and initializes the converter
func NewConverter(cfg Config) *Converter {
   return &Converter{
      cfg: cfg,
   }
}
```

您可能还记得，这个构造函数使用配置注入和本地定义的`Config`接口。但是，我们注入的实际配置对象是`*config.Config`。我们的`wire.Bind()`调用告诉 Wire，在需要`exchange.Config`接口时使用`*config.Config`。

有了我们的提供程序集，我们现在可以更新我们的配置注入器，并添加一个`Converter`的注入器，如下所示：

```go
func initializeConfig() (*config.Config, error) {
   wire.Build(wireSet)
   return nil, nil
}

func initializeExchanger() (*exchange.Converter, error) {
   wire.Build(wireSet)
   return nil, nil
}
```

重要的是要注意，虽然`exchange.NewConverter()`不会返回错误，但我们的注入器必须。这是因为我们依赖于返回错误的配置提供程序。这可能听起来很麻烦，但不用担心，Wire 可以帮助我们做到这一点。

继续我们的对象列表，我们需要对我们的模型层做同样的事情。注入器是完全可预测的，几乎与`*exchange.Converter`完全相同，提供程序集的更改也是如此。

请注意，`main()`和更改后的提供程序集如下所示：

```go
func main() {
   // bind stop channel to context
   ctx := context.Background()

   // load config
   cfg, err := initializeConfig()
   if err != nil {
      os.Exit(-1)
   }

   // build model layer
   getModel, _ := initializeGetter()
   listModel, _ := initializeLister()
   registerModel, _ := initializeRegisterer()

   // start REST server
   server := rest.New(cfg, getModel, listModel, registerModel)
   server.Listen(ctx.Done())
}

// List of wire enabled objects
var wireSet = wire.NewSet(
   // *config.Config
   config.Load,

   // *exchange.Converter
   wire.Bind(new(exchange.Config), &config.Config{}),
   exchange.NewConverter,

   // *get.Getter
   wire.Bind(new(get.Config), &config.Config{}),
   get.NewGetter,

   // *list.Lister
   wire.Bind(new(list.Config), &config.Config{}),
   list.NewLister,

   // *register.Registerer
   wire.Bind(new(register.Config), &config.Config{}),
   wire.Bind(new(register.Exchanger), &exchange.Converter{}),
   register.NewRegisterer,
)
```

有几件重要的事情。首先，我们的提供程序集变得相当长。这可能没关系，因为我们所做的唯一更改是添加更多的提供程序和绑定语句。

其次，我们不再调用`initializeExchanger()`，我们实际上已经删除了该注入器。我们不再需要这个的原因是 Wire 正在为我们处理对模型层的注入。

最后，为了简洁起见，我忽略了可能从模型层注入器返回的错误。这是一个不好的做法，但不用担心，我们将在下一组更改后很快删除这些行。

快速运行 Wire 和我们的测试以确保一切仍然按预期工作后，我们准备继续进行最后一个对象，即 REST 服务器。

首先，我们对提供程序集进行了以下可能可预测的添加：

```go
// List of wire enabled objects
var wireSet = wire.NewSet(
   // lines omitted

   // *rest.Server
   wire.Bind(new(rest.Config), &config.Config{}),
   wire.Bind(new(rest.GetModel), &get.Getter{}),
   wire.Bind(new(rest.ListModel), &list.Lister{}),
   wire.Bind(new(rest.RegisterModel), &register.Registerer{}),
   rest.New,
)
```

之后，我们在`wire.go`中为我们的 REST 服务器定义注入器，如下所示：

```go
func initializeServer() (*rest.Server, error) {
   wire.Build(wireSet)
   return nil, nil
}
```

现在，我们可以更新`main()`，只调用 REST 服务器注入器，如下所示：

```go
func main() {
   // bind stop channel to context
   ctx := context.Background()

   // start REST server
   server, err := initializeServer()
   if err != nil {
      os.Exit(-1)
   }

   server.Listen(ctx.Done())
}
```

完成后，我们可以删除除`initializeServer()`之外的所有注入器，然后运行 Wire，完成！

现在可能是检查 Wire 为我们生成的代码的好时机：

```go
func initializeServer() (*rest.Server, error) {
   configConfig, err := config.Load()
   if err != nil {
      return nil, err
   }
   getter := get.NewGetter(configConfig)
   lister := list.NewLister(configConfig)
   converter := exchange.NewConverter(configConfig)
   registerer := register.NewRegisterer(configConfig, converter)
   server := rest.New(configConfig, getter, lister, registerer)
   return server, nil
}
```

这看起来熟悉吗？这与我们采用 wire 之前的`main()`非常相似。

鉴于我们的代码已经在使用构造函数注入，并且我们的服务相当小，很容易感觉我们为了获得最小的收益而做了很多工作。如果我们从一开始就采用 Wire，肯定不会有这种感觉。在我们的特定情况下，好处更多是长期的。现在 Wire 正在处理构造函数注入以及与实例化和实例化顺序相关的所有复杂性，我们的服务的所有扩展将会更加简单，而且更不容易出现人为错误。

# API 回归测试

完成 Wire 转换后，我们如何确保我们的服务仍然按我们的期望工作？

我们唯一的即时选择是运行应用程序并尝试。这个选择现在可能还可以，但我不喜欢它作为长期选择，所以让我们看看是否可以添加一些自动化测试。

我们应该问自己的第一个问题是*我们在测试什么？*我们不应该需要测试 Wire 本身，我们可以相信工具的作者会这样做。其他方面可能出现什么问题？

一个典型的答案可能是我们使用 Wire。如果我们配置错误 Wire，它将无法生成，所以这个问题已经解决了。这让我们只剩下了应用本身。

为了测试应用程序，我们需要运行它，然后进行 HTTP 调用，并验证响应是否符合我们的预期。

我们需要考虑的第一件事是如何启动应用程序，也许更重要的是，如何以一种可以同时运行多个测试的方式来做到这一点。

目前，我们的配置（数据库连接、HTTP 端口等）是硬编码在磁盘上的一个文件中的。我们可以使用它，但它包括一个固定的 HTTP 服务器端口。另一方面，在我们的测试中硬编码数据库凭据要糟糕得多。

让我们采取一个折中的方法。首先，让我们加载标准的`config`文件：

```go
// load the standard config (from the ENV)
cfg, err := config.Load()
require.NoError(t, err)
```

现在，让我们找一个空闲的 TCP 端口来绑定我们的服务器。我们可以使用端口`0`，并允许系统自动分配一个，就像下面的代码所示：

```go
func getFreePort() (string, error) {
   for attempt := 0; attempt <= 10; attempt++ {
      addr := net.JoinHostPort("", "0")
      listener, err := net.Listen("tcp", addr)
      if err != nil {
         continue
      }

      port, err := getPort(listener.Addr())
      if err != nil {
         continue
      }

      // close/free the port
      tcpListener := listener.(*net.TCPListener)
      cErr := tcpListener.Close()
      if cErr == nil {
         file, fErr := tcpListener.File()
         if fErr == nil {
            // ignore any errors cleaning up the file
            _ = file.Close()
         }
         return port, nil
      }
   }

   return "", errors.New("no free ports")
}
```

我们现在可以使用那个空闲端口，并将`config`文件中的地址替换为使用空闲端口的地址，就像这样：

```go
// get a free port (so tests can run concurrently)
port, err := getFreePort()
require.NoError(t, err)

// override config port with free one
cfg.Address = net.JoinHostPort("0.0.0.0", port)
```

现在我们陷入了困境。目前，要创建服务器的实例，代码看起来是这样的：

```go
// start REST server
server, err := initializeServer()
if err != nil {
   os.Exit(-1)
}

server.Listen(ctx.Done())
```

配置会自动注入，我们没有机会使用我们的自定义配置。幸运的是，Wire 也可以帮助解决这个问题。

为了能够在我们的测试中手动注入配置，但不修改`main()`，我们需要将我们的提供者集分成两部分。第一部分是除了配置之外的所有依赖项：

```go
var wireSetWithoutConfig = wire.NewSet(
   // *exchange.Converter
   exchange.NewConverter,

   // *get.Getter
   get.NewGetter,

   // *list.Lister
   list.NewLister,

   // *register.Registerer
   wire.Bind(new(register.Exchanger), &exchange.Converter{}),
   register.NewRegisterer,

   // *rest.Server
   wire.Bind(new(rest.GetModel), &get.Getter{}),
   wire.Bind(new(rest.ListModel), &list.Lister{}),
   wire.Bind(new(rest.RegisterModel), &register.Registerer{}),
   rest.New,
)
```

第二个包括第一个，然后添加配置和所有相关的绑定：

```go
var wireSet = wire.NewSet(
   wireSetWithoutConfig,

   // *config.Config
   config.Load,

   // *exchange.Converter
   wire.Bind(new(exchange.Config), &config.Config{}),

   // *get.Getter
   wire.Bind(new(get.Config), &config.Config{}),

   // *list.Lister
   wire.Bind(new(list.Config), &config.Config{}),

   // *register.Registerer
   wire.Bind(new(register.Config), &config.Config{}),

   // *rest.Server
   wire.Bind(new(rest.Config), &config.Config{}),
)
```

下一步是创建一个以 config 为参数的注入器。在我们的情况下，这有点奇怪，因为这是由我们的 config 注入引起的，但它看起来是这样的：

```go
func initializeServerCustomConfig(_ exchange.Config, _ get.Config, _ list.Config, _ register.Config, _ rest.Config) *rest.Server {
   wire.Build(wireSetWithoutConfig)
   return nil
}
```

运行 Wire 后，我们现在可以启动我们的测试服务器，就像下面的代码所示：

```go
// start the test server on a random port
go func() {
   // start REST server
   server := initializeServerCustomConfig(cfg, cfg, cfg, cfg, cfg)
   server.Listen(ctx.Done())
}()
```

将所有内容放在一起，我们现在有一个函数，它在一个随机端口上创建一个服务器，并返回服务器的地址，这样我们的测试就知道在哪里调用。以下是完成的函数：

```go
func startTestServer(t *testing.T, ctx context.Context) string {
   // load the standard config (from the ENV)
   cfg, err := config.Load()
   require.NoError(t, err)

   // get a free port (so tests can run concurrently)
   port, err := getFreePort()
   require.NoError(t, err)

   // override config port with free one
   cfg.Address = net.JoinHostPort("0.0.0.0", port)

   // start the test server on a random port
   go func() {
      // start REST server
      server := initializeServerCustomConfig(cfg, cfg, cfg, cfg, cfg)
      server.Listen(ctx.Done())
   }()

   // give the server a chance to start
   <-time.After(100 * time.Millisecond)

   // return the address of the test server
   return "http://" + cfg.Address
}
```

现在，让我们来看一个测试。同样，我们将使用注册端点作为示例。首先，我们的测试需要启动一个测试服务器。在下面的示例中，您还会注意到我们正在定义一个带有超时的上下文。当上下文完成时，通过超时或被取消，测试服务器将关闭；因此，这个超时成为了我们测试的*最大执行时间*。以下是启动服务器的代码：

```go
// start a context with a max execution time
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

// start test server
serverAddress := startTestServer(t, ctx)
```

接下来，我们需要构建并发送请求。在这种情况下，我们选择了硬编码负载和 URL。这可能看起来有点奇怪，但实际上有点帮助。如果负载或 URL（这两者都构成我们服务的 API）意外更改，这些测试将会失败。另一方面，考虑一下，如果我们使用一个常量来配置服务器的 URL。如果那个常量被更改，API 将会更改，并且会破坏我们的用户。负载也是一样，我们可以使用内部使用的相同 Go 对象，但那里的更改也不会导致测试失败。

是的，这种重复工作更多，确实使测试更加脆弱，这两者都不好，但是我们的测试出问题总比我们的用户出问题要好。

构建和发送请求的代码如下：

```go
    // build and send request
   payload := bytes.NewBufferString(`
{
   "fullName": "Bob",
   "phone": "0123456789",
   "currency": "AUD"
}
`)

   req, err := http.NewRequest("POST", serverAddress+"/person/register", payload)
   require.NoError(t, err)

   resp, err := http.DefaultClient.Do(req)
   require.NoError(t, err)
```

现在剩下的就是验证结果。将所有内容放在一起后，我们有了这个：

```go
func TestRegister(t *testing.T) {
   // start a context with a max execution time
   ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
   defer cancel()

   // start test server
   serverAddress := startTestServer(t, ctx)

   // build and send request
   payload := bytes.NewBufferString(`
{
   "fullName": "Bob",
   "phone": "0123456789",
   "currency": "AUD"
}
`)

   req, err := http.NewRequest("POST", serverAddress+"/person/register", payload)
   require.NoError(t, err)

   resp, err := http.DefaultClient.Do(req)
   require.NoError(t, err)

   // validate expectations
   assert.Equal(t, http.StatusCreated, resp.StatusCode)
   assert.NotEmpty(t, resp.Header.Get("Location"))
}
```

就是这样。我们现在有了一个自动化测试，确保我们的应用程序启动，可以被调用，并且响应如我们所期望的那样。如果您感兴趣，本章的代码中还有另外两个端点的测试。

# 现成的注入的缺点

尽管框架作者希望他们的工作成为一种万能解决方案，解决所有世界上的 DI 问题，但很遗憾，事实并非如此；采用框架是有一些成本的，也有一些原因可能会选择不使用它。这些包括以下内容。

**仅支持构造函数注入**-你可能已经注意到在本章中，所有的例子都使用构造函数注入。这并非偶然。与许多框架一样，Wire 只支持构造函数注入。我们不必删除其他 DI 方法的使用，但框架无法帮助我们处理它。

**采用可能成本高昂**-正如你在前一节中看到的，采用框架的最终结果可能相当不错，但我们的服务规模较小，而且我们已经在使用 DI。如果这两者中有任何一种情况不成立，我们将需要进行大量的重构工作。正如我们之前讨论过的，我们做的改变越多，我们承担的风险就越大。

这些成本和风险可以通过具有框架的先前经验以及在项目早期采用框架来减轻。

**意识形态问题**-这本身并不是一个缺点，而更多的是你可能不想采用框架的原因。在 Go 社区中，你会遇到一种观点，即框架与 Go 的哲学不符。虽然我没有找到官方声明或文件支持这一观点，但我相信这是基于 Go 的创作者是 Unix 哲学的粉丝和作者，该哲学规定*在隔离中做琐事，然后组合起来使事情有用*。

框架可能被视为违反这种意识形态，特别是如果它们成为整个系统的普遍部分。我们在本章中提到的框架范围相对较小；所以和其他一切一样，我会让你自己做决定。

# 总结

在本章中，我们讨论了使用 DI 框架来减轻管理和注入依赖关系的负担。我们讨论了 DI 框架中常见的优缺点，并将 Google 的 Wire 框架应用到我们的示例服务中。

这是我们将讨论的最后一个 DI 方法，在下一章中，我们将采取完全不同的策略，看看不使用 DI 的原因。我们还将看看应用 DI 实际上使代码变得更糟的情况。

# 问题

1.  在采用 DI 框架时，你可以期待获得什么？

1.  在评估 DI 框架时，你应该注意哪些问题？

1.  采用现成的注入的理想用例是什么？

1.  为什么重要保护服务免受意外 API 更改的影响？


# 第十一章：控制你的热情

在本章中，我们将研究**依赖注入**（**DI**）可能出错的一些方式。

作为程序员，我们对新工具或技术的热情有时会让我们失去理智。希望本章能帮助我们保持理智，避免麻烦。

重要的是要记住，DI 是一种工具，因此应该在方便和适合的时候进行选择性应用。

本章将涵盖以下主题：

+   DI 引起的损害

+   过早的未来保护

+   模拟 HTTP 请求

+   不必要的注入？

# 技术要求

您可能还会发现阅读和运行本章的完整代码版本很有用，这些代码可以在[`github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/tree/master/ch11`](https://github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/tree/master/ch11)上找到。

# DI 引起的损害

DI 引起的损害是指使用 DI 使代码更难理解、维护或以其他方式使用的情况。

# 长构造函数参数列表

长构造函数参数列表可能是由 DI 引起的代码损害中最常见和最经常抱怨的。虽然 DI 并非代码损害的根本原因，但它确实没有帮助。

考虑以下示例，它使用构造函数注入：

```go
func NewMyHandler(logger Logger, stats Instrumentation,
   parser Parser, formatter Formatter,
   limiter RateLimiter,
   cache Cache, db Datastore) *MyHandler {

   return &MyHandler{
      // code removed
   }
}

// MyHandler does something fantastic
type MyHandler struct {
   // code removed
}

func (m *MyHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
   // code removed
}
```

构造函数参数太多了。这使得使用、测试和维护都变得困难。那么问题的原因是什么呢？实际上有三个不同的问题。

第一个，也许是最常见的，当第一次采用 DI 时，出现错误的抽象。考虑构造函数的最后两个参数是`Cache`和`Datastore`。假设`cache`用于`datastore`的前端，而不是用于缓存`MyHandler`的输出，那么这些应该合并为不同的抽象。`MyHandler`代码不需要深入了解数据存储的位置和方式；它只需要对它需要的内容进行规定。我们应该用更通用的抽象替换这两个输入值，如下面的代码所示：

```go
// Loader is responsible for loading the data
type Loader interface {
   Load(ID int) ([]byte, error)
}
```

顺便说一句，这也是另一个包/层的绝佳位置。

第二个问题与第一个类似，违反了单一责任原则。我们的`MyHandler`承担了太多责任。它目前正在解码请求，从数据存储和/或缓存加载数据，然后呈现响应。解决这个问题的最佳方法是考虑软件的层次结构。这是顶层，我们的 HTTP 处理程序；它需要理解和使用 HTTP。因此，我们应该寻找方法让它成为其主要（也许是唯一）责任。

第三个问题是横切关注点。我们的参数包括日志记录和仪表盘依赖项，这些依赖项可能会被大多数代码使用，并且很少在少数测试之外进行更改。我们有几种处理这个问题的选择；我们可以应用配置注入，从而将它们合并为一个依赖项，并将它们与我们可能拥有的任何配置合并。或者我们可以使用**即时**（**JIT**）注入来访问全局单例。

在这种情况下，我们决定使用配置注入。应用后，我们得到以下代码：

```go
func NewMyHandler(config Config,
   parser Parser, formatter Formatter,
   limiter RateLimiter,
   loader Loader) *MyHandler {

   return &MyHandler{
      // code removed
   }
}
```

我们仍然有五个参数，这比我们开始时要好得多，但仍然相当多。

我们可以通过组合进一步减少这个问题。首先，让我们看看我们之前示例的构造函数，如下面的代码所示：

```go
func NewMyHandler(config Config,
   parser Parser, formatter Formatter,
   limiter RateLimiter,
   loader Loader) *MyHandler {

   return &MyHandler{
      config:    config,
      parser:    parser,
      formatter: formatter,
      limiter:   limiter,
      loader:    loader,
   }
}
```

从`MyHandler`作为*基本处理程序*开始，我们可以定义一个包装我们基本处理程序的新处理程序，如下面的代码所示：

```go
type FancyFormatHandler struct {
   *MyHandler
}
```

现在我们可以按以下方式为我们的`FancyFormatHandler`定义一个新的构造函数：

```go
func NewFancyFormatHandler(config Config,
   parser Parser,
   limiter RateLimiter,
   loader Loader) *FancyFormatHandler {

   return &FancyFormatHandler{
      &MyHandler{
         config:    config,
         formatter: &FancyFormatter{},
         parser:    parser,
         limiter:   limiter,
         loader:    loader,
      },
   }
}
```

就像那样，我们少了一个参数。这里真正的魔力在于匿名组合；因为这样，对`FancyFormatHandler.ServeHTTP()`的任何调用实际上都会调用`MyHandler.ServeHTTP()`。在这种情况下，我们添加了一点代码，以改进我们用户的处理程序的用户体验。

# 注入一个对象时，配置就可以了

通常情况下，你的第一反应是注入一个依赖，这样你就可以在隔离环境中测试你的代码。然而，为了这样做，你不得不引入如此多的抽象和间接性，以至于代码量和复杂性呈指数增长。

这种情况的一个普遍发生是使用通用库来访问外部资源，比如网络资源、文件或数据库。例如，让我们使用我们样本服务的`data`包。如果我们想要抽象出对`sql`包的使用，我们可能会从定义一个接口开始，如下面的代码所示：

```go
type Connection interface {
   QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
   QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
   ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}
```

然后我们意识到`QueryRowContext()`和`QueryContext()`分别返回`*sql.Row`和`*sql.Rows`。深入研究这些结构，我们发现没有办法从`sql`包的外部填充它们的内部状态。为了解决这个问题，我们不得不定义我们自己的`Row`和`Rows`接口，如下面的代码所示：

```go
type Row interface {
   Scan(dest ...interface{}) error
}

type Rows interface {
   Scan(dest ...interface{}) error
   Close() error
   Next() bool
}

type Result interface {
   LastInsertId() (int64, error)
   RowsAffected() (int64, error)
}
```

我们现在完全与`sql`包解耦，并且能够在我们的测试中模拟它。

但让我们停下来一分钟，考虑一下我们所处的位置：

+   我们引入了大约 60 行代码，但我们还没有为它们编写任何测试

+   我们无法在不使用实际数据库的情况下测试新代码，这意味着我们永远无法完全与数据库解耦

+   我们增加了另一层抽象和一些复杂性

现在，将这与本地安装数据库并确保其处于良好状态进行比较。这里也有复杂性，但可以说是一个微不足道的一次性成本，特别是当分摊到我们所工作的所有项目时。我们还必须创建和维护数据库中的表。这个最简单的选择是一个`SQL`脚本——一个也可以用来支持实时系统的脚本。

对于我们的样本服务，我们决定维护一个`SQL`文件和一个本地安装的数据库。由于这个决定，我们不需要模拟对数据库的调用，而只需要将数据库配置传递给我们的本地数据库。

这种情况经常出现，特别是在来自可信来源的低级包中，比如标准库。解决这个问题的关键是要实事求是。问问自己，我真的需要模拟这个吗？有没有一些配置我可以传递进去，从而减少工作量？

最终，我们必须确保我们从额外的工作、代码和复杂性中获得足够的回报来证明这种努力是值得的。

# 不必要的间接性

DI 被误用的另一种方式是引入有限（或没有）目的的抽象。类似于我们之前讨论的注入配置而不是对象，这种额外的间接性导致了额外的工作、代码和复杂性。

让我们看一个例子，你可以引入一个抽象来帮助测试，但实际上并不需要。

在标准的 HTTP 库中，有一个名为`http.ServeMux`的结构体。`ServeMux`用于构建 HTTP 路由器，即 URL 和 HTTP 处理程序之间的映射。一旦`ServeMux`配置好了，它就会被传递到 HTTP 服务器中，如下面的代码所示：

```go
func TestExample(t *testing.T) {
   router := http.NewServeMux()
   router.HandleFunc("/health", func(resp http.ResponseWriter, req *http.Request) {
      _, _ = resp.Write([]byte(`OK`))
   })

   // start a server
   address := ":8080"
   go func() {
      _ = http.ListenAndServe(address, router)
   }()

   // call the server
   resp, err := http.Get("http://:8080/health")
   require.NoError(t, err)

   // validate the response
   responseBody, err := ioutil.ReadAll(resp.Body)
   assert.Equal(t, []byte(`OK`), responseBody)
}
```

随着我们的服务扩展，我们需要确保添加更多的端点。为了防止 API 回归，我们决定添加一些测试来确保我们的路由器配置正确。由于我们熟悉 DI，我们可以立即介绍一个`ServerMux`的抽象，以便我们可以添加一个模拟实现。这在下面的例子中显示：

```go
type MyMux interface {
   Handle(pattern string, handler http.Handler)
   Handler(req *http.Request) (handler http.Handler, pattern string)
   ServeHTTP(resp http.ResponseWriter, req *http.Request)
}

// build HTTP handler routing
func buildRouter(mux MyMux) {
   mux.Handle("/get", &getEndpoint{})
   mux.Handle("/list", &listEndpoint{})
   mux.Handle("/save", &saveEndpoint{})
}
```

有了我们的抽象，我们可以定义一个模拟实现`MyMux`，并编写一个测试，如下面的例子所示：

```go
func TestBuildRouter(t *testing.T) {
   // build mock
   mockRouter := &MockMyMux{}
   mockRouter.On("Handle", "/get", &getEndpoint{}).Once()
   mockRouter.On("Handle", "/list", &listEndpoint{}).Once()
   mockRouter.On("Handle", "/save", &saveEndpoint{}).Once()

   // call function
   buildRouter(mockRouter)

   // assert expectations
   assert.True(t, mockRouter.AssertExpectations(t))
}
```

这一切看起来都很好。然而，问题在于这是不必要的。我们的目标是通过测试端点和 URL 之间的映射来防止意外的 API 回归。

我们的目标可以在不模拟`ServeMux`的情况下实现。首先，让我们回到我们引入`MyMux`接口之前的原始函数，就像下面的例子所示：

```go
// build HTTP handler routing
func buildRouter(mux *http.ServeMux) {
   mux.Handle("/get", &getEndpoint{})
   mux.Handle("/list", &listEndpoint{})
   mux.Handle("/save", &saveEndpoint{})
}
```

深入了解`ServeMux`，我们可以看到，如果我们调用`Handler(req *http.Request)`方法，它将返回配置到该 URL 的`http.Handler`。

因为我们知道我们将为每个端点执行一次，所以我们应该定义一个函数来做到这一点，就像下面的例子中所示：

```go
func extractHandler(router *http.ServeMux, path string) http.Handler {
   req, _ := http.NewRequest("GET", path, nil)
   handler, _ := router.Handler(req)
   return handler
}
```

有了我们的函数，我们现在可以构建一个测试，验证每个 URL 返回预期的处理程序，就像下面的例子中所示：

```go
func TestBuildRouter(t *testing.T) {
   router := http.NewServeMux()

   // call function
   buildRouter(router)

   // assertions
   assert.IsType(t, &getEndpoint{}, extractHandler(router, "/get"))
   assert.IsType(t, &listEndpoint{}, extractHandler(router, "/list"))
   assert.IsType(t, &saveEndpoint{}, extractHandler(router, "/save"))
}
```

在前面的例子中，您可能还注意到我们的`buildRouter()`函数和我们的测试非常相似。这让我们对测试的效果产生了疑问。

在这种情况下，更有效的做法是确保我们有 API 回归测试，验证不仅路由器的配置，还有输入和输出格式，就像我们在第十章的结尾所做的那样，*现成的注入*。

# 服务定位器

首先，定义一下——服务定位器是围绕一个对象的软件设计模式，该对象充当所有依赖项的中央存储库，并能够按名称返回它们。您会发现这种模式在许多语言中使用，并且是一些 DI 框架和容器的核心。

在我们深入探讨为什么这是 DI 引起的损害之前，让我们看一个过于简化的服务定位器的例子：

```go
func NewServiceLocator() *ServiceLocator {
   return &ServiceLocator{
      deps: map[string]interface{}{},
   }
}

type ServiceLocator struct {
   deps map[string]interface{}
}

// Store or map a dependency to a key
func (s *ServiceLocator) Store(key string, dep interface{}) {
   s.deps[key] = dep
}

// Retrieve a dependency by key
func (s *ServiceLocator) Get(key string) interface{} {
   return s.deps[key]
}
```

为了使用我们的服务定位器，我们首先必须创建它，并将我们的依赖项与它们的名称进行映射，就像下面的例子所示：

```go
// build a service locator
locator := NewServiceLocator()

// load the dependency mappings
locator.Store("logger", &myLogger{})
locator.Store("converter", &myConverter{})
```

有了我们构建的服务定位器和设置的依赖项，我们现在可以传递它并根据需要提取依赖项，就像下面的代码所示：

```go
func useServiceLocator(locator *ServiceLocator) {
   // use the locators to get the logger
   logger := locator.Get("logger").(Logger)

   // use the logger
   logger.Info("Hello World!")
}
```

现在，如果我们想在测试期间*替换*日志记录器，那么我们只需要构建一个带有模拟日志记录器的新服务定位器，并将其传递给我们的函数。

那有什么问题呢？首先，我们的服务定位器现在是一个上帝对象（如第一章中提到的*永远不要停止追求更好*），我们可能最终会在各个地方传递它。只需要将一个对象传递到每个函数中听起来可能是一件好事，但这会导致第二个问题。

对象和它使用的依赖之间的关系现在完全对外部隐藏了。我们不再能够查看函数或结构定义并立即知道需要哪些依赖。

最后，我们在没有 Go 类型系统和编译器保护的情况下操作。在前面的例子中，下面的这行可能引起了你的注意：

```go
logger := locator.Get("logger").(Logger)
```

因为服务定位器接受并返回`interface{}`，每次我们需要访问一个依赖项，我们都需要转换为适当的类型。这种转换不仅使代码变得混乱，还可能在值缺失或类型错误时导致运行时崩溃。我们可以通过更多的代码解决这些问题，就像下面的例子所示：

```go
// use the locators to get the logger
loggerRetrieved := locator.Get("logger")
if loggerRetrieved == nil {
   return
}
logger, ok := loggerRetrieved.(Logger)
if !ok {
   return
}

// use the logger
logger.Info("Hello World!")
```

采用先前的方法，我们的应用程序将不再崩溃，但变得非常混乱。

# 过早的未来保护

有时，DI 的应用并不是错误的，而只是不必要的。这种常见的表现形式是过早的未来保护。过早的未来保护是指我们根据可能有一天会需要它的假设，向软件添加我们目前不需要的功能。正如你所期望的那样，这会导致不必要的工作和复杂性。

让我们借鉴我们的服务的例子来看一个例子。目前，我们有一个 Get 端点，如下面的代码所示：

```go
// GetHandler is the HTTP handler for the "Get Person" endpoint
type GetHandler struct {
   cfg    GetConfig
   getter GetModel
}

// ServeHTTP implements http.Handler
func (h *GetHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
   // extract person id from request
   id, err := h.extractID(request)
   if err != nil {
      // output error
      response.WriteHeader(http.StatusBadRequest)
      return
   }

   // attempt get
   person, err := h.getter.Do(id)
   if err != nil {
      // not need to log here as we can expect other layers to do so
      response.WriteHeader(http.StatusNotFound)
      return
   }

   // happy path
   err = h.writeJSON(response, person)
   if err != nil {
      response.WriteHeader(http.StatusInternalServerError)
   }
}

// output the supplied person as JSON
func (h *GetHandler) writeJSON(writer io.Writer, person *get.Person) error {
   output := &getResponseFormat{
      ID:       person.ID,
      FullName: person.FullName,
      Phone:    person.Phone,
      Currency: person.Currency,
      Price:    person.Price,
   }

   return json.NewEncoder(writer).Encode(output)
}
```

这是一个简单的 REST 端点，返回 JSON。如果我们决定，有一天，我们可能想以不同的格式输出，我们可以将编码移到一个依赖项中，如下面的示例所示：

```go
// GetHandler is the HTTP handler for the "Get Person" endpoint
type GetHandler struct {
   cfg       GetConfig
   getter    GetModel
   formatter Formatter
}

// ServeHTTP implements http.Handler
func (h *GetHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
   // no changes to this method
}

// output the supplied person
func (h *GetHandler) buildOutput(writer io.Writer, person *Person) error {
   output := &getResponseFormat{
      ID:       person.ID,
      FullName: person.FullName,
      Phone:    person.Phone,
      Currency: person.Currency,
      Price:    person.Price,
   }

   // build output payload
   payload, err := h.formatter.Marshal(output)
   if err != nil {
      return err
   }

   // write payload to response and return
   _, err = writer.Write(payload)
   return err
}
```

那段代码看起来合理。那么问题出在哪里呢？简单地说，这是我们不需要做的工作。

因此，这是我们不需要编写或维护的代码。在这个简单的例子中，我们的更改只增加了一点额外的复杂性，这是相对常见的。这种少量的额外复杂性在整个系统中的扩散会减慢我们的速度。

如果这真的成为一个实际要求，那么这绝对是交付功能的正确方式，但在那时，它是一个功能，因此是我们必须承担的负担。

# 模拟 HTTP 请求

在本章的前面，我们谈到了注入并不是所有问题的答案，在某些情况下，传递配置要高效得多，而且代码要少得多。这种情况经常发生在处理外部服务时，特别是在处理 HTTP 服务时，比如我们示例服务中的上游货币转换服务。

虽然可以模拟对外部服务的 HTTP 请求并使用模拟来彻底测试对外部服务的调用，但这并不是必要的。让我们通过使用我们示例服务的代码来比较模拟和配置的差异。

以下是我们示例服务的代码，调用外部货币转换服务：

```go
// Converter will convert the base price to the currency supplied
type Converter struct {
   cfg Config
}

// Exchange will perform the conversion
func (c *Converter) Exchange(ctx context.Context, basePrice float64, currency string) (float64, error) {
   // load rate from the external API
   response, err := c.loadRateFromServer(ctx, currency)
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
func (c *Converter) loadRateFromServer(ctx context.Context, currency string) (*http.Response, error) {
   // build the request
   url := fmt.Sprintf(urlFormat,
      c.cfg.ExchangeBaseURL(),
      c.cfg.ExchangeAPIKey(),
      currency)

   // perform request
   req, err := http.NewRequest("GET", url, nil)
   if err != nil {
      c.logger().Warn("[exchange] failed to create request. err: %s", err)
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
      c.logger().Warn("[exchange] failed to load. err: %s", err)
      return nil, err
   }

   if response.StatusCode != http.StatusOK {
      err = fmt.Errorf("request failed with code %d", response.StatusCode)
      c.logger().Warn("[exchange] %s", err)
      return nil, err
   }

   return response, nil
}

func (c *Converter) extractRate(response *http.Response, currency string) (float64, error) {
   defer func() {
      _ = response.Body.Close()
   }()

   // extract data from response
   data, err := c.extractResponse(response)
   if err != nil {
      return defaultPrice, err
   }

   // pull rate from response data
   rate, found := data.Quotes["USD"+currency]
   if !found {
      err = fmt.Errorf("response did not include expected currency '%s'", currency)
      c.logger().Error("[exchange] %s", err)
      return defaultPrice, err
   }

   // happy path
   return rate, nil
}
```

在我们着手撰写测试之前，我们应该首先问自己，我们想要测试什么？以下是典型的测试场景：

+   **正常路径**：外部服务器返回数据，我们成功提取数据

+   **失败/慢请求**：外部服务器返回错误或在时间上没有响应

+   **错误响应**：外部服务器返回无效的 HTTP 响应代码，表示它有问题

+   **无效响应**：外部服务器返回我们不期望的格式的有效负载

我们将通过模拟 HTTP 请求来开始我们的比较。

# 使用 DI 模拟 HTTP 请求

如果我们要使用 DI 和模拟，那么最干净的选项是模拟 HTTP 请求，以便我们可以使其返回我们需要的任何响应。

为了实现这一点，我们需要做的第一件事是抽象构建和发送 HTTP 请求，如下面的代码所示：

```go
// Requester builds and sending HTTP requests
//go:generate mockery -name=Requester -case underscore -testonly -inpkg -note @generated
type Requester interface {
   doRequest(ctx context.Context, url string) (*http.Response, error)
}
```

您可以看到，我们还包括了一个*go generate*注释，它将为我们创建模拟实现。

然后我们可以更新我们的`Converter`以使用`Requester`抽象，如下面的示例所示：

```go
// NewConverter creates and initializes the converter
func NewConverter(cfg Config, requester Requester) *Converter {
   return &Converter{
      cfg:       cfg,
      requester: requester,
   }
}

// Converter will convert the base price to the currency supplied
type Converter struct {
   cfg       Config
   requester Requester
}

// load rate from the external API
func (c *Converter) loadRateFromServer(ctx context.Context, currency string) (*http.Response, error) {
   // build the request
   url := fmt.Sprintf(urlFormat,
      c.cfg.ExchangeBaseURL(),
      c.cfg.ExchangeAPIKey(),
      currency)

   // perform request
   response, err := c.requester.doRequest(ctx, url)
   if err != nil {
      c.logger().Warn("[exchange] failed to load. err: %s", err)
      return nil, err
   }

   if response.StatusCode != http.StatusOK {
      err = fmt.Errorf("request failed with code %d", response.StatusCode)
      c.logger().Warn("[exchange] %s", err)
      return nil, err
   }

   return response, nil
}
```

有了`requester`抽象，我们可以使用模拟实现进行测试，如下面的代码所示：

```go
func TestExchange_invalidResponse(t *testing.T) {
   // build response
   response := httptest.NewRecorder()
   _, err := response.WriteString(`invalid payload`)
   require.NoError(t, err)

   // configure mock
   mockRequester := &mockRequester{}
   mockRequester.On("doRequest", mock.Anything, mock.Anything).Return(response.Result(), nil).Once()

   // inputs
   ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
   defer cancel()

   basePrice := 12.34
   currency := "AUD"

   // perform call
   converter := &Converter{
      requester: mockRequester,
      cfg:       &testConfig{},
   }
   result, resultErr := converter.Exchange(ctx, basePrice, currency)

   // validate response
   assert.Equal(t, float64(0), result)
   assert.Error(t, resultErr)
   assert.True(t, mockRequester.AssertExpectations(t))
}
```

在前面的示例中，我们的模拟请求者返回了一个无效的响应，而不是调用外部服务。通过这样做，我们可以确保我们的代码在发生这种情况时表现得恰当。

为了覆盖其他典型的测试场景，我们只需要复制这个测试，并更改模拟的响应和期望。

现在让我们将基于模拟的测试与基于配置的等效测试进行比较。

# 使用配置模拟 HTTP 请求

我们可以在不进行任何代码更改的情况下测试`Converter`。第一步是定义一个返回我们需要的响应的 HTTP 服务器。在下面的示例中，服务器返回的与前一节中的模拟相同：

```go
server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
   payload := []byte(`invalid payload`)
   response.Write(payload)
}))
```

然后我们从测试服务器获取 URL，并将其作为配置传递给`Converter`，如下面的示例所示：

```go
cfg := &testConfig{
   baseURL: server.URL,
   apiKey:  "",
}

converter := NewConverter(cfg)
```

现在，下面的示例显示了我们如何执行 HTTP 调用并验证响应，就像我们在模拟版本中所做的那样：

```go
result, resultErr := converter.Exchange(ctx, basePrice, currency)

// validate response
assert.Equal(t, float64(0), result)
assert.Error(t, resultErr)
```

通过这种方法，我们可以实现与基于模拟的版本相同的测试场景覆盖率，但代码和复杂性要少得多。或许更重要的是，我们不会因为额外的构造函数参数而导致测试引起的损害。

# 不必要的注入

到目前为止，您可能会想，“有时使用 DI 并不是最佳选择，但我怎么知道呢？”为此，我想再给您提供一个自我调查。

当您不确定如何继续，或者在进行潜在的大规模重构之前，首先快速浏览一下我的 DI 调查：

+   依赖是否是环境问题（比如日志记录）？

环境依赖是必要的，但往往会污染函数的用户体验，特别是构造函数。注入它们是合适的，但您应该更倾向于使用较不显眼的 DI 方法，比如即时注入或配置注入。

+   在重构期间是否有测试来保护我们？

在对测试覆盖率较低的现有代码应用 DI 时，添加一些猴子补丁将是您可以进行的最小更改，因此也是风险最小的更改。一旦测试就位，它将受到保护，即使这些更改意味着删除猴子补丁。

+   依赖的存在是否具有信息性？

依赖的存在告诉用户有关结构体的什么？如果答案不多或没有，那么依赖可以合并到任何配置注入中。同样，如果依赖在这个结构体的范围之外不存在，那么您可以使用即时注入来管理它。

+   你将有多少个依赖的实现？

如果答案是多于一个，那么注入依赖是正确的选择。如果答案是一个，那么您需要深入一点。依赖是否会发生变化？如果它从未发生过变化，那么注入它就是一种浪费，而且很可能增加了不必要的复杂性。

+   依赖是否在测试之外发生过变化？

如果它只在测试期间更改，那么这是一个很好的即时注入的候选项，毕竟，我们希望避免测试引起的损害。

+   依赖是否需要在每次执行时更改？

如果答案是肯定的，那么你应该使用方法注入。在可能的情况下，尽量避免向结构体添加任何决定要使用哪个依赖的逻辑（例如`switch`语句）。相反，确保您要么注入依赖并使用它，要么注入一个包含决定依赖的逻辑的工厂或定位器对象。这将确保您的结构体不会受到任何与单一职责相关的问题的影响。它还有助于我们避免在添加新的依赖实现时进行大规模的手术式变更。

+   依赖是否稳定？

稳定的依赖是已经存在的，不太可能改变（或以向后兼容的方式改变），并且不太可能被替换的东西。这方面的很好的例子是标准库和良好管理、很少更改的公共包。如果依赖是稳定的，那么为了解耦而注入它的价值就不那么大，因为代码没有改变，可以信任。

您可能希望注入一个稳定的依赖，以便测试您如何使用它，就像我们之前看到的 SQL 包和 HTTP 客户端的例子一样。然而，为了避免测试引起的损害和不必要的复杂性，我们应该要么采用即时注入，以避免污染用户体验，要么完全避免注入。

+   这个结构体将有一个还是多个用途？

如果结构体只有一个用途，那么对于代码的灵活性和可扩展性的压力就很低。因此，我们可以更倾向于少注入，更具体地实现；至少在我们的情况发生变化之前是这样。另一方面，在许多地方使用的代码将承受更大的变化压力，并且可以说更希望具有更大的灵活性，以便在更多情况下更有用。在这些情况下，您将希望更倾向于注入，以给用户更多的灵活性。只是要小心，不要注入太多，以至于函数的用户体验变得糟糕。

对于共享代码，您还应该更加努力地将代码与尽可能多的外部（不稳定的）依赖解耦。当用户采用您的代码时，他们可能不想采用您的所有依赖项。

+   **这段代码是否包装了依赖项？**

如果我们包装一个包以使其用户体验更方便，以隔离我们免受该包中的更改影响，那么注入该包是不必要的。我们编写的代码与其包装的代码紧密耦合，因此引入抽象并没有取得显著成效。

+   **应用 DI 会让代码变得更好吗？**

当然，这是非常主观的，但也可能是最关键的问题。抽象是有用的，但它也增加了间接性和复杂性。

解耦很重要，但并非总是必要的。包和层之间的解耦比包内对象之间的解耦更重要。

通过经验和重复，您会发现许多这些问题会变得自然而然，因为您会在何时应用 DI 以及使用哪种方法方面形成直觉。

与此同时，以下表格可能会有所帮助：

| ** 方法** | ** 理想用于：** |
| --- | --- |
| Monkey patching |

+   依赖于单例的代码

+   当前没有测试或现有依赖注入的代码

+   解耦包而不对依赖包做任何更改

|

| 构造函数注入 |
| --- |

+   需要的依赖

+   必须在调用任何方法之前准备好的依赖项

+   被对象的大多数或所有方法使用的依赖

+   在请求之间不会改变的依赖

+   有多个实现的依赖项

|

| 方法注入 |
| --- |

+   与函数、框架和共享库一起使用

+   请求范围的依赖

+   无状态对象

+   在请求中提供上下文或数据的依赖，因此预计在调用之间会有所变化

|

| 配置注入 |
| --- |

+   替换构造函数或方法注入以改善代码的用户体验

|

| JIT 注入 |
| --- |

+   替换本来应该注入到构造函数中的依赖项，并且只有一个生产实现。

+   在对象和全局单例或环境依赖之间提供一层间接或抽象。特别是当我们想在测试期间替换全局单例时

+   允许用户可选地提供依赖项

|

| 现成的注入 |
| --- |

+   减少采用构造函数注入的成本

+   减少创建依赖项顺序的复杂性

|

# 总结

在本章中，我们研究了不必要或不正确地应用 DI 的影响。我们还讨论了一些情况，在这些情况下，采用 DI 并不是最佳选择。

然后，我们用列出了 10 个问题来帮助您确定 DI 是否适用于您当前的用例。

在下一章中，我们将总结我们对 DI 的研究，回顾我们在整本书中讨论过的所有内容。特别是，我们将对比我们样本服务的当前状态和原始状态。我们还将简要介绍如何使用 DI 启动新服务。

# 问题

1.  你最常见到的 DI 引起的损害形式是什么？

1.  为什么重要的是不要盲目地一直应用 DI？

1.  采用 Google Wire 等框架是否可以消除 DI 引起的所有损害形式？


# 第十二章：回顾我们的进展

在我们的最后一章中，我们将回顾并比较应用**依赖注入**（**DI**）后，我们的示例服务的状态和质量与我们开始时的情况。

我们将回顾我们所做的改进，以及最后一次查看我们的依赖图，并讨论我们在测试覆盖率和服务的可测试性方面的改进。

最后，我们将以简要讨论结束本章，讨论如果我们从头开始使用 DI 而不是将其应用于现有代码，我们本可以做些什么。

本章将涵盖以下主题：

+   改进概述

+   依赖图的回顾

+   测试覆盖率和可测试性的回顾

+   使用 DI 开始一个新服务

# 技术要求

熟悉我们服务的代码将是有益的，如第四章中介绍的*ACME 注册服务简介*。本章还假设您已经阅读了第五章中的*使用 Monkey Patching 进行依赖注入*，一直到第十章中的*现成的注入*，介绍了我们在这一过程中所做的各种 DI 方法和其他各种改进。

您可能还会发现阅读和运行本章的完整代码版本很有用，这些代码可以在[`github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/tree/master/ch12`](https://github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/tree/master/ch12)找到。

获取代码并配置示例服务的说明可在 README 中找到，该 README 位于[`github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/`](https://github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/)。

您可以在[`github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/tree/master/ch12/acme`](https://github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/tree/master/ch12/acme)找到我们服务的代码，其中已经应用了本章的更改。

# 改进概述

呼，我们做到了。您认为我们做得如何？您认为这些改进值得努力吗？让我们看看。

为了了解我们已经走了多远，我们首先应该回顾我们的起点。

在第四章中，*ACME 注册服务简介*，我们有一个小型、简单、可工作的服务。它为我们的用户完成了工作，但对于我们必须维护和扩展它的人来说，它造成了许多不便。

# 全局单例

最大的痛点之一无疑是使用全局公共单例。乍一看，它们似乎使代码更简洁，但实际上使我们的测试工作变得更加困难。

使用`init()`函数创建变量意味着我们要么必须使用实时版本（即数据库上的版本），要么必须对全局变量进行 Monkey Patch，这可能导致数据竞争。

我们最初有两个公共全局变量（`config`和`logger`）和一个私有全局变量（数据库连接池）。在第五章中，*使用 Monkey Patching 进行依赖注入*，我们使用了 Monkey Patching 来使我们能够测试依赖于数据库连接池单例的代码。

在第十章中，*现成的注入*，我们终于成功移除了`config`全局变量，在我们在第八章中进行的更改中，首先移除了对它的大部分直接访问，*通过配置进行依赖注入*。

通过删除直接访问并定义本地配置接口，我们能够完全将我们的模型和数据层与配置解耦。这意味着我们的代码是可移植的，如果我们将来想在另一个应用程序中使用它。

也许最重要的是，这意味着现在在这段代码上编写测试的工作要少得多，我们的测试可以独立并发地运行。没有与全局实例的链接，我们不必进行猴子补丁。没有依赖链接，我们只剩下一个更小、更专注的`config`接口，更容易模拟、存根和理解。

全局`logger`实例设法在我们的许多重构中幸存下来，但它唯一被使用的地方是在`config`加载代码中。因此，现在让我们将其移除。我们当前的`config`加载函数看起来像下面的代码所示：

```go
// Load returns the config loaded from environment
func Load() (*Config, error) {
   filename, found := os.LookupEnv(DefaultEnvVar)
   if !found {
      err := fmt.Errorf("failed to locate file specified by %s", DefaultEnvVar)
      logging.L.Error(err.Error())
      return nil, err
   }

   cfg, err := load(filename)
   if err != nil {
      logging.L.Error("failed to load config with err %s", err)
      return nil, err
   }

   return cfg, nil
}
```

可以非常肯定地说，如果我们未能加载配置，我们的服务就无法工作。因此，我们可以直接将错误更改为直接写入*标准错误*。我们更新后的函数如下所示：

```go
// Load returns the config loaded from environment
func Load() (*Config, error) {
   filename, found := os.LookupEnv(DefaultEnvVar)
   if !found {
      err := fmt.Errorf("failed to locate file specified by %s", DefaultEnvVar)
      fmt.Fprintf(os.Stderr, err.Error())
      return nil, err
   }

   cfg, err := load(filename)
   if err != nil {
      fmt.Fprintf(os.Stderr, "failed to load config with err %s", err)
      return nil, err
   }

   return cfg, nil
}
```

否则，日志记录器是通过配置注入*传递*的。通过使用配置注入，我们能够忘记常见的关注点（如`logger`），而不会影响我们构造函数的用户体验。现在我们也能够轻松编写测试来验证日志记录，而不会出现任何数据竞争问题。虽然这样的测试可能会感觉奇怪，但请考虑一下——日志是我们系统的输出，当出现问题需要调试时，我们经常会依赖于它们。

因此，可能有些情况下，确保我们按预期创建日志并继续这样做是有用的。这不是我们经常想要测试的事情，但当我们这样做时，测试本身就像下面这样简单：

```go
func TestLogging(t *testing.T) {
   // build log recorder
   recorder := &LogRecorder{}

   // Call struct that uses a logger
   calculator := &Calculator{
      logger: recorder,
   }
   result := calculator.divide(10, 0)

   // validate expectations, including that the logger was called
   assert.Equal(t, 0, result)
   require.Equal(t, 1, len(recorder.Logs))
   assert.Equal(t, "cannot divide by 0", recorder.Logs[0])
}

type Calculator struct {
   logger Logger
}

func (c *Calculator) divide(dividend int, divisor int) int {
   if divisor == 0 {
      c.logger.Error("cannot divide by 0")
      return 0
   }

   return dividend / divisor
}

// Logger is our standard interface
type Logger interface {
   Error(message string, args ...interface{})
}

// LogRecorder implements Logger interface
type LogRecorder struct {
   Logs []string
}

func (l *LogRecorder) Error(message string, args ...interface{}) {
   // build log message
   logMessage := fmt.Sprintf(message, args...)

   // record log message
   l.Logs = append(l.Logs, logMessage)
}
```

最后，数据库连接池的全局实例仍然存在；然而，与`Config`和`Logger`不同，它是私有的，因此与之相关的任何风险都有限的范围。事实上，通过使用**即时**（**JIT**）DI，我们能够完全将我们的模型层测试与数据包完全解耦，而不会影响模型层包的用户体验。

# 与 config 包的高耦合

当我们在第四章中开始时，*ACME 注册服务简介*，我们根本没有使用任何接口，因此我们所有的包都彼此紧密耦合。因此，我们的包对变化的抵抗力很强；其中最突出的是`config`包。这是我们原来的`Config`结构和全局单例：

```go
// App is the application config
var App *Config

// Config defines the JSON format for the config file
type Config struct {
   // DSN is the data source name (format: https://github.com/go-sql-driver/mysql/#dsn-data-source-name)
   DSN string

   // Address is the IP address and port to bind this rest to
   Address string

   // BasePrice is the price of registration
   BasePrice float64

   // ExchangeRateBaseURL is the server and protocol part of the 
   // URL from which to load the exchange rate
   ExchangeRateBaseURL string

   // ExchangeRateAPIKey is the API for the exchange rate API
   ExchangeRateAPIKey string
}
```

由于全局单例的组合、缺乏接口，以及几乎每个包都引用了这个包，我们对`Config`结构所做的任何更改都有可能导致一切都被破坏。同样地，如果我们决定将配置格式从平面 JSON 文件更改为更复杂的结构，我们将面临一些非常恶劣的手术。

让我们比较一下我们原来的`Config`结构和现在的情况：

```go
// Config defines the JSON format for the config file
type Config struct {
   // DSN is the data source name (format: https://github.com/go-sql-driver/mysql/#dsn-data-source-name)
   DSN string

   // Address is the IP address and port to bind this rest to
   Address string

   // BasePrice is the price of registration
   BasePrice float64

   // ExchangeRateBaseURL is the server and protocol part of the 
   // URL from which to load the exchange rate
   ExchangeRateBaseURL string

   // ExchangeRateAPIKey is the API for the exchange rate API
   ExchangeRateAPIKey string

   // environmental dependencies
   logger logging.Logger
}

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

// DataDSN returns the DSN
func (c *Config) DataDSN() string {
   return c.DSN
}

// ExchangeBaseURL returns the Base URL from which we can load 
// exchange rates
func (c *Config) ExchangeBaseURL() string {
   return c.ExchangeRateBaseURL
}

// ExchangeAPIKey returns the DSN
func (c *Config) ExchangeAPIKey() string {
   return c.ExchangeRateAPIKey
}

// BindAddress returns the host and port this service should bind to
func (c *Config) BindAddress() string {
   return c.Address
}
```

可以看到，我们现在有了更多的代码。然而，额外的代码主要包括实现包的各种配置接口的`getter`函数。这些`getter`函数为我们提供了一层间接，使我们能够更改配置的加载和存储方式，而无需影响其他包。

通过在许多包中引入本地`Config`接口，我们能够将这些包与我们的`config`包解耦。虽然其他包仍然间接使用`config`包，但我们获得了两个好处。首先，它们可以分别发展。其次，这些包都在本地*记录*它们的需求，这使我们在处理包时有了更小的范围。这在测试期间特别有帮助，当我们使用模拟和存根时。

# 测试覆盖率和可测试性的回顾

当我们引入我们的示例服务时，我们发现了与测试相关的几个问题。其中一个问题是*缺乏隔离*，其中一个层的测试也间接测试了所有在它下面的层，如下面的代码所示：

```go
func TestGetHandler_ServeHTTP(t *testing.T) {
   // ensure the test always fails by giving it a timeout
   ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
   defer cancel()

   // Create and start a server
   // With out current implementation, we cannot test this handler without 
   // a full server as we need the mux.
   address, err := startServer(ctx)
   require.NoError(t, err)

   // build inputs
   response, err := http.Get("http://" + address + "/person/1/")

   // validate outputs
   require.NoError(t, err)
   require.Equal(t, http.StatusOK, response.StatusCode)

   expectedPayload := []byte(`{"id":1,"name":"John","phone":"0123456780","currency":"USD","price":100}` + "\n")
   payload, _ := ioutil.ReadAll(response.Body)
   defer response.Body.Close()

   assert.Equal(t, expectedPayload, payload)
}
```

这是 REST 层的测试，但因为它调用实际的模型，因此也调用了实际的数据层，它实际上测试了一切。这使它成为一个合理的集成测试，因为它确保各层之间适当地协同工作。但它是一个糟糕的单元测试，因为各层没有被隔离。

我们的单元测试现在如下所示：

```go
func TestGetHandler_ServeHTTP(t *testing.T) {
   scenarios := []struct {
      desc            string
      inRequest       func() *http.Request
      inModelMock     func() *MockGetModel
      expectedStatus  int
      expectedPayload string
   }{
      // scenarios removed
   }

   for _, s := range scenarios {
      scenario := s
      t.Run(scenario.desc, func(t *testing.T) {
         // define model layer mock
         mockGetModel := scenario.inModelMock()

         // build handler
         handler := NewGetHandler(&testConfig{}, mockGetModel)

         // perform request
         response := httptest.NewRecorder()
         handler.ServeHTTP(response, scenario.inRequest())

         // validate outputs
         require.Equal(t, scenario.expectedStatus, response.Code, scenario.desc)

         payload, _ := ioutil.ReadAll(response.Body)
         assert.Equal(t, scenario.expectedPayload, string(payload), scenario.desc)
      })
   }
}
```

这个测试被认为是隔离的，因为我们不是依赖于其他层，而是依赖于一个抽象——在我们的例子中，是一个名为`*MockGetModel`的模拟实现。让我们看一个典型的模拟实现：

```go
type MockGetModel struct {
   mock.Mock
}

func (_m *MockGetModel) Do(ID int) (*Person, error) {
   outputs := _m.Called(ID)

   if outputs.Get(0) != nil {
      return outputs.Get(0).(*Person), outputs.Error(1)
   }

   return nil, outputs.Error(1)
}
```

正如你所看到的，模拟实现非常简单；绝对比这个依赖的实际实现简单。由于这种简单性，我们能够相信它的表现与我们期望的一样，因此，测试中出现的任何问题都将是由实际代码而不是模拟引起的。通过使用代码生成器（如在第三章中介绍的 Mockery，*用户体验编码*），这种信任可以得到进一步加强，它生成可靠和一致的代码。

模拟还使我们能够轻松测试其他场景。我们现在对以下内容进行了测试：

+   快乐路径

+   请求中缺少 ID

+   请求中的无效 ID

+   依赖（模型层或更低层）失败

+   请求的记录不存在

在没有我们所做的更改的情况下，许多这些情况很难进行可靠的测试。

现在我们的测试与其他层隔离，测试本身的范围更小。这意味着我们需要了解的东西更少；我们只需要了解我们正在测试的层的 API 契约。

在我们的例子中，这意味着我们只需要担心 HTTP 相关的问题，比如从请求中提取数据，输出正确的状态代码和呈现响应有效负载。此外，我们正在测试的代码可能失败的方式也减少了。因此，我们得到了更少的测试设置，更短的测试和更多的场景覆盖。

与测试相关的第二个问题是*工作重复*。由于缺乏隔离，我们原始的测试通常有些多余。例如，Get 端点的模型层测试看起来是这样的：

```go
func TestGetter_Do(t *testing.T) {
   // inputs
   ID := 1

   // call method
   getter := &Getter{}
   person, err := getter.Do(ID)

   // validate expectations
   require.NoError(t, err)
   assert.Equal(t, ID, person.ID)
   assert.Equal(t, "John", person.FullName)
}
```

这看起来表面上没问题，但当我们考虑到这个测试场景已经被我们的`REST`包测试覆盖时，我们实际上从这个测试中得不到任何东西。另一方面，让我们看看我们现在有的几个测试中的一个：

```go
func TestGetter_Do_noSuchPerson(t *testing.T) {
   // inputs
   ID := 5678

   // configure the mock loader
   mockLoader := &mockMyLoader{}
   mockLoader.On("Load", mock.Anything, ID).Return(nil, data.ErrNotFound).Once()

   // call method
   getter := &Getter{
      data: mockLoader,
   }
   person, err := getter.Do(ID)

   // validate expectations
   require.Equal(t, errPersonNotFound, err)
   assert.Nil(t, person)
   assert.True(t, mockLoader.AssertExpectations(t))
}
```

这个测试现在是 100%可预测的，因为它不依赖于数据库的当前状态。它不测试数据库，也不测试我们如何与数据库交互，而是测试我们如何与*数据加载器*抽象交互。这意味着数据层的实现可以自由地发展或更改，而无需重新审视和更新测试。这个测试还验证了，如果我们从数据层收到错误，我们会如我们的 API 契约所期望的那样适当地转换这个错误。

我们仍然在两个层上进行测试，但现在，这些测试不再毫无价值，而是带来了重大的价值。

第三，我们在测试中遇到的另一个问题是*测试冗长*。我们所做的许多更改之一是采用表驱动测试。我们注册端点的原始服务测试看起来如下：

```go
func TestRegisterHandler_ServeHTTP(t *testing.T) {
   // ensure the test always fails by giving it a timeout
   ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
   defer cancel()

   // Create and start a server
   // With out current implementation, we cannot test this handler without 
   // a full server as we need the mux.
   address, err := startServer(ctx)
   require.NoError(t, err)

   // build inputs
   validRequest := buildValidRequest()
   response, err := http.Post("http://"+address+"/person/register", "application/json", validRequest)

   // validate outputs
   require.NoError(t, err)
   require.Equal(t, http.StatusCreated, response.StatusCode)
   defer response.Body.Close()

   // call should output the location to the new person
   headerLocation := response.Header.Get("Location")
   assert.Contains(t, headerLocation, "/person/")
}
```

现在，考虑它在以下代码块中的样子：

```go
func TestRegisterHandler_ServeHTTP(t *testing.T) {
   scenarios := []struct {
      desc           string
      inRequest      func() *http.Request
      inModelMock    func() *MockRegisterModel
      expectedStatus int
      expectedHeader string
   }{
      // scenarios removed
   }

   for _, s := range scenarios {
      scenario := s
      t.Run(scenario.desc, func(t *testing.T) {
         // define model layer mock
         mockRegisterModel := scenario.inModelMock()

         // build handler
         handler := NewRegisterHandler(mockRegisterModel)

         // perform request
         response := httptest.NewRecorder()
         handler.ServeHTTP(response, scenario.inRequest())

         // validate outputs
         require.Equal(t, scenario.expectedStatus, response.Code)

         // call should output the location to the new person
         resultHeader := response.Header().Get("Location")
         assert.Equal(t, scenario.expectedHeader, resultHeader)

         // validate the mock was used as we expected
         assert.True(t, mockRegisterModel.AssertExpectations(t))
      })
   }
}
```

我知道你在想什么，测试变得更啰嗦了，而不是更简洁。是的，这个单独的测试确实是。然而，在原始测试中，如果我们要测试另一种情况，第一步将是*复制并粘贴*几乎整个测试，留下大约 10 行重复的代码和只有几行是该测试场景独有的。

使用我们的表驱动测试风格，我们有八行共享代码，每个场景都会执行，并且清晰可见。每个场景都被整洁地指定为切片中的一个对象，如下所示：

```go
{
   desc: "Happy Path",
   inRequest: func() *http.Request {
      validRequest := buildValidRegisterRequest()
      request, err := http.NewRequest("POST", "/person/register", validRequest)
      require.NoError(t, err)

      return request
   },
   inModelMock: func() *MockRegisterModel {
      // valid downstream configuration
      resultID := 1234
      var resultErr error

      mockRegisterModel := &MockRegisterModel{}
      mockRegisterModel.On("Do", mock.Anything, mock.Anything).Return(resultID, resultErr).Once()

      return mockRegisterModel
   },
   expectedStatus: http.StatusCreated,
   expectedHeader: "/person/1234/",
},

```

我们只需向切片添加另一个项目，就可以添加另一个场景。这既非常简单，又相当整洁。

最后，如果我们需要对测试进行更改，也许是因为 API 合同发生了变化，现在我们只需要修复一个测试，而不是很多个。

我们遇到的第四个问题是*依赖于我们的上游服务*。这是我非常讨厌的事情之一。测试应该是可靠和可预测的，测试失败应该是存在问题需要修复的绝对指标。当测试依赖于第三方和互联网连接时，任何事情都可能出错，测试可能因任何原因而失败。幸运的是，在我们在第八章中的更改之后，除了外部边界测试，我们的所有测试现在都依赖于上游服务的抽象和模拟实现。我们的测试不仅可靠，而且现在可以轻松地测试我们的错误处理条件，类似于我们之前讨论的方式。

在以下测试中，我们已经删除并模拟了对`converter`包的调用，以测试当我们无法加载货币转换时我们的注册会发生什么：

```go
func TestRegisterer_Do_exchangeError(t *testing.T) {
   // configure the mocks
   mockSaver := &mockMySaver{}
   mockExchanger := &MockExchanger{}
   mockExchanger.
      On("Exchange", mock.Anything, mock.Anything, mock.Anything).
      Return(0.0, errors.New("failed to load conversion")).
      Once()

   // define context and therefore test timeout
   ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
   defer cancel()

   // inputs
   in := &Person{
      FullName: "Chang",
      Phone:    "11122233355",
      Currency: "CNY",
   }

   // call method
   registerer := &Registerer{
      cfg:       &testConfig{},
      exchanger: mockExchanger,
      data:      mockSaver,
   }
   ID, err := registerer.Do(ctx, in)

   // validate expectations
   require.Error(t, err)
   assert.Equal(t, 0, ID)
   assert.True(t, mockSaver.AssertExpectations(t))
   assert.True(t, mockExchanger.AssertExpectations(t))
}
```

您可能还记得我们的 exchange 包中仍然有测试。事实上，我们有两种类型。我们有*内部边界测试*，它们调用我们创建的一个虚假 HTTP 服务器。这些测试确保当服务器给出特定响应时，我们的代码会如我们所期望的那样做出反应，如下面的代码片段所示：

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
   assert.Equal(t, 158.79, resultRate)
   assert.NoError(t, resultErr)
}

type happyExchangeRateService struct{}

// ServeHTTP implements http.Handler
func (*happyExchangeRateService) ServeHTTP(response http.ResponseWriter, request *http.Request) {
   payload := []byte(`
{
  "success":true,
  "timestamp":1535250248,
  "base":"EUR",
  "date":"2018-08-26",
  "rates": {
   "AUD":1.587884
  }
}
`)
   response.Write(payload)
}
```

但我们还有*外部边界测试*，它们仍然调用上游服务。这些测试帮助我们验证上游服务是否按照我们的需求执行，与我们的代码协同工作。但是，为了确保我们的测试是可预测的，我们不经常运行外部测试。我们通过向该文件添加构建标签来实现这一点，从而可以轻松地决定何时包括这些测试。通常情况下，我只会在出现问题时运行这些测试，或者为了设置构建流水线中仅运行这些测试的特殊步骤。然后，我们可以在这些测试期间的任何失败后决定如何继续。

# 测试覆盖率

说到原始数字，当我们开始时，我们服务的测试覆盖率如下：

```go
-------------------------------------------------------------------------
|      Branch     |       Dir       |                                   |
|   Cov% |  Stmts |   Cov% |  Stmts | Package                           |
-------------------------------------------------------------------------
|  52.94 |    238 |   0.00 |      3 | acme/                             |
|  73.33 |     15 |  73.33 |     15 | acme/internal/config/             |
|   0.00 |      4 |   0.00 |      4 | acme/internal/logging/            |
|  63.33 |     60 |  63.33 |     60 | acme/internal/modules/data/       |
|   0.00 |     38 |   0.00 |     38 | acme/internal/modules/exchange/   |
|  50.00 |      6 |  50.00 |      6 | acme/internal/modules/get/        |
|  25.00 |     12 |  25.00 |     12 | acme/internal/modules/list/       |
|  64.29 |     28 |  64.29 |     28 | acme/internal/modules/register/   |
|  73.61 |     72 |  73.61 |     72 | acme/internal/rest/               |
-------------------------------------------------------------------------
```

如您所见，测试覆盖率有些低。由于编写测试的难度以及我们无法模拟或存根我们的依赖关系，这并不奇怪。

在我们的更改之后，我们的测试覆盖率正在提高：

```go
-------------------------------------------------------------------------
|      Branch     |       Dir       |                                   |
|   Cov% |  Stmts |   Cov% |  Stmts | Package                           |
-------------------------------------------------------------------------
|  63.11 |    309 |  30.00 |     20 | acme/                             |
|  28.57 |     28 |  28.57 |     28 | acme/internal/config/             |
|   0.00 |      4 |   0.00 |      4 | acme/internal/logging/            |
|  74.65 |     71 |  74.65 |     71 | acme/internal/modules/data/       |
|  61.70 |     47 |  61.70 |     47 | acme/internal/modules/exchange/   |
|  81.82 |     11 |  81.82 |     11 | acme/internal/modules/get/        |
|  38.10 |     21 |  38.10 |     21 | acme/internal/modules/list/       |
|  75.76 |     33 |  75.76 |     33 | acme/internal/modules/register/   |
|  77.03 |     74 |  77.03 |     74 | acme/internal/rest/               |
-------------------------------------------------------------------------
```

虽然我们对服务进行的大部分更改使得测试变得更容易，但我们并没有花太多时间添加额外的测试。我们所取得的改进主要来自增加了场景覆盖，主要涉及能够测试非正常路径代码。

如果我们想要提高测试覆盖率，找出需要更多测试的最简单方法是使用标准的 go 工具来计算覆盖率并将其显示为 HTML。为此，我们在终端中运行以下命令：

```go
# Change directory to the code for this chapter
$ cd $GOPATH/src/github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/ch12/

# Set the config location
$ export ACME_CONFIG=cd $GOPATH/src/github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/config.json

# Calculate coverage
$ go test ./acme/ -coverprofile=coverage.out

# Render as HTML
$ go tool cover -html=coverage.out
```

运行这些命令后，覆盖率将在您的默认浏览器中打开。为了找到潜在的改进位置，我们会浏览文件，寻找红色代码块。红色高亮的代码表示在测试期间未执行的行。

删除所有未经测试的代码并不现实，特别是因为有些错误几乎不可能触发——关键是审查代码，决定是否应该对其进行测试。

考虑以下示例（未覆盖的行用粗体标出）——我们现在将更详细地检查它：

```go
// load rate from the external API
func (c *Converter) loadRateFromServer(ctx context.Context, currency string) (*http.Response, error) {
   // build the request
   url := fmt.Sprintf(urlFormat,
      c.cfg.ExchangeBaseURL(),
      c.cfg.ExchangeAPIKey(),
      currency)

   // perform request
   req, err := http.NewRequest("GET", url, nil)
   if err != nil {
      c.logger().Warn("[exchange] failed to create request. err: %s", err) return nil, err
   }

   // set latency budget for the upstream call
   subCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
   defer cancel()

   // replace the default context with our custom one
   req = req.WithContext(subCtx)

   // perform the HTTP request
   response, err := http.DefaultClient.Do(req)
   if err != nil {
      c.logger().Warn("[exchange] failed to load. err: %s", err)
 return nil, err
   }

   if response.StatusCode != http.StatusOK {
      err = fmt.Errorf("request failed with code %d", response.StatusCode)
 c.logger().Warn("[exchange] %s", err)
 return nil, err
   }

   return response, nil
}
```

首先，让我们谈谈这些行：

```go
if response.StatusCode != http.StatusOK {
   err = fmt.Errorf("request failed with code %d", response.StatusCode)
   c.logger().Warn("[exchange] %s", err)
   return nil, err
}
```

这些行处理了上游服务未能返回 HTTP `200`（OK）的情况。考虑到互联网和 HTTP 服务的性质，这种情况很有可能发生。因此，我们应该构建一个测试来确保我们的代码处理了这种情况。

现在，看一下这些行：

```go
req, err := http.NewRequest("GET", url, nil)
if err != nil {
   c.logger().Warn("[exchange] failed to create request. err: %s", err)
   return nil, err
}
```

你知道`http.NewRequest()`如何失败吗？在标准库中查找后，似乎它会在我们指定有效的 HTTP 方法或 URL 无法解析时失败。这些都是程序员的错误，而且我们不太可能犯这些错误。即使我们犯了，结果也是显而易见的，并且会被现有的测试捕捉到。

此外，为这些情况添加测试将会很困难，并且几乎肯定会对我们的代码的整洁度产生不利影响。

最后，到目前为止，我们的测试缺乏*端到端测试*。在第十章 *现成的注入* 结束时，我们添加了少量端到端测试。最初，我们使用这些测试来验证 Google Wire 的表现是否符合我们的预期。从长远来看，它们将用于保护我们的 API 免受意外的回归。对我们服务的公共 API 进行更改，无论是 URL、输入还是输出负载，都很有可能导致我们用户的代码出现问题。有时更改是必要的，在这种情况下，这些测试也将提醒我们需要采取其他措施，比如通知我们的用户或对 API 进行版本控制。

# 消除对上游服务的依赖

在第六章 *构造函数注入的依赖注入* 中，我们使用构造函数注入来将我们的模型层与`exchange`包解耦。你可能还记得`exchange`包是对我们上游货币转换服务的一个薄抽象。这不仅确保我们的模型层测试不再需要上游服务正常工作才能通过，而且还使我们能够确保我们已充分处理了服务失败的情况。

在第八章 *配置的依赖注入* 中，我们添加了边界测试，进一步减少了对上游服务的依赖，使我们能够独立测试`exchange`包，而不依赖上游服务。在我们的频繁运行的单元测试中移除了对上游服务的所有依赖之后，我们添加了一个外部边界来测试外部服务。然而，我们用一个构建标签来保护这个测试，使我们能够有选择地偶尔运行它，从而保护我们免受互联网和上游服务的问题。

# 提前停止和延迟预算

在第七章 *方法注入的依赖注入* 中，我们使用方法注入引入了`context`包和请求范围的依赖。通过将`context`用作请求范围的依赖，我们随后能够实现延迟预算和*提前停止*。有了这些，我们能够在异常系统行为期间减少资源使用。例如，如果检索数据（从上游货币转换服务或数据库）花费的时间太长，以至于客户端不再等待响应，我们可以取消请求并停止任何进一步的处理。

# 简化依赖创建

当我们在第四章 *ACME 注册服务简介* 中开始时，我们的`main()`函数看起来相当简单，如下面的代码所示：

```go
func main() {
   // bind stop channel to context
   ctx := context.Background()

   // start REST server
   server := rest.New(config.App.Address)
   server.Listen(ctx.Done())
}
```

在我们的代码中应用了几种 DI 方法之后，到了第九章 *即时依赖注入*，我们的`main()`函数变成了以下形式：

```go
func main() {
   // bind stop channel to context
   ctx := context.Background()

   // build the exchanger
   exchanger := exchange.NewConverter(config.App)

   // build model layer
   getModel := get.NewGetter(config.App)
   listModel := list.NewLister(config.App)
   registerModel := register.NewRegisterer(config.App, exchanger)

   // start REST server
   server := rest.New(config.App, getModel, listModel, registerModel)
   server.Listen(ctx.Done())
}
```

如你所见，它变得更长、更复杂了。这是关于 DI 的一个常见抱怨。因此，在第十章中，*现成的注入*，我们通过让 Wire 为我们完成来减少这种成本。这使我们回到了一个简洁的`main()`函数，如下所示：

```go
func main() {
   // bind stop channel to context
   ctx := context.Background()

   // start REST server
   server, err := initializeServer()
   if err != nil {
      os.Exit(-1)
   }

   server.Listen(ctx.Done())
}
```

同样，在第九章中，*即时依赖注入*，我们意识到数据层只会有一个活动实现，而我们唯一需要注入不同内容的时间是在测试期间。因此，我们决定不将数据层作为构造函数参数，而是使用即时注入，如下面的代码所示：

```go
// Getter will attempt to load a person.
type Getter struct {
   cfg  Config
   data myLoader
}

// Do will perform the get
func (g *Getter) Do(ID int) (*data.Person, error) {
   // load person from the data layer
   person, err := g.getLoader().Load(context.TODO(), ID)
   if err != nil {
      if err == data.ErrNotFound {
         return nil, errPersonNotFound
      }
      return nil, err
   }

   return person, err
}

// Use JIT DI to lessen the constructor parameters
func (g *Getter) getLoader() myLoader {
   if g.data == nil {
      g.data = data.NewDAO(g.cfg)
   }

   return g.data
}
```

正如所见，这为我们提供了简化的本地依赖创建，而不会减少我们构造函数的用户体验，也不会在测试期间丢失我们模拟数据层的能力。

# 耦合和可扩展性

在所有的变化之后，也许我们最重要的胜利是解耦我们的包。在可能的情况下，我们的包只定义并依赖于本地接口。由于这个，我们的单元测试完全与其他包隔离，并验证我们对依赖关系的使用——包之间的契约——而不依赖于它们。这意味着在处理我们的包时需要的知识范围是最小的。

或许更重要的是，我们可能想要进行的任何更改或扩展都可能只限于一个或少数几个包。例如，如果我们想在上游货币转换服务前添加一个缓存，所有的更改都将只在`exchange`包中进行。同样，如果我们想在另一个服务中重用这个包，我们可以复制或提取它并在不进行任何更改的情况下使用它。

# 依赖图的审查

在整本书中，我们一直将依赖图作为发现潜在问题的一种方式。这是我们开始时的样子：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/deda18e8-1200-451b-9c5e-549f7674c82f.png)

对于只有三个端点的小服务来说，它有点复杂。从这个图表中，我们还注意到有很多箭头指向`data`、`config`和`logging`包。

在假设更多箭头进入或离开一个包意味着更多的风险、复杂性和耦合的前提下，我们开始尝试减少这些关系。

最大的影响是我们采用了配置注入，其中包括本地`config`接口的定义（如前一节所讨论的）。这移除了所有进入 config 包的箭头，除了来自`main()`的箭头，这个我们无法移除。

此外，在我们进行配置注入工作期间，我们还移除了对全局日志实例的所有引用，并改为注入日志记录器。然而，这并没有改变图表。这是因为我们决定重用该包中定义的`Logger`接口。

我们本可以在每个包内定义一个此接口的副本并移除这种耦合，但我们决定不这样做，因为日志记录器的定义可能不会改变。在图中移除箭头之外，复制接口到每个地方只会增加代码而没有任何好处。

在所有重构和解耦工作之后，我们的依赖图看起来像下面的图表：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/5d2b5a97-95ca-4631-a7e2-1ecdb5f7277e.png)

这样做更好了，但遗憾的是，仍然相当混乱。为了解决这个问题以及我们之前提到的关于日志接口的问题，我还有一个技巧要向你展示。

到目前为止，我们一直使用以下命令生成图表：

```go
$ BASE_PKG=github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/ch12/acme
godepgraph -s -o $BASE_PKG $BASE_PKG | dot -Tpng -o depgraph.png
```

我们可以通过使用 Godepgraph 的排除功能来从图表中移除`logging`包，将命令改为以下形式：

```go
$ BASE_PKG=github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/ch12/acme
godepgraph -s -o $BASE_PKG -p $BASE_PKG/internal/logging $BASE_PKG | dot -Tpng -o depgraph.png
```

最终，这给我们带来了我们一直追求的清晰的金字塔形图表：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/dfda7ea1-d6bd-488c-aee5-15a924125867.png)

你可能想知道我们是否可以通过移除`REST`和`model`包之间的链接（`get`、`list`和`register`）来进一步扁平化图形。

我们目前正在将模型代码注入到`REST`包中；然而，两者之间仅剩下的链接是`model`包的输出格式。现在让我们来看看这个。

我们的列表模型 API 看起来是这样的：

```go
// Lister will attempt to load all people in the database.
// It can return an error caused by the data layer
type Lister struct {
   cfg  Config
   data myLoader
}

// Exchange will load the people from the data layer
func (l *Lister) Do() ([]*data.Person, error) {
   // code removed
}
```

我们返回的是`*data.Person`类型的切片，这迫使我们在`REST`包中定义本地接口如下：

```go
type ListModel interface {
   Do() ([]*data.Person, error)
}
```

鉴于`data.Person`是一个**数据传输对象**（**DTO**），我倾向于务实地保留它。当然，我们可以移除它。要这样做，我们需要改变我们的`ListModel`定义，以期望一个`interface{}`切片，然后定义一个接口，我们可以将我们的`*data.Person`转换成它。

这有两个主要问题。首先，这需要做很多额外的工作，只是为了从依赖图中删除一行，但会使代码变得更混乱。其次，我们实际上是绕过了类型系统，创建了一种让我们的代码在运行时失败的方式，如果我们的模型层的返回类型与`REST`包的期望不同。

# 使用 DI 开始一个新的服务

在本书中，我们已经将 DI 应用到了现有的服务中。虽然这是我们最常见的情况，但有时我们会有幸从头开始启动一个新项目。

那么，我们能做些什么不同的吗？

# 用户体验

我们应该做的第一件事是停下来思考我们要解决的问题。回到 UX 发现调查（第三章，*为用户体验编码*）。问自己以下问题：

+   我们的用户是谁？

+   我们的用户想要实现什么？

+   我们的用户能做什么？

+   我们的用户期望如何使用我们即将创建的系统？

想象一下，如果你要开始 ACME 注册服务，你会如何回答这些问题？

答案可能是以下内容：

+   **我们的用户是谁？**—这项服务的用户将是负责注册前端的移动应用程序和 Web 开发人员。

+   **我们的用户想要实现什么？**—他们希望能够创建、查看和管理注册。

+   **我们的用户能做什么？**—他们熟悉调用基于 HTTP 的 REST 服务。他们熟悉传递和消费 JSON 编码的数据。

+   **我们的用户期望如何使用我们即将创建的系统？**—鉴于他们对 JSON 和 REST 的熟悉程度，他们希望通过 HTTP 请求来完成所有操作。第一组最明显的用户已经处理完毕，我们可以转向第二重要的用户群：开发团队。

+   **我们代码的用户是谁？**—我和开发团队的其他成员。

+   **我们的用户想要实现什么？**—我们想要构建一个快速、可靠的系统，易于管理和扩展。

+   **我们的用户能做什么？**—我们也熟悉 HTTP、REST 和 JSON。我们也熟悉 MySQL 和 Go。我们也熟悉 DI 的许多形式。

+   **我们的用户期望如何使用我们即将创建的代码？**—我们希望使用 DI 来确保我们的代码松耦合，易于测试和维护。

通过考虑我们的用户，你可以看到我们已经开始概述我们的服务。我们已经确定了从用户和开发者对 HTTP、JSON 和 REST 的熟悉程度来看，这是通信的最佳选择。鉴于开发人员对 Go 和 MySQL 的熟悉程度，这些将是关于实现技术的最佳选择。

# 代码结构

通过了解我们的用户提供的框架，我们已经准备好考虑实现和代码结构。

假设我们正在开发一个独立的服务，我们将需要一个`main()`函数。之后，我总是在`main()`下直接添加一个`internal`文件夹。这样可以在此服务的代码和同一存储库中的任何其他代码之间建立清晰的边界。

当您发布一个供他人使用的包或 SDK 时，这是一种简单的方法，可以确保您的内部实现包不会泄漏到公共 API 中。如果您的团队使用单一存储库或一个存储库中有多个服务，那么这是一种确保您不会与其他团队发生包名称冲突的好方法。

我们原始服务中的层相对正常，因此可以在此处重用它们。这些层如下图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/e317a542-b91a-4ae5-9814-0b7f4ea479c1.png)

使用这组特定层的主要优势是，每个层代表处理请求时所需的不同方面。**REST**层仅处理与 HTTP 相关的问题；具体来说，从请求中提取数据和呈现响应。**业务逻辑**层是业务逻辑所在的地方。它还倾向于包含与调用**外部服务和数据**层相关的协调逻辑。**外部服务和数据**将处理与外部服务和系统（如数据库）的交互。

正如您所看到的，每个层都有完全独立的责任和视角。任何系统级的更改，例如更改数据库或从 JSON 更改为其他格式，都可以完全在一个层中处理，并且不应该对其他层造成任何更改。层之间的依赖关系将被定义为接口，这就是我们将利用的不仅是 DI，还有使用模拟和存根进行测试。

随着服务的增长，我们的层可能会由许多小包组成，而不是每个层一个大包。这些小包将导出它们自己的公共 API，以便该层中的其他包可以使用它们。然而，这会破坏层的封装。让我们看一个例子。

假设我们的数据库存在性能问题，想要添加缓存以减少对其的调用次数。代码可能看起来像下面所示：

```go
// DAO is a data access object that provides an abstraction over our 
// database interactions.
type DAO struct {
   cfg Config

   db    *sql.DB
   cache *cache.Cache
}

// Load will attempt to load and return a person.
// It will return ErrNotFound when the requested person does not exist.
// Any other errors returned are caused by the underlying database or 
// our connection to it.
func (d *DAO) Load(ctx context.Context, ID int) (*Person, error) {
   // load from cache
   out := d.loadFromCache(ID)
   if out != nil {
      return out, nil
   }

   // load from database
   row := d.db.QueryRowContext(ctx, sqlLoadByID, ID)

   // retrieve columns and populate the person object
   out, err := populatePerson(row.Scan)
   if err != nil {
      if err == sql.ErrNoRows {
         d.cfg.Logger().Warn("failed to load requested person '%d'. err: %s", ID, err)
         return nil, ErrNotFound
      }

      d.cfg.Logger().Error("failed to convert query result. err: %s", err)
      return nil, err
   }

   // save person into the cache
   d.saveToCache(ID, out)

   return out, nil
}
```

然而，**业务逻辑**层无需知道此缓存的存在。我们可以通过在`data`文件夹下添加另一个`internal`文件夹来确保数据层的封装不会泄漏`cache`包。

这种改变可能看起来是不必要的，对于小项目来说，这是一个很好的论点。但随着项目的增长，添加额外的`internal`文件夹的成本很小，将会得到回报，并确保我们的封装永远不会泄漏。

# 横切关注点

我们已经看到处理横切关注点（如日志和配置）有许多不同的方法。建议提前决定一种策略，并让团队对此达成一致意见。猴子补丁，构造函数注入，配置注入和 JIT 注入都是传递或访问配置和日志单例的可能方式。选择完全取决于您和您的偏好。

# 从外部到内部的设计

从项目开始应用 DI 的一个很大的好处是，它使我们能够推迟决策，直到我们更好地了解情况。

例如，在决定实现 HTTP REST 服务后，我们可以继续设计我们的端点。在设计我们的 Get 端点时，我们可以这样描述：

**Get 端点以 JSON 格式返回一个人的对象，形式为{"id":1,"name":"John","phone":"0123456789","currency":"USD","price":100}**

您可能会注意到，这只描述了用户的需求，并没有指定数据来自何处。然后我们可以实际编写我们的端点来实现这个确切的目标。它甚至可能看起来很像第十章中的*现成注入*：

```go
type GetHandler struct {
   getter GetModel
}

// ServeHTTP implements http.Handler
func (h *GetHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
   // extract person id from request
   id, err := h.extractID(request)
   if err != nil {
      // output error
      response.WriteHeader(http.StatusBadRequest)
      return
   }

   // attempt get
   person, err := h.getter.Do(id)
   if err != nil {
      // not need to log here as we can expect other layers to do so
      response.WriteHeader(http.StatusNotFound)
      return
   }

   // happy path
   err = h.writeJSON(response, person)
   if err != nil {
      // this error should not happen but if it does there is nothing we
      // can do to recover
      response.WriteHeader(http.StatusInternalServerError)
   }
}
```

由于`GetModel`是一个本地定义的抽象，它也没有描述数据存储在哪里或如何存储。

同样的过程也可以应用到我们在业务逻辑层中对`GetModel`的实现。它不需要知道它是如何被调用的或数据存储在哪里，它只需要知道它需要协调这个过程，并将来自数据层的任何响应转换为 REST 层期望的格式。

在每个步骤中，问题的范围都很小。与下层的交互取决于抽象，每个层的实现都很简单。

当一个函数的所有层都实现后，我们可以使用 DI 将它们全部连接起来。

# 总结

在本章中，我们审查了应用 DI 后我们样本服务的状态和质量，并将其与原始状态进行了对比，从而提醒自己我们为什么做出了这些改变，以及我们从中获得了什么。

我们最后再次查看了我们的依赖图，以直观地了解我们成功地将包解耦的程度。

我们还看到了在进行改变后，我们的样本服务在测试时更容易，而且我们的测试更加专注。

在本章末尾，我们还讨论了如何开始一个新的服务，以及 DI 如何在这方面提供帮助。

通过这样，我们完成了对 Go 语言 DI 的审查。感谢您抽出时间阅读本书——我希望您觉得它既实用又有用。

愉快的编码！

# 问题

1.  我们的样本服务中最重要的改进是什么？

1.  在我们的依赖图中，为什么数据包不在`main`下面？

1.  如果您要启动一个新的服务，您会做些什么不同？
