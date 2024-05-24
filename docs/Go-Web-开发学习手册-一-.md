# Go Web 开发学习手册（一）

> 原文：[`zh.annas-archive.org/md5/2756E08144D91329B3B7569E0C2831DA`](https://zh.annas-archive.org/md5/2756E08144D91329B3B7569E0C2831DA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

感谢您购买本书。我们希望通过本书中的示例和项目，您能从 Go Web 开发新手变成一个能够承担面向生产的严肃项目的人。因此，本书在相对较高的水平上涉及了许多 Web 开发主题。在本书结束时，您应该能够实现一个非常简单的博客，包括显示、身份验证和评论，同时关注性能和安全性。

# 本书涵盖内容

第一章，“介绍和设置 Go”，通过向您展示如何设置环境和依赖项，以便您可以在 Go 中创建 Web 应用程序，开启了本书。

第二章，“服务和路由”，讨论了如何生成对某些 Web 端点做出反应的响应服务器。我们将探讨 net/http 之外的各种 URL 路由选项的优点。

第三章，“连接到数据”，实现数据库连接，开始获取要在我们的网站上呈现和操作的数据。

第四章，“使用模板”，涵盖了模板包，展示了我们如何向最终用户呈现和修改正在使用的数据。

第五章，“与 RESTful API 集成的前端”，详细介绍了如何创建一个基础 API 来驱动演示和功能。

第六章，“会话和 Cookie”，与我们的最终用户保持状态，从而使他们能够在页面之间保留信息，如身份验证。

第七章，“微服务和通信”，将一些功能拆分为微服务进行重新实现。本章将作为对微服务理念的轻微介绍。

第八章，“日志和测试”，讨论了成熟的应用程序将需要测试和广泛的日志记录来调试和捕获问题，以防它们进入生产环境。

第九章，“安全性”，将专注于 Web 开发的最佳实践，并审查 Go 在这一领域为开发人员提供的内容。

第十章，“缓存、代理和性能改进”，审查了确保没有瓶颈或其他可能对性能产生负面影响的最佳选项。

# 您需要为本书准备的内容

Go 在跨平台兼容性方面表现出色，因此任何运行标准 Linux 版本、OS X 或 Windows 的现代计算机都足以开始。您可以在[`golang.org/dl/`](https://golang.org/dl/)找到完整的要求列表。在本书中，我们使用至少 Go 1.5，但任何更新的版本都应该没问题。

# 本书适合对象

本书适用于 Go 新手开发人员，但具有构建 Web 应用程序和 API 的经验。如果您了解 HTTP 协议、RESTful 架构、通用模板和 HTML，那么您应该已经准备好接手本书中的项目了。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些样式的示例及其含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“例如，为了尽快开始，您可以在任何喜欢的地方创建一个简单的`hello.go`文件，并且编译没有问题。”

代码块设置如下：

```go
func Double(n int) int {

  if (n == 0) {
    return 0
  } else {
    return n * 2
  }
}
```

当我们希望引起您对代码块特定部分的注意时，相关行或项目会以粗体显示：

```go
routes := mux.NewRouter()
  routes.HandleFunc("/page/{guid:[0-9a-zA\\-]+}", ServePage)
  routes.HandleFunc("/", RedirIndex)
  routes.HandleFunc("/home", ServeIndex)
  http.Handle("/", routes)
```

任何命令行输入或输出都以以下方式编写：

```go
export PATH=$PATH:/usr/local/go/bin

```

**新术语**和**重要单词**以粗体显示。例如，屏幕上显示的单词，例如菜单或对话框中的单词，会以这样的方式出现在文本中：“第一次点击您的 URL 和端点时，您将看到**我们刚刚设置了值！**，如下面的屏幕截图所示。”

### 注意

警告或重要提示会以这样的方式显示在框中。

### 提示

技巧和窍门会以这样的方式显示。


# 第一章：介绍和设置 Go

开始使用 Go 时，您最常听到的一句话是它是一种系统语言。

事实上，Go 团队早期对 Go 的描述之一是，该语言是为了成为一种现代系统语言而构建的。它旨在将诸如 C 之类的语言的速度和功能与诸如 Python 之类的现代解释语言的语法优雅和节俭相结合。当您查看 Go 代码的一些片段时，您可以看到这个目标得以实现。

从 Go FAQ 中关于为什么创建 Go 的原因：

> *"Go 是出于对现有语言和系统编程环境的不满而诞生的。"*

也许当今系统编程的最大部分是设计后端服务器。显然，网络构成了其中的一个巨大但并非是唯一的部分。

直到最近，Go 还没有被认为是一种 Web 语言。毫不奇怪，开发人员花了几年时间涉足、试验，最终拥抱这种语言，开始将其引向新的领域。

虽然 Go 可以直接用于 Web，但它缺少许多人们在 Web 开发中经常视为理所当然的关键框架和工具。随着围绕 Go 的社区的增长，支架开始以许多新颖和令人兴奋的方式显现。结合现有的辅助工具，Go 现在是端到端 Web 开发的完全可行选择。但回到最初的问题：为什么选择 Go？公平地说，它并不适合每个 Web 项目，但任何可以从内置高性能、安全的 Web 服务以及美丽的并发模型的附加优势中受益的应用程序都是一个很好的选择。

在本书中，我们将探讨这些方面和其他方面，以概述 Go 是您的 Web 架构和应用程序的正确语言的原因。

我们不会涉及 Go 语言的许多低级方面。例如，我们假设您熟悉变量和常量声明。我们假设您了解控制结构。

在本章中，我们将涵盖以下主题：

+   安装 Go

+   项目结构

+   导入软件包

+   介绍 net 包

+   你好，Web

# 安装 Go

当然，最关键的第一步是确保 Go 可用并准备好启动我们的第一个 Web 服务器。

### 注意

虽然 Go 最大的卖点之一是其跨平台支持（在本地构建和使用时针对其他操作系统），但在 Nix 兼容平台上，您的生活会变得更加轻松。

如果您使用 Windows，不要害怕。在本地，您可能会遇到不兼容的软件包、使用`go run`命令时的防火墙问题以及其他一些怪癖，但 Go 生态系统的 95%将对您可用。您也可以非常容易地运行虚拟机，事实上，这是模拟潜在生产环境的一个很好的方法。

在[`golang.org/doc/install`](https://golang.org/doc/install)上提供了深入的安装说明，但在继续之前我们将在这里讨论一些古怪的地方。

对于 OS X 和 Windows，Go 作为二进制安装包的一部分提供。对于任何具有软件包管理器的 Linux 平台，事情可能会变得非常简单。

### 注意

**通过常见的 Linux 软件包管理器安装：**

Ubuntu：`sudo apt-get golang`

CentOS：`sudo yum install golang`

在 OS X 和 Linux 上，您需要将几行添加到您的路径中——`GOPATH`和`PATH`。首先，您需要找到 Go 二进制安装的位置。这因发行版而异。找到后，您可以配置`PATH`和`GOPATH`，如下所示：

```go
export PATH=$PATH:/usr/local/go/bin
export GOPATH="/usr/share/go"

```

虽然要使用的路径没有严格定义，但一些惯例已经形成，即从用户的主目录下的子目录开始，例如`$HOME/go`或`~Home/go`。只要这个位置被永久设置并且不改变，您就不会遇到冲突或缺少软件包的问题。

您可以通过运行`go env`命令来测试这些更改的影响。如果您在此方面遇到任何问题，这意味着您的目录不正确。

请注意，这可能不会阻止 Go 运行——这取决于 GOBIN 目录是否正确设置——但会阻止您在整个系统上全局安装软件包。

要测试安装，您可以通过`go get`命令获取任何 Go 软件包，并在某个地方创建一个 Go 文件。作为一个快速的例子，首先随机获取一个软件包，我们将使用 Gorilla 框架的一个软件包，因为我们将在本书中经常使用它。

```go
go get github.com/gorilla/mux

```

如果这一切顺利进行，Go 将正确找到您的`GOPATH`。为了确保 Go 能够访问您下载的软件包，请编写一个非常快速的软件包，该软件包将尝试使用 Gorilla 的 mux 软件包并运行它以验证软件包是否被找到。

```go
package main

import (
  "fmt"
  "github.com/gorilla/mux"
  "net/http"
)

func TestHandler(w http.ResponseWriter, r *http.Request) {

}

func main() {
  router := mux.NewRouter()
  router.HandleFunc("/test", TestHandler)
  http.Handle("/", router)
  fmt.Println("Everything is set up!")
}
```

在命令行中运行`go run test.go`。它不会做太多事情，但会像下面的截图所示一样传递好消息：

![安装 Go](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_01_01.jpg)

# 项目结构

当您刚开始并且大多数时间都在玩耍时，将应用程序设置为懒惰运行是没有问题的。

例如，为了尽快开始，您可以在任何喜欢的地方创建一个简单的`hello.go`文件，并且无需编译问题。

但是，当您进入需要多个或不同软件包（稍后会详细介绍）或具有更明确的跨平台要求的环境时，设计项目的方式以便利用 go 构建工具是有意义的。

以这种方式设置代码的价值在于 go 构建工具的工作方式。如果您有本地（针对您的项目）软件包，构建工具将首先查找`src`目录，然后查找您的`GOPATH`。当您为其他平台构建时，go build 将利用本地 bin 文件夹来组织二进制文件。

构建用于大规模使用的软件包时，您可能会发现在`GOPATH`目录下启动应用程序，然后将其符号链接到另一个目录，或者反过来，都可以让您在不需要随后获取自己的代码的情况下进行开发。

## 代码约定

与任何语言一样，成为 Go 社区的一部分意味着不断考虑他人创建代码的方式。特别是如果您要在开源存储库中工作，您将希望以其他人的方式生成代码，以减少其他人获取或包含您的代码时的摩擦量。

Go 团队包含的一个非常有用的工具是`go fmt`。这里的`fmt`当然是格式，这正是这个工具所做的，它会根据设计的约定自动格式化您的代码。

通过强制执行样式约定，Go 团队已经帮助减轻了许多其他语言中存在的最常见和普遍的争论之一。

虽然语言社区倾向于推动编码约定，但个人编写程序的方式总是有一些小怪癖。让我们使用一个最常见的例子——在哪里放开括号。

有些程序员喜欢将其放在与语句相同的一行上：

```go
for (int i = 0; i < 100; i++) {
  // do something
}
```

而其他人则更喜欢将其放在随后的一行上：

```go
for (int i = 0; i < 100; i++)
{
  // do something
}
```

这些微小的差异引发了重大的、近乎宗教性的争论。Gofmt 工具通过允许您遵循 Go 的指令来帮助缓解这一问题。

现在，Go 通过将您的代码格式化为前面讨论过的后一种样式来绕过这个明显的争议源。编译器会抱怨，您将得到一个致命错误。但其他样式选择具有一定的灵活性，这在您使用该工具进行格式化时会得到执行。

例如，这是一个在`go fmt`之前的 Go 代码片段：

```go
func Double(n int) int {

  if (n == 0) {
    return 0
  } else {
    return n * 2
  }
}
```

任意的空白可能是团队在共享和阅读代码时的噩梦，特别是当每个团队成员使用的 IDE 不同的时候。

通过运行`go fmt`，我们可以清理这些内容，从而根据 Go 的约定转换我们的空白：

```go
func Double(n int) int {
  if n == 0 {
    return 0
  } else {
    return n * 2
  }
}
```

长话短说：在发布或推送代码之前，始终运行`go fmt`。

# 导入包

除了绝对和最琐碎的应用程序之外——即连**Hello World**输出都不能产生的应用程序——您必须在 Go 应用程序中导入一些包。

举个例子，要说**Hello World**，我们需要一种生成输出的方式。与许多其他语言不同，即使核心语言库也可以通过命名空间包访问。在 Go 中，命名空间由存储库终端点 URL 处理，即[github.com/nkozyra/gotest](http://github.com/nkozyra/gotest)，可以直接在 GitHub（或任何其他公共位置）上进行审查。

## 处理私有存储库

go get 工具可以轻松处理托管在仓库中的包，例如 GitHub、Bitbucket 和 Google Code（以及其他一些）。您还可以在其他地方托管自己的项目，理想情况下是一个 git 项目，尽管这可能会引入一些依赖和错误源，您可能希望避免。

但私有存储库呢？虽然 go get 是一个很好的工具，但如果没有一些额外的配置、SSH 代理转发等，您会发现自己面临错误。

您可以通过几种方法解决这个问题，但一个非常简单的方法是直接在本地克隆存储库，使用您的版本控制软件。

## 处理版本控制

当您阅读关于 Go 应用程序中命名空间的定义和导入方式时，您可能会停顿。如果您正在使用应用程序的版本 1，但想引入版本 2 会发生什么？在大多数情况下，这必须在`import`的路径中明确定义。例如：

```go
import (
  "github.com/foo/foo-v1"
)
```

与之相对：

```go
import (
  "github.com/foo/foo-v2"
)
```

正如您所想象的那样，这可能是 Go 处理远程包的一个特别棘手的方面。

与许多其他包管理器不同，go get 是去中心化的——也就是说，没有人维护包和版本的官方参考库。这有时可能会让新开发人员感到头疼。

在大多数情况下，包始终通过`go get`命令导入，该命令读取远程存储库的主分支。这意味着在同一终端点维护多个版本的包在大多数情况下是不可能的。

正是利用 URL 终端点作为命名空间，才实现了去中心化，但也导致了对版本控制的内部支持的缺乏。

作为开发人员，您最好将每个包视为执行`go get`命令时最新的版本。如果需要更新版本，您可以始终遵循作者决定的任何模式，例如前面的例子。

作为您自己包的创建者，请确保您也遵守这一理念。保持您的主分支 HEAD 最新将确保您的代码符合其他 Go 作者的约定。

# 介绍 net 包

在 Go 中，所有网络通信的核心是名为 net 的包，其中包含了非常相关的 HTTP 操作，以及其他 TCP/UDP 服务器、DNS 和 IP 工具的子包。

简而言之，您需要创建一个强大的服务器环境。

当然，我们关心的主要是`net/http`包，但我们将看一下其他一些使用该包的函数，比如 TCP 连接以及 WebSockets。

让我们快速看一下执行我们一直在谈论的 Hello World（或 Web，在这种情况下）示例。

# 你好，Web

以下应用程序作为位置`/static`的静态文件服务，并在位置`/dynamic`提供动态`response`：

```go
package main

import (
  "fmt"
  "net/http"
  "time"
)

const (
  Port = ":8080"
)

func serveDynamic(w http.ResponseWriter, r *http.Request) {
  response := "The time is now " + time.Now().String()
  fmt.Fprintln(w,response)
}
```

就像`fmt.Println`会在控制台级别产生所需的内容一样，`Fprintln`允许你将输出定向到任何写入器。我们将在第二章中更多地讨论写入器，*服务和路由*，但它们代表了一个在许多 Go 应用程序中使用的基本灵活接口，不仅仅是用于 Web：

```go
func serveStatic(w http.ResponseWriter, r *http.Request) {
  http.ServeFile(w, r, "static.html")
}
```

我们的`serveStatic`方法只服务一个文件，但可以轻松地允许它直接服务任何文件，并使用 Go 作为一个老式的 Web 服务器，只提供静态内容：

```go
func main() {
  http.HandleFunc("/static",serveStatic)
  http.HandleFunc("/",serveDynamic)
  http.ListenAndServe(Port,nil)
}
```

请随意选择可用的端口——较高的端口将更容易绕过内置的安全功能，特别是在 Nix 系统中。

如果我们采用上述示例并访问相应的 URL——在这种情况下是根目录`/`和静态页面`/static`，我们应该看到预期的输出如下所示：

在根目录`/`，输出如下：

![Hello, Web](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_01_02.jpg)

在`/static`，输出如下：

![Hello, Web](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_01_03.jpg)

正如你所看到的，用 Go 为 Web 制作一个非常简单的输出是非常简单的。内置的包允许我们只用几行代码就能在 Go 中创建一个基本但非常快速的网站。

这可能并不是很令人兴奋，但在我们能够奔跑之前，我们必须先学会走路。生成上述输出引入了一些关键概念。

首先，我们看到了`net/http`如何使用 URI 或 URL 端点将请求定向到必须实现`http.ResponseWriter`和`http.Request`方法的辅助函数。如果它们没有实现，我们会在那一端得到一个非常清晰的错误。

以下是一个尝试以这种方式实现的示例：

```go
func serveError() {
  fmt.Println("There's no way I'll work!")
}

func main() {
  http.HandleFunc("/static", serveStatic)
  http.HandleFunc("/", serveDynamic)
  http.HandleFunc("/error",serveError)
  http.ListenAndServe(Port, nil)
}
```

以下截图显示了 Go 返回的错误：

![Hello, Web](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_01_04.jpg)

你可以看到`serveError`没有包括所需的参数，因此导致编译错误。

# 总结

本章作为 Go 的最基本概念和在 Go 中为 Web 制作的介绍，但这些要点是语言和社区中的关键基础元素，对于提高生产力至关重要。

我们已经看过编码规范和包的设计和组织，我们也制作了我们的第一个程序——司空见惯的 Hello, World 应用程序——并通过本地主机访问了它。

显然，我们离真正成熟的网络应用还有很长的路要走，但构建基础是到达目标的关键。

在第二章中，*服务和路由*，我们将看看如何使用 Go 的内置路由功能以及一些第三方路由器包将不同的请求定向到不同的应用逻辑。


# 第二章：服务和路由

作为商业实体的 Web 的基石——营销和品牌依赖的基础——是 URL。虽然我们还没有看到顶级域处理，但我们需要掌握我们的 URL 及其路径（或端点）。

在本章中，我们将通过引入多个路由和相应的处理程序来做到这一点。首先，我们将通过简单的平面文件服务来做到这一点，然后我们将引入复杂的混合物，通过实现一个利用正则表达式的路由的库来实现更灵活的路由。

在本章结束时，您应该能够在本地主机上创建一个可以通过任意数量的路径访问并返回相对于请求路径的内容的站点。

在本章中，我们将涵盖以下主题：

+   直接提供文件

+   基本路由

+   使用 Gorilla 进行更复杂的路由

+   重定向请求

+   提供基本错误

# 直接提供文件

在上一章中，我们利用了`fmt.Fprintln`函数在浏览器中输出了一些通用的 Hello, World 消息。

这显然有限的效用。在 Web 和 Web 服务器的早期，整个 Web 都是通过将请求定向到相应的静态文件来提供的。换句话说，如果用户请求`home.html`，Web 服务器将查找名为`home.html`的文件并将其返回给用户。

今天这可能看起来有点古怪，因为现在绝大多数的 Web 都以某种动态方式提供，内容通常是通过数据库 ID 确定的，这允许页面在没有人修改单个文件的情况下生成和重新生成。

让我们看看我们可以以类似于 Web 早期的方式提供文件的最简单方法：

```go
package main

import (
  "net/http"
)

const (
  PORT = ":8080"
)

func main() {

  http.ListenAndServe(PORT, http.FileServer(http.Dir("/var/www")))
}
```

相当简单，对吧？对站点发出的任何请求都将尝试在我们本地的`/var/www`目录中找到相应的文件。但是，虽然与第一章 *介绍和设置 Go*中的例子相比，这更具实际用途，但仍然相当有限。让我们看看如何扩展我们的选择。

# 基本路由

在第一章 *介绍和设置*中，我们生成了一个非常基本的 URL 端点，允许静态文件服务。

以下是我们为该示例生成的简单路由：

```go
func main() {
  http.HandleFunc("/static",serveStatic)
  http.HandleFunc("/",serveDynamic)
  http.ListenAndServe(Port,nil)
}
```

回顾一下，你可以看到两个端点，`/static`和`/`，它们要么提供单个静态文件，要么生成`http.ResponseWriter`的输出。

我们可以有任意数量的路由器并排坐着。但是，考虑这样一个情景，我们有一个基本的网站，包括关于、联系和员工页面，每个页面都驻留在`/var/www/about/index.html`、`/var/www/contact.html`和`/var/www/staff/home.html`。虽然这是一个故意晦涩的例子，但它展示了 Go 内置和未修改的路由系统的局限性。我们无法在本地将所有请求路由到同一个目录，我们需要一些提供更灵活 URL 的东西。

# 使用 Gorilla 进行更复杂的路由

在上一节中，我们看了基本路由，但这只能带我们走到这里，我们必须明确地定义我们的端点，然后将它们分配给处理程序。如果我们的 URL 中有通配符或变量会发生什么？这是 Web 和任何严肃的 Web 服务器的绝对必要部分。

举一个非常简单的例子，考虑托管一个博客，每篇博客文章都有唯一的标识符。这可以是代表数据库 ID 条目的数字 ID，也可以是基于文本的全局唯一标识符，比如`my-first-block-entry`。

### 注意

在上面的例子中，我们希望将类似`/pages/1`的 URL 路由到名为`1.html`的文件。或者，在基于数据库的情况下，我们希望使用`/pages/1`或`/pages/hello-world`来映射到具有 GUID`1`或`hello-world`的数据库条目。为了做到这一点，我们要么需要包含一个可能的端点的详尽列表，这是非常浪费的，要么通过正则表达式实现通配符，这是理想的。

无论哪种情况，我们都希望能够直接在应用程序中利用 URL 中的值。这在使用`GET`或`POST`的 URL 参数时非常简单。我们可以简单地提取这些参数，但它们在干净、分层或描述性 URL 方面并不特别优雅，而这些通常是搜索引擎优化所必需的。

内置的`net/http`路由系统可能出于设计考虑相对简单。要从任何给定请求的值中获得更复杂的内容，我们要么需要扩展路由功能，要么使用已经完成这一点的包。

在 Go 公开可用并且社区不断发展的几年中，出现了许多 Web 框架。我们将在本书的后续部分更深入地讨论这些内容，但其中一个特别受欢迎和非常有用的是 Gorilla Web Toolkit。

正如其名称所暗示的，Gorilla 更像是一组非常有用的工具，而不是一个框架。具体来说，Gorilla 包含：

+   `gorilla/context`：这是一个用于从请求中创建全局可访问变量的包。它对于在整个应用程序中共享 URL 的值而不重复访问代码非常有用。

+   `gorilla/rpc`：这实现了 RPC-JSON，这是一种用于远程代码服务和通信的系统，而不实现特定协议。这依赖于 JSON 格式来定义任何请求的意图。

+   `gorilla/schema`：这是一个允许将表单变量简单打包到`struct`中的包，否则这是一个繁琐的过程。

+   `gorilla/securecookie`：毫不奇怪，这个包实现了应用程序的经过身份验证和加密的 cookie。

+   `gorilla/sessions`：类似于 cookie，这个包通过使用基于文件和/或基于 cookie 的会话系统提供了独特的、长期的和可重复的数据存储。

+   `gorilla/mux`：旨在创建灵活的路由，允许正则表达式来指示路由器可用的变量。

+   最后一个包是我们在这里最感兴趣的包，它还带有一个相关的包叫做`gorilla/reverse`，它基本上允许您反转基于正则表达式的 mux 创建过程。我们将在后面的章节中详细介绍这个主题。

### 注意

您可以通过它们的 GitHub 位置使用`go get`获取单独的 Gorilla 包。例如，要获取 mux 包，只需访问[github.com/gorilla/mux](http://github.com/gorilla/mux)即可将该包带入您的`GOPATH`。有关其他包的位置（它们都相当自明），请访问[`www.gorillatoolkit.org/`](http://www.gorillatoolkit.org/)。

让我们深入了解如何创建一个灵活的路由，并使用正则表达式将参数传递给我们的处理程序：

```go
package main

import (
  "github.com/gorilla/mux"
  "net/http"
)

const (
  PORT = ":8080"
)
```

这应该看起来很熟悉，除了 Gorilla 包的导入之外：

```go
func pageHandler(w http.ResponseWriter, r *http.Request) {
  vars := mux.Vars(r)
  pageID := vars["id"]
  fileName := "files/" + pageID + ".html"
  http.ServeFile(w,r,fileName)
}
```

在这里，我们创建了一个路由处理程序来接受响应。这里需要注意的是使用了`mux.Vars`，这是一个方法，它将从`http.Request`中查找查询字符串变量并将它们解析成一个映射。然后可以通过键引用结果来访问这些值，本例中是`id`，我们将在下一节中介绍。

```go
func main() {
  rtr := mux.NewRouter()
  rtr.HandleFunc("/pages/{id:[0-9]+}",pageHandler)
  http.Handle("/",rtr)
  http.ListenAndServe(PORT,nil)
}
```

在这里，我们可以看到处理程序中的（非常基本的）正则表达式。我们将`/pages/`后面的任意数量的数字分配给名为`id`的参数，即`{id:[0-9]+}`；这是我们在`pageHandler`中提取出来的值。

一个更简单的版本显示了如何用它来划分不同的页面，可以通过添加一对虚拟端点来看到：

```go
func main() {
  rtr := mux.NewRouter()
  rtr.HandleFunc("/pages/{id:[0-9]+}", pageHandler)
  rtr.HandleFunc("/homepage", pageHandler)
  rtr.HandleFunc("/contact", pageHandler)
  http.Handle("/", rtr)
  http.ListenAndServe(PORT, nil)
}
```

当我们访问与此模式匹配的 URL 时，我们的`pageHandler`会尝试在`files/`子目录中找到页面并直接返回该文件。

对`/pages/1`的响应会像这样：

![使用 Gorilla 进行更复杂的路由](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_02_01.jpg)

在这一点上，你可能已经在问，但是如果我们没有请求的页面怎么办？或者，如果我们移动了那个位置会发生什么？这引出了网络服务中的两个重要机制——返回错误响应，以及作为其中一部分，可能重定向已移动或具有其他需要向最终用户报告的有趣属性的请求。

# 重定向请求

在我们看简单和非常常见的错误，比如 404 之前，让我们先讨论重定向请求的想法，这是非常常见的。尽管并非总是对于普通用户来说是明显或可触及的原因。

那么我们为什么要将请求重定向到另一个请求呢？好吧，根据 HTTP 规范的定义，有很多原因可能导致我们在任何给定的请求上实现自动重定向。以下是其中一些及其相应的 HTTP 状态码：

+   非规范地址可能需要重定向到规范地址以用于 SEO 目的或站点架构的更改。这由*301 永久移动*或*302 找到*处理。

+   在成功或不成功的`POST`之后重定向。这有助于防止意外重新提交相同的表单数据。通常，这由*307 临时重定向*定义。

+   页面不一定丢失，但现在位于另一个位置。这由状态码*301 永久移动*处理。

在基本的 Go 中使用`net/http`执行任何一个都非常简单，但是正如你所期望的那样，使用更健壮的框架，比如 Gorilla，可以更加方便和改进。

# 提供基本错误

在这一点上，谈论一下错误是有些合理的。很可能，当你玩我们的基本平面文件服务服务器时，特别是当你超出两三页时，你可能已经遇到了错误。

我们的示例代码包括四个用于平面服务的示例 HTML 文件，编号为`1.html`，`2.html`等等。然而，当你访问`/pages/5`端点时会发生什么？幸运的是，`http`包会自动处理文件未找到错误，就像大多数常见的网络服务器一样。

此外，与大多数常见的网络服务器类似，错误页面本身很小，单调，毫无特色。在接下来的部分中，你可以看到我们从 Go 得到的**404 页面未找到**状态响应：

![提供基本错误](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_02_02.jpg)

正如前面提到的，这是一个非常基本和毫无特色的页面。通常情况下，这是一件好事——错误页面包含的信息或风格超过必要的可能会产生负面影响。

考虑这个错误——`404`——作为一个例子。如果我们包含对同一服务器上存在的图像和样式表的引用，如果这些资产也丢失了会发生什么？

简而言之，你很快就会遇到递归错误——每个`404`页面都会调用一个触发`404`响应的图像和样式表，循环重复。即使网络服务器足够聪明以停止这一点，而且很多都是，它也会在日志中产生噩梦般的场景，使它们充满了噪音，变得毫无用处。

让我们看一些代码，我们可以用来为我们的`/files`目录中任何丢失的文件实现一个全局的`404`页面：

```go
package main

import (
  "github.com/gorilla/mux"
  "net/http"
  "os"
)

const (
  PORT = ":8080"
)

func pageHandler(w http.ResponseWriter, r *http.Request) {
  vars := mux.Vars(r)
  pageID := vars["id"]
  fileName := "files/" + pageID + ".html"_, 
  err := os.Stat(fileName)
    if err != nil {
      fileName = "files/404.html"
    }

  http.ServeFile(w,r,fileName)
}
```

在这里，你可以看到我们首先尝试使用`os.Stat`检查文件（及其潜在错误），并输出我们自己的`404`响应：

```go
func main() {
  rtr := mux.NewRouter()
  rtr.HandleFunc("/pages/{id:[0-9]+}",pageHandler)
  http.Handle("/",rtr)
  http.ListenAndServe(PORT,nil)
}
```

现在，如果我们看一下`404.html`页面，我们会发现我们创建了一个自定义的 HTML 文件，它产生的东西比我们之前调用的默认**Go 页面未找到**消息更加用户友好。

让我们看看这是什么样子，但请记住，它可以看起来任何你想要的样子：

```go
<!DOCTYPE html>
<html>
<head>
<title>Page not found!</title>
<style type="text/css">
body {
  font-family: Helvetica, Arial;
  background-color: #cceeff;
  color: #333;
  text-align: center;
}
</style>
<link rel="stylesheet" type="text/css" media="screen" href="http://code.ionicframework.com/ionicons/2.0.1/css/ionicons.min.css"></link>
</head>

<body>
<h1><i class="ion-android-warning"></i> 404, Page not found!</h1>
<div>Look, we feel terrible about this, but at least we're offering a non-basic 404 page</div>
</body>

</html>
```

另外，请注意，虽然我们将`404.html`文件保存在与其他文件相同的目录中，但这仅仅是为了简单起见。

实际上，在大多数生产环境中，具有自定义错误页面，我们更希望它存在于自己的目录中，最好是在我们网站的公开可用部分之外。毕竟，现在您可以通过访问`http://localhost:8080/pages/404`的方式访问错误页面，这实际上并不是一个错误。这会返回错误消息，但实际情况是，在这种情况下找到了文件，我们只是返回它。

让我们通过访问`http://localhost/pages/5`来看一下我们新的、更漂亮的`404`页面，这指定了一个在我们的文件系统中不存在的静态文件：

![提供基本错误](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_02_03.jpg)

通过显示更加用户友好的错误消息，我们可以为遇到错误的用户提供更有用的操作。考虑一些其他可能受益于更具表现力的错误页面的常见错误。

# 总结

现在我们不仅可以从`net/http`包中产生基本路由，还可以使用 Gorilla 工具包产生更复杂的路由。通过利用 Gorilla，我们现在可以创建正则表达式，并实现基于模式的路由，并允许我们的路由模式更加灵活。

有了这种增加的灵活性，我们现在也必须注意错误，因此我们已经考虑了处理基于错误的重定向和消息，包括自定义的**404，页面未找到**消息，以产生更定制的错误消息。

现在我们已经掌握了创建端点、路由和处理程序的基础知识，我们需要开始进行一些非平凡的数据服务。

在第三章 *连接到数据*中，我们将开始从数据库中获取动态信息，这样我们就可以更智能、更可靠地管理数据。通过连接到一些不同的常用数据库，我们将能够构建强大、动态和可扩展的 Web 应用程序。


# 第三章：连接到数据

在上一章中，我们探讨了如何获取 URL 并将其转换为 Web 应用程序中的不同页面。这样做，我们构建了动态的 URL，并从我们（非常简单的）`net/http`处理程序中获得了动态响应。

通过从 Gorilla 工具包实现扩展的 mux 路由器，我们扩展了内置路由器的功能，允许使用正则表达式，从而使我们的应用程序具有更大的灵活性。

这是一些最流行的 Web 服务器的固有特性。例如，Apache 和 Nginx 都提供了在路由中利用正则表达式的方法，与常见解决方案保持一致应该是我们功能的最低基线。

但这只是构建具有多样功能的强大 Web 应用程序的一个重要的步骤。要进一步发展，我们需要考虑引入数据。

我们在上一章的示例中依赖于从静态文件中抓取的硬编码内容，这显然是过时的，不可扩展的。在 Web 的 CGI 早期，任何需要更新网站的人都需要重新制作静态文件，或者解释服务器端包含的过时性。

但幸运的是，Web 在 20 世纪 90 年代后期变得非常动态，数据库开始统治世界。虽然 API、微服务和 NoSQL 在某些地方取代了这种架构，但它仍然是 Web 工作的基础。

因此，话不多说，让我们获取一些动态数据。

在本章中，我们将涵盖以下主题：

+   连接到数据库

+   使用 GUID 创建更美观的 URL

+   处理 404 错误

# 连接到数据库

在访问数据库方面，Go 的 SQL 接口提供了一种非常简单可靠的方式来连接具有驱动程序的各种数据库服务器。

在这一点上，大多数大名鼎鼎的数据库都已经涵盖了——MySQL、Postgres、SQLite、MSSQL 等等都有由 Go 提供的`database/sql`接口提供的维护良好的驱动程序。

Go 处理这一点的最好之处在于通过标准化的 SQL 接口，您不必学习自定义的 Go 库来与数据库交互。这并不排除需要了解数据库的 SQL 实现或其他功能的细微差别，但它确实消除了一个潜在的困惑领域。

在继续之前，您需要确保通过`go get`命令安装了您选择的数据库的库和驱动程序。

Go 项目维护了所有当前 SQL 驱动程序的 Wiki，这是寻找适配器的一个很好的起始参考点，网址为[`github.com/golang/go/wiki/SQLDrivers`](https://github.com/golang/go/wiki/SQLDrivers)

### 注意

注意：在本书的各种示例中，我们使用 MySQL 和 Postgres，但请使用最适合您的解决方案。在任何 Nix、Windows 或 OS X 机器上安装 MySQL 和 Postgres 都相当基本。

MySQL 可以从[`www.mysql.com/`](https://www.mysql.com/)下载，虽然 Google 列出了一些驱动程序，但我们推荐使用 Go-MySQL-Driver。虽然您也可以选择 Go 项目推荐的替代方案，但 Go-MySQL-Driver 非常干净且经过了充分测试。您可以在[`github.com/go-sql-driver/mysql/`](https://github.com/go-sql-driver/mysql/)获取它。对于 Postgres，可以从[`www.postgresql.org/`](http://www.postgresql.org/)下载二进制文件或包管理器命令。这里选择的 Postgres 驱动是`pq`，可以通过`go get`安装，网址为[github.com/lib/pq](http://github.com/lib/pq)

## 创建 MySQL 数据库

您可以选择设计任何您想要的应用程序，但在这些示例中，我们将看一个非常简单的博客概念。

我们的目标是在数据库中尽可能少地拥有博客条目，以便能够通过 GUID 直接从数据库中调用它们，并在特定请求的博客条目不存在时显示错误。

为了做到这一点，我们将创建一个包含我们页面的 MySQL 数据库。这些页面将具有内部自动递增的数字 ID，一个文本全局唯一标识符或 GUID，以及一些关于博客条目本身的元数据。

为了简单起见，我们将创建一个标题`page_title`，正文文本`page_content`和一个 Unix 时间戳`page_date`。您可以随意使用 MySQL 的内置日期字段之一；使用整数字段存储时间戳只是一种偏好，并且可以允许在查询中进行一些更复杂的比较。

以下是在 MySQL 控制台（或 GUI 应用程序）中创建数据库`cms`和必需表`pages`的 SQL：

```go
CREATE TABLE `pages` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `page_guid` varchar(256) NOT NULL DEFAULT '',
  `page_title` varchar(256) DEFAULT NULL,
  `page_content` mediumtext,
  `page_date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `page_guid` (`page_guid`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
```

### 注意

如前所述，您可以通过任意数量的接口执行此查询。要连接到 MySQL，请选择您的数据库并尝试这些查询，您可以在[`dev.mysql.com/doc/refman/5.7/en/connecting.html`](http://dev.mysql.com/doc/refman/5.7/en/connecting.html)上查看命令行文档。

注意`page_guid`上的`UNIQUE KEY`。这非常重要，因为如果我们允许重复的 GUID，那么我们就有问题了。全局唯一键的概念是它不能存在于其他地方，而且由于我们将依赖它进行 URL 解析，因此我们希望确保每个 GUID 只有一个条目。

您可能已经注意到，这是一个非常基本的博客数据库内容类型。我们有一个自动递增的 ID 值，一个标题，一个日期和页面内容，没有太多其他事情发生。

虽然不多，但足以演示在 Go 中利用数据库接口动态页面。

只是为了确保`pages`表中有一些数据，请添加以下查询以填充一些数据：

```go
INSERT INTO `pages` (`id`, `page_guid`, `page_title`, `page_content`, `page_date`) VALUES (NULL, 'hello-world', 'Hello, World', 'I\'m so glad you found this page!  It\'s been sitting patiently on the Internet for some time, just waiting for a visitor.', CURRENT_TIMESTAMP);
```

这将给我们一些开始的东西。

现在我们有了结构和一些虚拟数据，让我们看看如何连接到 MySQL，检索数据，并根据 URL 请求和 Gorilla 的 mux 模式动态提供数据。

要开始，让我们创建一个连接所需的外壳：

```go
package main

import (
  "database/sql"
  "fmt"
  _ "github.com/go-sql-driver/mysql"
  "log"
)
```

我们正在导入 MySQL 驱动程序包，以实现所谓的*副作用*。通常情况下，这意味着该包是与另一个包相辅相成，并提供各种不需要特别引用的接口。

您可以通过下划线`_`语法来注意到这一点，该语法位于包的导入之前。您可能已经熟悉这种忽略方法返回值的快速而粗糙的方法。例如，`x，_：= something()`允许您忽略第二个返回值。

当开发人员计划使用库但尚未使用时，通常会这样使用。通过这种方式在包名前加下划线，可以使导入声明保持而不会导致编译器错误。虽然这是不被赞同的，但在前面的方法中使用下划线或空白标识符来产生副作用是相当常见且通常可接受的。

不过，这一切都取决于您使用标识符的方式和原因：

```go
const (
  DBHost  = "127.0.0.1"
  DBPort  = ":3306"
  DBUser  = "root"
  DBPass  = "password!"
  DBDbase = "cms"
)
```

当然，确保用与您的安装相关的内容替换这些值：

```go
var database *sql.DB
```

通过将数据库连接引用保持为全局变量，我们可以避免大量重复的代码。为了清晰起见，我们将在代码中相当高的位置定义它。没有什么可以阻止您将其变为常量，但我们将其保留为可变的，以便在必要时具有未来的灵活性，例如向单个应用程序添加多个数据库：

```go
type Page struct {
  Title   string
  Content string
  Date    string
}
```

当然，这个`struct`与我们的数据库模式非常相似，`Title`，`Content`和`Date`表示我们表中的非 ID 值。正如我们稍后在本章中看到的（以及在下一章中看到的），在一个设计良好的结构中描述我们的数据有助于利用 Go 的模板函数。在这一点上，请确保您的结构字段是可导出的或公共的，方法是保持它们的大小写正确。任何小写字段都不会被导出，因此在模板中不可用。我们稍后会详细讨论这一点：

```go
func main() {
  dbConn := fmt.Sprintf("%s:%s@tcp(%s)/%s", DBUser, DBPass, DBHost, DBDbase)
  db, err := sql.Open("mysql", dbConn)
  if err != nil {
    log.Println("Couldn't connect!")
    log.Println(err.Error)
  }
  database = db
}
```

正如我们之前提到的，这在很大程度上是搭架子。我们在这里要做的就是确保我们能够连接到我们的数据库。如果您遇到错误，请检查您的连接以及`Couldn't connect`后的日志条目输出。

如果幸运的话，您能够连接到这个脚本，我们可以继续创建一个通用路由，并从我们的数据库中输出该特定请求的 GUID 的相关数据。

为此，我们需要重新实现 Gorilla，创建一个单一路由，然后实现一个处理程序，生成一些非常简单的输出，与我们在数据库中的内容相匹配。

让我们看看我们需要进行的修改和添加，以便实现这一点：

```go
package main

import (
  "database/sql"
  "fmt"
  _ "github.com/go-sql-driver/mysql"
  "github.com/gorilla/mux"
  "log"
  "net/http"
)
```

这里的重大变化是我们重新引入了 Gorilla 和`net/http`到项目中。显然，我们需要这些来提供页面：

```go
const (
  DBHost  = "127.0.0.1"
  DBPort  = ":3306"
  DBUser  = "root"
  DBPass  = "password!"
  DBDbase = "cms"
  PORT    = ":8080"
)
```

我们添加了一个`PORT`常量，它指的是我们的 HTTP 服务器端口。

请注意，如果您的主机是`localhost`/`127.0.0.1`，则不需要指定`DBPort`，但我们已经在常量部分保留了这一行。我们在 MySQL 连接中不使用主机：

```go
var database *sql.DB

type Page struct {
  Title   string
  Content string
  Date    string
}

func ServePage(w http.ResponseWriter, r *http.Request) {
  vars := mux.Vars(r)
  pageID := vars["id"]
  thisPage := Page{}
  fmt.Println(pageID)
  err := database.QueryRow("SELECT page_title,page_content,page_date FROM pages WHERE id=?", pageID).Scan(&thisPage.Title, &thisPage.Content, &thisPage.Date)
  if err != nil {

    log.Println("Couldn't get page: +pageID")
    log.Println(err.Error)
  }
  html := `<html><head><title>` + thisPage.Title + `</title></head><body><h1>` + thisPage.Title + `</h1><div>` + thisPage.Content + `</div></body></html>`
  fmt.Fprintln(w, html)
}
```

`ServePage`是一个函数，它从`mux.Vars`中获取一个`id`并查询我们的数据库以获取博客条目的 ID。我们在查询方式上有一些微妙之处值得注意；消除 SQL 注入漏洞的最简单方法是使用预处理语句，比如`Query`、`QueryRow`或`Prepare`。利用其中任何一个，并包含一个可变的要注入到预处理语句中的变量，可以消除手工构建查询的固有风险。

`Scan`方法然后获取查询结果并将其转换为一个结构体；您需要确保结构体与查询中请求字段的顺序和数量匹配。在这种情况下，我们将`page_title`、`page_content`和`page_date`映射到`Page`结构体的`Title`、`Content`和`Date`：

```go
func main() {
  dbConn := fmt.Sprintf("%s:%s@/%s", DBUser, DBPass, DBDbase)
  fmt.Println(dbConn)
  db, err := sql.Open("mysql", dbConn)
  if err != nil {
    log.Println("Couldn't connect to"+DBDbase)
    log.Println(err.Error)
  }
  database = db

  routes := mux.NewRouter()
  routes.HandleFunc("/page/{id:[0-9]+}", ServePage)
  http.Handle("/", routes)
  http.ListenAndServe(PORT, nil)

}
```

请注意我们的正则表达式：它只是数字，由一个或多个数字组成，这些数字将成为我们处理程序中可访问的`id`变量。

还记得我们谈到使用内置的 GUID 吗？我们马上就会谈到这个，但现在让我们看一下`local` `host:8080/page/1`的输出：

![创建 MySQL 数据库](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_03_01.jpg)

在前面的示例中，我们可以看到我们在数据库中的博客条目。这很好，但显然在很多方面还是不够的。

# 使用 GUID 创建更美观的 URL

在本章的前面，我们谈到使用 GUID 作为所有请求的 URL 标识符。相反，我们首先让步于数字，因此自动递增表中的列。这是为了简单起见，但将其切换为字母数字 GUID 是微不足道的。

我们需要做的就是切换我们的正则表达式，并在我们的`ServePage`处理程序中更改我们的 SQL 查询结果。

如果我们只改变我们的正则表达式，我们上一个 URL 的页面仍然可以工作：

```go
routes.HandleFunc("/page/{id:[0-9a-zA\\-]+}", ServePage)
```

当然，页面仍然会通过我们的处理程序。为了消除任何歧义，让我们为路由分配一个`guid`变量：

```go
routes.HandleFunc("/page/{guid:[0-9a-zA\\-]+}", ServePage)
```

在那之后，我们改变了我们的调用和 SQL：

```go
func ServePage(w http.ResponseWriter, r *http.Request) {
  vars := mux.Vars(r)
  pageGUID := vars["guid"]
  thisPage := Page{}
  fmt.Println(pageGUID)
  err := database.QueryRow("SELECT page_title,page_content,page_date FROM pages WHERE page_guid=?", pageGUID).Scan(&thisPage.Title, &thisPage.Content, &thisPage.Date)
```

在这样做之后，通过`/pages/hello-world` URL 访问我们的页面将导致与通过`/pages/1`访问它时得到的相同页面内容。唯一的真正优势是外观上更美观，它创建了一个更易读的 URL，对搜索引擎可能更有用：

![使用 GUID 创建更美观的 URL](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_03_02.jpg)

# 处理 404s

我们前面的代码中一个非常明显的问题是，它没有处理请求无效 ID（或 GUID）的情况。

目前，对`/page/999`的请求将只会导致用户看到一个空白页面，而在后台会显示**无法获取页面！**的消息，如下面的屏幕截图所示：

![处理 404](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_03_04.jpg)

通过传递适当的错误来解决这个问题是非常简单的。在上一章中，我们探讨了自定义的`404`页面，您当然可以在这里实现其中一个，但最简单的方法是当找不到帖子时只返回一个 HTTP 状态代码，并允许浏览器处理呈现。

在我们之前的代码中，我们有一个错误处理程序，除了将问题返回到我们的日志文件之外，没有做太多事情。让我们把它变得更具体：

```go
  err := database.QueryRow("SELECT page_title,page_content,page_date FROM pages WHERE page_guid=?", pageGUID).Scan(&thisPage.Title, &thisPage.Content, &thisPage.Date)
  if err != nil {
    http.Error(w, http.StatusText(404), http.StatusNotFound)
    log.Println("Couldn't get page!")
  }
```

您将在以下屏幕截图中看到输出。再次强调，将这个页面替换为自定义的`404`页面是微不足道的，但现在我们要确保通过校验它们来处理无效的请求：

![处理 404](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_03_03.jpg)

提供良好的错误消息有助于提高开发人员和其他用户的可用性。此外，对于 SEO 也有好处，因此使用 HTTP 标准中定义的 HTTP 状态代码是有意义的。

# 摘要

在本章中，我们已经从简单地显示内容转向了以可持续和可维护的方式使用数据库维护内容。虽然这使我们能够轻松显示动态数据，但这只是实现完全功能的应用程序的核心步骤。

我们已经学习了如何创建数据库，然后从中检索数据并将其注入到路由中，同时保持我们的查询参数经过清理，以防止 SQL 注入。

我们还考虑了潜在的坏请求，比如无效的 GUID，对于任何在我们的数据库中不存在的请求的 GUID，我们返回*404 Not Found*状态。我们还查看了通过 ID 和字母数字 GUID 请求数据。

然而，这只是我们应用程序的开始。

在第四章中，*使用模板*，我们将使用从 MySQL（和 Postgres）中获取的数据，并应用一些 Go 模板语言，以便在前端上更灵活地使用它们。

到了那一章的结束，我们将拥有一个允许直接从我们的应用程序创建和删除页面的应用程序。


# 第四章：使用模板

在第二章中，*服务和路由*，我们探讨了如何将 URL 转换为网络应用程序中的不同页面。这样做的结果是，我们构建了动态的 URL，并从我们（非常简单的）`net/http`处理程序中获得了动态响应。

我们将我们的数据呈现为真实的 HTML，但我们将我们的 HTML 直接硬编码到我们的 Go 源代码中。这对于生产级环境来说并不理想，原因有很多。

幸运的是，Go 配备了一个强大但有时棘手的模板引擎，用于文本模板和 HTML 模板。

与许多其他模板语言不同，这些语言将逻辑排除在演示方面，Go 的模板包使您能够在模板中使用一些逻辑结构，例如循环、变量和函数声明。这使您能够将一些逻辑偏移至模板，这意味着您可以编写应用程序，但需要允许模板方面为产品提供一些可扩展性，而无需重写源代码。

我们说一些逻辑结构，因为 Go 模板被称为无逻辑。我们将在稍后讨论这个话题。

在本章中，我们将探讨不仅呈现数据的方式，还将探索本章中的一些更高级的可能性。最后，我们将能够将我们的模板转化为推进演示和源代码分离的方式。

我们将涵盖以下主题：

+   介绍模板、上下文和可见性

+   HTML 模板和文本模板

+   显示变量和安全性

+   使用逻辑和控制结构

# 介绍模板、上下文和可见性

很值得注意的是，虽然我们正在讨论将 HTML 部分从源代码中提取出来，但是在 Go 应用程序中使用模板是可能的。事实上，像这样声明模板是没有问题的：

```go
tpl, err := template.New("mine").Parse(`<h1>{{.Title}}</h1>`)
```

然而，如果我们这样做，每次模板需要更改时，我们都需要重新启动应用程序。如果我们使用基于文件的模板，就不必这样做；相反，我们可以在不重新启动的情况下对演示（和一些逻辑）进行更改。

从应用程序内的 HTML 字符串转移到基于文件的模板的第一件事是创建一个模板文件。让我们简要地看一下一个示例模板，它在某种程度上接近我们在本章后面将得到的结果：

```go
<!DOCTYPE html>
<html>
<head>
<title>{{.Title}}</title>
</head>
<body>
  <h1>{{.Title}}</h1>

  <div>{{.Date}}</div>

  {{.Content}}
</body>
</html>
```

非常简单，对吧？变量通过双大括号内的名称清楚地表示。那么所有的句号/点是怎么回事？与其他一些类似风格的模板系统（如 Mustache、Angular 等）一样，句号表示范围或上下文。

最容易演示这一点的地方是变量可能重叠的地方。想象一下，我们有一个标题为**博客条目**的页面，然后我们列出所有已发布的博客文章。我们有一个页面标题，但我们也有单独的条目标题。我们的模板可能看起来类似于这样：

```go
{{.Title}}
{{range .Blogs}}
  <li><a href="{{.Link}}">{{.Title}}</a></li>
{{end}}
```

这里的点指定了特定的范围，这种情况下是通过 range 模板操作符语法进行循环。这允许模板解析器正确地使用`{{.Title}}`作为博客的标题，而不是页面的标题。

这一切都值得注意，因为我们将创建的第一个模板将利用通用范围变量，这些变量以点表示。

# HTML 模板和文本模板

在我们第一个示例中，我们将从数据库中将博客的值显示到网络上，我们生成了一个硬编码的 HTML 字符串，并直接注入了我们的值。

以下是我们在第三章中使用的两行：

```go
  html := `<html><head><title>` + thisPage.Title + `</title></head><body><h1>` + thisPage.Title + `</h1><div>` + thisPage.Content + `</div></body></html>
  fmt.Fprintln(w, html)
```

这不难理解为什么这不是一个可持续的系统，用于将我们的内容输出到网络上。最好的方法是将其转换为模板，这样我们就可以将演示与应用程序分开。

为了尽可能简洁地做到这一点，让我们修改调用前面代码的方法`ServePage`，使用模板而不是硬编码的 HTML。

所以我们将删除之前放置的 HTML，而是引用一个文件，该文件将封装我们想要显示的内容。从你的根目录开始，创建一个`templates`子目录，并在其中创建一个`blog.html`。

以下是我们包含的非常基本的 HTML，随意添加一些花样：

```go
<html>
<head>
<title>{{.Title}}</title>
</head>
<body>
  <h1>{{.Title}}</h1>
  <p>
    {{.Content}}
  </p>
  <div>{{.Date}}</div>
</body>
</html>
```

回到我们的应用程序，在`ServePage`处理程序中，我们将稍微改变我们的输出代码，不再留下显式的字符串，而是解析和执行我们刚刚创建的 HTML 模板：

```go
func ServePage(w http.ResponseWriter, r *http.Request) {
  vars := mux.Vars(r)
  pageGUID := vars["guid"]
  thisPage := Page{}
  fmt.Println(pageGUID)
  err := database.QueryRow("SELECT page_title,page_content,page_date FROM pages WHERE page_guid=?", pageGUID).Scan(&thisPage.Title, &thisPage.Content, &thisPage.Date)
  if err != nil {
    http.Error(w, http.StatusText(404), http.StatusNotFound)
    log.Println("Couldn't get page!")
    return
  }
  // html := <html>...</html>

  t, _ := template.ParseFiles("templates/blog.html")
  t.Execute(w, thisPage)
}
```

如果你以某种方式未能创建文件或者文件无法访问，应用程序在尝试执行时将会发生 panic。如果你引用了不存在的`struct`值，也会发生 panic——我们需要更好地处理错误。

### 注意

注意：不要忘记在你的导入中包含`html/template`。

远离静态字符串的好处是显而易见的，但现在我们已经为一个更具扩展性的呈现层奠定了基础。

如果我们访问`http://localhost:9500/page/hello-world`，我们将看到类似于这样的东西：

![HTML 模板和文本模板](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_04_01.jpg)

# 显示变量和安全性

为了演示这一点，让我们通过在 MySQL 命令行中添加这个 SQL 命令来创建一个新的博客条目：

```go
INSERT INTO `pages` (`id`, `page_guid`, `page_title`, page_content`, `page_date`)
```

值：

```go
  (2, 'a-new-blog', 'A New Blog', 'I hope you enjoyed the last blog!  Well brace yourself, because my latest blog is even <i>better</i> than the last!', '2015-04-29 02:16:19');
```

另一个令人兴奋的内容，当然。但是请注意，当我们尝试给单词 better 加上斜体时，我们在其中嵌入了一些 HTML。

不管如何存储格式的争论，这使我们能够查看 Go 的模板如何默认处理这个问题。如果我们访问`http://localhost:9500/page/a-new-blog`，我们将看到类似于这样的东西：

![显示变量和安全性](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_04_02.jpg)

正如你所看到的，Go 会自动为我们的输出数据进行消毒。有很多非常非常明智的原因来做这个，这就是为什么这是默认行为的最大原因。当然，最大的原因是为了避免来自不受信任的输入源（例如网站的一般用户等）的 XSS 和代码注入攻击向量。

但表面上，我们正在创建这个内容，应该被视为受信任的。因此，为了将其验证为受信任的 HTML，我们需要改变`template.HTML`的类型：

```go
type Page struct {
  Title   string
  Content template.HTML
  Date   string
}
```

如果你尝试将生成的 SQL 字符串值简单地扫描到`template.HTML`中，你会发现以下错误：

```go
sql: Scan error on column index 1: unsupported driver -> Scan pair: []uint8 -> *template.HTML
```

解决这个问题的最简单方法是保留`RawContent`中的字符串值，并将其重新分配给`Content`：

```go
type Page struct {
  Title    string
  RawContent string
  Content    template.HTML
  Date    string
}
  err := database.QueryRow("SELECT page_title,page_content,page_date FROM pages WHERE page_guid=?", pageGUID).Scan(&thisPage.Title, &thisPage.RawContent, &thisPage.Date)
  thisPage.Content = template.HTML(thisPage.RawContent)
```

如果我们再次`go run`，我们将看到我们的 HTML 是受信任的：

![显示变量和安全性](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_04_03.jpg)

# 使用逻辑和控制结构

在本章的前面，我们看到了如何在我们的模板中使用范围，就像我们直接在我们的代码中使用一样。看一下下面的代码：

```go
{{range .Blogs}}
  <li><a href="{{.Link}}">{{.Title}}</a></li>
{{end}}
```

你可能还记得我们说过，Go 的模板没有任何逻辑，但这取决于你如何定义逻辑，以及共享逻辑是否完全存在于应用程序、模板中，还是两者都有一点。这是一个小问题，但因为 Go 的模板提供了很大的灵活性，所以这是值得思考的一个问题。

在前面的模板中具有一个范围功能，本身就为我们的博客的新呈现打开了很多可能性。现在我们可以显示博客列表，或者将我们的博客分成段落，并允许每个段落作为一个单独的实体存在。这可以用来允许评论和段落之间的关系，这在最近的一些出版系统中已经开始成为一个功能。

但现在，让我们利用这个机会在一个新的索引页面中创建一个博客列表。为此，我们需要添加一个路由。由于我们有`/page`，我们可以选择`/pages`，但由于这将是一个索引，让我们选择`/`和`/home`：

```go
  routes := mux.NewRouter()
  routes.HandleFunc("/page/{guid:[0-9a-zA\\-]+}", ServePage)
  routes.HandleFunc("/", RedirIndex)
  routes.HandleFunc("/home", ServeIndex)
  http.Handle("/", routes)
```

我们将使用`RedirIndex`自动重定向到我们的`/home`端点作为规范的主页。

在我们的方法中提供简单的`301`或`永久移动`重定向需要非常少的代码，如下所示：

```go
func RedirIndex(w http.ResponseWriter, r *http.Request) {
  http.Redirect(w, r, "/home", 301)
}
```

这足以接受来自`/`的任何请求，并自动将用户带到`/home`。现在，让我们看看如何在`ServeIndex`HTTP 处理程序中循环遍历我们的博客在我们的索引页面上：

```go
func ServeIndex(w http.ResponseWriter, r *http.Request) {
  var Pages = []Page{}
  pages, err := database.Query("SELECT page_title,page_content,page_date FROM pages ORDER BY ? DESC", "page_date")
  if err != nil {
    fmt.Fprintln(w, err.Error)
  }
  defer pages.Close()
  for pages.Next() {
    thisPage := Page{}
    pages.Scan(&thisPage.Title, &thisPage.RawContent, &thisPage.Date)
    thisPage.Content = template.HTML(thisPage.RawContent)
    Pages = append(Pages, thisPage)
  }
  t, _ := template.ParseFiles("templates/index.html")
  t.Execute(w, Pages)
}
```

这是`templates/index.html`：

```go
<h1>Homepage</h1>

{{range .}}
  <div><a href="!">{{.Title}}</a></div>
  <div>{{.Content}}</div>
  <div>{{.Date}}</div>
{{end}}
```

使用逻辑和控制结构

在这里我们突出了`Page struct`的一个问题——我们无法获取页面的`GUID`引用。因此，我们需要修改我们的`struct`以包括可导出的`Page.GUID`变量：

```go
type Page struct {
  Title  string
  Content  template.HTML
  RawContent  string
  Date  string
  GUID   string
}
```

现在，我们可以将我们索引页面上的列表链接到它们各自的博客条目，如下所示：

```go
  var Pages = []Page{}
  pages, err := database.Query("SELECT page_title,page_content,page_date,page_guid FROM pages ORDER BY ? DESC", "page_date")
  if err != nil {
    fmt.Fprintln(w, err.Error)
  }
  defer pages.Close()
  for pages.Next() {
    thisPage := Page{}
    pages.Scan(&thisPage.Title, &thisPage.Content, &thisPage.Date, &thisPage.GUID)
    Pages = append(Pages, thisPage)
  }
```

我们可以使用以下代码更新我们的 HTML 部分：

```go
<h1>Homepage</h1>

{{range .}}
  <div><a href="/page/{{.GUID}}">{{.Title}}</a></div>
  <div>{{.Content}}</div>
  <div>{{.Date}}</div>
{{end}}
```

但这只是模板强大功能的开始。如果我们有一个更长的内容，并且想要截断它的描述呢？

我们可以在`Page struct`中创建一个新字段并对其进行截断。但这有点笨拙；它要求该字段始终存在于`struct`中，无论是否填充了数据。将方法暴露给模板本身要高效得多。

所以让我们这样做。

首先，创建另一个博客条目，这次内容值更大。选择任何你喜欢的内容，或者按照所示选择`INSERT`命令：

```go
INSERT INTO `pages` (`id`, `page_guid`, `page_title`, `page_content`, `page_date`)
```

值：

```go
  (3, 'lorem-ipsum', 'Lorem Ipsum', 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Maecenas sem tortor, lobortis in posuere sit amet, ornare non eros. Pellentesque vel lorem sed nisl dapibus fringilla. In pretium...', '2015-05-06 04:09:45');
```

### 注意

注意：为了简洁起见，我们已经截断了我们之前的 Lorem Ipsum 文本的完整长度。

现在，我们需要将我们的截断表示为`Page`类型的方法。让我们创建该方法，以返回表示缩短文本的字符串。

这里的酷之处在于，我们可以在应用程序和模板之间共享方法：

```go
func (p Page) TruncatedText() string {
  chars := 0
  for i, _ := range p.Content {
    chars++
    if chars > 150 {
      return p.Content[:i] + ` ...`
    }
  }
  return p.Content
}
```

这段代码将循环遍历内容的长度，如果字符数超过`150`，它将返回索引中的切片直到该数字。如果它从未超过该数字，`TruncatedText`将返回整个内容。

在模板中调用这个方法很简单，只是你可能期望需要传统的函数语法调用，比如`TruncatedText()`。相反，它被引用为作用域内的任何变量一样：

```go
<h1>Homepage</h1>

{{range .}}
  <div><a href="/page/{{.GUID}}">{{.Title}}</a></div>
  <div>{{.TruncatedText}}</div>
  <div>{{.Date}}</div>
{{end}}
```

通过调用.`TruncatedText`，我们本质上通过该方法内联处理值。结果页面反映了我们现有的博客，而不是截断的博客，以及我们新的博客条目，其中包含截断的文本和省略号：

使用逻辑和控制结构

我相信你可以想象在模板中直接引用嵌入方法将打开一系列的演示可能性。

# 总结

我们只是初步了解了 Go 模板的功能，随着我们的继续探索，我们将进一步探讨更多的主题，但是这一章节已经介绍了开始直接利用模板所需的核心概念。

我们已经研究了简单的变量，以及在应用程序中实现方法，在模板本身中实现方法。我们还探讨了如何绕过受信任内容的注入保护。

在下一章中，我们将集成后端 API，以 RESTful 方式访问信息以读取和操作底层数据。这将允许我们在模板上使用 Ajax 做一些更有趣和动态的事情。


# 第五章：RESTful API 与前端集成

在第二章*服务和路由*中，我们探讨了如何将 URL 路由到我们 Web 应用程序中的不同页面。在这样做时，我们构建了动态的 URL，并从我们（非常简单的）`net/http`处理程序中获得了动态响应。

我们刚刚触及了 Go 模板的一小部分功能，随着我们的继续，我们还将探索更多主题，但在本章中，我们试图介绍直接开始使用模板所必需的核心概念。

我们已经研究了简单的变量以及在应用程序中使用模板本身实现的方法。我们还探讨了如何绕过对受信任内容的注入保护。

网站开发的呈现方面很重要，但也是最不根深蒂固的方面。几乎任何框架都会呈现其内置的 Go 模板和路由语法的扩展。真正将我们的应用程序提升到下一个水平的是构建和集成 API，用于通用数据访问，以及允许我们的呈现层更具动态驱动性。

在本章中，我们将开发一个后端 API，以 RESTful 方式访问信息，并读取和操作我们的基础数据。这将允许我们在模板中使用 Ajax 做一些更有趣和动态的事情。

在本章中，我们将涵盖以下主题：

+   设置基本的 API 端点

+   RESTful 架构和最佳实践

+   创建我们的第一个 API 端点

+   实施安全性

+   使用 POST 创建数据

+   使用 PUT 修改数据

# 设置基本的 API 端点

首先，我们将为页面和单独的博客条目设置一个基本的 API 端点。

我们将为`GET`请求创建一个 Gorilla 端点路由，该请求将返回有关我们页面的信息，还有一个接受 GUID 的请求，GUID 匹配字母数字字符和连字符：

```go
routes := mux.NewRouter()
routes.HandleFunc("/api/pages", APIPage).
  Methods("GET").
  Schemes("https")
routes.HandleFunc("/api/pages/{guid:[0-9a-zA\\-]+}", APIPage).
  Methods("GET").
  Schemes("https")
routes.HandleFunc("/page/{guid:[0-9a-zA\\-]+}", ServePage)
http.Handle("/", routes)
http.ListenAndServe(PORT, nil)
```

请注意，我们再次捕获了 GUID，这次是为我们的`/api/pages/*`端点，它将反映网页端点的功能，返回与单个页面相关的所有元数据。

```go
func APIPage(w http.ResponseWriter, r *http.Request) {
vars := mux.Vars(r)
pageGUID := vars["guid"]
thisPage := Page{}
fmt.Println(pageGUID)
err := database.QueryRow("SELECT page_title,page_content,page_date FROM pages WHERE page_guid=?", pageGUID).Scan(&thisPage.Title, &thisPage.RawContent, &thisPage.Date)
thisPage.Content = template.HTML(thisPage.RawContent)
if err != nil {
  http.Error(w, http.StatusText(404), http.StatusNotFound)
  log.Println(err)
  return
}
APIOutput, err := json.Marshal(thisPage)
    fmt.Println(APIOutput)
if err != nil {
  http.Error(w, err.Error(), http.StatusInternalServerError)
  return
}
w.Header().Set("Content-Type", "application/json")
fmt.Fprintln(w, thisPage)
}
```

前面的代码代表了最简单的基于 GET 的请求，它从我们的`/pages`端点返回单个记录。现在让我们来看看 REST，看看我们将如何构建和实现其他动词和数据操作。

# RESTful 架构和最佳实践

在 Web API 设计领域，已经有一系列迭代的，有时是竞争的努力，以找到跨多个环境传递信息的标准系统和格式。

近年来，网站开发社区似乎已经—至少是暂时地—将 REST 作为事实上的方法。REST 在几年 SOAP 的主导之后出现，并引入了一种更简单的数据共享方法。

REST API 不受格式限制，通常可以缓存并通过 HTTP 或 HTTPS 传递。

开始时最重要的是遵守 HTTP 动词；最初为 Web 指定的那些动词在其原始意图上受到尊重。例如，HTTP 动词，如`DELETE`和`PATCH`，尽管非常明确地说明了它们的目的，但在多年的不使用后，REST 已成为使用正确方法的主要推动力。在 REST 之前，很常见看到`GET`和`POST`请求被互换使用来做各种事情，而这些事情本来是内置在 HTTP 设计中的。

在 REST 中，我们遵循**创建-读取-更新-删除**（CRUD）的方法来检索或修改数据。`POST`主要用于创建，`PUT`用于更新（尽管它也可以用于创建），熟悉的`GET`用于读取，`DELETE`用于删除，就是这样。

也许更重要的是，一个符合 RESTful 的 API 应该是无状态的。我们的意思是每个请求应该独立存在，而服务器不一定需要了解先前或潜在的未来请求。这意味着会话的概念在技术上违反了这一原则，因为我们会在服务器上存储某种状态。有些人持不同意见；我们将在以后详细讨论这个问题。

最后一点是关于 API URL 结构，因为方法已经作为请求的一部分嵌入到头部中，所以我们不需要在请求中明确表达它。

换句话说，我们不需要像`/api/blogs/delete/1`这样的东西。相反，我们可以简单地使用`DELETE`方法向`api/blogs/1`发出请求。

URL 结构没有严格的格式，您可能很快就会发现一些操作缺乏合理的 HTTP 动词，但简而言之，我们应该追求一些目标：

+   资源在 URL 中清晰表达

+   我们正确地利用 HTTP 动词

+   我们根据请求的类型返回适当的响应

我们在本章的目标是用我们的 API 实现前面三点。

如果有第四点，它会说我们与我们的 API 保持向后兼容。当您检查这里的 URL 结构时，您可能会想知道版本是如何处理的。这往往因组织而异，但一个很好的政策是保持最近的 URL 规范，并废弃显式版本的 URL。

例如，即使我们的评论可以在`/api/comments`中访问，但旧版本将在`/api/v2.0/comments`中找到，其中`2`显然代表我们的 API，就像它在版本`2.0`中存在一样。

### 注意

尽管在本质上相对简单且定义明确，REST 是一个常常争论的主题，有足够的模糊性，往往会引发很多辩论。请记住，REST 不是一个标准；例如，W3C 从未并且可能永远不会对 REST 是什么以及不是什么发表意见。如果您还没有，您将开始对什么是真正符合 REST 的内容产生一些非常强烈的看法。

# 创建我们的第一个 API 端点

鉴于我们希望从客户端和服务器之间访问数据，我们需要开始通过 API 公开其中的一些数据。

对我们来说最合理的事情是简单地读取，因为我们还没有方法在直接的 SQL 查询之外创建数据。我们在本章的开头就用我们的`APIPage`方法做到了这一点，通过`/api/pages/{UUID}`端点路由。

这对于`GET`请求非常有用，因为我们不会操纵数据，但是如果我们需要创建或修改数据，我们需要利用其他 HTTP 动词和 REST 方法。为了有效地做到这一点，现在是时候在我们的 API 中调查一些身份验证和安全性了。

# 实施安全性

当您考虑使用我们刚刚设计的 API 创建数据时，您首先会考虑什么问题？如果是安全性，那就太好了。访问数据并不总是没有安全风险，但当我们允许修改数据时，我们需要真正开始考虑安全性。

在我们的情况下，读取数据是完全无害的。如果有人可以通过`GET`请求访问我们所有的博客条目，那又有什么关系呢？好吧，我们可能有一篇关于禁运的博客，或者意外地在某些资源上暴露了敏感数据。

无论如何，安全性始终应该是一个关注点，即使是像我们正在构建的博客平台这样的小型个人项目。

有两种分离这些问题的方法：

+   我们的 API 请求是否安全且私密？

+   我们是否在控制对数据的访问？

让我们先解决第 2 步。如果我们想允许用户创建或删除信息，我们需要为他们提供对此的特定访问权限。

有几种方法可以做到这一点：

我们可以提供 API 令牌，允许短暂的请求窗口，这可以通过共享密钥进行验证。这是 Oauth 的本质；它依赖于共享密钥来验证加密编码的请求。没有共享密钥，请求及其令牌将永远不匹配，然后 API 请求可以被拒绝。

`cond`方法是一个简单的 API 密钥，这将我们带回到上述列表中的第 1 点。

如果我们允许明文 API 密钥，那么我们可能根本不需要安全性。如果我们的请求可以轻松地从线路上被嗅探到，那么甚至要求 API 密钥也没有多大意义。

这意味着无论我们选择哪种方法，我们的服务器都应该通过 HTTPS 提供 API。幸运的是，Go 提供了一种非常简单的方式来利用 HTTP 或 HTTPS 通过**传输层安全性**（**TLS**）；TLS 是 SSL 的后继者。作为 Web 开发人员，您必须已经熟悉 SSL，并且也意识到其安全问题的历史，最近是其易受 POODLE 漏洞攻击的问题，该漏洞于 2014 年曝光。

为了允许任一方法，我们需要有一个用户注册模型，这样我们就可以有新用户，他们可以有某种凭据来修改数据。为了调用 TLS 服务器，我们需要一个安全证书。由于这是一个用于实验的小项目，我们不会太担心具有高度信任级别的真实证书。相反，我们将自己生成。

创建自签名证书因操作系统而异，超出了本书的范围，因此让我们只看看 OS X 的方法。

自签名证书显然没有太多的安全价值，但它允许我们在不需要花费金钱或时间验证服务器所有权的情况下测试事物。对于任何希望被认真对待的证书，您显然需要做这些事情。

要在 OS X 中快速创建一组证书，请转到终端并输入以下三个命令：

```go
openssl genrsa -out key.pem
openssl req -new -key key.pem -out cert.pem
openssl req -x509 -days 365 -key key.pem -in cert.pem -out certificate.pem

```

在这个例子中，我使用 Ubuntu 上的 OpenSSL 生成了证书。

### 注意

注意：OpenSSL 预装在 OS X 和大多数 Linux 发行版上。如果您使用后者，请在寻找特定于 Linux 的说明之前尝试上述命令。如果您使用 Windows，特别是较新版本，如 8，您可以以多种方式执行此操作，但最可访问的方式可能是通过 MSDN 提供的 MakeCert 工具。

阅读有关 MakeCert 的更多信息[`msdn.microsoft.com/en-us/library/bfsktky3%28v=vs.110%29.aspx`](https://msdn.microsoft.com/en-us/library/bfsktky3%28v=vs.110%29.aspx)。

一旦您拥有证书文件，请将它们放在文件系统中的某个位置，而不要放在您可以访问的应用程序目录/目录中。

要从 HTTP 切换到 TLS，我们可以使用对这些证书文件的引用；除此之外，在我们的代码中基本上是相同的。让我们首先将证书添加到我们的代码中。

### 注意

注意：再次，您可以选择在同一服务器应用程序中维护 HTTP 和 TLS/HTTPS 请求，但我们将全面切换。

早些时候，我们通过监听以下行来启动我们的服务器：

```go
http.ListenAndServe(PORT, nil)
```

现在，我们需要稍微扩展一下。首先，让我们加载我们的证书：

```go
  certificates, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
  tlsConf := tls.Config{Certificates: []tls.Certificate{certificates}}
  tls.Listen("tcp", PORT, &tlsConf)
```

### 注意

注意：如果您发现您的服务器似乎没有错误地运行，但无法保持运行；您的证书可能存在问题。尝试再次运行上述生成代码，并使用新证书进行操作。

# 使用 POST 创建数据

现在我们已经有了一个安全证书，我们可以为我们的 API 调用切换到 TLS，包括`GET`和其他请求。让我们现在这样做。请注意，您可以保留 HTTP 用于我们其余的端点，或者在这一点上也将它们切换。

### 注意

注意：现在大多数人普遍采用仅使用 HTTPS 的方式，这可能是未来保护您的应用程序的最佳方式。这不仅适用于 API 或者明文发送显式和敏感信息的地方，隐私是首要考虑的；主要提供商和服务都在强调随处使用 HTTPS 的价值。

让我们在我们的博客上添加一个匿名评论的简单部分：

```go
<div id="comments">
  <form action="/api/comments" method="POST">
    <input type="hidden" name="guid" value="{{Guid}}" />
    <div>
      <input type="text" name="name" placeholder="Your Name" />
    </div>
    <div>
      <input type="email" name="email" placeholder="Your Email" />
    </div>
    <div>
      <textarea name="comments" placeholder="Your Com-ments"></textarea>
    </div>
    <div>
      <input type="submit" value="Add Comments" />
    </div>
  </form>
</div>
```

这将允许任何用户在我们的网站上对我们的任何博客项目添加匿名评论，如下截图所示：

![使用 POST 创建数据](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_05_01.jpg)

但是安全性呢？目前，我们只想创建一个开放的评论区，任何人都可以在其中发布他们的有效、明晰的想法，以及他们的垃圾药方交易。我们稍后会担心锁定这一点；目前我们只想演示 API 和前端集成的并行。

显然，我们的数据库中需要一个`comments`表，所以在实现任何 API 之前，请确保创建该表。

```go
CREATE TABLE `comments` (
`id` int(11) unsigned NOT NULL AUTO_INCREMENT,
`page_id` int(11) NOT NULL,
`comment_guid` varchar(256) DEFAULT NULL,
`comment_name` varchar(64) DEFAULT NULL,
`comment_email` varchar(128) DEFAULT NULL,
`comment_text` mediumtext,
`comment_date` timestamp NULL DEFAULT NULL,
PRIMARY KEY (`id`),
KEY `page_id` (`page_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
```

有了表格，让我们把表单`POST`到 API 端点。为了创建一个通用和灵活的 JSON 响应，你可以添加一个`JSONResponse struct`，它基本上是一个哈希映射，如下所示：

```go
type JSONResponse struct {
  Fields map[string]string
}
```

然后我们需要一个 API 端点来创建评论，所以让我们在`main()`的路由下添加它：

```go
func APICommentPost(w http.ResponseWriter, r *http.Request) {
  var commentAdded bool
  err := r.ParseForm()
  if err != nil {
    log.Println(err.Error)
  }
  name := r.FormValue("name")
  email := r.FormValue("email")
  comments := r.FormValue("comments")

  res, err := database.Exec("INSERT INTO comments SET comment_name=?, comment_email=?, comment_text=?", name, email, comments)

  if err != nil {
    log.Println(err.Error)
  }

  id, err := res.LastInsertId()
  if err != nil {
    commentAdded = false
  } else {
    commentAdded = true
  }
  commentAddedBool := strconv.FormatBool(commentAdded)
  var resp JSONResponse
  resp.Fields["id"] = string(id)
  resp.Fields["added"] =  commentAddedBool
  jsonResp, _ := json.Marshal(resp)
  w.Header().Set("Content-Type", "application/json")
  fmt.Fprintln(w, jsonResp)
}
```

关于前面的代码有一些有趣的事情：

首先，注意我们使用`commentAdded`作为`string`而不是`bool`。我们这样做主要是因为 json marshaller 不能优雅地处理布尔值，而且直接从布尔值转换为字符串也是不可能的。我们还利用`strconv`及其`FormatBool`来处理这个转换。

您可能还注意到，对于这个例子，我们直接将表单`POST`到 API 端点。虽然这是演示数据进入数据库的有效方式，但在实践中使用它可能会强制一些 RESTful 反模式，比如启用重定向 URL 以返回到调用页面。

通过客户端利用一个常见的库或者通过`XMLHttpRequest`本地化来实现 Ajax 调用是更好的方法。

### 注意

注意：虽然内部函数/方法的名称在很大程度上是个人偏好的问题，但我们建议通过资源类型和请求方法来保持所有方法的区分。这里使用的实际约定并不重要，但在遍历代码时，诸如`APICommentPost`、`APICommentGet`、`APICommentPut`和`APICommentDelete`这样的命名方式可以更好地组织方法，使其更易读。

考虑到前端和后端的代码，我们可以看到这将如何呈现给访问我们第二篇博客文章的用户：

![使用 POST 创建数据](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_05_02.jpg)

正如前面提到的，实际在这里添加评论将直接发送表单到 API 端点，希望它会悄悄成功。

# 使用 PUT 修改数据

根据您询问的人，`PUT`和`POST`可以互换地用于创建记录。有些人认为两者都可以用于更新记录，大多数人认为两者都可以用于创建记录，只要给定一组变量。为了避免陷入一场有些混乱且常常带有政治色彩的辩论，我们将两者分开如下：

+   创建新记录：`POST`

+   更新现有记录，幂等性：`PUT`

根据这些准则，当我们希望更新资源时，我们将利用`PUT`动词。我们将允许任何人编辑评论，仅仅作为使用 REST `PUT`动词的概念验证。

在第六章*会话和 Cookie*中，我们将更加严格地限制这一点，但我们也希望能够通过 RESTful API 演示内容的编辑；因此，这将代表一个将来更安全和完整的不完整存根。

与创建新评论一样，在这里没有安全限制。任何人都可以创建评论，任何人都可以编辑它。至少在这一点上，这是博客软件的狂野西部。

首先，我们希望能够看到我们提交的评论。为此，我们需要对我们的`Page struct`进行微小的修改，并创建一个`Comment struct`以匹配我们的数据库结构：

```go
type Comment struct {
  Id    int
  Name   string
  Email  string
  CommentText string
}

type Page struct {
  Id         int
  Title      string
  RawContent string
  Content    template.HTML
  Date       string
  Comments   []Comment
  Session    Session
  GUID       string
}
```

由于之前发布的所有评论都没有任何真正的喧闹，博客文章页面上没有实际评论的记录。为了解决这个问题，我们将添加一个简单的`Comments`查询，并使用`.Scan`方法将它们扫描到一个`Comment struct`数组中。

首先，我们将在`ServePage`中添加查询：

```go
func ServePage(w http.ResponseWriter, r *http.Request) {
  vars := mux.Vars(r)
  pageGUID := vars["guid"]
  thisPage := Page{}
  fmt.Println(pageGUID)
  err := database.QueryRow("SELECT id,page_title,page_content,page_date FROM pages WHERE page_guid=?", pageGUID).Scan(&thisPage.Id, &thisPage.Title, &thisPage.RawContent, &thisPage.Date)
  thisPage.Content = template.HTML(thisPage.RawContent)
  if err != nil {
    http.Error(w, http.StatusText(404), http.StatusNotFound)
    log.Println(err)
    return
  }

  comments, err := database.Query("SELECT id, comment_name as Name, comment_email, comment_text FROM comments WHERE page_id=?", thisPage.Id)
  if err != nil {
    log.Println(err)
  }
  for comments.Next() {
    var comment Comment
    comments.Scan(&comment.Id, &comment.Name, &comment.Email, &comment.CommentText)
    thisPage.Comments = append(thisPage.Comments, comment)
  }

  t, _ := template.ParseFiles("templates/blog.html")
  t.Execute(w, thisPage)
}
```

现在我们已经将`Comments`打包进我们的`Page struct`中，我们可以在页面上显示**Comments**：

![使用 PUT 修改数据](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_05_03.jpg)

由于我们允许任何人进行编辑，我们将不得不为每个项目创建一个表单，这将允许修改。一般来说，HTML 表单只允许`GET`或`POST`请求，所以我们被迫使用`XMLHttpRequest`来发送这个请求。为了简洁起见，我们将利用 jQuery 及其`ajax()`方法。

首先，对于我们模板中的评论范围：

```go
{{range .Comments}}
  <div class="comment">
    <div>Comment by {{.Name}} ({{.Email}})</div>
    {{.CommentText}}

    <div class="comment_edit">
    <h2>Edit</h2>
    <form onsubmit="return putComment(this);">
      <input type="hidden" class="edit_id" value="{{.Id}}" />
      <input type="text" name="name" class="edit_name" placeholder="Your Name" value="{{.Name}}" />
     <input type="text" name="email" class="edit_email" placeholder="Your Email" value="{{.Email}}" />
      <textarea class="edit_comments" name="comments">{{.CommentText}}</textarea>
      <input type="submit" value="Edit" />
    </form>
    </div>
  </div>
{{end}}
```

然后，我们的 JavaScript 将使用`PUT`来处理表单：

```go
<script>
    function putComment(el) {
        var id = $(el).find('.edit_id');
        var name = $(el).find('.edit_name').val();
        var email = $(el).find('.edit_email').val();
        var text = $(el).find('.edit_comments').val();
        $.ajax({
            url: '/api/comments/' + id,
            type: 'PUT',
            succes: function(res) {
                alert('Comment Updated!');
            }
        });
        return false;
    }
</script>
```

为了处理这个使用`PUT`动词的调用，我们需要一个更新路由和函数。现在让我们添加它们：

```go
  routes.HandleFunc("/api/comments", APICommentPost).
    Methods("POST")
  routes.HandleFunc("/api/comments/{id:[\\w\\d\\-]+}", APICommentPut).
 Methods("PUT")

```

这样就可以启用一个路由，现在我们只需要添加相应的函数，它看起来会和我们的`POST`/`Create`方法非常相似：

```go
func APICommentPut(w http.ResponseWriter, r *http.Request) {
  err := r.ParseForm()
  if err != nil {
  log.Println(err.Error)
  }
  vars := mux.Vars(r)
  id := vars["id"]
  fmt.Println(id)
  name := r.FormValue("name")
  email := r.FormValue("email")
  comments := r.FormValue("comments")
  res, err := database.Exec("UPDATE comments SET comment_name=?, comment_email=?, comment_text=? WHERE comment_id=?", name, email, comments, id)
  fmt.Println(res)
  if err != nil {
    log.Println(err.Error)
  }

  var resp JSONResponse

  jsonResp, _ := json.Marshal(resp)
  w.Header().Set("Content-Type", "application/json")
  fmt.Fprintln(w, jsonResp)
}
```

简而言之，这将把我们的表单转变为基于评论内部 ID 的数据更新。正如前面提到的，这与我们的`POST`路由方法并没有完全不同，就像那个方法一样，它也不返回任何数据。

# 总结

在本章中，我们从独占服务器生成的 HTML 演示转变为利用 API 的动态演示。我们研究了 REST 的基础知识，并为我们的博客应用程序实现了一个 RESTful 接口。

虽然这可以使用更多客户端的修饰，但我们有`GET`/`POST`/`PUT`请求是功能性的，并允许我们为我们的博客文章创建、检索和更新评论。

在第六章，“会话和 Cookie”中，我们将研究用户认证、会话和 Cookie，以及如何将本章中我们所建立的基本组件应用到一些非常重要的安全参数上。在本章中，我们对评论进行了开放式的创建和更新；我们将在下一章中将其限制为唯一用户。

通过这一切，我们将把我们的概念验证评论管理转变为可以在生产中实际使用的东西。


# 第六章：会话和 Cookie

我们的应用现在开始变得更加真实；在上一章中，我们为它们添加了一些 API 和客户端接口。

在我们应用的当前状态下，我们已经添加了`/api/comments`、`/api/comments/[id]`、`/api/pages`和`/api/pages/[id]`，这样我们就可以以 JSON 格式获取和更新我们的数据，并使应用更适合 Ajax 和客户端访问。

虽然我们现在可以通过我们的 API 直接添加评论和编辑评论，但是对谁可以执行这些操作没有任何限制。在本章中，我们将探讨限制对某些资产的访问、建立身份和在拥有它们时进行安全认证的方法。

最终，我们应该能够让用户注册和登录，并利用会话、cookie 和闪存消息以安全的方式在我们的应用中保持用户状态。

# 设置 cookie

创建持久内存跨用户会话的最常见、基本和简单的方式是利用 cookie。

Cookie 提供了一种在请求、URL 端点甚至域之间共享状态信息的方式，并且它们已经被以各种可能的方式使用（和滥用）。

它们通常用于跟踪身份。当用户登录到一个服务时，后续的请求可以通过利用存储在 cookie 中的会话信息来访问前一个请求的某些方面（而不需要重复查找或登录模块）。

如果你熟悉其他语言中 cookie 的实现，基本的`struct`会很熟悉。即便如此，以下相关属性与向客户端呈现 cookie 的方式基本一致：

```go
type Cookie struct {
  Name       string
  Value      string
  Path       string
  Domain     string
  Expires    time.Time
  RawExpires string
  MaxAge   int
  Secure   bool
  HttpOnly bool
  Raw      string
  Unparsed []string
}
```

对于一个非常基本的`struct`来说，这是很多属性，所以让我们专注于重要的属性。

`Name`属性只是 cookie 的键。`Value`属性代表其内容，`Expires`是一个`Time`值，表示 cookie 应该被浏览器或其他无头接收者刷新的时间。这就是你在 Go 中设置一个有效 cookie 所需要的一切。

除了基础知识，如果你想要限制 cookie 的可访问性，你可能会发现设置`Path`、`Domain`和`HttpOnly`是有用的。

# 捕获用户信息

当一个具有有效会话和/或 cookie 的用户尝试访问受限数据时，我们需要从用户的浏览器中获取它。

一个会话本身就是一个在网站上的单个会话。它并不会自然地无限期持续，所以我们需要留下一个线索，但我们也希望留下一个相对安全的线索。

例如，我们绝不希望在 cookie 中留下关键的用户信息，比如姓名、地址、电子邮件等等。

然而，每当我们有一些标识信息时，我们都会留下一些不良行为的可能性——在这种情况下，我们可能会留下代表我们会话 ID 的会话标识符。在这种情况下，这个向量允许获得这个 cookie 的人以我们其中一个用户的身份登录并更改信息，查找账单详情等等。

这些类型的物理攻击向量远远超出了这个（以及大多数）应用的范围，而且在很大程度上，这是一个让步，即如果有人失去了对他们的物理机器的访问权限，他们也可能会遭受账户被破坏的风险。

在这里我们想要做的是确保我们不会在明文或没有安全连接的情况下传输个人或敏感信息。我们将在第九章 *安全*中介绍如何设置 TLS，所以在这里我们想要专注于限制我们在 cookie 中存储的信息量。

## 创建用户

在上一章中，我们允许非授权的请求通过`POST`命中我们的 REST API 来创建新的评论。在互联网上待了一段时间的人都知道一些真理，比如：

1.  评论部分通常是任何博客或新闻帖子中最有毒的部分

1.  即使用户必须以非匿名的方式进行身份验证，步骤 1 也是正确的

现在，让我们限制评论部分，以确保用户已注册并已登录。

我们现在不会深入探讨身份验证的安全方面，因为我们将在第九章 *安全*中更深入地讨论这个问题。

首先，在我们的数据库中添加一个`users`表：

```go
CREATE TABLE `users` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `user_name` varchar(32) NOT NULL DEFAULT '',
  `user_guid` varchar(256) NOT NULL DEFAULT '',
  `user_email` varchar(128) NOT NULL DEFAULT '',
  `user_password` varchar(128) NOT NULL DEFAULT '',
  `user_salt` varchar(128) NOT NULL DEFAULT '',
  `user_joined_timestamp` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
```

我们当然可以深入研究用户信息，但这已经足够让我们开始了。正如前面提到的，我们不会深入研究安全性，所以现在我们只是为密码生成一个哈希值，不用担心盐。

最后，为了在应用程序中启用会话和用户，我们将对我们的 structs 进行一些更改：

```go
type Page struct {
  Id         int
  Title      string
  RawContent string
  Content    template.HTML
  Date       string
  Comments   []Comment
  Session    Session
}

type User struct {
  Id   int
  Name string
}

type Session struct {
  Id              string
  Authenticated   bool
  Unauthenticated bool
  User            User
}
```

以下是用于注册和登录的两个存根处理程序。同样，我们并没有将全部精力投入到将它们完善成健壮的东西，我们只是想打开一点门。

## 启用会话

除了存储用户本身之外，我们还需要一种持久性内存的方式来访问我们的 cookie 数据。换句话说，当用户的浏览器会话结束并且他们回来时，我们将验证和调和他们的 cookie 值与我们数据库中的值。

使用此 SQL 创建`sessions`表：

```go
CREATE TABLE `sessions` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `session_id` varchar(256) NOT NULL DEFAULT '',
  `user_id` int(11) DEFAULT NULL,
  `session_start` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `session_update` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `session_active` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `session_id` (`session_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
```

最重要的值是`user_id`、`session_id`和更新和开始的时间戳。我们可以使用后两者来决定在一定时间后会话是否实际上是有效的。这是一个很好的安全实践，仅仅因为用户有一个有效的 cookie 并不一定意味着他们应该保持身份验证，特别是如果您没有使用安全连接。

## 让用户注册

为了让用户能够自行创建账户，我们需要一个注册和登录的表单。现在，大多数类似的系统都会进行一些多因素身份验证，以允许用户备份系统进行检索，并验证用户的真实性和唯一性。我们会做到这一点，但现在让我们尽可能简单。

我们将设置以下端点，允许用户`POST`注册和登录表单：

```go
  routes.HandleFunc("/register", RegisterPOST).
    Methods("POST").
    Schemes("https")
  routes.HandleFunc("/login", LoginPOST).
    Methods("POST").
    Schemes("https")
```

请记住，这些目前设置为 HTTPS 方案。如果您不使用 HTTPS，请删除`HandleFunc`注册的部分。

由于我们只向未经身份验证的用户显示以下视图，我们可以将它们放在我们的`blog.html`模板中，并将它们包裹在`{{if .Session.Unauthenticated}} … {{end}}`模板片段中。我们在应用程序中的`Session` `struct`下定义了`.Unauthenticated`和`.Authenticated`，如下例所示：

```go
{{if .Session.Unauthenticated}}<form action="/register" method="POST">
  <div><input type="text" name="user_name" placeholder="User name" /></div>
  <div><input type="email" name="user_email" placeholder="Your email" /></div>
  <div><input type="password" name="user_password" placeholder="Password" /></div>
  <div><input type="password" name="user_password2" placeholder="Password (repeat)" /></div>
  <div><input type="submit" value="Register" /></div>
</form>{{end}}
```

和我们的`/register`端点：

```go
func RegisterPOST(w http.ResponseWriter, r *http.Request) {
  err := r.ParseForm()
  if err != nil {
    log.Fatal(err.Error)
  }
  name := r.FormValue("user_name")
  email := r.FormValue("user_email")
  pass := r.FormValue("user_password")
  pageGUID := r.FormValue("referrer")
  // pass2 := r.FormValue("user_password2")
  gure := regexp.MustCompile("[^A-Za-z0-9]+")
  guid := gure.ReplaceAllString(name, "")
  password := weakPasswordHash(pass)

  res, err := database.Exec("INSERT INTO users SET user_name=?, user_guid=?, user_email=?, user_password=?", name, guid, email, password)
  fmt.Println(res)
  if err != nil {
    fmt.Fprintln(w, err.Error)
  } else {
    http.Redirect(w, r, "/page/"+pageGUID, 301)
  }
}
```

请注意，由于多种原因，这种方式并不优雅。如果密码不匹配，我们不会检查并向用户报告。如果用户已经存在，我们也不会告诉他们注册失败的原因。我们会解决这个问题，但现在我们的主要目的是生成一个会话。

供参考，这是我们的`weakPasswordHash`函数，它只用于生成测试哈希：

```go
func weakPasswordHash(password string) []byte {
  hash := sha1.New()
  io.WriteString(hash, password)
  return hash.Sum(nil)
}
```

## 让用户登录

用户可能已经注册过了；在这种情况下，我们也希望在同一个页面上提供登录机制。这显然可以根据更好的设计考虑来实现，但我们只是想让它们都可用：

```go
<form action="/login" method="POST">
  <div><input type="text" name="user_name" placeholder="User name" /></div>
  <div><input type="password" name="user_password" placeholder="Password" /></div>
  <div><input type="submit" value="Log in" /></div>
</form>
```

然后我们将需要为每个 POST 表单设置接收端点。我们在这里也不会进行太多的验证，但我们也没有验证会话的位置。

# 启动服务器端会话

在 Web 上验证用户并保存其状态的最常见方式之一是通过会话。您可能还记得我们在上一章中提到过 REST 是无状态的，这主要是因为 HTTP 本身是无状态的。

如果您考虑一下，要建立与 HTTP 一致的状态，您需要包括一个 cookie 或 URL 参数或其他不是协议本身内置的东西。

会话是使用通常不是完全随机但足够唯一以避免大多数逻辑和合理情况下的冲突的唯一标识符创建的。当然，这并不是绝对的，当然，有很多（历史上的）会话令牌劫持的例子与嗅探无关。

作为一个独立的过程，会话支持在 Go 核心中并不存在。鉴于我们在服务器端有一个存储系统，这有点无关紧要。如果我们为生成服务器密钥创建一个安全的过程，我们可以将它们存储在安全的 cookie 中。

但生成会话令牌并不完全是微不足道的。我们可以使用一组可用的加密方法来实现这一点，但是由于会话劫持是一种非常普遍的未经授权进入系统的方式，这可能是我们应用程序中的一个不安全的点。

由于我们已经在使用 Gorilla 工具包，好消息是我们不必重新发明轮子，已经有一个强大的会话系统。

我们不仅可以访问服务器端会话，而且还可以获得一个非常方便的工具，用于会话中的一次性消息。这些工作方式与消息队列有些类似，一旦数据进入其中，当数据被检索时，闪存消息就不再有效。

## 创建存储

要使用 Gorilla 会话，我们首先需要调用一个 cookie 存储，它将保存我们想要与用户关联的所有变量。您可以通过以下代码很容易地测试这一点：

```go
package main

import (
  "fmt"
  "github.com/gorilla/sessions"
  "log"
  "net/http"
)

func cookieHandler(w http.ResponseWriter, r *http.Request) {
  var cookieStore = sessions.NewCookieStore([]byte("ideally, some random piece of entropy"))
  session, _ := cookieStore.Get(r, "mystore")
  if value, exists := session.Values["hello"]; exists {
    fmt.Fprintln(w, value)
  } else {
    session.Values["hello"] = "(world)"
    session.Save(r, w)
    fmt.Fprintln(w, "We just set the value!")
  }
}

func main() {
  http.HandleFunc("/test", cookieHandler)
  log.Fatal(http.ListenAndServe(":8080", nil))
}
```

第一次访问您的 URL 和端点时，您将看到**我们刚刚设置了值！**，如下面的截图所示：

![创建存储](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_06_04.jpg)

在第二个请求中，您应该看到**(world)**，如下面的截图所示：

![创建存储](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_06_05.jpg)

这里有几点需要注意。首先，在通过`io.Writer`（在这种情况下是`ResponseWriter w`）发送任何其他内容之前，您必须设置 cookies。如果您交换这些行：

```go
    session.Save(r, w)
    fmt.Fprintln(w, "We just set the value!")
```

您可以看到这个过程。您永远不会得到设置为 cookie 存储的值。

现在，让我们将其应用到我们的应用程序中。我们将在对`/login`或`/register`的任何请求之前初始化一个会话存储。

我们将初始化一个全局的`sessionStore`：

```go
var database *sql.DB
var sessionStore = sessions.NewCookieStore([]byte("our-social-network-application"))
```

也可以自由地将这些分组在`var()`中。接下来，我们将创建四个简单的函数，用于获取活动会话，更新当前会话，生成会话 ID，并评估现有的 cookie。这将允许我们通过 cookie 的会话 ID 检查用户是否已登录，并启用持久登录。

首先是`getSessionUID`函数，如果会话已经存在，它将返回用户的 ID：

```go
func getSessionUID(sid string) int {
  user := User{}
  err := database.QueryRow("SELECT user_id FROM sessions WHERE session_id=?", sid).Scan(user.Id)
  if err != nil {
    fmt.Println(err.Error)
    return 0
  }
  return user.Id
}
```

接下来是更新函数，它将在每个面向前端的请求中调用，从而使时间戳更新或者在尝试新的登录时包含用户 ID：

```go
func updateSession(sid string, uid int) {
  const timeFmt = "2006-01-02T15:04:05.999999999"
  tstamp := time.Now().Format(timeFmt)
  _, err := database.Exec("INSERT INTO sessions SET session_id=?, user_id=?, session_update=? ON DUPLICATE KEY UPDATE user_id=?, session_update=?", sid, uid, tstamp, uid, tstamp)
  if err != nil {
    fmt.Println(err.Error)
  }
}
```

一个重要的部分是能够生成一个强大的随机字节数组（转换为字符串），以允许唯一的标识符。我们可以通过以下`generateSessionId()`函数来实现：

```go
func generateSessionId() string {
  sid := make([]byte, 24)
  _, err := io.ReadFull(rand.Reader, sid)
  if err != nil {
    log.Fatal("Could not generate session id")
  }
  return base64.URLEncoding.EncodeToString(sid)
}
```

最后，我们有一个函数，它将在每个请求中被调用，检查 cookie 的会话是否存在，如果不存在则创建一个。

```go
func validateSession(w http.ResponseWriter, r *http.Request) {
  session, _ := sessionStore.Get(r, "app-session")
  if sid, valid := session.Values["sid"]; valid {
    currentUID := getSessionUID(sid.(string))
    updateSession(sid.(string), currentUID)
    UserSession.Id = string(currentUID)
  } else {
    newSID := generateSessionId()
    session.Values["sid"] = newSID
    session.Save(r, w)
    UserSession.Id = newSID
    updateSession(newSID, 0)
  }
  fmt.Println(session.ID)
}
```

这是建立在有一个全局的`Session struct`的基础上的，在这种情况下定义如下：

```go
var UserSession Session
```

这让我们只剩下一个部分——在我们的`ServePage()`方法和`LoginPost()`方法上调用`validateSession()`，然后在后者上验证密码并在成功登录尝试时更新我们的会话：

```go
func LoginPOST(w http.ResponseWriter, r *http.Request) {
  validateSession(w, r)
```

在我们之前定义的对表单值的检查中，如果找到一个有效的用户，我们将直接更新会话：

```go
  u := User{}
  name := r.FormValue("user_name")
  pass := r.FormValue("user_password")
  password := weakPasswordHash(pass)
  err := database.QueryRow("SELECT user_id, user_name FROM users WHERE user_name=? and user_password=?", name, password).Scan(&u.Id, &u.Name)
  if err != nil {
    fmt.Fprintln(w, err.Error)
    u.Id = 0
    u.Name = ""
  } else {
    updateSession(UserSession.Id, u.Id)
    fmt.Fprintln(w, u.Name)
  }
```

## 利用闪存消息

正如本章前面提到的，Gorilla 会话提供了一种简单的系统，用于在请求之间利用基于单次使用和基于 cookie 的数据传输。

闪存消息背后的想法与浏览器/服务器消息队列并没有太大的不同。它最常用于这样的过程：

+   一个表单被提交

+   数据被处理

+   发起一个头部重定向

+   生成的页面需要一些关于`POST`过程（成功、错误）的信息访问

在这个过程结束时，应该删除消息，以便消息不会在其他地方错误地重复。Gorilla 使这变得非常容易，我们很快就会看到，但是展示一下如何在原生 Go 中实现这一点是有意义的。

首先，我们将创建一个包含起始点处理程序`startHandler`的简单 HTTP 服务器：

```go
package main

import (
  "fmt"
  "html/template"
  "log"
  "net/http"
  "time"
)

var (
  templates = template.Must(template.ParseGlob("templates/*"))
  port      = ":8080"
)

func startHandler(w http.ResponseWriter, r *http.Request) {
  err := templates.ExecuteTemplate(w, "ch6-flash.html", nil)
  if err != nil {
    log.Fatal("Template ch6-flash missing")
  }
}
```

我们在这里没有做任何特别的事情，只是渲染我们的表单：

```go
func middleHandler(w http.ResponseWriter, r *http.Request) {
  cookieValue := r.PostFormValue("message")
  cookie := http.Cookie{Name: "message", Value: "message:" + cookieValue, Expires: time.Now().Add(60 * time.Second), HttpOnly: true}
  http.SetCookie(w, &cookie)
  http.Redirect(w, r, "/finish", 301)
}
```

我们的`middleHandler`演示了通过`Cookie struct`创建 cookie，正如本章前面所述。这里没有什么重要的要注意，除了您可能希望将到期时间延长一点，以确保在请求之间没有办法使 cookie 过期（自然地）：

```go
func finishHandler(w http.ResponseWriter, r *http.Request) {
  cookieVal, _ := r.Cookie("message")

  if cookieVal != nil {
    fmt.Fprintln(w, "We found: "+string(cookieVal.Value)+", but try to refresh!")
    cookie := http.Cookie{Name: "message", Value: "", Expires: time.Now(), HttpOnly: true}
    http.SetCookie(w, &cookie)
  } else {
    fmt.Fprintln(w, "That cookie was gone in a flash")
  }

}
```

`finishHandler`函数执行闪存消息的魔术——仅在找到值时删除 cookie。这确保了 cookie 是一次性可检索的值：

```go
func main() {

  http.HandleFunc("/start", startHandler)
  http.HandleFunc("/middle", middleHandler)
  http.HandleFunc("/finish", finishHandler)
  log.Fatal(http.ListenAndServe(port, nil))

}
```

以下示例是我们用于将我们的 cookie 值 POST 到`/middle`处理程序的 HTML：

```go
<html>
<head><title>Flash Message</title></head>
<body>
<form action="/middle" method="POST">
  <input type="text" name="message" />
  <input type="submit" value="Send Message" />
</form>
</body>
</html>
```

如果您按照页面的建议再次刷新，cookie 值将被删除，页面将不会呈现，就像您之前看到的那样。

要开始闪存消息，我们点击我们的`/start`端点，并输入一个预期的值，然后点击**发送消息**按钮：

![利用闪存消息](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_06_01.jpg)

在这一点上，我们将被发送到`/middle`端点，该端点将设置 cookie 值并将 HTTP 重定向到`/finish`：

![利用闪存消息](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_06_02.jpg)

现在我们可以看到我们的价值。由于`/finish`端点处理程序还取消了 cookie，我们将无法再次检索该值。如果我们在第一次出现时按照`/finish`的指示做什么，会发生什么：

![利用闪存消息](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_06_03.jpg)

就这些了。

# 总结

希望到目前为止，您已经掌握了如何在 Go 中利用基本的 cookie 和会话，无论是通过原生 Go 还是通过使用 Gorilla 等框架。我们已经尝试演示了后者的内部工作原理，以便您能够在不使用额外库混淆功能的情况下进行构建。

我们已经将会话实现到我们的应用程序中，以实现请求之间的持久状态。这是 Web 身份验证的基础。通过在数据库中启用`users`和`sessions`表，我们能够登录用户，注册会话，并在后续请求中将该会话与正确的用户关联起来。

通过利用闪存消息，我们利用了一个非常特定的功能，允许在两个端点之间传输信息，而不需要启用可能看起来像错误或生成错误输出的额外请求。我们的闪存消息只能使用一次，然后过期。

在第七章中，*微服务和通信*，我们将研究如何连接现有和新 API 之间的不同系统和应用程序，以允许基于事件的操作在这些系统之间协调。这将有助于连接到同一环境中的其他服务，以及应用程序之外的服务。
