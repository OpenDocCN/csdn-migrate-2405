# 同构的 Go 应用（四）

> 原文：[`zh.annas-archive.org/md5/70B74CAEBE24AE2747234EE512BCFA98`](https://zh.annas-archive.org/md5/70B74CAEBE24AE2747234EE512BCFA98)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：测试同构 Go Web 应用

通过在上一章中对网站进行可重用组件（齿轮）的点缀，我们已经达到了一个项目里程碑——我们完成了第二章《同构 Go 工具链》中规划的 IGWEB 功能集。然而，我们还不能立即启动 IGWEB。在启动之前，我们必须通过验证它是否满足一定的基本功能要求来确保同构 Web 应用的质量。为此，我们必须实施端到端测试，跨环境（服务器端和客户端）测试同构 Web 应用的功能。

在本章中，您将学习如何为 IGWEB 提供端到端的测试覆盖。我们将使用 Go 的内置测试框架测试服务器端功能，并使用 CasperJS 测试客户端功能。通过实施一套端到端测试，我们不仅可以进行自动化测试，而且在编写的每个测试中还有一个有价值的项目工件，因为每个测试都传达了同构 Web 应用中预期功能的意图。到本章结束时，我们将创建一个端到端测试套件，为稳固的测试策略奠定基础，读者可以进一步构建。

在本章中，我们将涵盖以下主题：

+   使用 Go 的测试框架测试服务器端功能

+   使用 CasperJS 测试客户端功能

# 测试服务器端功能

正如我们在第一章《使用 Go 构建同构 Web 应用》中所学到的，同构 Web 应用架构利用了经典的 Web 应用架构，这意味着 Web 页面响应将在服务器端呈现。这意味着 Web 客户端无需启用 JavaScript 即可消费从服务器响应接收到的内容。这对于机器用户（如搜索引擎爬虫）尤为重要，他们需要爬行网站上找到的各种链接并对其进行索引。通常情况下，搜索引擎蜘蛛是不启用 JavaScript 的。这意味着我们必须确保服务器端路由正常运行，并且 Web 页面响应也正确呈现。

除此之外，我们在第七章《同构 Web 表单》中，付出了很大的努力，创建了一个可访问的、同构的 Web 表单，可以被有更高辅助功能需求的用户访问。我们需要确保联系表单的验证功能正常运行，并且我们可以成功发送有效的联系表单提交。

因此，在服务器端，我们将测试的基本功能包括以下项目：

1.  验证服务器端路由和模板呈现

1.  验证联系表单的验证功能

1.  验证成功的联系表单提交

# Go 的测试框架

我们将使用 Go 的内置测试框架编写一组测试，测试 IGWEB 的服务器端功能。所有服务器端测试都存储在`tests`文件夹中。

如果您对 Go 内置的测试框架还不熟悉，可以通过此链接了解更多：[`golang.org/pkg/testing/`](https://golang.org/pkg/testing/)。

在运行`go test`命令执行所有测试之前，您必须启动 Redis 服务器实例和 IGWEB（最好分别在它们自己的专用终端窗口或选项卡中）。

您可以使用以下命令启动 Redis 服务器实例：

```go
$ redis-server
```

您可以使用以下命令在`$IGWEB_APP_ROOT`文件夹中启动 IGWEB 实例：

```go
$ go run igweb.go
```

要运行套件中的所有测试，我们只需在`tests`文件夹中运行`go test`命令：

```go
$ go test
```

# 验证服务器端路由和模板呈现

我们创建了一个测试来验证 IGWEB 应用程序的所有服务器端路由。我们测试的每个路由都将与一个预期的字符串令牌相关联，该令牌在页面响应中呈现，特别是在主要内容`div`容器中。因此，我们不仅能够验证服务器端路由是否正常运行，还能知道服务器端模板呈现是否正常运行。

以下是在`tests`文件夹中找到的`routes_test.go`源文件的内容：

```go
package tests

import (
  "io/ioutil"
  "net/http"
  "strings"
  "testing"
)

func checkRoute(t *testing.T, route string, expectedToken string) {

  testURL := testHost + route
  response, err := http.Get(testURL)
  if err != nil {
    t.Errorf("Could not connect to URL: %s. Failed with error: %s",     
    testURL, err)
  } else {
    defer response.Body.Close()
    contents, err := ioutil.ReadAll(response.Body)
    if err != nil {
      t.Errorf("Could not read response body. Failed with error: %s",   
      err)
    }
    if strings.Contains(string(contents), expectedToken) == false {
      t.Errorf("Could not find expected string token: \"%s\", in 
      response body for URL: %s", expectedToken, testURL)
    }
  }
}

func TestServerSideRoutes(t *testing.T) {

  routesTokenMap := map[string]string{"": "IGWEB", "/": "IGWEB",   
  "/index": "IGWEB", "/products": "Add To Cart", "/product-  
  detail/swiss-army-knife": "Swiss Army Knife", "/about": "Molly",   
  "/contact": "Enter your message for us here"}

  for route, expectedString := range routesTokenMap {
    checkRoute(t, route, expectedString)
  }
}
```

我们定义的`testHost`变量用于指定运行 IGWEB 实例的主机名和端口。

`TestServerSideRoutes`函数负责测试服务器端路由，并验证预期的令牌字符串是否存在于响应正文中。在函数内部，我们声明并初始化了`routesTokenMap`变量，类型为`map[string]string`。此`map`中的键表示我们正在测试的服务器端路由，给定键的值表示应该存在于从服务器返回的网页响应中的预期`string`令牌。因此，这个测试不仅会告诉我们服务器端路由是否正常运行，还会让我们对模板呈现的健康状况有一个很好的了解，因为我们提供的预期`string`令牌都是应该在网页正文中找到的字符串。然后，我们通过`routesTokenMap`进行`range`，对于每次迭代，我们将`route`和`expectedString`传递给`checkRoute`函数。

`checkRoute`函数负责访问给定路由，读取其响应正文并验证`expectedString`是否存在于响应正文中。有三种情况可能导致测试失败：

1.  当无法连接到路由 URL 时

1.  如果无法读取从服务器检索到的响应正文

1.  如果从服务器返回的网页响应中不存在预期的字符串令牌

如果发生这三种错误中的任何一种，测试将失败。否则函数将正常返回。

我们可以通过发出以下`go test`命令来运行此测试：

```go
$ go test -run TestServerSideRoutes
```

检查运行测试的输出显示测试已通过：

```go
$ go test -run TestServerSideRoutes
PASS
ok github.com/EngineerKamesh/igb/igweb/tests 0.014s
```

我们现在已成功验证了访问服务器端路由并确保每个路由中的预期字符串在网页响应中正确呈现。现在，让我们开始验证联系表单功能，从表单验证功能开始。

# 验证联系表单的验证功能

我们将要实现的下一个测试将测试联系表单的服务器端表单验证功能。我们将测试两种类型的验证：

+   当未填写必填表单字段时显示的错误消息

+   当在电子邮件字段中提供格式不正确的电子邮件地址值时显示的错误消息

以下是在`tests`文件夹中找到的`contactvalidation_test.go`源文件的内容：

```go
package tests

import (
  "io/ioutil"
  "net/http"
  "net/url"
  "strconv"
  "strings"
  "testing"
)

func TestContactFormValidation(t *testing.T) {

  testURL := testHost + "/contact"
  expectedTokenMap := map[string]string{"firstName": "The first name 
  field is required.", "/": "The last name field is required.",   
  "email": "The e-mail address entered has an improper syntax.",   
  "messageBody": "The message area must be filled."}

  form := url.Values{}
  form.Add("firstName", "")
  form.Add("lastName", "")
  form.Add("email", "devnull@g@o")
  form.Add("messageBody", "")

  req, err := http.NewRequest("POST", testURL,   
  strings.NewReader(form.Encode()))

  if err != nil {
    t.Errorf("Failed to create new POST request to URL: %s, with error:   
    %s", testURL, err)
  }

  req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
  req.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))

  hc := http.Client{}
  response, err := hc.Do(req)

  if err != nil {
    t.Errorf("Failed to make POST request to URL: %s, with error: %s", 
    testURL, err)
  }

  defer response.Body.Close()
  contents, err := ioutil.ReadAll(response.Body)

  if err != nil {
    t.Errorf("Failed to read response body contents with error: %s",         
    err)
  }

  for k, v := range expectedTokenMap {
    if strings.Contains(string(contents), v) == false {
      t.Errorf("Could not find expected string token: \"%s\" for field 
      \"%s\"", v, k)
    }
  }

}
```

`TestContactFormValidation`函数负责测试联系表单的服务器端表单验证功能。我们声明并初始化了`testURL`变量，该变量是 IGWEB 联系部分的 URL。

我们声明并初始化了`expectedTokenMap`变量，类型为`map[string]string`，其中`map`中的键是表单字段的名称，每个键的值表示在提交表单时应返回的预期错误消息。

我们创建一个新表单，并使用表单对象的`Add`方法填充表单字段值。请注意，我们为`firstName`、`lastName`和`messageBody`字段提供了空的`string`值。我们还为`email`字段提供了格式不正确的电子邮件地址。

我们使用`http`包中找到的`NewRequest`函数使用 HTTP POST 请求提交表单。

我们创建一个`http.Client`，`hc`，并通过调用它的`Do`方法提交 POST 请求。我们使用`ioutil`包中的`ReadAll`函数获取响应正文的内容。我们通过`expectedTokenMap`进行`range`，在每次迭代中，我们检查响应正文中是否包含预期的错误消息。

这些是可能导致此测试失败的四种可能条件：

+   如果无法创建 POST 请求

+   如果由于与 Web 服务器的连接问题而导致 POST 请求失败

+   如果网页客户端无法读取从 Web 服务器返回的网页响应的响应正文

+   如果在网页正文中找不到预期的错误消息

如果遇到任何这些错误中的一个，这个测试将失败。

我们可以通过发出以下命令来运行这个测试：

```go
$ go test -run TestContactFormValidation
```

运行测试的输出显示测试已经通过：

```go
$ go test -run TestContactFormValidation
PASS
ok github.com/EngineerKamesh/igb/igweb/tests 0.009s
```

# 验证成功的联系表单提交

我们将要实现的下一个测试将测试成功的联系表单提交。这个测试将与上一个测试非常相似，唯一的区别是我们将填写所有表单字段，并在`email`表单字段中提供一个格式正确的电子邮件地址。

以下是`tests`文件夹中`contact_test.go`源文件的内容：

```go
package tests

import (
  "io/ioutil"
  "net/http"
  "net/url"
  "strconv"
  "strings"
  "testing"
)

func TestContactForm(t *testing.T) {

  testURL := testHost + "/contact"
  expectedTokenString := "The contact form has been successfully   
  completed."

  form := url.Values{}
  form.Add("firstName", "Isomorphic")
  form.Add("lastName", "Gopher")
  form.Add("email", "devnull@test.com")
  form.Add("messageBody", "This is a message sent from the automated   
  contact form test.")

  req, err := http.NewRequest("POST", testURL,   
  strings.NewReader(form.Encode()))

  if err != nil {
    t.Errorf("Failed to create new POST request to URL: %s, with error: 
    %s", testURL, err)
  }

  req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
  req.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))

  hc := http.Client{}
  response, err := hc.Do(req)

  if err != nil {
    t.Errorf("Failed to make POST request to URL: %s, with error: %s", 
    testURL, err)
  }

  defer response.Body.Close()
  contents, err := ioutil.ReadAll(response.Body)

  if err != nil {
    t.Errorf("Failed to read response body contents with error: %s", 
    err)
  }

  if strings.Contains(string(contents), expectedTokenString) == false {
    t.Errorf("Could not find expected string token: \"%s\"", 
    expectedTokenString)
  }
}
```

再次，这个测试与我们之前实现的测试非常相似，只是我们填充了所有表单字段并提供了一个格式正确的电子邮件地址。我们声明并初始化`expectedTokenString`变量，以确认我们期望在成功提交表单后在响应正文中打印出的确认字符串。函数的最后一个`if`条件块检查响应正文是否包含`expectedTokenString`。如果没有，那么测试将失败。

这些是可能导致此测试失败的四种可能条件：

+   如果无法创建 POST 请求

+   如果由于与 Web 服务器的连接问题而导致 POST 请求失败

+   如果网页客户端无法读取从 Web 服务器返回的网页响应的响应正文

+   如果在网页正文中找不到预期的确认消息

同样，如果遇到任何这些错误中的一个，这个测试将失败。

我们可以通过发出以下命令来运行测试：

```go
$ go test - run TestContactForm
```

通过检查运行测试后的输出，我们可以看到测试已经通过：

```go
$ go test - run TestContactForm
PASS
ok github.com/EngineerKamesh/igb/igweb/tests 0.012s
```

您可以通过在`tests`目录中简单地发出`go test`命令来运行测试套件中的所有测试：

```go
$ go test
PASS
ok github.com/EngineerKamesh/igb/igweb/tests 0.011s
```

到目前为止，我们已经编写了测试来覆盖测试服务器端 Web 应用程序的基线功能集。现在，是时候专注于测试客户端应用程序了。

# 测试客户端功能

正如[第一章](https://cdp.packtpub.com/isomorphic_go/wp-admin/post.php?post=616&action=edit#post_26)中所述，《使用 Go 构建同构 Web 应用程序》，在初始页面加载后，网站上的后续导航使用单页面应用程序架构提供。这意味着会发起 XHR 调用到 Rest API 端点，以提供渲染内容所需的数据，这些内容将显示在网页上。例如，当客户端处理程序显示产品列表页面时，会利用 Rest API 端点来获取要显示的产品列表。在某些情况下，甚至不需要 Rest API 端点，因为页面内容只需要渲染模板。一个这样的例子是当用户通过点击导航栏中的联系链接访问联系表单时。在这种情况下，我们只需渲染联系表单模板，并在主要内容区域显示内容。

让我们花点时间思考一下我们需要在客户端测试的所有基本功能。我们需要验证客户端路由是否正常运行，并且对于每个路由都会呈现正确的页面，类似于我们在上一节中验证服务器端路由的方式。除此之外，我们还需要确认客户端表单验证对联系表单是否有效，并测试有效表单提交的情况。目前，添加和移除购物车中物品的功能仅在客户端实现。这意味着我们必须编写测试来验证此功能是否按预期工作。目前仅在客户端可用的另一个功能是实时聊天功能。我们必须验证用户能否与实时聊天机器人进行通信，机器人是否回复，并且在用户导航到网站的不同部分时，对话是否保持。

最后，我们必须测试我们的齿轮集合。我们必须确保时间齿轮以人类可理解的格式显示时间实例。我们必须验证实时时钟齿轮是否正常运行。我们必须验证当点击时间敏感日期字段时，日期选择器齿轮是否出现。我们必须验证主页上是否出现了轮播齿轮。最后，我们必须验证当向购物车中添加和移除物品时，通知齿轮是否正确显示通知。

因此，在客户端，我们将测试的基线功能包括以下项目：

1.  验证客户端路由和模板呈现

1.  验证联系表单

1.  验证购物车功能

1.  验证实时聊天功能

1.  验证时间齿轮

1.  验证实时时钟齿轮

1.  验证日期选择器齿轮

1.  验证轮播齿轮

1.  验证通知齿轮

为了在客户端执行自动化测试，包括用户交互，我们需要一个内置 JavaScript 运行时的工具。因此，在测试客户端功能时，我们不能使用`go test`。

我们将使用 CasperJS 在客户端执行自动化测试。

# CasperJS

CasperJS 是一个自动化测试工具，它建立在 PhantomJS 之上，后者是用于自动化用户交互的无头浏览器。CasperJS 允许我们使用断言编写测试，并组织测试，以便它们可以按顺序一起运行。测试运行后，我们可以收到有关通过的测试数量与失败的测试数量的摘要。除此之外，CasperJS 可以利用 PhantomJS 内部的功能，在进行测试时获取网页截图。这使人类用户可以视觉评估测试运行。

为了安装 CasperJS，我们必须先安装 NodeJS 和 PhantomJS。

您可以通过从此链接下载适用于您操作系统的 NodeJS 安装程序来安装 NodeJS：[`nodejs.org/en/download/`](https://nodejs.org/en/download/)。

安装 NodeJS 后，您可以通过发出以下命令来安装 PhantomJS：

```go
$ npm install -g phantomjs
```

您可以通过发出以下命令来查看系统上安装的 PhantomJS 版本号，以验证`phantomjs`是否已正确安装：

```go
$ phantomjs --version
2.1.1
```

一旦您验证了系统上安装了 PhantomJS，您可以发出以下命令来安装 CasperJS：

```go
$ npm install -g casperjs
```

要验证`casperjs`是否已正确安装，您可以发出以下命令来查看系统上安装的 CasperJS 版本号：

```go
$ casperjs --version
1.1.4
```

我们的客户端 CasperJS 测试将存放在`client/tests`目录中。请注意`client/tests`文件夹内的子文件夹：

```go
 ⁃ tests
    ⁃ go
    ⁃ js
    ⁃ screenshots
```

我们将在 Go 中编写所有的 CasperJS 测试，并将它们放在`go`文件夹中。我们将使用`scripts`目录中的`build_casper_tests.sh` bash 脚本来将在 Go 中实现的 CasperJS 测试转换为它们相应的 JavaScript 表示。生成的 JavaScript 源文件将放在`js`文件夹中。我们将创建许多测试，这些测试将生成正在进行的测试运行的屏幕截图，并且这些屏幕截图图像将存储在`screenshots`文件夹中。

你应该运行以下命令，使`build_casper_tests.sh` bash 脚本可执行：

```go
$ chmod +x $IGWEB_APP_ROOT/scripts/build_casper_tests.sh
```

每当我们在 Go 中编写 CasperJS 测试或对其进行更改时，都必须执行`build_casper_tests.sh` bash 脚本。

```go
$ $IGWEB_APP_ROOT/scripts/build_casper_tests.sh 
```

在开始编写 CasperJS 测试之前，让我们看一下`client/tests/go/caspertest`目录中的`caspertest.go`源文件：

```go
package caspertest

import "github.com/gopherjs/gopherjs/js"

type ViewportParams struct {
  *js.Object
  Width int `js:"width"`
  Height int `js:"height"`
}
```

`ViewportParams`结构将用于定义 Web 浏览器的视口尺寸。我们将使用 1440×960 的尺寸来模拟所有客户端测试的桌面浏览体验。设置视口尺寸的影响可以通过运行生成一个或多个屏幕截图的 CasperJS 测试后立即查看到。

现在，让我们开始使用 CasperJS 编写客户端测试。

# 验证客户端路由和模板渲染

我们在 Go 中实现的用于测试客户端路由的 CasperJS 测试可以在`client/tests/go`目录中的`routes_test.go`源文件中找到。

在导入分组中，请注意我们包含了`caspertestjs`包，其中我们定义了`ViewportParams` `struct`，并且我们包含了`js`包：

```go
package main

import (
  "strings"

  "github.com/EngineerKamesh/igb/igweb/client/tests/go/caspertest"
 "github.com/gopherjs/gopherjs/js"
)
```

我们将广泛使用`js`包中的功能来利用 CasperJS 功能，因为目前尚无 GopherJS 绑定可用于 CasperJS。

我们将定义一个名为`wait`的 JavaScript 函数，它负责等待，直到远程 DOM 中的主要内容`div`容器加载完成：

```go
var wait = js.MakeFunc(func(this *js.Object, arguments []*js.Object) interface{} {
  this.Call("waitForSelector", "#primaryContent")
  return nil
})
```

我们声明并初始化`casper`变量为`casper`实例，这是一个 JavaScript 对象，在执行 CasperJS 时已经在远程 DOM 中填充：

```go
var casper = js.Global.Get("casper")
```

我们在`main`函数中实现了客户端路由测试。我们首先声明了一个`routesTokenMap`（类似于我们在服务器端路由测试中所做的），类型为`map[string]string`：

```go
func main() {

  routesTokenMap := map[string]string{"/": "IGWEB", "/index": "IGWEB",   
  "/products": "Add To Cart", "/product-detail/swiss-army-knife":   
  "Swiss Army Knife", "/about": "Molly", "/contact": "Contact",  
  "/shopping-cart": "Shopping Cart"}
```

键表示客户端路由，给定键的值表示在访问给定客户端路由时应在网页上呈现的预期字符串标记。

使用以下代码，我们设置了 Web 浏览器的视口大小：

```go
viewportParams := &caspertest.ViewportParams{Object: js.Global.Get("Object").New()}
  viewportParams.Width = 1440
  viewportParams.Height = 960
  casper.Get("options").Set("viewportSize", viewportParams)
```

请注意，PhantomJS 使用默认视口为 400×300。由于我们将模拟桌面浏览体验，因此我们必须覆盖此值。

在编写测试时，我们将使用 CasperJS 的`tester`模块。`Tester`类提供了一个 API，用于单元测试和功能测试，并且可以通过`casper`实例的`test`属性访问。`tester`模块的完整文档可在此链接找到：[`docs.casperjs.org/en/latest/modules/tester.html`](http://docs.casperjs.org/en/latest/modules/tester.html)。

我们调用`test`对象的`begin`方法来启动一系列计划测试：

```go
  casper.Get("test").Call("begin", "Client-Side Routes Test Suite", 7, func(test *js.Object) {
    casper.Call("start", "http://localhost:8080", wait)
  })
```

提供给`begin`方法的第一个参数是测试套件的描述。我们提供了一个描述为`"客户端路由测试套件"`。

第二个参数表示计划测试的数量。在这里，我们指定将进行总共七项测试，因为我们将测试七个客户端路由。如果计划测试的数量与实际执行的测试数量不匹配，那么 CasperJS 将认为这是一个*可疑*错误，因此始终要确保正确设置计划测试的数量是一个良好的做法。我们将向您展示如何在此示例中计算执行的测试数量。

第三个参数是一个包含将执行的测试套件的 JavaScript 回调函数。请注意，回调函数将`test`实例作为输入参数。在此函数内部，我们调用`casper`对象的`start`方法。这将启动 Casper 并打开方法中指定的 URL。`start`方法的第二个输入参数被认为是下一步，一个 JavaScript 回调函数，将在访问 URL 后立即运行。我们指定的下一步是我们之前创建的`wait`函数。这将导致访问 IGWEB 主页的 URL，并等待直到远程 DOM 中的主要内容`div`容器可用。

此时，我们可以开始我们的测试。我们通过`routesTokenMap`中的每个路由和`expectedString`进行`range`：

```go
  for route, expectedString := range routesTokenMap {
    func(route, expectedString string) {
```

我们调用`casper`对象的`then`方法向堆栈添加一个新的导航步骤：

```go
      casper.Call("then", func() {
        casper.Call("click", "a[href^='"+route+"']")
      })
```

在代表导航步骤的函数内部，我们调用了`casper`对象的`click`方法。`click`方法将在与提供的 CSS 选择器匹配的元素上触发鼠标点击事件。我们为每个路由创建了一个 CSS 选择器，它将匹配网页正文中的链接。CSS 选择器允许我们模拟用户点击导航链接的情景。

不属于导航链接的两个路由是`/`和`/product-detail/swiss-army-knife`路由。`/`路由的 CSS 选择器将匹配网页左上角标志的链接。当测试这种情况时，相当于用户点击网站标志。在瑞士军刀产品详情页面的链接`/product-detail/swiss-army-knife`的情况下，一旦产品页面的内容被渲染，它将在主要内容区域 div 中找到。当测试这种情况时，相当于用户点击产品列表页面上的瑞士军刀图片。

在下一个导航步骤中，我们将生成测试用例的屏幕截图，并检查网页正文中是否找到了`expectedString`：

```go
      casper.Call("then", func() {
        casper.Call("wait", 1800, func() {
          routeName := strings.Replace(route, `/`, "", -1)
          screenshotName := "route_render_test_" + routeName + ".png"
          casper.Call("capture", "screenshots/"+screenshotName)
          casper.Get("test").Call("assertTextExists", expectedString,  
          "Expected text \""+expectedString+"\", in body of web page, 
          when accessing route: "+route)
        })
      })
    }(route, expectedString)
  }
```

在这里，我们调用`casper`对象的`capture`方法来提供生成的屏幕截图图像的路径。我们将为我们测试的每个路由生成一个屏幕截图，因此我们将从此测试中生成总共七个屏幕截图图像。

请注意，我们调用 casper 的`wait`方法引入了 1800 毫秒的延迟，并提供了一个`then`回调函数。在对话式英语中，我们可以解释这个调用为“等待 1800 毫秒，然后执行此操作。”在我们提供的`then`回调函数中，我们调用了 casper 的`test`对象（`tester`模块）上的`assertTextExists`方法。在`assertTextExists`方法调用中，我们提供了应该存在于网页正文中的`expectedString`，第二个参数是描述测试的消息。我们添加了 1800 毫秒的延迟，以便页面内容有足够的时间显示在网页上。

请注意，每当调用`casper`的`tester`模块中`assert`方法系列中的任何一种`assert`方法时，都算作一个单独的测试。回想一下，当我们调用测试模块的`begin`方法时，我们提供了一个值为`7`，表示预计将在此测试套件中进行 7 个预期测试。因此，您在测试中使用的`assert`方法调用的数量必须与将进行的预期测试数量相匹配，否则在运行测试套件时将会出现可疑的错误。

我们调用`casper`对象的`run`方法来运行测试套件：

```go
  casper.Call("run", func() {
    casper.Get("test").Call("done")
  })
```

请注意，我们向 run 方法提供了一个回调函数。当所有步骤完成运行时，将调用此回调函数。在回调函数内部，我们调用 tester 模块的 done 方法来表示测试套件的结束。请记住，在 CasperJS 测试中，每当我们在 tester 模块上调用 begin 方法时，测试中必须有一个相应的地方调用 tester 模块的 done 方法。如果我们忘记留下对 done 方法的调用，程序将挂起，我们将不得不中断程序（使用 Ctrl + C 按键）。

我们必须将测试转换为其 JavaScript 等效形式，可以通过运行 build_casper_tests.sh bash 脚本来实现：

```go
$ $IGWEB_APP_ROOT/scripts/build_casper_tests.sh
```

bash 脚本将转换位于 client/tests/go 目录中的 Go 中编写的所有 CasperJS 测试，并将生成的 JavaScript 源文件放在 client/tests/js 目录中。我们将在后续的测试运行中省略此步骤。只需记住，如果对任何测试进行更改，需要重新运行此脚本，以便更改生效，下次运行测试套件时。

我们可以通过发出以下命令来运行测试以检查客户端路由：

```go
$ cd $IGWEB_APP_ROOT/client/tests
$ casperjs test js/routes_test.js
```

*图 10.1*显示了运行客户端路由测试套件的屏幕截图：

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/41dfb567-3a37-4b6c-8814-5928926b71ef.png)

图 10.1：运行客户端路由测试套件

测试生成的屏幕截图可以在 client/tests/screenshots 文件夹中找到。屏幕截图非常有用，因为它们允许人类用户直观地查看测试结果。

*图 10.2*显示了测试/路由的屏幕截图：

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/fb2e82c8-a64f-4f2b-9f2b-014b2f11dccf.jpg)

图 10.2：测试/路由

*图 10.3*显示了测试/index 路由的屏幕截图。请注意，页面渲染与*图 10.2*相同，这是应该的：

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/1eaa6278-ca2f-4f14-bb58-48db34218b0c.jpg)

图 10.3：测试/index 路由

请注意，通过提供 1800 毫秒的延迟时间，我们为轮播齿轮和实时时钟齿轮提供了足够的时间来加载。在本章后面，您将学习如何测试这些齿轮。

*图 10.4*显示了测试/products 路由的屏幕截图：

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/4bd932f1-20ee-4f35-943b-54e3a4e13f07.jpg)

图 10.4：测试/products 路由

通过此测试，我们可以直观确认产品列表页面已经成功加载。下一步测试将点击瑞士军刀的图像，以导航到其产品详细信息页面。

*图 10.5*显示了测试/product-detail/swiss-army-knife 路由的屏幕截图：

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/6cc75f81-3bfe-46f3-8191-244984eea02c.jpg)

图 10.5：测试/product-detail 路由

*图 10.6*显示了测试/about 路由的屏幕截图：

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/0ea50626-d930-4c4b-a750-adab177c1edd.jpg)

图 10.6：测试/about 路由

请注意，时间已经为所有三只地鼠正确渲染。

*图 10.7*显示了测试/contact 路由的屏幕截图：

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/24d218b2-ecb9-4a99-8aab-ad4490824fff.jpg)

图 10.7：测试/contact 路由

*图 10.8*显示了测试/shopping-cart 路由的屏幕截图。

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/7d93df9f-ec48-4fdd-bbde-00e75c0dfce5.jpg)

图 10.8：测试/shopping-cart 路由

通过屏幕截图提供的视觉确认，我们现在可以确信客户端路由正在按预期工作。除此之外，生成的屏幕截图帮助我们在视觉上确认模板渲染正常运作。现在让我们来验证联系表单功能。

# 验证联系表单

我们实施的用于验证联系表单功能的测试可以在 client/tests/go 目录中的 contactform_test.go 源文件中找到。

在此测试中，我们定义了`FormParams`结构，该结构表示在进行测试步骤时应填充联系表单的表单参数：

```go
type FormParams struct {
  *js.Object
  FirstName string `js:"firstName"`
  LastName string `js:"lastName"`
  Email string `js:"email"`
  MessageBody string `js:"messageBody"`
}
```

我们创建了一个 JavaScript 的`wait`函数，以确保测试运行程序在运行其他步骤之前等待主要内容`div`容器加载完成：

```go
var wait = js.MakeFunc(func(this *js.Object, arguments []*js.Object) interface{} {
  this.Call("waitForSelector", "#primaryContent")
  return nil
})
```

我们将引入以下三个 JavaScript 函数来填充联系表单的字段，具体取决于我们正在进行的测试类型：

+   `fillOutContactFormWithPoorlyFormattedEmailAddress`

+   `fillOutContactFormPartially`

+   `filloutContactFormCompletely`

`fillOutContactFormWithPoorlyFormattedEmailAddress`函数将向`email`字段提供一个无效的电子邮件地址，正如其名称所示：

```go
var fillOutContactFormWithPoorlyFormattedEmailAddress = js.MakeFunc(func(this *js.Object, arguments []*js.Object) interface{} {
  params := &FormParams{Object: js.Global.Get("Object").New()}
  params.FirstName = "Isomorphic"
  params.LastName = "Gopher"
  params.Email = "dev@null@test@test.com"
  params.MessageBody = "Sending a contact form submission using CasperJS and PhantomJS"
  this.Call("fill", "#contactForm", params, true)
  return nil
})
```

请注意，我们创建了一个新的`FormParams`实例，并填充了`FirstName`、`LastName`、`Email`和`MessageBody`字段。特别注意，我们为`Email`字段提供了一个无效的电子邮件地址。

在这个函数的上下文中，`this`变量代表`tester`模块。我们调用`tester`模块的`fill`方法，提供联系表单的 CSS 选择器、`params`对象，以及一个布尔值`true`来指示应该提交表单。

在填写并提交表单后，我们期望客户端表单验证向我们呈现一个错误消息，指示我们提供了一个无效的电子邮件地址。

`fillOutContactFormPartially`函数将部分填写联系表单，留下一些必填字段未填写，导致表单不完整。

```go
var fillOutContactFormPartially = js.MakeFunc(func(this *js.Object, arguments []*js.Object) interface{} {
  params := &FormParams{Object: js.Global.Get("Object").New()}
  params.FirstName = "Isomorphic"
  params.LastName = ""
  params.Email = "devnull@test.com"
  params.MessageBody = ""
  this.Call("fill", "#contactForm", params, true)
  return nil
})
```

在这里，我们创建一个新的`FormParams`实例，并注意到我们为`LastName`和`MessageBody`字段提供了空的`string`值。

在填写并提交表单后，我们期望客户端表单验证向我们呈现一个错误消息，指示我们没有填写这两个必填字段。

`fillOutContactFormCompletely`函数将填写联系表单的所有字段，并包括一个格式正确的电子邮件地址：

```go
var fillOutContactFormCompletely = js.MakeFunc(func(this *js.Object, arguments []*js.Object) interface{} {
  params := &FormParams{Object: js.Global.Get("Object").New()}
  params.FirstName = "Isomorphic"
  params.LastName = "Gopher"
  params.Email = "devnull@test.com"
  params.MessageBody = "Sending a contact form submission using CasperJS and PhantomJS"
  this.Call("fill", "#contactForm", params, true)
  return nil
})
```

在这里，我们创建一个新的`FormParams`实例，并填充了联系表单的所有字段。在`Email`字段的情况下，我们确保提供了一个格式正确的电子邮件地址。

在填写并提交表单后，我们期望客户端表单验证通过，这在后台将启动一个 XHR 调用到 REST API 端点，以验证联系表单已经通过服务器端表单验证正确填写。我们期望服务器端验证也通过，结果是一个确认消息。如果我们能成功验证已获得确认消息，我们的测试将通过。

与前面的例子一样，我们首先声明视口参数，并设置 Web 浏览器的视口大小：

```go
func main() {

  viewportParams := &caspertest.ViewportParams{Object: 
  js.Global.Get("Object").New()}
  viewportParams.Width = 1440
  viewportParams.Height = 960
  casper.Get("options").Set("viewportSize", viewportParams)
```

请注意，我们调用`tester`模块的`begin`方法来启动联系表单测试套件中的测试：

```go
  casper.Get("test").Call("begin", "Contact Form Test Suite", 4, 
  func(test *js.Object) {
    casper.Call("start", "http://localhost:8080/contact", wait)
  })
```

我们向`begin`方法提供了测试的描述，“联系表单测试套件”。然后我们提供了这个套件中预期的测试数量，即`4`。请记住，这个值对应于我们进行的测试数量。进行的测试数量可以通过我们对`tester`模块的`assert`系列方法之一进行调用的次数来确定。我们提供了`then`回调函数，在其中我们调用`casper`对象的`start`方法，提供联系页面的 URL，并提供`wait`函数以指示我们应该在进行任何测试步骤之前等待主要内容`div`容器加载。

我们测试的第一个场景是在提供格式不正确的电子邮件地址时检查客户端验证：

```go
  casper.Call("then", 
  fillOutContactFormWithPoorlyFormattedEmailAddress)
  casper.Call("wait", 450, func() {
    casper.Call("capture", 
    "screenshots/contactform_test_invalid_email_error_message.png")
    casper.Get("test").Call("assertSelectorHasText", "#emailError", 
    "The e-mail address entered has an improper syntax", "Display e-
    mail address syntax error when poorly formatted e-mail entered.")
  })
```

我们调用`casper`对象的`then`方法，提供`fillOutContactFormWithPoorlyFormattedEmailAddress` JavaScript 函数作为`then`回调函数。我们等待`450`毫秒以获取结果，捕获测试运行的截图（显示在*图 10.10*中），然后在`tester`模块上调用`assertSelectorHasText`方法，提供了包含错误消息的元素的 CSS 选择器，以及错误消息应该显示的预期文本，然后是我们正在进行的测试的描述。

我们测试的第二个场景是在提交不完整的表单时检查客户端验证：

```go
  casper.Call("then", fillOutContactFormPartially)
  casper.Call("wait", 450, func() {
    casper.Call("capture", 
    "screenshots/contactform_test_partially_filled_form_errors.png")
    casper.Get("test").Call("assertSelectorHasText", "#lastNameError", 
    "The last name field is required.", "Display error message when the 
    last name field has not been filled out.")
    casper.Get("test").Call("assertSelectorHasText",  
    "#messageBodyError", "The message area must be filled.", "Display 
    error message when the message body text area has not been filled 
    out.")
  })
```

我们调用`casper`对象的`then`方法，提供`fillOutContactFormPartially` JavaScript 函数作为`then`回调函数。我们等待`450`毫秒以获取结果，捕获测试运行的截图（显示在*图 10.11*中），并在此场景中进行了两个测试。

在第一个测试中，我们在`tester`模块上调用`assertSelectorHasText`方法，提供了包含姓氏字段错误消息的元素的 CSS 选择器，以及预期文本，错误消息应该有的，然后是测试的描述。在第二个测试中，我们在`tester`模块上调用`assertSelectorHasText`方法，提供了包含消息正文文本区域错误消息的元素的 CSS 选择器，错误消息应该有的预期文本，然后是测试的描述。

我们测试的第三个场景是检查在正确填写联系表单后是否显示了确认消息：

```go
  casper.Call("then", fillOutContactFormCompletely)
  casper.Call("wait", 450, func() {
    casper.Call("capture", 
    "screenshots/contactform_confirmation_message.png")
    casper.Get("test").Call("assertSelectorHasText", "#primaryContent 
    h1", "Confirmation", "Display confirmation message after submitting 
    contact form.")
  })
```

我们调用`casper`对象的`then`方法，提供`fillOutContactFormCompletely` JavaScript 函数作为`then`回调函数。我们等待`450`毫秒以获取结果，捕获测试运行的截图（显示在*图 10.12*中），并调用`casper`对象的`assertSelectorHasText`方法。我们提供 CSS 选择器`"#primaryContent h1"`，因为确认消息将在`<h1>`标签内。我们提供确认消息应包含的预期文本，即`"Confirmation"`。最后，我们为`assertSelectorHasText`方法的最后一个参数提供了测试的描述。

为了表示测试套件的结束，我们调用`casper`对象的`run`方法，并在`then`回调函数内调用 tester 模块的`done`方法：

```go
  casper.Call("run", func() {
    casper.Get("test").Call("done")
  })
```

假设您在`client/tests`文件夹中，您可以发出以下命令来运行联系表单测试套件：

```go
$ casperjs test js/contactform_test.js
```

*图 10.9*显示了运行联系表单测试套件的截图图像：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/23a64aa1-e615-485d-8963-23c087ae03b9.png)

图 10.9：运行联系表单测试套件

*图 10.10*显示了运行第一个测试生成的截图图像，该测试检查客户端端表单验证是否正确检测到格式不正确的电子邮件地址：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/e460f8a1-c6f5-48d1-b820-b84ae40699ef.jpg)

图 10.10：测试电子邮件验证语法

*图 10.11*显示了运行第二个和第三个测试生成的截图图像，该测试检查客户端端表单验证是否正确检测到姓氏字段和消息正文文本区域是否未填写：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/38941cab-a572-415b-9fc3-d1af80f33375.jpg)

图 10.11：验证表单验证是否检测到未填写必填字段的测试

*图 10.12*显示了运行第四个测试生成的截图图像，该测试检查成功填写并提交联系表单后是否显示了确认消息：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/6ac84bc0-7438-47bf-a309-700223b90e08.jpg)

图 10.12：验证确认消息的测试

现在我们已经验证了联系表单的客户端验证功能，让我们来研究为购物车功能实施 CasperJS 测试套件。

# 验证购物车功能

为了验证购物车功能，我们必须能够多次向购物车中添加产品，检查产品是否以正确的数量显示在购物车中，并且能够从购物车中移除产品。因此，我们需要购物车测试套件中的 3 个预期测试。

位于`client/tests/go`目录中的`shoppingcart_test.go`源文件中的`main`函数实现了购物车测试套件：

```go
func main() {

  viewportParams := &caspertest.ViewportParams{Object: 
  js.Global.Get("Object").New()}
  viewportParams.Width = 1440
  viewportParams.Height = 960
  casper.Get("options").Set("viewportSize", viewportParams)

  casper.Get("test").Call("begin", "Shopping Cart Test Suite", 3, 
  func(test *js.Object) {
    casper.Call("start", "http://localhost:8080/products", wait)
  })
```

在`main`函数内，我们设置了网页浏览器的视口大小。我们通过在`casper`对象上调用`begin`方法来启动一个新的测试套件。请注意，我们已经指示在这个测试套件中有 3 个预期测试。在`begin`方法的最后一个参数中构成的`then`回调函数内，我们调用`casper`对象的`start`方法，提供产品列表页面的 URL，并提供 JavaScript 的`wait`函数作为`then`回调函数。这将导致程序在进行任何测试之前等待，直到 DOM 中加载了主要内容`div`容器。

通过以下代码，我们向购物车中添加了三把瑞士军刀：

```go
  for i := 0; i < 3; i++ {
    casper.Call("then", func() {
      casper.Call("click", ".addToCartButton:first-child")
    })
  }
```

请注意，我们已经通过`casper`对象的`click`方法传递了 CSS 选择器`".addToCartButton:first-child"`，以确保点击瑞士军刀产品，因为它是产品列表页面上显示的第一个产品。

为了验证瑞士军刀是否正确放置在购物车中，我们需要导航到购物车页面：

```go
  casper.Call("then", func() {
    casper.Call("click", "a[href^='/shopping-cart']")
  })
```

我们的第一个测试包括验证购物车中存在正确的产品类型：

```go
  casper.Call("wait", 207, func() {
    casper.Get("test").Call("assertTextExists", "Swiss Army Knife", "Display correct product in shopping cart.")
  })
```

我们通过在`tester`模块对象上调用`assertTextExists`方法并提供预期文本值`"Swiss Army Knife"`来检查购物车页面上是否存在`"Swiss Army Knife"`文本。

我们的第二个测试包括验证购物车页面上存在正确的产品数量：

```go
  casper.Call("wait", 93, func() {
    casper.Get("test").Call("assertTextExists", "Quantity: 3", "Display 
    correct product quantity in shopping cart.")
  })
```

同样，我们调用`tester`模块对象的`assertTextExists`方法，传入预期文本`"Quantity: 3"`。

我们生成了一个购物车的截图，这个截图（显示在*图 10.14*中）应该显示瑞士军刀的数量值为`3`：

```go
  casper.Call("wait", 450, func() {
    casper.Call("capture", "screenshots/shoppingcart_test_add_item.png")
  })
```

我们的最后一个测试包括从购物车中移除一个项目。我们使用以下代码从购物车中移除产品：

```go
  casper.Call("then", func() {
    casper.Call("click", ".removeFromCartButton:first-child")
  })
```

为了验证产品是否成功从购物车中移除，我们需要检查购物车页面上是否存在指示购物车为空的消息：

```go
  casper.Call("wait", 5004, func() {
    casper.Call("capture", "screenshots/shoppingcart_test_empty.png")
    casper.Get("test").Call("assertTextExists", "Your shopping cart is   
    empty.", "Empty the shopping cart.")
  })
```

请注意，在我们对`tester`模块对象的`assertTextExists`方法进行调用时，我们检查网页上是否存在`"Your shopping cart is empty."`文本。在此之前，我们还生成了一个截图（显示在*图 10.15*中），它将显示购物车处于空状态。

最后，我们将用以下代码表示购物车测试套件的结束：

```go
  casper.Call("run", func() {
    casper.Get("test").Call("done")
  })
```

我们可以通过发出以下命令来运行购物车测试套件的 CasperJS 测试：

```go
$ casperjs test js/shoppingcart_test.js
```

*图 10.13*显示了运行购物车测试套件的结果的截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/198e3138-fef7-4a77-aaac-3d297f1761a1.png)

图 10.13：运行购物车测试套件

*图 10.14*显示了生成的截图，显示了测试用例，其中`3`把瑞士军刀已成功添加到购物车中：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/bc3bbfd2-e87e-482b-9d5b-0511eb5cffe9.jpg)

图 10.14：将产品多次添加到购物车的测试用例

*图 10.15*显示了生成的截图，显示了测试用例，其中瑞士军刀产品已被移除，因此购物车为空：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/f46a1785-f500-4a37-b10c-e58ceb670de9.jpg)

图 10.15：验证清空购物车的测试

现在我们已经验证了购物车的功能，让我们来测试一下实时聊天功能。

# 验证实时聊天功能

实时聊天测试套件包括三个测试。首先，我们必须确保单击顶部栏上的实时聊天图标时，聊天框会打开。其次，我们必须确保当我们向它提问时，聊天机器人会回应我们。第三，我们必须确保在导航到网站的另一部分时，对话会被保留。

实时聊天测试套件实现在`client/tests/go`目录中的`livechat_test.go`源文件中。

`waitChat` JavaScript 函数将用于等待聊天框打开：

```go
var waitChat = js.MakeFunc(func(this *js.Object, arguments []*js.Object) interface{} {
  this.Call("waitForSelector", "#chatbox")
  return nil
})
```

`askQuestion` JavaScript 函数将用于向聊天机器人发送问题：

```go
var askQuestion = js.MakeFunc(func(this *js.Object, arguments []*js.Object) interface{} {
  this.Call("sendKeys", "input#chatboxInputField", "What is Isomorphic 
  Go?")
  this.Call("sendKeys", "input#chatboxInputField", 
  casper.Get("page").Get("event").Get("key").Get("Enter"))
  return nil
})
```

请注意，我们使用`tester`模块对象的`sendKeys`方法（`this`变量绑定到`tester`模块对象）来输入“什么是同构 Go”问题，然后再次调用`sendKeys`方法来发送`enter`键（相当于在键盘上按下`enter`键）。

在`main`函数中，我们设置了 Web 浏览器的视口大小并开始测试套件：

```go
func main() {

  viewportParams := &caspertest.ViewportParams{Object: 
  js.Global.Get("Object").New()}
  viewportParams.Width = 1440
  viewportParams.Height = 960
  casper.Get("options").Set("viewportSize", viewportParams)

  casper.Get("test").Call("begin", "Live Chat Test Suite", 3, func(test 
  *js.Object) {
    casper.Call("start", "http://localhost:8080/index", wait)
  })
```

以下代码将通过模拟用户单击顶部栏上的实时聊天图标来激活实时聊天功能：

```go
  casper.Call("then", func() {
    casper.Call("click", "#livechatContainer img")
  })
```

以下代码将等待聊天框打开后再继续：

```go
casper.Call("then", waitChat)
```

打开聊天框后，我们可以使用以下代码验证聊天框是否可见：

```go
  casper.Call("wait", 1800, func() {
    casper.Call("capture", 
    "screenshots/livechat_test_chatbox_open.png")
    casper.Get("test").Call("assertSelectorHasText", "#chatboxTitle 
    span", "Chat with", "Display chatbox.")
  })
```

请注意，我们调用`tester`模块对象的`assertSelectorHasText`方法，提供 CSS 选择器`"#chatboxTitle span"`来定位聊天框的标题`span`元素。然后我们检查`span`元素内是否存在`"Chat with"`文本，以验证聊天框是否可见。

请注意，我们已生成了一个屏幕截图图像，应该显示聊天框已打开，并且聊天机器人提供了问候消息（*图 10.17*中显示）。

以下代码用于验证当我们向聊天机器人提问时，它是否会给出答案：

```go
  casper.Call("then", askQuestion)
  casper.Call("wait", 450, func() {
    casper.Call("capture", 
    "screenshots/livechat_test_answer_question.png")
    casper.Get("test").Call("assertSelectorHasText", 
    "#chatboxConversationContainer", "Isomorphic Go is the methodology 
    to create isomorphic web applications", "Display the answer to 
    \"What is Isomorphic Go?\"")
  })
```

我们调用`askQuestion`函数来模拟用户输入“什么是同构 Go”问题并按下`enter`键。我们等待 450 毫秒，然后生成一个屏幕截图，应该显示实时聊天机器人回答我们的问题（*图 10.18*中显示）。我们通过调用`tester`模块对象的`assertSelectorHasText`方法并向其提供 CSS 选择器来验证聊天机器人是否已经给出答案，该选择器用于访问包含对话和预期答案子字符串的`div`容器。

目前，我们在主页上。为了测试在导航到网站的不同部分时对话是否保留，我们使用以下代码：

```go
  casper.Call("then", func() {
    casper.Call("click", "a[href^='/about']")
  })

  casper.Call("then", wait)
```

在这里，我们指定导航到关于页面，然后等待直到主要内容`div`容器加载完成。

我们等待 450 毫秒，拍摄一个屏幕截图（*图 10.19*中显示），然后进行我们测试套件中的最后一个测试：

```go
  casper.Call("wait", 450, func() {
    casper.Call("capture", 
    "screenshots/livechat_test_conversation_retained.png")
    casper.Get("test").Call("assertSelectorHasText", 
    "#chatboxConversationContainer", "Isomorphic Go is the methodology 
    to create isomorphic web applications", "Verify that the 
    conversation is retained when navigating to another page in the 
    website.")
  })
```

这里的最后一个测试是前面进行的测试的重复。由于我们正在测试对话是否已保留，我们期望在上一个测试之后，聊天机器人给出的答案会保留在包含对话的`div`容器中。

我们将通过模拟用户点击关闭控件（聊天框右上角的Χ）来关闭聊天框，以便正常关闭 websocket 连接：

```go
  casper.Call("then", func() {
    casper.Call("click", "#chatboxCloseControl")
  })
```

最后，我们将使用以下代码表示实时聊天测试套件的结束：

```go
  casper.Call("run", func() {
    casper.Get("test").Call("done")
  })
```

我们可以通过发出以下命令来运行实时聊天测试套件的 CasperJS 测试：

```go
$ casperjs test js/livechat_test.js
```

*图 10.16*显示了运行实时聊天测试套件的结果的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/3a3a32ac-e59b-46df-8825-8444727993e5.png)

图 10.16：运行实时聊天测试套件

*图 10.17*显示了生成的屏幕截图，显示了测试用例，我们检查聊天框是否已打开：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/2356f933-0a29-4f85-9cb1-e16773ef5aa0.jpg)

图 10.17：验证聊天框是否出现的测试

*图 10.18*显示了生成的屏幕截图，显示了测试用例，我们在其中检查了聊天机器人是否回答了给定的问题：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/287800b7-6d60-4eb6-95b2-ead61e61aa08.jpg)

图 10.18：验证聊天机器人是否回答问题

*图 10.19*显示了生成的屏幕截图，显示了测试用例，我们在其中检查了在网站上导航到不同页面后是否保留了聊天对话：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/b035846b-882a-430c-abe3-f4f36f65c4ef.jpg)

图 10.19：测试在导航到网站的不同部分后是否保留了聊天对话

现在我们已经验证了实时聊天功能，让我们来测试差齿轮，从时间差齿轮开始。

为了简洁起见，图 10.17、10.18、10.19、10.21、10.23、10.25、10.27 和 10.29 中显示的生成的屏幕截图已被裁剪。

# 验证时间差齿轮

测试时间差齿轮包括确定地鼠加入 IGWEB 团队的已知日期。我们将确定 2017 年 5 月 24 日为 Molly 的开始日期，并将其用作在关于页面上 Molly 的生物数据下显示的人类可理解时间的测试基础。

以下是时间差齿轮的测试套件，实现在`client/tests/go`目录中的`humantimecog_test.go`源文件中：

```go
package main

import (
  "time"

  "github.com/EngineerKamesh/igb/igweb/client/tests/go/caspertest"
  humanize "github.com/dustin/go-humanize"
  "github.com/gopherjs/gopherjs/js"
)

var wait = js.MakeFunc(func(this *js.Object, arguments []*js.Object) interface{} {
  this.Call("waitForSelector", "#primaryContent")
  return nil
})

var casper = js.Global.Get("casper")

func main() {

  viewportParams := &caspertest.ViewportParams{Object: 
  js.Global.Get("Object").New()}
  viewportParams.Width = 1440
  viewportParams.Height = 960
  casper.Get("options").Set("viewportSize", viewportParams)

  casper.Get("test").Call("begin", "Time Ago Cog Test Suite", 1, 
  func(test *js.Object) {
    casper.Call("start", "http://localhost:8080/about", wait)
  })

  // Verify the human time representation of Molly's start date
  casper.Call("then", func() {
    mollysStartDate := time.Date(2017, 5, 24, 17, 9, 0, 0, time.UTC)
    mollysStartDateInHumanTime := humanize.Time(mollysStartDate)
    casper.Call("capture", "screenshots/timeago_cog_test.png")
    casper.Get("test").Call("assertSelectorHasText", "#Gopher-Molly 
    .timeagoSpan", mollysStartDateInHumanTime, "Verify human time of 
    Molly's start date produced by the Time Ago Cog.")
  })

  casper.Call("run", func() {
    casper.Get("test").Call("done")
  })

}
```

在`main`函数内，我们设置了视口大小并开始测试套件后，创建了一个名为`mollysStartDate`的新`time`实例，表示 Molly 加入 IGWEB 团队的时间。然后，我们将`mollyStartDate`传递给`go-humanize`包的`Time`函数（请注意，我们已将此包别名为`"humanize"`），并将开始日期的人类可理解值存储在`mollysStartDateHumanTime`变量中。

我们生成了测试运行的屏幕截图（显示在*图 10.21*中）。然后，我们调用`tester`模块对象的`assertSelectorHasText`方法，传入包含 Molly 开始日期的`div`容器的 CSS 选择器。我们还传入`mollysStartDateInHumanTime`变量，因为这是应该存在于选择器中的预期文本。

我们将通过在`tester`模块对象上调用`done`方法来表示时间差齿轮测试套件的结束。

我们可以通过发出以下命令来运行时间差齿轮测试套件的 CasperJS 测试：

```go
$ casperjs test js/humantimecog_test.js
```

*图 10.20*显示了运行时间差齿轮测试套件的结果的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/167feaf5-4996-4f62-b9f6-f6ad7d46c6cf.png)

图 10.20：运行时间差齿轮测试套件

*图 10.21*显示了生成的屏幕截图，显示了关于页面，其中 Molly 的开始日期以人类可读的时间格式打印出来：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/4939e782-a0bc-42a1-b2a9-0dc531f15f44.jpg)

图 10.21：验证时间差齿轮

现在我们已经验证了时间差齿轮的功能，让我们来测试实时时钟差齿轮的功能。

# 验证实时时钟差齿轮

验证用户本地时间的实时时钟差齿轮的功能包括创建一个新的`time`实例，根据本地区域名称和本地时区偏移量格式化的当前时间，并将其与主页上显示的`myLiveClock` `div`容器中的值进行比较。

以下是实时时钟差齿轮的测试套件，实现在`client/tests/go`目录中的`liveclockcog_test.go`源文件中：

```go
package main

import (
  "time"

  "github.com/EngineerKamesh/igb/igweb/client/tests/go/caspertest"
  "github.com/gopherjs/gopherjs/js"
)

var wait = js.MakeFunc(func(this *js.Object, arguments []*js.Object) interface{} {
  this.Call("waitForSelector", "#myLiveClock div")
  return nil
})

var casper = js.Global.Get("casper")

func main() {

  viewportParams := &caspertest.ViewportParams{Object: 
  js.Global.Get("Object").New()}
  viewportParams.Width = 1440
  viewportParams.Height = 960
  casper.Get("options").Set("viewportSize", viewportParams)

  casper.Get("test").Call("begin", "Live Clock Cog Test Suite", 1, 
  func(test *js.Object) {
    casper.Call("start", "http://localhost:8080/index", wait)
  })

  // Verify that the live clock shows the current time for the local 
  time zone
  casper.Call("then", func() {
    casper.Call("wait", 900, func() {

      localZonename, localOffset := time.Now().In(time.Local).Zone()
      const layout = time.RFC1123
      var location *time.Location
      location = time.FixedZone(localZonename, localOffset)
      casper.Call("wait", 10, func() {
        t := time.Now()
        currentTime := t.In(location).Format(layout)
        casper.Get("test").Call("assertSelectorHasText", "#myLiveClock 
        div", currentTime, "Display live clock for local timezone.")
      })

    })
  })

  casper.Call("then", func() {
    casper.Call("capture", "screenshots/liveclock_cog_test.png")
  })

  casper.Call("run", func() {
    casper.Get("test").Call("done")
  })

}
```

设置了 Web 浏览器的视口大小并通过访问主页启动测试套件后，我们等待`900ms`，然后收集用户的本地时区名称和本地时区偏移量。我们将根据 RFC1123 布局格式化时间。这恰好是实时时钟差齿轮用于显示时间的相同布局。

我们从`time`包中调用`FixedZone`函数，传入`localZonename`和`localOffset`来获取位置。我们创建一个新的时区实例，并使用`location`和 RFC1123`layout`对其进行格式化。我们使用`tester`模块对象的`assertSelectorHasText`方法来查看当前时间是否使用 RFC1123`layout`和用户当前`location`格式化，是否存在于指定给`assertSelectorHasText`方法的选择器中。

我们生成测试运行的截图（显示在*图 10.23*中），然后在`tester`模块对象上调用`done`方法，表示测试套件的结束。

我们可以通过发出以下命令来运行实时时钟齿轮测试套件的 CasperJS 测试：

```go
$ casperjs test js/liveclockcog_test.js
```

*图 10.22*显示了运行实时时钟齿轮测试套件的结果的截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/2e537569-a9fc-488b-a40b-35643edd978c.png)

图 10.22：运行实时时钟齿轮测试套件

*图 10.23*显示了在主页上显示实时时钟齿轮的生成截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/85e8e540-f8e5-4f98-acf1-ca380e3bb0ba.jpg)

图 10.23：在主页上测试实时时钟齿轮

现在我们已经验证了实时时钟齿轮的功能，让我们来测试日期选择器齿轮的功能。

# 验证日期选择器齿轮

验证日期选择器齿轮的功能包括导航到联系人页面，并单击时间敏感日期输入字段。这应该触发日历小部件的显示。

这是日期选择器齿轮的测试套件，它是在`datepickercog_test.go`源文件中实现的，位于`client/tests/go`目录中：

```go
package main

import (
  "github.com/EngineerKamesh/igb/igweb/client/tests/go/caspertest"
  "github.com/gopherjs/gopherjs/js"
)

var wait = js.MakeFunc(func(this *js.Object, arguments []*js.Object) interface{} {
  this.Call("waitForSelector", "#primaryContent")
  return nil
})

var casper = js.Global.Get("casper")

func main() {

  viewportParams := &caspertest.ViewportParams{Object: 
  js.Global.Get("Object").New()}
  viewportParams.Width = 1440
  viewportParams.Height = 960
  casper.Get("options").Set("viewportSize", viewportParams)

  casper.Get("test").Call("begin", "Date Picker Cog Test Suite", 1, 
  func(test *js.Object) {
    casper.Call("start", "http://localhost:8080/contact", wait)
  })

  // Verify that the date picker is activated upon clicking the date 
  input field
  casper.Call("then", func() {
    casper.Call("click", "#byDateInput")
    casper.Call("capture", "screenshots/datepicker_cog_test.png")
    casper.Get("test").Call("assertVisible", ".pika-single", "Display 
    Datepicker Cog.")
  })

  casper.Call("run", func() {
    casper.Get("test").Call("done")
  })
}
```

在`main`函数中，我们设置了 Web 浏览器的视口大小，并通过导航到联系人页面来启动测试套件。

然后，我们调用`casper`对象的`click`方法，并提供 CSS 选择器`"#byDateInput"`，这将向时间敏感日期输入字段发送鼠标单击事件，这应该会显示日历小部件。

我们对测试运行进行截图（显示在*图 10.25*中），然后调用`tester`模块对象的`assertVisible`方法，将`".pika-single"`选择器和测试名称作为输入参数传递给该方法。`assertVisible`方法将断言至少有一个与提供的选择器表达式匹配的元素是可见的。

最后，我们在`tester`模块对象上调用`done`方法，表示测试套件的结束。

我们可以通过发出以下命令来运行日期选择器齿轮测试套件的 CasperJS 测试：

```go
$ casperjs test js/datepickercog_test.js
```

*图 10.24*显示了运行日期选择器齿轮测试套件的结果的截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/b21e8409-5679-499d-b43f-2c07f6351391.png)

图 10.24：运行日期选择器齿轮测试套件

*图 10.25*显示了单击时间敏感日期输入字段后显示日历小部件的生成截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/e736752f-9000-4c4a-8520-62d18ef8be0a.jpg)

图 10.25：验证日期选择器是否出现

现在我们已经验证了日期选择器齿轮的功能，让我们来测试旋转齿轮的功能。

# 验证旋转齿轮

验证旋转齿轮的功能包括提供足够的时间来加载旋转齿轮的图像，并且第一张图像，即`watch.jpg`图像文件出现在网页上。

这是旋转齿轮的测试套件，它是在`carouselcog_test.go`源文件中实现的，位于`client/tests/go`目录中：

```go
package main

import (
  "github.com/EngineerKamesh/igb/igweb/client/tests/go/caspertest"
  "github.com/gopherjs/gopherjs/js"
)

var wait = js.MakeFunc(func(this *js.Object, arguments []*js.Object) interface{} {
  this.Call("waitForSelector", "#carousel")
  return nil
})

var casper = js.Global.Get("casper")

func main() {

  viewportParams := &caspertest.ViewportParams{Object: 
  js.Global.Get("Object").New()}
  viewportParams.Width = 1440
  viewportParams.Height = 960
  casper.Get("options").Set("viewportSize", viewportParams)

  casper.Get("test").Call("begin", "Carousel Cog Test Suite", 1, 
  func(test *js.Object) {
    casper.Call("start", "http://localhost:8080/index", wait)
  })

  // Verify that the carousel cog has been loaded.
  casper.Call("wait", 1800, func() {
    casper.Get("test").Call("assertResourceExists", "watch.jpg", 
    "Display carousel cog.")
  })

  casper.Call("then", func() {
    casper.Call("capture", "screenshots/carousel_cog_test.png")
  })

  casper.Call("run", func() {
    casper.Get("test").Call("done")
  })

}
```

设置 Web 浏览器的视口大小并启动测试套件后，通过导航到主页，我们等待`1800`毫秒，然后在`tester`模块对象上调用`assetResourceExists`方法，提供要检查的资源的名称，这恰好是`"watch.jpg"`图像文件，以及测试的描述。`assertResourceExists`函数检查`"watch.jpg"`图像文件是否存在于加载在网页上的资源集中。

我们拍摄了测试运行的屏幕截图（如图 10.27 所示），然后在`casper`对象上调用`done`方法，表示测试套件的结束。

我们可以通过发出以下命令来运行旋转木马齿轮测试套件的 CasperJS 测试：

```go
$ casperjs test js/carouselcog_test.js
```

图 10.26 显示了运行旋转木马齿轮测试套件的结果的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/17e19dbb-85e2-46db-b799-0f4e08e90ac5.png)

图 10.26：运行旋转木马齿轮测试套件

图 10.27 显示了生成的屏幕截图，显示了旋转木马齿轮：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/682d8e25-dc8f-45b3-a254-22e383f29bff.jpg)

图 10.27：验证旋转木马齿轮是否出现的测试

现在我们已经验证了旋转木马齿轮的功能，让我们来测试通知齿轮的功能。

# 验证通知齿轮

验证通知齿轮的功能包括导航到产品列表页面，通过单击列出产品的“添加到购物车”按钮将商品添加到购物车，然后验证通知是否出现在网页上。

这是通知齿轮的测试套件，它是在`client/test/go`目录中的`notifycog_test.go`源文件中实现的：

```go
package main

import (
  "github.com/EngineerKamesh/igb/igweb/client/tests/go/caspertest"
  "github.com/gopherjs/gopherjs/js"
)

var wait = js.MakeFunc(func(this *js.Object, arguments []*js.Object) interface{} {
  this.Call("waitForSelector", "#primaryContent")
  return nil
})

var casper = js.Global.Get("casper")

func main() {

  viewportParams := &caspertest.ViewportParams{Object: 
  js.Global.Get("Object").New()}
  viewportParams.Width = 1440
  viewportParams.Height = 960
  casper.Get("options").Set("viewportSize", viewportParams)

  casper.Get("test").Call("begin", "Notify Cog Test Suite", 1, 
  func(test *js.Object) {
    casper.Call("start", "http://localhost:8080/products", wait)
  })

  // Add an item to the shopping cart
  casper.Call("then", func() {
    casper.Call("click", ".addToCartButton:nth-child(1)")
  })

  // Verify that the notification has been displayed
  casper.Call("wait", 450, func() {
    casper.Get("test").Call("assertSelectorHasText", "#alertify-logs 
    .alertify-log-success", "Item added to cart", "Display Notify Cog 
    when item added to shopping cart.")
  })

  casper.Call("wait", 450, func() {
    casper.Call("capture", "screenshots/notify_cog_test.png")
  })

  // Navigate to Shopping Cart page
  casper.Call("then", func() {
    casper.Call("click", "a[href^='/shopping-cart']")

  })

  // Remove product from shopping cart
  casper.Call("wait", 450, func() {
    casper.Call("click", ".removeFromCartButton:first-child")
  })

  casper.Call("run", func() {
    casper.Get("test").Call("done")
  })
}
```

设置了网页浏览器的视口并通过导航到产品列表页面开始测试套件后，我们调用`casper`对象的`click`方法，提供`".addToCartButton:nth-child(1)"`选择器。这会向网页上的第一个“添加到购物车”按钮发送鼠标单击事件。

我们等待`450`毫秒，然后调用`tester`模块的`assertSelectorHasText`方法，提供 CSS 选择器、应该存在于从选择器返回的元素中的文本，以及测试描述作为输入参数。

我们拍摄了测试运行的屏幕截图（如图 10.29 所示）。然后我们导航到购物车页面，并从购物车中移除该商品。

最后，我们在`tester`模块对象上调用`done`方法，表示测试套件的结束。

我们可以通过发出以下命令来运行通知齿轮测试套件的 CasperJS 测试：

```go
$ casperjs test js/notifycog_test.js
```

图 10.28 显示了运行通知齿轮测试套件的结果的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/7b92c81a-fd43-4a2a-ae48-6dcd8626da95.png)

图 10.28：运行通知齿轮测试套件

图 10.29 显示了生成的屏幕截图，显示了通知消息如预期般显示在网页右下角：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/19ffe05f-950c-4448-9608-7f34d1addbb4.jpg)

图 10.29：运行测试以验证是否显示了通知消息

我们现在已经验证了通知齿轮的功能是否符合预期，这结束了我们对 IGWEB 客户端功能的测试。

图 10.30 显示了运行整个测试套件的屏幕截图，方法是运行以下命令：

```go
$ casperjs test js/*.js
```

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/2b9a606e-627b-4472-b0a2-af934ca2ff35.png)

图 10.30：运行整个 CasperJS 测试套件

# 摘要

在本章中，您学习了如何执行端到端测试，以验证同构 Go Web 应用程序的功能。为了确保 IGWEB 的质量，在网站上线之前，我们首先收集了要测试的基线功能集。

为了验证服务器端功能，我们使用 Go 的标准库中的`testing`包实现了测试。我们实现了验证服务器端路由/模板渲染、联系表单的验证功能以及成功的联系表单提交场景的测试。

为了验证客户端功能，我们使用 CasperJS 实施了测试，验证了多个用户交互场景。我们能够使用 CasperJS 执行自动化用户交互测试，因为它建立在 PhantomJS 之上，后者是一个配备 JavaScript 运行时的无头浏览器。我们实施了 CasperJS 测试来验证客户端路由/模板渲染、联系表单的客户端验证功能、客户端成功提交联系表单的场景、购物车功能以及实时聊天功能。我们还实施了 CasperJS 测试，验证了我们在第九章“齿轮-可重用组件”中实施的齿轮集合的功能。

在第十一章“部署同构 Go Web 应用”中，您将学习如何将 IGWEB 部署到云端。我们将首先探讨将网站发布到独立服务器的过程。之后，您将学习如何利用 Docker 将网站发布为多容器 Docker 应用程序。


# 第十一章：部署同构 Go Web 应用程序

通过我们在上一章中实施的自动化端到端测试，IGWEB 演示网站现在满足了一组预期功能的基线。现在是时候将我们的同构 Go Web 应用程序释放到网络中了。是时候专注于将 IGWEB 部署到生产环境了。

我们对同构 Go 生产部署的探索将包括将 IGWEB 作为静态二进制可执行文件以及静态资产部署到独立服务器（真实或虚拟）上，以及将 IGWEB 作为多 Docker 容器应用程序部署。

部署 Web 应用程序是一个广阔的主题，一个值得专门讨论的海洋，有许多专门讨论这个主题的书籍。现实世界的 Web 应用程序部署可能包括持续集成、配置管理、自动化测试、部署自动化工具和敏捷团队管理。这些部署可能还包括多个团队成员，在部署过程中扮演各种角色。

本章的重点将仅仅是通过单个个体部署同构 Go Web 应用程序。为了说明，部署过程将手动执行。

需要考虑一些特定的因素，以成功地准备一个用于生产的同构 Go web 应用程序，例如，对由 GopherJS 生成的 JavaScript 源文件进行缩小，并确保静态资产以启用 GZIP 压缩的方式传输到 Web 客户端。通过将本章中呈现的材料重点放在同构 Go 上，读者可以根据自己特定的部署需求来调整本章中呈现的概念和技术。

在本章中，我们将涵盖以下主题：

+   IGWEB 在生产模式下的运行方式

+   将同构 Go Web 应用程序部署到独立服务器。

+   使用 Docker 部署同构 Go Web 应用程序

# IGWEB 在生产模式下的运行方式

在进行生产部署之前，我们需要了解当将服务器端 Web 应用程序`igweb`放入生产模式时，它是如何运行的。可以通过在启动`igweb`服务器端应用程序之前设置`IGWEB_MODE`环境变量的值为`"production"`来打开生产模式。

```go
$ export IGWEB_MODE=production
```

IGWEB 在生产模式下运行时将发生三种重要的行为：

1.  在头部部分模板中包含客户端应用程序的 JavaScript 外部`<script>`标签将请求位于`$IGWEB_APP_ROOT/static/js/client.min.js`的缩小 JavaScript 源文件。

1.  当 Web 服务器实例启动时，cogs（`cogimport.css`和`cogimport.js`）的静态资产将不会自动生成。相反，包含捆绑静态资产的缩小源文件将分别位于`$IGWEB_APP_ROOT/static/css/cogimports.min.css`和`$IGWEB_APP_ROOT/static/js/cogimports.min.js`。

1.  与依赖于`$IGWEB_APP_ROOT/shared/templates`文件夹中的模板不同，模板将从单个、gob 编码的模板捆绑文件中读取，该文件将持久保存在磁盘上。

我们将考虑服务器端 Web 应用程序如何响应这些行为。

# 由 GopherJS 生成的 JavaScript 源文件

在`funcs.go`源文件中定义我们的模板函数的地方，我们引入了一个名为`IsProduction`的新函数：

```go
func IsProduction() bool {
  if isokit.OperatingEnvironment() == isokit.ServerEnvironment {
    return os.Getenv("IGWEB_MODE") == "production"
  } else {
    return false
  }
}
```

这个函数是用于在服务器端使用的，如果当前操作模式是生产模式，则返回`true`，否则返回`false`。我们可以在模板中使用这个自定义函数来确定客户端 JavaScript 应用程序应该从哪里获取。

在非生产模式下运行时，`client.js`源文件将从服务器相对路径`/js/client.js`获取。在生产模式下，缩小的 JavaScript 源文件将从服务器相对路径`/static/js/client.min.js`获取。

在头部部分模板中，我们调用`productionmode`自定义函数来确定从哪个路径提供客户端 JavaScript 源文件，如下所示：

```go
<head>
  <meta name="viewport" content="initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>{{.PageTitle}}</title> 
  <link rel="icon" type="image/png" href="/static/images/isomorphic_go_icon.png">
  <link rel="stylesheet" href="/static/css/pure.min.css">
 {{if productionmode}}
  <link rel="stylesheet" type="text/css" href="/static/css/cogimports.min.css">
  <link rel="stylesheet" type="text/css" href="/static/css/igweb.min.css">
  <script type="text/javascript" src="img/client.min.js" async></script>
  <script src="img/cogimports.min.js" type="text/javascript" async></script>
 {{else}}
  <link rel="stylesheet" type="text/css" href="/static/css/cogimports.css">
  <link rel="stylesheet" type="text/css" href="/static/css/igweb.css">
  <script src="img/cogimports.js" type="text/javascript" async></script>
  <script type="text/javascript" src="img/client.js" async></script>
  {{end}}
</head>
```

你可能会想为什么在非生产模式和生产模式之间包含不同的 JavaScript 源文件（`client.js`与`client.min.js`）。回想一下，在运行`kick`的开发环境中，`client.js`和`client.js.map`源文件会在`$IGWEB_APP_ROOT/client`文件夹中生成。在`igweb.go`中，我们注册了路由处理函数，将`/js/client.js`路径和`/js/client.js.map`路径映射到`$IGWEB_APP_ROOT/client`文件夹中的相应源文件：

```go
  // Register Handlers for Client-Side JavaScript Application
  if WebAppMode != "production" {
    r.Handle("/js/client.js", isokit.GopherjsScriptHandler(WebAppRoot)).Methods("GET")
    r.Handle("/js/client.js.map", isokit.GopherjsScriptMapHandler(WebAppRoot)).Methods("GET")
  }
```

这为我们提供了便利，我们可以让`kick`在我们对应用程序代码进行更改时自动转换 JavaScript 代码。在非生产模式下，我们更喜欢不缩小 JavaScript 源文件，以便通过 Web 控制台获得更详细的调试信息，例如恐慌堆栈跟踪（在附录中介绍，*调试同构 Go*）。

在生产模式下，无需使用`kick`。如果你检查`client.js`源文件的文件大小，你会注意到它大约有 8.1MB！这确实是一个严重的震惊！在下一节中，我们将学习如何将这个笨重的文件大小缩小。

# 驯服 GopherJS 生成的 JavaScript 文件大小

在生产部署过程中，我们必须发出`gopherjs build`命令，指定选项来缩小生成的 JavaScript 源文件，并将 JavaScript 源文件的输出保存到指定的目标位置。

我们必须缩小生成的 JavaScript 代码以减小文件大小。如前所述，未缩小的 JavaScript 源文件为 8.1MB！通过缩小它，使用`gopherjs build`命令运行`-m`选项，并指定`--tags`选项值为`clientonly`，我们可以将源文件的大小进一步减小到 2.9MB，如下所示：

```go
$ gopherjs build -m --verbose --tags clientonly -o $IGWEB_APP_ROOT/static/js/client.min.js
```

`clientonly`标签告诉 isokit 避免转换客户端应用程序未使用的源文件。`-o`选项将把生成的输出 JavaScript 源文件放在指定的目标位置。

在运行`gopherjs build`命令之前，执行`$IGWEB_APP_ROOT/scripts`目录中找到的`clear_gopherjs_cache.sh` bash 脚本总是一个好主意。它将清除从先前的`gopherjs build`运行中缓存的项目构件。

提供一个将近 3MB 大的 JavaScript 源文件仍然是一个不可行的方案。通过启用 GZIP 压缩，我们可以进一步减小传输文件的大小。一旦使用 GZIP 压缩发送源文件，传输文件大小将约为 510KB。我们将在*启用 GZIP 压缩*部分学习如何在 Web 服务器上启用 GZIP 压缩。

# 生成静态资产

在部署服务器端 Go Web 应用程序时，通常不仅会推送 Web 服务器实例的二进制可执行文件，还会推送静态资产文件（CSS、JavaScript、模板文件、图像、字体等）和模板文件。在传统的 Go Web 应用程序中，我们必须将单独的模板文件推送到生产系统，因为传统的 Go Web 应用程序依赖于每个单独的文件可用以在服务器端呈现给定的模板。

由于我们利用了在运行应用程序中通过内存持久化的模板集的概念，因此无需将单独的模板文件带到生产环境中。这是因为我们生成内存模板集所需的一切只是一个`gob`编码的模板捆绑文件，它被持久化在`$IGWEB_APP_ROOT/static/templates`文件夹中。

通过在`isokit`包中设置导出的`StaticTemplateBundleFilePath`变量，我们指示 isokit 在我们提供的文件路径生成静态模板捆绑文件。以下是在`igweb.go`源文件中的`initializeTemplateSet`函数中设置变量的行：

```go
 isokit.StaticTemplateBundleFilePath = StaticAssetsPath + "/templates/igweb.tmplbundle"
```

在第九章中，*Cogs-可重用组件*，我们了解到当首次启动`igweb`应用程序时，isokit 将所有 cogs 的 JavaScript 源文件捆绑到单个`cogimports.js`源文件中。类似地，所有 cogs 的 CSS 样式表都捆绑到单个`cogimports.css`源文件中。在非生产模式下运行 IGWEB 时，通过在`igweb.go`源文件中的`initailizeCogs`函数中调用`isokit.BundleStaticAssets`函数（以粗体显示）自动捆绑静态资产：

```go
func initializeCogs(ts *isokit.TemplateSet) {
  timeago.NewTimeAgo().CogInit(ts)
  liveclock.NewLiveClock().CogInit(ts)
  datepicker.NewDatePicker().CogInit(ts)
  carousel.NewCarousel().CogInit(ts)
  notify.NewNotify().CogInit(ts)
  isokit.BundleStaticAssets()
}
```

不应在生产环境中使用自动静态资产捆绑，因为捆绑 JavaScript 和 CSS 的动态功能取决于服务器上安装了配置了 Go 工作区的 Go 发行版，并且该 Go 工作区中必须存在 cogs 的源文件。

这立即消除了 Go 默认的优势之一。由于 Go 生成静态链接的二进制可执行文件，我们不需要在生产服务器上安装 Go 运行时即可部署我们的应用程序。

当我们以生产模式运行 IGWEB 时，可以通过在`igweb.go`源文件中的`initializeTemplateSet`函数中引入以下代码来阻止自动静态资产捆绑：

```go
  if WebAppMode == "production" && oneTimeStaticAssetsGeneration == false {
    isokit.UseStaticTemplateBundleFile = true
    isokit.ShouldBundleStaticAssets = false
  }
```

我们指示 isokit 使用静态模板捆绑文件，并指示 isokit 不自动捆绑静态资产。

为了生成我们的同构 Go Web 应用程序所需的静态资产（CSS、JavaScript 和模板捆绑），我们可以在非生产系统上使用`igweb`运行`--generate-static-assets`标志：

```go
$ igweb --generate-static-assets
```

此命令将生成必要的静态资产，然后退出`igweb`程序。此功能的实现可以在`igweb.go`源文件中定义的`generateStaticAssetsAndExit`函数中找到：

```go
func generateStaticAssetsAndExit(env *common.Env) {
  fmt.Print("Generating static assets...")
  isokit.ShouldMinifyStaticAssets = true
  isokit.ShouldBundleStaticAssets = true
  initializeTemplateSet(env, true)
  initializeCogs(env.TemplateSet)
  fmt.Println("Done")
  os.Exit(0)
}
```

在指示`igweb`生成静态资产后，将创建三个文件：

+   `$IGWEB_APP_ROOT/static/templates/igweb.tmplbundle`（模板捆绑）

+   `$IGWEB_APP_ROOT/static/css/cogimports.min.css`（压缩的 CSS 捆绑包）

+   `$IGWEB_APP_ROOT/static/js/cogimports.min.js`（压缩的 JavaScript 捆绑包）

在执行生产部署时，可以将整个`$IGWEB_APP_ROOT/static`文件夹复制到生产系统，确保三个前述的静态资产将在生产系统上提供。

此时，我们已经建立了 IGWEB 在生产模式下的操作方式。现在，是时候执行最简单的部署了-将同构 Go Web 应用程序部署到独立服务器。

# 将同构 Go Web 应用程序部署到独立服务器

为了演示独立的同构 Go 部署，我们将使用 Linode（[`www.linode.com`](http://www.linode.com)）托管的虚拟专用服务器（VPS）。此处提出的程序适用于任何其他云提供商，以及独立服务器恰好是位于服务器室中的真实服务器的情况。我们将概述的独立部署过程是手动执行的，以说明每个步骤。

# 为服务器提供服务

在本演示中的服务器，以及本章后续演示中提到的服务器将在 Linode 上运行 Ubuntu Linux 16.04 LTS 版本，Linode 是**虚拟专用服务器（VPS）**实例的提供商。我们将运行 Linode 的默认 Ubuntu 16.04 存储映像，而不进行任何内核修改。

当我们在本章中发出任何以`sudo`为前缀的命令时，我们假设您的用户帐户是 sudoers 组的一部分。如果您使用服务器的 root 帐户，则无需在命令前加上`sudo`。

我们将通过发出以下命令创建一个名为`igweb`的权限较低的用户：

```go
$ sudo adduser igweb
```

运行`adduser`命令后，您将被提示为`igweb`用户和密码输入附加信息。如果您没有提示输入用户密码，您可以通过发出以下命令来设置密码：

```go
$ sudo passwd igweb
```

`igweb`应用程序依赖于两个组件才能正常运行。首先，我们需要安装 Redis 数据库。其次，我们需要安装`nginx`。我们将使用`nginx`作为反向代理服务器，这将允许我们在为 Web 客户端提供静态资产时启用 GZIP 压缩。正如您将看到的，这在 GopherJS 生成的 JavaScript 源文件的文件大小方面有很大的区别（510 KB 与 3MB）。*图 11.1*描述了 Linode VPS 实例与三个关键组件`igweb`、`nginx`和`redis-server`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/61f49e5a-74f7-42a8-939a-3006cb47bb45.png)

图 11.1：运行 igweb、nginx 和 redis-server 的 Linode VPS 实例

# 设置 Redis 数据库实例

您可以按照第二章中演示的相同过程来安装 Redis 数据库。在这之前，您应该发出以下命令来安装必要的构建工具：

```go
$ sudo apt-get install build-essential tcl
```

安装了 Redis 数据库后，您应该通过发出以下命令来启动 Redis 服务器：

```go
$ sudo redis-server --daemonize yes
```

`--daemonize`命令行参数允许我们在后台运行 Redis 服务器。即使我们的会话结束后，服务器也将继续运行。

您应该通过添加足够的防火墙规则来保护 Redis 安装，以防止外部流量访问端口 6379，Redis 服务器实例的默认端口。

# 设置 NGINX 反向代理

虽然`igweb` Web 服务器实例，一个 Go 应用程序，可以独自满足服务 IGWEB 的主要需求，但将`igweb` Web 服务器实例置于反向代理之后更有利。

反向代理服务器是一种代理服务器类型，它将通过将请求分派到指定的目标服务器（在本例中为`igweb`）来为客户端请求提供服务，从`igweb`服务器实例获取响应，并将响应发送回客户端。

反向代理有几个方面的便利。释放 IGWEB 的即时好处最重要的原因是我们可以在出站静态资产上启用 GZIP 压缩。除此之外，反向代理还允许我们在需要时轻松添加重定向规则来控制流量。

NGINX 是一种流行的高性能 Web 服务器。我们将使用`nginx`作为`igweb` Web 服务器实例前面的反向代理。*图 11.2*描述了一个典型的反向代理配置，其中 Web 客户端将通过端口 80 发出 HTTP 请求，`nginx`将通过端口 8080 将 HTTP 请求发送到`igweb`服务器实例，从`igweb`服务器检索响应，并通过端口 80 将响应发送回 Web 客户端：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/4fdfd999-0d8b-41d8-b393-5815a7bda632.png)

图 11.2：反向代理配置

以下是我们将用于运行`nginx`作为反向代理的`nginx.conf`配置文件清单：

```go
user igweb;
worker_processes 1;

error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    sendfile on;
    keepalive_timeout 65;

 gzip on;
 gzip_min_length 1100;
 gzip_buffers 16 8k;
 gzip_types text/plain application/javascript text/css;
 gzip_vary on;
 gzip_comp_level 9;

    server_tokens off;

    server {
        listen 80;
        access_log /var/log/nginx/access.log main;
        location / {
 proxy_pass http://192.168.1.207:8080/;
 proxy_set_header X-Forwarded-For $remote_addr;
 proxy_http_version 1.1;
 proxy_set_header Upgrade $http_upgrade;
 proxy_set_header Connection "upgrade";
 proxy_set_header Host $host;
        }
    }
}
```

我们对我们感兴趣的两个设置部分，即启用 GZIP 压缩的部分和代理设置的部分。

# 启用 GZIP 压缩

让我们检查与启用 GZIP 压缩相关的`nginx`配置设置。

我们将`gzip`指令设置为`on`以启用服务器响应的压缩。

`gzip_min_length`指令允许我们指定将进行 gzip 压缩的响应的最小长度。

`gzip_buffers`指令设置用于压缩响应的缓冲区的数量和大小。我们指定将使用 16 个缓冲区，内存页大小为 8K。

`gzip_types`指令允许我们指定应在其上启用 GZIP 压缩的 MIME 类型，除了*text/HTML*之外。我们已指定纯文本文件、JavaScript 源文件和 CSS 源文件的 MIME 类型。

`gzip_vary`指令用于启用或禁用*Vary: Accept-Encoding*响应头。*Vary: Accept-Encoding*响应头指示缓存存储网页的不同版本，如果头部有变化，则特别重要。对于不支持 GZIP 编码的 Web 浏览器，这个设置特别重要，以便正确接收文件的未压缩版本。

`gzip_comp_level`指令指定将使用的 GZIP 压缩级别。我们指定了一个值为 9 的最大 GZIP 压缩级别。

# 代理设置

`nginx`配置设置中的第二部分是反向代理设置。

我们在`location`块内包括`proxy_pass`指令，值为 web 服务器的地址和端口。这指定所有请求应发送到指定的代理服务器（`igweb`），位于`http://192.168.1.207:8080`。

请记住，将此示例中显示的 IP 地址 192.168.1.207 替换为运行您的`igweb`实例的机器的 IP 地址。

反向代理将从`igweb`服务器实例获取响应并将其发送回 Web 客户端。

`proxy_set_header`指令允许我们重新定义（或追加）传递给代理服务器的请求头字段。我们已经包括了*X-Forwaded-For*头，以便代理服务器可以识别发起请求的 Web 客户端的原始 IP 地址。

为了支持 websockets 的正常运行（这是实时聊天功能所依赖的），我们包括以下代理设置。首先，我们指定使用`proxy_http_version`指令，服务器将使用 HTTP 版本 1.1。默认情况下，`"Upgrade"`和`"Connection"`头不会传递给代理服务器。因此，我们必须使用`proxy_set_header`指令将这些头发送到代理服务器。

我们可以通过以下命令安装`nginx`：

```go
$ sudo apt-get install nginx
```

安装`nginx`后，Web 服务器通常会默认启动。但是如果没有启动，我们可以通过以下命令启动`nginx`：

```go
$ sudo systemctl start nginx
```

`$IGWEB_APP_ROOT/deployments-config/standalone-setup`文件夹中找到的`nginx.conf`文件可以放置在生产服务器的`/etc/nginx`文件夹中。

*图 11.3*描述了当我们尝试访问`igweb.kamesh.com` URL 时遇到的 502 Bad Gateway 错误：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/90fe7f2d-4a43-4cd6-afa4-5160595d45f9.png)

图 11.3：502 Bad Gateway 错误

我们遇到了这个服务器错误，因为我们还没有启动`igweb`。要让`igweb`运行起来，我们首先需要在服务器上设置一个位置，用于存放`igweb`二进制可执行文件和静态资产。

# 设置 IGWEB 根文件夹

IGWEB 根文件夹是生产服务器上`igweb`可执行文件和静态资产所驻留的地方。我们使用以下命令在生产服务器上成为`igweb`用户：

```go
$ su - igweb
```

我们在`igweb`用户的主目录中创建一个`igweb`文件夹，如下所示：

```go
mkdir ~/igweb
```

这是包含`igweb` Web 服务器实例的二进制可执行文件和 IGWEB 演示网站所需的静态资产的目录。请注意，静态资产将驻留在`~/igweb/static`文件夹中。

# 交叉编译 IGWEB

使用 `go build` 命令，我们实际上可以为不同的目标操作系统构建二进制文件，这种技术称为**交叉编译**。例如，在我的 macOS 机器上，我可以构建一个 64 位 Linux 二进制文件，然后将其推送到运行 Ubuntu Linux 的独立生产服务器上。在构建我们的二进制文件之前，我们通过设置 `GOOS` 环境变量来指定我们要构建的目标操作系统：

```go
$ export GOOS=linux
```

通过将 `GOOS` 环境变量设置为 `linux`，我们已经指定我们希望为 Linux 生成一个二进制文件。

为了指定我们希望二进制文件是 64 位二进制文件，我们设置 `GOARCH` 环境变量来指定目标架构：

```go
$ export GOARCH=amd64
```

通过将 `GOARCH` 变量设置为 `amd64`，我们已经指定我们需要一个 64 位二进制文件。

通过发出 `mkdir` 命令，在 `igweb` 文件夹内创建一个 `builds` 目录：

```go
$ mkdir $IGWEB/builds
```

这个目录将作为包含各种操作系统的 `igweb` 二进制可执行文件的仓库。在本章中，我们只考虑构建 64 位 Linux 二进制文件，但在将来，我们可以在此目录中适应其他操作系统的构建，比如 Windows。

我们发出 `go build` 命令，并提供 `-o` 参数来指定生成的二进制文件应该位于哪里：

```go
$ go build -o $IGWEB_APP_ROOT/builds/igweb-linux64
```

我们已经指示生成的 64 位 Linux 二进制文件应该创建在 `$IGWEB_APP_ROOT/builds` 文件夹中，并且可执行文件的名称将是 `igweb-linux64`。

您可以通过发出 `file` 命令来验证生成的二进制文件是否为 Linux 二进制文件：

```go
$ file builds/igweb-linux64
builds/igweb-linux64: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped
```

从结果中，我们可以看到 `go build` 命令生成了一个 `64 位 LSB`（Linux 标准基础）可执行文件。

如果您有兴趣为 Linux 以外的其他操作系统构建 Go 二进制文件，此链接将为您提供所有可能的 `GOOS` 和 `GOARCH` 值的完整列表：[`golang.org/doc/install/source#environment`](https://golang.org/doc/install/source#environment)。

# 准备部署包

除了发布 `igweb` 可执行文件，我们还需要发布存放所有 IGWEB 静态资产的静态文件夹的内容。

准备部署包的静态资产包括以下步骤：

1.  转换客户端应用程序

1.  生成静态资产包（模板包、CSS 和 JavaScript）

1.  缩小 IGWEB 的 CSS 样式表

首先，我们转换客户端应用程序：

```go
$ cd $IGWEB_APP_ROOT/client
$ $IGWEB_APP_ROOT/scripts/clear_gopherjs_cache.sh
$ gopherjs build --verbose -m --tags clientonly -o  $IGWEB_APP_ROOT/static/js/client.min.js
```

其次，我们需要生成静态资产包：

```go
$ $IGWEB_APP_ROOT/igweb --generate-static-assets
Generating static assets...Done
```

准备部署包的第三个也是最后一个步骤是压缩 CSS 样式表。

首先，我们需要通过发出以下命令来安装基于 Go 的缩小器：

```go
$ go get -u github.com/tdewolff/minify/cmd/minify
$ go install github.com/tdewolff/minify
```

现在，我们可以压缩 IGWEB 的 CSS 样式表：

```go
$ minify --mime="text/css" $IGWEB_APP_ROOT/static/css/igweb.css > $IGWEB_APP_ROOT/static/css/igweb.min.css
```

有了这些项目，我们现在准备创建一个部署包，一个 tarball，其中包括 `igweb` Linux 二进制文件以及 `static` 文件夹。我们通过发出以下命令来创建 tarball：

```go
$ cd $IGWEB_APP_ROOT
$ tar zcvf /tmp/bundle.tgz builds/igweb-linux64 static
```

我们将使用 `scp` 命令将包发送到远程服务器：

```go
$ scp /tmp/bundle.tgz igweb@targetserver:/tmp/.
```

`scp` 命令将 tarball `bundle.tgz` 复制到具有主机名 `targetserver` 的服务器上的 `/tmp` 目录。现在部署包已放置在服务器上，是时候让 `igweb` 运行起来了。

# 部署包并启动 IGWEB

我们将安全复制到 `/tmp` 文件夹的模板包移动到 `~/igweb` 文件夹，并提取 tarball 的内容：

```go
 $ cd ~/igweb
 $ mv /tmp/bundle.tgz .
 $ tar zxvf bundle.tgz
```

在我们提取 `bundle.tgz` 压缩包的内容后，通过发出 `rm` 命令来删除压缩包文件。

```go
$ rm bundle.tgz
```

我们可以使用 `mv` 命令将二进制文件重新命名为 `igweb`：

```go
$ mv igweb-linux64 igweb
```

我们在本地机器上将 `-linux64` 附加到二进制文件的名称上，以便我们可以将其与其他操作系统/架构组合的构建区分开。

此时我们已经将包部署到生产服务器。现在是运行 `igweb` 的时候了。

# 运行 IGWEB

在运行`igweb`可执行文件之前，我们必须在生产服务器上设置`$IGWEB_APP_ROOT`和`$IGWEB_MODE`环境变量：

```go
 $ export IGWEB_APP_ROOT=/home/igweb/igweb
 $ export IGWEB_MODE=production
```

设置`$IGWEB_APP_ROOT`环境变量允许`igweb`应用程序知道指定的`igweb`目录，该目录将包含依赖资源，如静态资产。

将`$IGWEB_MODE`环境变量设置为`production`允许我们以生产模式运行`igweb`应用程序。

您应该在`igweb`用户的`.bashrc`配置文件中为这两个环境变量添加条目：

```go
export IGWEB_APP_ROOT=/home/igweb/igweb
export IGWEB_MODE=production
```

在生产服务器上注销并重新登录，以使对`.bashrc`所做的更改生效。

# 在前台运行 IGWEB

让我们启动`igweb` Web 服务器实例：

```go
$ cd $IGWEB_APP_ROOT
$ ./igweb
```

*图 11.4*显示了 IGWEB 在地址[`igweb.kamesh.com`](http://igweb.kamesh.com)上运行的独立服务器实例的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/e852eed5-74cf-40ee-927b-847e741cec07.png)

图 11.4：IGWEB 在独立服务器实例上运行

当我们按下*Ctrl* + *C*组合键退出`igweb`程序时，我们的 Web 服务器实例会因为一直在前台运行而停止。NGINX 将为任何客户端请求返回 502 Bad Gateway 服务器错误。我们需要一种方法来使`igweb`以守护进程方式运行，以便在后台运行。

# 在后台运行 IGWEB

`igweb` Web 服务器实例可以使用`nohup`命令在后台运行：

```go
$ nohup ./igweb 2>&1 &
```

`nohup`命令用于在当前会话终止后继续运行`igweb`程序。在类 Unix 系统上，`2>&1`构造意味着将标准错误（`stderr`）重定向到与标准输出（`stdout`）相同的位置。`igweb`程序的日志消息将通过尾随`/var/log/syslog`文件进行查看。最后，命令中的最后一个`&`表示在后台运行该程序。

我们可以通过首先获取**PID**（进程 ID）来停止`igweb`进程：

```go
$ ps -ef | grep igweb | grep -v grep
```

从运行此命令返回的输出中，PID 值将紧邻可执行文件`igweb`的名称。一旦确定了进程的 PID，我们可以使用`kill`命令并指定 PID 的值来停止`igweb`进程：

```go
$ kill PID
```

请注意，我们在前述`kill`命令中放置了名称`PID`，仅用于说明目的。您将需要使用从运行`ps`命令返回的 PID 的数字值来为`kill`命令提供 PID。

# 使用 systemd 在后台运行 IGWEB

这种运行`igweb`的方法暂时有效，但是如果服务器重新启动会怎么样？我们需要一种方法使`igweb`程序更具弹性。它必须能够在服务器重新上线后再次启动，并且`nohup`不是实现此目标的合适选择。

我们真正需要的是将`igweb`转换为系统服务的方法。我们可以使用`sysytemd`来实现这一点，`sysytemd`是一个可用于 Ubuntu 16.04 LTS 的初始化系统。使用`systemd`，我们可以初始化、管理和跟踪系统服务。它可以在系统启动时或系统运行时使用。

您需要以`root`用户身份运行以下命令，因为您需要成为`root`用户才能添加新的系统服务。

为了将`igweb`转换为服务，我们创建一个名为`igweb.service`的单元文件，并将其放在`/etc/systemd/system`目录中。以下是单元文件的内容：

```go
[Unit]
Description=IGWEB

[Service]
USER=igweb
GROUP=igweb
Environment=IGWEB_APP_ROOT=/home/igweb/igweb
Environment=IGWEB_MODE=production
WorkingDirectory=/home/igweb/igweb
ExecStart=/home/igweb/igweb/igweb
Restart=always

[Install]
WantedBy=multi-user.target
```

指定`.service`文件扩展名表示我们正在创建一个服务单元，描述如何在服务器上管理应用程序。这包括执行诸如启动或停止服务的操作，以及服务是否应在系统启动时启动。

单元文件分为多个部分，每个部分的开头用一对方括号*[*和*]*标示，括号之间包含部分的名称。

单元文件中的部分名称区分大小写！

第一部分是`[Unit]`部分。这用于定义单元的元数据以及该单元与其他单元的关系。在`[Unit]`部分中，我们已经为`Description`指定了一个值，用于描述单元的名称。例如，我们运行以下命令：

```go
$ systemctl status nginx
```

当我们运行它时，我们在`nginx`的描述中看到的是使用`Description`指令指定的描述。

`[Service]`部分用于指定服务的配置。`USER`和`GROUP`指令指定命令应该以什么用户和组身份运行。我们使用`Environment`指令来设置`$IGWEB_APP_ROOT`环境变量，并再次使用它来设置`$IGWEB_MODE`环境变量。

`WorkingDirectory`指令设置了执行命令的工作目录。`ExecStart`指令指定了要执行的命令的完整路径；在这种情况下，我们提供了`igweb`可执行文件的完整路径。

`Restart`指令用于指定`systemd`将尝试重新启动服务的情况。通过提供*always*的值，我们指定服务应始终运行，如果出现某种原因停止，应该再次启动。

我们定义的最后一个部分是`[Install]`部分。这个部分允许我们指定单元在启用或禁用时的行为。

在这个部分声明的`WantedBy`指令告诉`systemd`如何启用一个单元，也就是说，当启用服务时，该服务应该在什么系统运行级别下运行。通过将此指令的值设置为`multi-user.target`，我们指定该服务在系统运行级别 3（多用户模式）下运行。

每当我们引入新的`systemd`服务脚本或对现有脚本进行更改时，我们必须重新加载`systemd`守护程序。我们可以通过发出以下命令来实现：

```go
$ systemctl daemon-reload
```

我们可以指定，我们希望`igweb`服务在启动时自动启动，方法是发出以下命令：

```go
$ systemctl enable igweb
```

如果我们不希望`igweb`服务在启动时自动启动，我们可以发出以下命令：

```go
$ systemctl disable igweb
```

我们可以通过发出以下命令来启动`igweb`服务：

```go
$ systemctl start igweb
```

我们可以通过发出以下命令来停止`igweb`服务：

```go
$ systemctl stop igweb
```

我们现在已经完成了`igweb`的独立部署。令人惊讶的是，我们可以在目标生产系统上运行`igweb`应用程序，而无需安装 Go。

然而，这种方法对于负责保持 IGWEB 运行的 DevOps 团队来说相当不透明。我所说的*不透明*是指 DevOps 工程师无法通过检查静态二进制可执行文件和一堆静态资产来确定太多信息。

我们需要一种更简化的方式来部署 IGWEB，一种程序可以显示从头开始启动`igweb`实例所需的所有依赖关系。为了实现这个目标，我们需要将 IGWEB 放入 Docker 容器中。

# 使用 Docker 部署同构 Go Web 应用程序

本节概述了在 Linode 云上将`igweb`部署为多容器 Docker 应用程序的过程。Docker 是一种技术和平台，允许我们在单台机器上运行和管理多个 Docker 容器。您可以将 Docker 容器视为模块化、轻量级的虚拟机。我们可以通过将应用程序（如`igweb`）打包为 Docker 容器，使其立即可移植。无论在哪个环境中运行，应用程序都保证在容器内以相同的方式运行。

您可以在以下链接了解有关 Docker 的更多信息：[`www.docker.com`](https://www.docker.com)。

大多数云提供商都支持 Docker，使其成为云部署的非常方便的工具。正如您将在本章后面看到的，将多容器 Docker 应用程序部署到 Linode 云上相对容易。

# 安装 Docker

在生产系统上安装 Docker 之前，我们首先需要安装一些先决条件：

```go
$ sudo apt-get install dmsetup && dmsetup mknodes
```

现在，我们可以发出以下命令来安装 Docker：

```go
$ sudo apt-get install docker-ce
```

要验证 Docker 是否已经在生产系统上正确安装，您可以发出以下命令：

```go
$ docker --version
Docker version 17.09.0-ce, build afdb6d4
```

运行命令后，您应该看到安装的 Docker 版本。

# Docker 化 IGWEB

docker 化`igweb`的过程首先涉及创建一个`Dockerfile`，该文件指定了如何创建 Docker 镜像的指令。然后将使用 Docker 镜像来创建 Docker 容器。

创建了 Dockerfile 之后，我们将使用`docker-compose`工具来定义和运行多个容器，以支持 IGWEB 网站的运行。

将`igweb`部署为多容器 Docker 应用程序是一个三步过程：

1.  从中可以创建一个 IGWEB docker 镜像的`Dockerfile`

1.  在`docker-compose.yml`文件中定义组成 IGWEB 的服务

1.  运行`docker-compose up`来启动多容器应用程序

# Dockerfile

`Dockerfile`描述了应该由`igweb` docker 镜像制作的内容。该文件位于`deployments-config/docker-single-setup`文件夹中。让我们检查`Dockerfile`以了解它的工作原理。

`FROM`指令指定了当前镜像派生的基本父镜像：

```go
FROM golang
```

在这里，我们指定将使用基本的`golang` docker 镜像。

有关`golang` docker 镜像的更多信息可以在[`hub.docker.com/_/golang/`](https://hub.docker.com/_/golang/)找到。

`MAINTAINER`指令指定了`Dockerfile`的维护者姓名以及他们的电子邮件地址：

```go
MAINTAINER Kamesh Balasubramanian kamesh@kamesh.com
```

我们已经指定了一组`ENV`指令，允许我们定义和设置所有必需的环境变量：

```go
ENV IGWEB_APP_ROOT=/go/src/github.com/EngineerKamesh/igb/igweb
ENV IGWEB_DB_CONNECTION_STRING="database:6379"
ENV IGWEB_MODE=production
ENV GOPATH=/go
```

为了使`igweb`应用程序正常运行，我们设置了`$IGWEB_APP_ROOT`、`$IGWEB_DB_CONNECTION`、`$IGWEB_MODE`和`$GOPATH`环境变量。

在这个块中，我们使用`RUN`指令来获取`igweb`应用程序所需的 Go 包：

```go
RUN go get -u github.com/gopherjs/gopherjs
RUN go get -u honnef.co/go/js/dom
RUN go get -u -d -tags=js github.com/gopherjs/jsbuiltin
RUN go get -u honnef.co/go/js/xhr
RUN go get -u github.com/gopherjs/websocket
RUN go get -u github.com/tdewolff/minify/cmd/minify
RUN go get -u github.com/isomorphicgo/isokit 
RUN go get -u github.com/uxtoolkit/cog
RUN go get -u github.com/EngineerKamesh/igb
```

这基本上是运行`igweb`所需的 Go 包列表。

以下`RUN`命令安装了一个基于 Go 的 CSS/JavaScript 缩小器：

```go
RUN go install github.com/tdewolff/minify
```

我们使用另一个`RUN`指令来转译客户端 Go 程序：

```go
RUN cd $IGWEB_APP_ROOT/client; go get ./..; /go/bin/gopherjs build -m --verbose --tags clientonly -o $IGWEB_APP_ROOT/static/js/client.min.js
```

这个命令实际上是三个连续命令的组合，每个命令使用分号分隔。

第一个命令将目录更改为`$IGWEB_APP_ROOT/client`目录。在第二个命令中，我们在当前目录和所有子目录中获取任何剩余所需的 Go 包。第三个命令将 Go 代码转译为一个缩小的 JavaScript 源文件`client.min.js`，并将其放置在`$IGWEB_APP_ROOT/static/js`目录中。

接下来的`RUN`指令构建并安装服务器端 Go 程序：

```go
>RUN go install github.com/EngineerKamesh/igb/igweb
```

请注意，`go install`命令不仅会通过执行构建操作生成`igweb`二进制可执行文件，还会将生成的可执行文件移动到`$GOPATH/bin`。

我们发出以下`RUN`指令来生成静态资产：

```go
RUN /go/bin/igweb --generate-static-assets
```

这个`RUN`指令缩小了 IGWEB 的 CSS 样式表：

```go
RUN /go/bin/minify --mime="text/css" $IGWEB_APP_ROOT/static/css/igweb.css > $IGWEB_APP_ROOT/static/css/igweb.min.css
```

`ENTRYPOINT`指令允许我们设置容器的主要命令：

```go
# Specify the entrypoint
ENTRYPOINT /go/bin/igweb
```

这使我们能够像运行命令一样运行镜像。我们将`ENTRYPOINT`设置为`igweb`可执行文件的路径：`/go/bin/igweb`。

我们使用`EXPOSE`指令来通知 Docker 容器在运行时应监听的网络端口：

```go
EXPOSE 8080
```

我们已经暴露了容器的端口`8080`。

除了能够使用`Dockerfile`构建 docker 镜像之外，该文件最重要的好处之一是它传达了意义和意图。它可以被视为一个一流的项目配置工件，以确切了解构建同构 Web 应用程序的过程，该应用程序由服务器端`igweb`应用程序和客户端应用程序`client.min.js`组成。通过查看`Dockerfile`，DevOps 工程师可以轻松地确定成功从头开始构建整个同构 Web 应用程序的过程。

# 闭源项目的 Dockerfile

我们提出的`Dockerfile`非常适合开源项目，但如果你的特定同构 Go 项目是闭源的，你该怎么办呢？你如何能够利用在云中运行 Docker 并同时保护源代码不被查看？我们需要对`Dockerfile`进行轻微修改以适应闭源项目。

让我们考虑一个场景，`igweb`的代码分发是闭源的。假设我们无法使用`go get`命令获取它。

假设您已经在项目目录的根目录下创建了一个闭源友好的`Dockerfile`，并且已经将闭源`igweb`项目的 tarball 捆绑包从本地机器安全地复制到目标机器，并且已经解压了 tarball。

以下是我们需要对`Dockerfile`进行的更改。首先，我们注释掉使用`go get`命令获取`igb`分发的相应`RUN`指令：

```go
# Get the required Go packages
RUN go get -u github.com/gopherjs/gopherjs
RUN go get -u honnef.co/go/js/dom
RUN go get -u -d -tags=js github.com/gopherjs/jsbuiltin
RUN go get -u honnef.co/go/js/xhr
RUN go get -u github.com/gopherjs/websocket
RUN go get -u github.com/tdewolff/minify/cmd/minify
RUN go get -u github.com/isomorphicgo/isokit 
RUN go get -u github.com/uxtoolkit/cog
# RUN go get -u github.com/EngineerKamesh/igb
```

在一系列`RUN`指令之后，我们立即引入了一个`COPY`指令：

```go
COPY . $IGWEB_APP_ROOT/.
```

这个`COPY`指令将递归地将当前目录中的所有文件和文件夹复制到由`$IGWEB_APP_ROOT/.`指定的目的地。就是这样。

现在我们已经深入研究了 IGWEB 的`Dockerfile`的结构，我们必须承认`igweb` web 服务器实例本身无法为 IGWEB 网站提供服务。它有一定的服务依赖性，我们必须考虑，比如 Redis 数据库用于数据持久性需求，以及 NGINX 反向代理以合理的 gzip 方式提供大型静态资产。

我们需要一个 Redis 的 Docker 容器，以及另一个 NGINX 的 Docker 容器。`igweb`正在成为一个多容器的 Docker 应用程序。现在是时候把注意力转向`docker-compose`，这是一个方便的工具，用于定义和运行多容器应用程序。

# Docker compose

`docker-compose`工具允许我们定义一个多容器的 Docker 应用程序，并使用单个命令`docker-compose up`来运行它。

`docker-compose`通过读取包含特定指令的`docker-compose.yml`文件来工作，这些指令不仅描述了应用程序中的容器，还描述了它们各自的依赖关系。让我们来检查`docker-compose.yml`文件中多容器`igweb`应用程序的每个部分。

在文件的第一行，我们指示将使用 Docker Compose 配置文件格式的第 2 版：

```go
version: '2'
```

我们在`services`部分内声明了应用程序的服务。每个服务（以粗体显示）都被赋予一个名称，以指示它在多容器应用程序中的角色：

```go
services:
  database:
    image: "redis"
  webapp:
    depends_on:
        - database 
    build: .
    ports:
        - "8080:8080"
  reverseproxy:
    depends_on:
        - webapp
    image: "nginx"
    volumes:
   - ./deployments-config/docker-single setup/nginx.conf:/etc/nginx/nginx.conf
    ports:
        - "80:80"
```

我们已经定义了一个名为`database`的服务，它将成为 Redis 数据库实例的容器。我们将 image 选项设置为`redis`，以告诉`docker-compose`基于 Redis 镜像运行一个容器。

紧接着，我们定义了一个名为`webapp`的服务，它将成为`igweb`应用程序的容器。我们使用`depends_on`选项明确说明`webapp`服务需要`database`服务才能运行。如果没有`database`服务，`webapp`服务就无法启动。

我们指定`build`选项告诉`docker-compose`根据指定路径中的`Dockerfile`构建镜像。通过指定相对路径`.`，我们指示应使用当前目录中存在的`Dockerfile`构建基础镜像。

在`ports`部分，我们指定了`8080:8080`（HOST:CONTAINER）的值，表示我们要在主机上打开端口`8080`并将连接转发到 Docker 容器的端口`8080`。

我们已经定义了名为`reverseproxy`的服务，它将作为`nginx`反向代理服务器的容器。我们将`depends_on`选项设置为`webapp`，以表示`reverseproxy`服务在`webapp`服务启动之前不能启动。我们将 image 选项设置为`nginx`，告诉`docker-compose`基于`nginx`镜像运行容器。

在`volumes`部分，我们可以定义我们的挂载路径，格式为 HOST:CONTAINER。我们定义了一个挂载路径，将位于`./deployments-config/docker-single-setup`目录中的`nginx.conf`配置文件挂载到容器内部的`/etc/nginx/nginx.conf`路径。

由于`reverseproxy`服务将为 HTTP 客户端请求提供服务，我们在`ports`部分指定了值为`80:80`，表示我们要在主机上打开端口`80`（默认 HTTP 端口）并将连接转发到 Docker 容器的端口`80`。

现在我们已经完成了 Docker Compose 配置文件，是时候使用`docker-compose up`命令启动`igweb`作为多容器 Docker 应用程序了。

# 运行 Docker Compose

我们发出以下命令来构建服务：

```go
$ docker-compose build
```

运行`docker-compose build`命令的输出如下（为了简洁起见，部分输出已省略）：

```go
database uses an image, skipping
Building webapp
Step 1/22 : FROM golang
 ---> 99e596fc807e
Step 2/22 : MAINTAINER Kamesh Balasubramanian kamesh@kamesh.com
 ---> Running in 107a99d5c4ee
 ---> 6facac83509e
Removing intermediate container 107a99d5c4ee
Step 3/22 : ENV IGWEB_APP_ROOT /go/src/github.com/EngineerKamesh/igb/igweb
 ---> Running in f009d8391fc4
 ---> ec1b1d15c6c3
Removing intermediate container f009d8391fc4
Step 4/22 : ENV IGWEB_DB_CONNECTION_STRING "database:6379"
 ---> Running in 2af5e98c71e2
 ---> 6748f0f5bc4d
Removing intermediate container 2af5e98c71e2
Step 5/22 : ENV IGWEB_MODE production
 ---> Running in 1a87b871f761
 ---> 9871fc511e80
Removing intermediate container 1a87b871f761
Step 6/22 : ENV GOPATH /go
 ---> Running in c6c2eff0ded2
 ---> 4dc456357dc9
Removing intermediate container c6c2eff0ded2
Step 7/22 : RUN go get -u github.com/gopherjs/gopherjs
 ---> Running in c8996108bd96
 ---> 6ae68fb84178
Removing intermediate container c8996108bd96
Step 8/22 : RUN go get -u honnef.co/go/js/dom
 ---> Running in a1ad103c4c10
 ---> abd1f7f3b8b7
Removing intermediate container a1ad103c4c10
Step 9/22 : RUN go get -u -d -tags=js github.com/gopherjs/jsbuiltin
 ---> Running in d7dc4ec21ee1
 ---> cd5829fb609f
Removing intermediate container d7dc4ec21ee1
Step 10/22 : RUN go get -u honnef.co/go/js/xhr
 ---> Running in b4e88d0233fb
 ---> 3fe4d470799e
Removing intermediate container b4e88d0233fb
Step 11/22 : RUN go get -u github.com/gopherjs/websocket
 ---> Running in 9cebc021cb34
 ---> 20cd1c09d6cd
Removing intermediate container 9cebc021cb34
Step 12/22 : RUN go get -u github.com/tdewolff/minify/cmd/minify
 ---> Running in 9875889cc267
 ---> 3c60c2de51b0
Removing intermediate container 9875889cc267
Step 13/22 : RUN go get -u github.com/isomorphicgo/isokit
 ---> Running in eb839d91588e
 ---> e952d6e6cbe2
Removing intermediate container eb839d91588e
Step 14/22 : RUN go get -u github.com/uxtoolkit/cog
 ---> Running in 3e6853ff7196
 ---> 3b00f78e5acf
Removing intermediate container 3e6853ff7196
Step 15/22 : RUN go get -u github.com/EngineerKamesh/igb
 ---> Running in f5082861ca8a
 ---> 93506a92526c
Removing intermediate container f5082861ca8a
Step 16/22 : RUN go install github.com/tdewolff/minify
 ---> Running in b0a72d9e9807
 ---> e3e49d9c2898
Removing intermediate container b0a72d9e9807
Step 17/22 : RUN cd $IGWEB_APP_ROOT/client; go get ./..; /go/bin/gopherjs build -m --verbose --tags clientonly -o $IGWEB_APP_ROOT/static/js/client.min.js
 ---> Running in 6f6684209cfd
Step 18/22 : RUN go install github.com/EngineerKamesh/igb/igweb
 ---> Running in 17ed6a871db7
 ---> 103f12e38c04
Removing intermediate container 17ed6a871db7
Step 19/22 : RUN /go/bin/igweb --generate-static-assets
 ---> Running in d6fb5ff48a08
Generating static assets...Done
 ---> cc7434fbb94d
Removing intermediate container d6fb5ff48a08
Step 20/22 : RUN /go/bin/minify --mime="text/css" $IGWEB_APP_ROOT/static/css/igweb.css > $IGWEB_APP_ROOT/static/css/igweb.min.css
 ---> Running in e1920eb49cc2
 ---> adbf78450b9c
Removing intermediate container e1920eb49cc2
Step 21/22 : ENTRYPOINT /go/bin/igweb
 ---> Running in 20246e214462
 ---> a5f1d978060d
Removing intermediate container 20246e214462
Step 22/22 : EXPOSE 8080
 ---> Running in 6e12e970dfe2
 ---> 4c7f474b2704
Removing intermediate container 6e12e970dfe2
Successfully built 4c7f474b2704
reverseproxy uses an image, skipping
```

构建完成后，我们可以通过以下命令运行多容器`igweb`应用：

```go
$ docker-compose up
```

*图 11.5*是 IGWEB 作为多容器应用程序运行的截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/8c58f00f-245d-4d24-bf98-36e9fd4877f4.png)

图 11.5：IGWEB 作为多容器应用程序运行

当我们运行`docker-compose up`命令时，该命令会提供所有运行容器的实时活动输出。要退出程序，可以使用*Ctrl* + *C*组合键。请注意，这将终止`docker-compose`程序，从而以一种优雅的方式关闭运行的容器。

另外，在启动多容器`igweb`应用程序时，可以指定`-d`选项以在后台运行，如下所示：

```go
$ docker-compose up -d
```

如果要关闭多容器应用程序，可以发出以下命令：

```go
$ docker-compose down
```

如果对`Dockerfile`或`docker-compose.yml`文件进行进一步更改，必须再次运行`docker-compose build`命令来重建服务：

```go
$ docker-compose build
```

在后台运行容器的`docker-compose up -d`非常方便，但现在我们知道最好将多容器 Docker 应用程序转换为`systemd`服务。

# 设置 docker 化的 IGWEB 服务

设置 docker 化的`igweb`的`systemd`服务非常简单。以下是`igweb-docker.service`文件的内容，应放置在生产系统的`/etc/systemd/system`目录中：

```go
[Unit]
Description=Dockerized IGWEB
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/igb/igweb
ExecStart=/usr/bin/docker-compose -f /opt/igb/igweb/docker-compose.yml up -d
ExecStop=/usr/bin/docker-compose -f /opt/igb/igweb/docker-compose.yml down

[Install]
WantedBy=multi-user.target
```

在`[Unit]`部分，我们使用`After`指令设置了值为`docker.service`。这表示`docker`单元必须在`igweb-docker`单元之前启动。`Requires`指令也设置为值为`docker.service`。这表示`igweb-docker`单元依赖于`docker`单元成功运行。如果无法启动`docker`单元，将导致无法启动`igweb-docker`单元。

在`[Service]`部分，我们将`Type`指令设置为`oneshot`。这表明我们正在启动的可执行文件是短暂的。使用它是有道理的，因为我们将使用`-d`标志指定（分离模式）运行`docker-compose up`，以便容器在后台运行。

我们已经在`RemainAfterExit`指令中指定了`Type`指令。通过将`RemainAfterExit`指令设置为`yes`，我们表明`igweb-docker`服务即使在`docker-compose`进程退出后也应被视为活动状态。

使用`ExecStart`指令，我们以分离模式启动`docker-compose`进程。我们已经指定了`ExecStop`指令，以指示停止服务所需的命令。

在`[Install]`部分，通过将`WantedBy`指令的值设置为`multi-user.target`，我们指定了该服务在系统运行级别 3（多用户模式）下运行。

请记住，在将`igweb-docker.service`文件放置在`/etc/systemd/system`目录后，我们必须像这样重新加载`systemd`守护程序：

```go
$ systemctl daemon-reload
```

现在，我们可以启动 docker 化的`igweb`应用程序：

```go
$ systemctl start igweb-docker
```

您可以使用`systemctl enable`命令指定`igweb-docker`应该在系统启动时启动。

通过发出以下命令，我们可以关闭服务：

```go
$ systemctl stop igweb-docker
```

到目前为止，我们已经演示了如何将`igweb`应用程序作为托管在 Linode 云上的多容器 Docker 应用程序运行。再次强调，虽然我们使用的是 Linode，但我们演示的过程可以在您选择的首选云提供商上复制。

# 总结

在本章中，我们学习了如何将等同构 Web 应用程序部署到云上。我们介绍了`igweb`服务器端应用程序在生产模式下的运行方式，向您展示了应用程序如何包含外部 CSS 和 JavaScript 源文件。我们还向您展示了如何控制 GopherJS 生成的 JavaScript 程序的文件大小。我们向您展示了如何为应用程序的模板包生成静态资产，以及要部署的齿轮使用的 JavaScript 和 CSS。

我们首先考虑了将等跨服务器部署等同构 Web 应用程序。这包括向服务器添加`igweb`用户，设置`redis-server`实例，使用启用了 GZIP 压缩的`nginx`作为反向代理，并设置`igweb`根文件夹。我们还向您展示了如何从开发系统（64 位 macOS）交叉编译 Go 代码到运行在生产系统上的操作系统（64 位 Linux）。我们指导您准备部署包的过程，然后部署包到生产系统。最后，我们向您展示了如何将`igweb`设置为`systemd`服务，以便可以轻松地启动、停止、重新启动，并在系统启动时自动启动。

然后，我们将注意力集中在将等同构 Web 应用程序部署为多容器 Docker 应用程序。我们向您展示了如何在生产系统上安装 Docker。我们带您完成了 dockerizing `igweb`的过程，其中包括创建`Dockerfile`，在`docker-compose.yml`文件中定义组成 IGWEB 的服务，并运行`docker-compose up`命令以将 IGWEB 作为多容器 Docker 应用程序启动。最后，我们向您展示了如何设置`igweb-docker systemd`脚本来管理`igweb`作为系统服务。
