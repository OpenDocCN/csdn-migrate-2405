# Go 编程秘籍第二版（四）

> 原文：[`zh.annas-archive.org/md5/6A3DCC49D461FA27A010AAE9FBA229E0`](https://zh.annas-archive.org/md5/6A3DCC49D461FA27A010AAE9FBA229E0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：Web 客户端和 API

使用 API 并编写 Web 客户端可能是一件棘手的事情。不同的 API 具有不同类型的授权、认证和协议。我们将探索`http.Client`结构对象，使用 OAuth2 客户端和长期令牌存储，并最后使用 GRPC 和额外的 REST 接口。

在本章结束时，您应该知道如何与第三方或内部 API 进行交互，并且对于常见操作（如对 API 的异步请求）有一些模式。

在本章中，我们将涵盖以下的步骤：

+   初始化、存储和传递 http.Client 结构

+   为 REST API 编写客户端

+   执行并行和异步客户端请求

+   使用 OAuth2 客户端

+   实现 OAuth2 令牌存储接口

+   在添加功能和函数组合中包装客户端

+   理解 GRPC 客户端

+   使用 twitchtv/twirp 进行 RPC

# 技术要求

为了继续本章中的所有示例，根据以下步骤配置您的环境：

1.  在您的操作系统上下载并安装 Go 1.12.6 或更高版本，网址为[`golang.org/doc/install`](https://golang.org/doc/install)。

1.  打开终端或控制台应用程序，创建一个项目目录，例如`~/projects/go-programming-cookbook`，并导航到该目录。所有的代码都将在这个目录中运行和修改。

1.  将最新的代码克隆到`~/projects/go-programming-cookbook-original`，并选择从该目录工作，而不是手动输入示例，如下所示：

```go
$ git clone git@github.com:PacktPublishing/Go-Programming-Cookbook-Second-Edition.git go-programming-cookbook-original
```

# 初始化、存储和传递 http.Client 结构

Go 的`net/http`包为处理 HTTP API 公开了一个灵活的`http.Client`结构。这个结构具有单独的传输功能，使得对请求进行短路、修改每个客户端操作的标头以及处理任何 REST 操作相对简单。创建客户端是一个非常常见的操作，这个示例将从工作和创建一个`http.Client`对象的基础知识开始。

# 如何做...

这些步骤涵盖了编写和运行应用程序的步骤：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter7/client`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter7/client 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter7/client 
```

1.  从`~/projects/go-programming-cookbook-original/chapter7/client`复制测试，或者自己编写一些代码来练习！

1.  创建一个名为`client.go`的文件，内容如下：

```go
        package client

        import (
            "crypto/tls"
            "net/http"
        )

        // Setup configures our client and redefines
        // the global DefaultClient
        func Setup(isSecure, nop bool) *http.Client {
            c := http.DefaultClient

            // Sometimes for testing, we want to
            // turn off SSL verification
            if !isSecure {
                c.Transport = &http.Transport{
                TLSClientConfig: &tls.Config{
                    InsecureSkipVerify: false,
                },
            }
        }
        if nop {
            c.Transport = &NopTransport{}
        }
        http.DefaultClient = c
        return c
        }

        // NopTransport is a No-Op Transport
        type NopTransport struct {
        }

        // RoundTrip Implements RoundTripper interface
        func (n *NopTransport) RoundTrip(*http.Request) 
        (*http.Response, error) {
            // note this is an unitialized Response
            // if you're looking at headers etc
            return &http.Response{StatusCode: http.StatusTeapot}, nil
        }
```

1.  创建一个名为`exec.go`的文件，内容如下：

```go
        package client

        import (
            "fmt"
            "net/http"
        )

        // DoOps takes a client, then fetches
        // google.com
        func DoOps(c *http.Client) error {
            resp, err := c.Get("http://www.google.com")
            if err != nil {
                return err
            }
            fmt.Println("results of DoOps:", resp.StatusCode)

            return nil
        }

        // DefaultGetGolang uses the default client
        // to get golang.org
        func DefaultGetGolang() error {
            resp, err := http.Get("https://www.golang.org")
            if err != nil {
                return err
            }
            fmt.Println("results of DefaultGetGolang:", 
            resp.StatusCode)
            return nil
        }
```

1.  创建一个名为`store.go`的文件，内容如下：

```go
        package client

        import (
            "fmt"
            "net/http"
        )

        // Controller embeds an http.Client
        // and uses it internally
        type Controller struct {
            *http.Client
        }

        // DoOps with a controller object
        func (c *Controller) DoOps() error {
            resp, err := c.Client.Get("http://www.google.com")
            if err != nil {
                return err
            }
            fmt.Println("results of client.DoOps", resp.StatusCode)
            return nil
        }
```

1.  创建一个名为`example`的新目录并导航到该目录。

1.  创建一个名为`main.go`的文件，内容如下：

```go
        package main

        import "github.com/PacktPublishing/
                Go-Programming-Cookbook-Second-Edition/
                chapter7/client"

        func main() {
            // secure and op!
            cli := client.Setup(true, false)

            if err := client.DefaultGetGolang(); err != nil {
                panic(err)
            }

            if err := client.DoOps(cli); err != nil {
                panic(err)
            }

            c := client.Controller{Client: cli}
            if err := c.DoOps(); err != nil {
                panic(err)
            }

            // secure and noop
            // also modifies default
            client.Setup(true, true)

            if err := client.DefaultGetGolang(); err != nil {
                panic(err)
            }
        }
```

1.  运行`go run main.go`。

1.  您也可以运行以下命令：

```go
$ go build $ ./example
```

现在您应该看到以下输出：

```go
$ go run main.go
results of DefaultGetGolang: 200
results of DoOps: 200
results of client.DoOps 200
results of DefaultGetGolang: 418
```

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 它是如何工作的...

`net/http`包公开了一个`DefaultClient`包变量，该变量被以下内部操作使用：`Do`、`GET`、`POST`等。我们的`Setup()`函数返回一个客户端，并将默认客户端设置为相同的客户端。在设置客户端时，大部分修改将发生在传输中，传输只需要实现`RoundTripper`接口。

这个示例提供了一个总是返回 418 状态码的无操作往返器的示例。您可以想象这对于测试可能有多么有用。它还演示了将客户端作为函数参数传递，将它们用作结构参数，并使用默认客户端来处理请求。

# 为 REST API 编写客户端

为 REST API 编写客户端不仅有助于更好地理解相关的 API，还将为所有将来使用该 API 的应用程序提供一个有用的工具。这个配方将探讨构建客户端的结构，并展示一些您可以立即利用的策略。

对于这个客户端，我们将假设认证是由基本认证处理的，但也应该可以命中一个端点来检索令牌等。为了简单起见，我们假设我们的 API 公开了一个端点`GetGoogle()`，它返回从[`www.google.com`](https://www.google.com)进行`GET`请求返回的状态码。

# 如何做...

这些步骤涵盖了编写和运行应用程序的过程：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter7/rest`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter7/rest 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter7/rest 
```

1.  从`~/projects/go-programming-cookbook-original/chapter7/rest`复制测试，或者利用这个机会编写一些自己的代码！

1.  创建一个名为`client.go`的文件，内容如下：

```go
        package rest

        import "net/http"

        // APIClient is our custom client
        type APIClient struct {
            *http.Client
        }

        // NewAPIClient constructor initializes the client with our
        // custom Transport
        func NewAPIClient(username, password string) *APIClient {
            t := http.Transport{}
            return &APIClient{
                Client: &http.Client{
                    Transport: &APITransport{
                        Transport: &t,
                        username: username,
                        password: password,
                    },
                },
            }
        }

        // GetGoogle is an API Call - we abstract away
        // the REST aspects
        func (c *APIClient) GetGoogle() (int, error) {
            resp, err := c.Get("http://www.google.com")
            if err != nil {
                return 0, err
            }
            return resp.StatusCode, nil
        }
```

1.  创建一个名为`transport.go`的文件，内容如下：

```go
        package rest

        import "net/http"

        // APITransport does a SetBasicAuth
        // for every request
        type APITransport struct {
            *http.Transport
            username, password string
        }

        // RoundTrip does the basic auth before deferring to the
        // default transport
        func (t *APITransport) RoundTrip(req *http.Request) 
        (*http.Response, error) {
            req.SetBasicAuth(t.username, t.password)
            return t.Transport.RoundTrip(req)
        }
```

1.  创建一个名为`exec.go`的文件，内容如下：

```go
        package rest

        import "fmt"

        // Exec creates an API Client and uses its
        // GetGoogle method, then prints the result
        func Exec() error {
            c := NewAPIClient("username", "password")

            StatusCode, err := c.GetGoogle()
            if err != nil {
                return err
            }
            fmt.Println("Result of GetGoogle:", StatusCode)
            return nil
        }
```

1.  创建一个名为`example`的新目录并导航到该目录。

1.  创建一个名为`main.go`的文件，内容如下：

```go
        package main

        import "github.com/PacktPublishing/
                Go-Programming-Cookbook-Second-Edition/
                chapter7/rest"

        func main() {
            if err := rest.Exec(); err != nil {
                panic(err)
            }
        }
```

1.  运行`go run main.go`。

1.  您还可以运行以下命令：

```go
$ go build $ ./example
```

现在您应该看到以下输出：

```go
$ go run main.go
Result of GetGoogle: 200
```

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 它是如何工作的...

这段代码演示了如何隐藏诸如认证和使用`Transport`接口执行令牌刷新等逻辑。它还演示了如何通过方法公开 API 调用。如果我们正在针对诸如用户 API 之类的东西进行实现，我们期望有以下方法：

```go
type API interface{
  GetUsers() (Users, error)
  CreateUser(User) error
  UpdateUser(User) error
  DeleteUser(User)
}
```

如果您阅读了第五章*关于数据库和存储的所有内容*，这可能看起来与名为*执行数据库事务接口*的配方相似。通过接口进行组合，特别是像`RoundTripper`接口这样的常见接口，为编写 API 提供了很大的灵活性。此外，编写一个顶层接口并传递接口而不是直接传递给客户端可能是有用的。在下一个配方中，我们将更详细地探讨这一点，因为我们将探讨编写 OAuth2 客户端。

# 执行并行和异步客户端请求

在 Go 中并行执行客户端请求相对简单。在下一个配方中，我们将使用客户端使用 Go 缓冲通道检索多个 URL。响应和错误都将发送到一个单独的通道，任何有权访问客户端的人都可以立即访问。

在这个配方的情况下，创建客户端，读取通道，处理响应和错误都将在`main.go`文件中完成。

# 如何做...

这些步骤涵盖了编写和运行应用程序的过程：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter7/async`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter7/async 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter7/async 
```

1.  从`~/projects/go-programming-cookbook-original/chapter7/async`复制测试，或者利用这个机会编写一些自己的代码！

1.  创建一个名为`config.go`的文件，内容如下：

```go
        package async

        import "net/http"

        // NewClient creates a new client and 
        // sets its appropriate channels
        func NewClient(client *http.Client, bufferSize int) *Client {
            respch := make(chan *http.Response, bufferSize)
            errch := make(chan error, bufferSize)
            return &Client{
                Client: client,
                Resp: respch,
                Err: errch,
            }
        }

        // Client stores a client and has two channels to aggregate
        // responses and errors
        type Client struct {
            *http.Client
            Resp chan *http.Response
            Err chan error
        }

        // AsyncGet performs a Get then returns
        // the resp/error to the appropriate channel
        func (c *Client) AsyncGet(url string) {
            resp, err := c.Get(url)
            if err != nil {
                c.Err <- err
                return
            }
            c.Resp <- resp
        }
```

1.  创建一个名为`exec.go`的文件，内容如下：

```go
        package async

        // FetchAll grabs a list of urls
        func FetchAll(urls []string, c *Client) {
            for _, url := range urls {
                go c.AsyncGet(url)
            }
        }
```

1.  创建一个名为`example`的新目录并导航到该目录。

1.  创建一个名为`main.go`的文件，内容如下：

```go
        package main

        import (
            "fmt"
            "net/http"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/chapter7/async"
        )

        func main() {
            urls := []string{
                "https://www.google.com",
                "https://golang.org",
                "https://www.github.com",
            }
            c := async.NewClient(http.DefaultClient, len(urls))
            async.FetchAll(urls, c)

            for i := 0; i < len(urls); i++ {
                select {
                    case resp := <-c.Resp:
                    fmt.Printf("Status received for %s: %d\n", 
                    resp.Request.URL, resp.StatusCode)
                    case err := <-c.Err:
                   fmt.Printf("Error received: %s\n", err)
                }
            }
        }
```

1.  运行`go run main.go`。

1.  您还可以运行以下命令：

```go
$ go build $ ./example
```

现在您应该看到以下输出：

```go
$ go run main.go
Status received for https://www.google.com: 200
Status received for https://golang.org: 200
Status received for https://github.com/: 200
```

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 它是如何工作的...

本配方创建了一个处理请求的框架，以一种`async`方式使用单个客户端。它将尝试尽快检索您指定的尽可能多的 URL。在许多情况下，您可能希望进一步限制这一点，例如使用工作池。在客户端之外处理这些`async` Go 例程并为特定的存储或检索接口处理这些也是有意义的。

本配方还探讨了使用 case 语句在多个通道上进行切换。由于获取是异步执行的，必须有一些机制等待它们完成。在这种情况下，只有当主函数读取与原始列表中的 URL 数量相同的响应和错误时，程序才会终止。在这种情况下，还需要考虑应用程序是否应该超时，或者是否有其他方法可以提前取消其操作。

# 利用 OAuth2 客户端

OAuth2 是一种与 API 通信的相对常见的协议。`golang.org/x/oauth2`包提供了一个非常灵活的客户端，用于处理 OAuth2。它有子包指定各种提供程序的端点，如 Facebook、Google 和 GitHub。

本配方将演示如何创建一个新的 GitHub OAuth2 客户端以及一些基本用法。

# 准备工作

完成本章开头“技术要求”部分提到的初始设置步骤后，继续以下步骤：

1.  在[`github.com/settings/applications/new`](https://github.com/settings/applications/new)上配置 OAuth 客户端。

1.  使用您的客户端 ID 和密钥设置环境变量：

+   `export GITHUB_CLIENT="your_client"`

+   `export GITHUB_SECRET="your_secret"`

1.  在[`developer.github.com/v3/`](https://developer.github.com/v3/)上查看 GitHub API 文档。

# 如何做...

这些步骤涵盖了编写和运行应用程序：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter7/oauthcli`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter7/oauthcli 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter7/oauthcli 
```

1.  从`~/projects/go-programming-cookbook-original/chapter7/oauthcli`复制测试，或者将其作为练习编写自己的代码！

1.  创建一个名为`config.go`的文件，内容如下：

```go
        package oauthcli

        import (
            "context"
            "fmt"
            "os"

            "golang.org/x/oauth2"
            "golang.org/x/oauth2/github"
        )

        // Setup return an oauth2Config configured to talk
        // to github, you need environment variables set
        // for your id and secret
        func Setup() *oauth2.Config {
            return &oauth2.Config{
                ClientID: os.Getenv("GITHUB_CLIENT"),
                ClientSecret: os.Getenv("GITHUB_SECRET"),
                Scopes: []string{"repo", "user"},
                Endpoint: github.Endpoint,
            }
        }

        // GetToken retrieves a github oauth2 token
        func GetToken(ctx context.Context, conf *oauth2.Config) 
        (*oauth2.Token, error) {
            url := conf.AuthCodeURL("state")
            fmt.Printf("Type the following url into your browser and 
            follow the directions on screen: %v\n", url)
            fmt.Println("Paste the code returned in the redirect URL 
            and hit Enter:")

            var code string
            if _, err := fmt.Scan(&code); err != nil {
                return nil, err
            }
            return conf.Exchange(ctx, code)
        }
```

1.  创建一个名为`exec.go`的文件，内容如下：

```go
        package oauthcli

        import (
            "fmt"
            "net/http"
        )

        // GetUsers uses an initialized oauth2 client to get
        // information about a user
        func GetUser(client *http.Client) error {
            url := fmt.Sprintf("https://api.github.com/user")

            resp, err := client.Get(url)
            if err != nil {
                return err
            }
            defer resp.Body.Close()
            fmt.Println("Status Code from", url, ":", resp.StatusCode)
            io.Copy(os.Stdout, resp.Body)
            return nil
        }
```

1.  创建一个名为`example`的新目录，并导航到该目录。

1.  创建一个`main.go`文件，内容如下：

```go
        package main

        import (
            "context"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter7/oauthcli"
        )

        func main() {
            ctx := context.Background()
            conf := oauthcli.Setup()

            tok, err := oauthcli.GetToken(ctx, conf)
            if err != nil {
                panic(err)
            }
            client := conf.Client(ctx, tok)

            if err := oauthcli.GetUser(client); err != nil {
                panic(err)
            }

        }
```

1.  运行`go run main.go`。

1.  您还可以运行以下命令：

```go
$ go build $ ./example
```

现在应该看到以下输出：

```go
$ go run main.go
Visit the URL for the auth dialog: 
https://github.com/login/oauth/authorize?
access_type=offline&client_id=
<your_id>&response_type=code&scope=repo+user&state=state
Paste the code returned in the redirect URL and hit Enter:
<your_code>
Status Code from https://api.github.com/user: 200
{<json_payload>}
```

1.  `go.mod`文件可能会更新，顶级配方目录中现在应该存在`go.sum`文件。

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 它是如何工作的...

标准的 OAuth2 流程是基于重定向的，并以服务器重定向到您指定的端点结束。然后您的服务器负责抓取代码并将其交换为令牌。本配方通过允许我们使用诸如`https://localhost`或`https://a-domain-you-own`之类的 URL 绕过了这一要求，手动复制/粘贴代码，然后按*Enter*。令牌交换后，客户端将根据需要智能地刷新令牌。

重要的是要注意，我们没有以任何方式存储令牌。如果程序崩溃，必须重新交换令牌。还需要注意的是，除非刷新令牌过期、丢失或损坏，否则只需要显式检索一次令牌。一旦客户端配置完成，只要在 OAuth2 流程期间请求了适当的范围，它就应该能够执行所有典型的 HTTP 操作。本配方请求了`"repo"`和`"user"`范围，但可以根据需要添加更多或更少。

# 实现 OAuth2 令牌存储接口

在上一个配方中，我们为客户端检索了一个令牌并执行了 API 请求。这种方法的缺点是我们没有长期存储令牌。例如，在 HTTP 服务器中，我们希望在请求之间对令牌进行一致的存储。

这个配方将探讨修改 OAuth2 客户端以在请求之间存储令牌，并使用密钥根据需要检索它。为了简单起见，这个密钥将是一个文件，但也可以是数据库、Redis 等。

# 准备工作

参考*准备工作*部分中*利用 OAuth2 客户端*配方。

# 如何做...

这些步骤涵盖了编写和运行应用程序：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter7/oauthstore`的新目录，并切换到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter7/oauthstore 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter7/oauthstore 
```

1.  从`~/projects/go-programming-cookbook-original/chapter7/oauthstore`复制测试，或者利用这个机会编写一些自己的代码！

1.  创建一个名为`config.go`的文件，内容如下：

```go
        package oauthstore

        import (
            "context"
            "net/http"

            "golang.org/x/oauth2"
        )

        // Config wraps the default oauth2.Config
        // and adds our storage
        type Config struct {
            *oauth2.Config
            Storage
        }

        // Exchange stores a token after retrieval
        func (c *Config) Exchange(ctx context.Context, code string)     
        (*oauth2.Token, error) {
            token, err := c.Config.Exchange(ctx, code)
            if err != nil {
                return nil, err
            }
            if err := c.Storage.SetToken(token); err != nil {
                return nil, err
            }
            return token, nil
        }

        // TokenSource can be passed a token which
        // is stored, or when a new one is retrieved,
        // that's stored
        func (c *Config) TokenSource(ctx context.Context, t 
        *oauth2.Token) oauth2.TokenSource {
            return StorageTokenSource(ctx, c, t)
        }

        // Client is attached to our TokenSource
        func (c *Config) Client(ctx context.Context, t *oauth2.Token) 
        *http.Client {
            return oauth2.NewClient(ctx, c.TokenSource(ctx, t))
        }
```

1.  创建一个名为`tokensource.go`的文件，内容如下：

```go
        package oauthstore

        import (
            "context"

            "golang.org/x/oauth2"
        )

        type storageTokenSource struct {
            *Config
            oauth2.TokenSource
        }

        // Token satisfies the TokenSource interface
        func (s *storageTokenSource) Token() (*oauth2.Token, error) {
            if token, err := s.Config.Storage.GetToken(); err == nil && 
            token.Valid() {
                return token, err
            }
            token, err := s.TokenSource.Token()
            if err != nil {
                return token, err
            }
            if err := s.Config.Storage.SetToken(token); err != nil {
                return nil, err
            }
            return token, nil
        }

        // StorageTokenSource will be used by out configs TokenSource
        // function
        func StorageTokenSource(ctx context.Context, c *Config, t 
        *oauth2.Token) oauth2.TokenSource {
            if t == nil || !t.Valid() {
                if tok, err := c.Storage.GetToken(); err == nil {
                   t = tok
                }
            }
            ts := c.Config.TokenSource(ctx, t)
            return &storageTokenSource{c, ts}
        }
```

1.  创建一个名为`storage.go`的文件，内容如下：

```go
        package oauthstore

        import (
            "context"
            "fmt"

            "golang.org/x/oauth2"
        )

        // Storage is our generic storage interface
        type Storage interface {
            GetToken() (*oauth2.Token, error)
            SetToken(*oauth2.Token) error
        }

        // GetToken retrieves a github oauth2 token
        func GetToken(ctx context.Context, conf Config) (*oauth2.Token, 
        error) {
            token, err := conf.Storage.GetToken()
            if err == nil && token.Valid() {
                return token, err
            }
            url := conf.AuthCodeURL("state")
            fmt.Printf("Type the following url into your browser and 
            follow the directions on screen: %v\n", url)
            fmt.Println("Paste the code returned in the redirect URL 
            and hit Enter:")

            var code string
            if _, err := fmt.Scan(&code); err != nil {
                return nil, err
            }
            return conf.Exchange(ctx, code)
        }
```

1.  创建一个名为`filestorage.go`的文件，内容如下：

```go
        package oauthstore

        import (
            "encoding/json"
            "errors"
            "os"
            "sync"

            "golang.org/x/oauth2"
        )

        // FileStorage satisfies our storage interface
        type FileStorage struct {
            Path string
            mu sync.RWMutex
        }

        // GetToken retrieves a token from a file
        func (f *FileStorage) GetToken() (*oauth2.Token, error) {
            f.mu.RLock()
            defer f.mu.RUnlock()
            in, err := os.Open(f.Path)
            if err != nil {
                return nil, err
            }
            defer in.Close()
            var t *oauth2.Token
            data := json.NewDecoder(in)
            return t, data.Decode(&t)
        }

        // SetToken creates, truncates, then stores a token
        // in a file
        func (f *FileStorage) SetToken(t *oauth2.Token) error {
            if t == nil || !t.Valid() {
                return errors.New("bad token")
            }

            f.mu.Lock()
            defer f.mu.Unlock()
            out, err := os.OpenFile(f.Path, 
            os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
            if err != nil {
                return err
            }
            defer out.Close()
            data, err := json.Marshal(&t)
            if err != nil {
                return err
            }

            _, err = out.Write(data)
            return err
        }
```

1.  创建一个名为`example`的新目录并切换到该目录。

1.  创建一个名为`main.go`的文件，内容如下：

```go
        package main

        import (
            "context"
            "io"
            "os"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter7/oauthstore"

            "golang.org/x/oauth2"
            "golang.org/x/oauth2/github"
        )

        func main() {
            conf := oauthstore.Config{
                Config: &oauth2.Config{
                    ClientID: os.Getenv("GITHUB_CLIENT"),
                    ClientSecret: os.Getenv("GITHUB_SECRET"),
                    Scopes: []string{"repo", "user"},
                    Endpoint: github.Endpoint,
                },
                Storage: &oauthstore.FileStorage{Path: "token.txt"},
            }
            ctx := context.Background()
            token, err := oauthstore.GetToken(ctx, conf)
            if err != nil {
                panic(err)
            }

            cli := conf.Client(ctx, token)
            resp, err := cli.Get("https://api.github.com/user")
            if err != nil {
                panic(err)
            }
            defer resp.Body.Close()
            io.Copy(os.Stdout, resp.Body)
        }
```

1.  运行`go run main.go`。

1.  您也可以运行以下命令：

```go
$ go build $ ./example
```

您现在应该看到以下输出：

```go
$ go run main.go
Visit the URL for the auth dialog: 
https://github.com/login/oauth/authorize?
access_type=offline&client_id=
<your_id>&response_type=code&scope=repo+user&state=state
Paste the code returned in the redirect URL and hit Enter:
<your_code>
{<json_payload>}

$ go run main.go
{<json_payload>}
```

1.  `go.mod`文件可能已更新，顶级配方目录中现在应该存在`go.sum`文件。

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 它是如何工作的...

这个配方负责将令牌的内容存储和检索到文件中。如果是第一次运行，它必须执行整个代码交换，但后续运行将重用访问令牌，并且如果有一个可用，它将使用刷新令牌进行刷新。

目前在这段代码中没有办法区分用户/令牌，但可以通过 cookie 作为文件名的密钥或数据库中的一行来实现。让我们来看看这段代码的功能：

+   `config.go`文件包装了标准的 OAuth2 配置。对于涉及检索令牌的每个方法，我们首先检查本地存储中是否有有效的令牌。如果没有，我们使用标准配置检索一个，然后存储它。

+   `tokensource.go`文件实现了我们自定义的`TokenSource`接口，与`Config`配对。与`Config`类似，我们总是首先尝试从文件中检索我们的令牌；如果失败，我们将使用新令牌设置它。

+   `storage.go`文件是`Config`和`TokenSource`使用的`storage`接口。它只定义了两种方法，我们还包括了一个辅助函数来启动 OAuth2 基于代码的流程，类似于我们在上一个配方中所做的，但如果已经存在一个有效令牌的文件，它将被使用。

+   `filestorage.go`文件实现了`storage`接口。当我们存储一个新令牌时，我们首先截断文件并写入`token`结构的 JSON 表示。否则，我们解码文件并返回`token`。

# 在客户端中添加功能和函数组合

2015 年，Tomás Senart 就如何使用接口包装`http.Client`结构并利用中间件和函数组合进行了出色的演讲。您可以在[`github.com/gophercon/2015-talks`](https://github.com/gophercon/2015-talks)找到更多信息。这个配方借鉴了他的想法，并演示了在`http.Client`结构的`Transport`接口上执行相同操作的示例，类似于我们之前的配方*为 REST API 编写客户端*。

以下教程将为标准的`http.Client`结构实现日志记录和基本 auth 中间件。它还包括一个`decorate`函数，可以在需要时与各种中间件一起使用。

# 如何做...

这些步骤涵盖了编写和运行应用程序的过程：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter7/decorator`的新目录，并进入此目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter7/decorator 
```

你应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter7/decorator 
```

1.  从`~/projects/go-programming-cookbook-original/chapter7/decorator`复制测试，或者利用这个机会编写一些自己的代码！

1.  创建一个名为`config.go`的文件，内容如下：

```go
        package decorator

        import (
            "log"
            "net/http"
            "os"
        )

        // Setup initializes our ClientInterface
        func Setup() *http.Client {
            c := http.Client{}

            t := Decorate(&http.Transport{},
                Logger(log.New(os.Stdout, "", 0)),
                BasicAuth("username", "password"),
            )
            c.Transport = t
            return &c
        }
```

1.  创建一个名为`decorator.go`的文件，内容如下：

```go
        package decorator

        import "net/http"

        // TransportFunc implements the RountTripper interface
        type TransportFunc func(*http.Request) (*http.Response, error)

        // RoundTrip just calls the original function
        func (tf TransportFunc) RoundTrip(r *http.Request) 
        (*http.Response, error) {
            return tf(r)
        }

        // Decorator is a convenience function to represent our
        // middleware inner function
        type Decorator func(http.RoundTripper) http.RoundTripper

        // Decorate is a helper to wrap all the middleware
        func Decorate(t http.RoundTripper, rts ...Decorator) 
        http.RoundTripper {
            decorated := t
            for _, rt := range rts {
                decorated = rt(decorated)
            }
            return decorated
        }
```

1.  创建一个名为`middleware.go`的文件，内容如下：

```go
        package decorator

        import (
            "log"
            "net/http"
            "time"
        )

        // Logger is one of our 'middleware' decorators
        func Logger(l *log.Logger) Decorator {
            return func(c http.RoundTripper) http.RoundTripper {
                return TransportFunc(func(r *http.Request) 
                (*http.Response, error) {
                   start := time.Now()
                   l.Printf("started request to %s at %s", r.URL,     
                   start.Format("2006-01-02 15:04:05"))
                   resp, err := c.RoundTrip(r)
                   l.Printf("completed request to %s in %s", r.URL, 
                   time.Since(start))
                   return resp, err
                })
            }
        }

        // BasicAuth is another of our 'middleware' decorators
        func BasicAuth(username, password string) Decorator {
            return func(c http.RoundTripper) http.RoundTripper {
                return TransportFunc(func(r *http.Request) 
                (*http.Response, error) {
                    r.SetBasicAuth(username, password)
                    resp, err := c.RoundTrip(r)
                    return resp, err
                })
            }
        }
```

1.  创建一个名为`exec.go`的文件，内容如下：

```go
        package decorator

        import "fmt"

        // Exec creates a client, calls google.com
        // then prints the response
        func Exec() error {
            c := Setup()

            resp, err := c.Get("https://www.google.com")
            if err != nil {
                return err
            }
            fmt.Println("Response code:", resp.StatusCode)
            return nil
        }
```

1.  创建一个名为`example`的新目录，并进入。

1.  创建一个名为`main.go`的文件，内容如下：

```go
        package main

        import "github.com/PacktPublishing/
                Go-Programming-Cookbook-Second-Edition/
                chapter7/decorator"

        func main() {
            if err := decorator.Exec(); err != nil {
                panic(err)
            }
        }
```

1.  运行`go run main.go`。

1.  您也可以运行以下命令：

```go
$ go build $ ./example
```

您现在应该看到以下输出：

```go
$ go run main.go
started request to https://www.google.com at 2017-01-01 13:38:42
completed request to https://www.google.com in 194.013054ms
Response code: 200
```

1.  如果您复制或编写了自己的测试，请返回到上一级目录并运行`go test`。确保所有测试都通过了。

# 工作原理...

这个教程利用了闭包作为一等公民和接口。实现这一点的主要技巧是让一个函数实现一个接口。这使我们能够用一个函数实现的接口来包装一个结构体实现的接口。

`middleware.go`文件包含两个示例客户端中间件函数。这些可以扩展为包含其他中间件，比如更复杂的 auth 和 metrics。这个教程也可以与前一个教程结合起来，生成一个可以通过其他中间件扩展的 OAuth2 客户端。

`Decorator`函数是一个方便的函数，允许以下操作：

```go
Decorate(RoundTripper, Middleware1, Middleware2, etc)

vs

var t RoundTripper
t = Middleware1(t)
t = Middleware2(t)
etc
```

与包装客户端相比，这种方法的优势在于我们可以保持接口的稀疏性。如果您想要一个功能齐全的客户端，您还需要实现`GET`、`POST`和`PostForm`等方法。

# 理解 GRPC 客户端

GRPC 是一个高性能的 RPC 框架，使用协议缓冲区([`developers.google.com/protocol-buffers`](https://developers.google.com/protocol-buffers))和 HTTP/2([`http2.github.io`](https://http2.github.io))构建。在 Go 中创建一个 GRPC 客户端涉及到与 Go HTTP 客户端相同的许多复杂性。为了演示基本客户端的使用，最容易的方法是同时实现一个服务器。这个教程将创建一个`greeter`服务，它接受一个问候和一个名字，并返回句子`<greeting> <name>!`。此外，服务器可以指定是否感叹`!`或不是`.`(句号)。

这个教程不会探讨 GRPC 的一些细节，比如流式传输；但是，它有望作为创建一个非常基本的服务器和客户端的介绍。

# 准备就绪

在本章开头的*技术要求*部分完成初始设置步骤后，安装 GRPC ([`grpc.io/docs/quickstart/go/`](https://grpc.io/docs/quickstart/go/)) 并运行以下命令：

+   `go get -u github.com/golang/protobuf/{proto,protoc-gen-go}`

+   `go get -u google.golang.org/grpc`

# 如何做...

这些步骤涵盖了编写和运行应用程序的过程：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter7/grpc`的新目录，并进入此目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter7/grpc 
```

你应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter7/grpc 
```

1.  从`~/projects/go-programming-cookbook-original/chapter7/grpc`复制测试，或者利用这个机会编写一些自己的代码！

1.  创建一个名为`greeter`的目录并进入。

1.  创建一个名为`greeter.proto`的文件，内容如下：

```go
        syntax = "proto3";

        package greeter;

        service GreeterService{
            rpc Greet(GreetRequest) returns (GreetResponse) {}
        }

        message GreetRequest {
            string greeting = 1;
            string name = 2;
        }

        message GreetResponse{
            string response = 1;
        }
```

1.  返回到`grpc`目录。

1.  运行以下命令：

```go
$ protoc --go_out=plugins=grpc:. greeter/greeter.proto
```

1.  创建一个名为`server`的新目录，并进入该目录。

1.  创建一个名为`greeter.go`的文件，内容如下。确保修改`greeter`导入，使用你在第 3 步设置的路径：

```go
        package main

        import (
            "fmt"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter7/grpc/greeter"
            "golang.org/x/net/context"
        )

        // Greeter implements the interface
        // generated by protoc
        type Greeter struct {
            Exclaim bool
        }

        // Greet implements grpc Greet
        func (g *Greeter) Greet(ctx context.Context, r 
        *greeter.GreetRequest) (*greeter.GreetResponse, error) {
            msg := fmt.Sprintf("%s %s", r.GetGreeting(), r.GetName())
            if g.Exclaim {
                msg += "!"
            } else {
                msg += "."
            }
            return &greeter.GreetResponse{Response: msg}, nil
        }
```

1.  创建一个名为`server.go`的文件，内容如下。确保修改`greeter`导入，使用你在第 3 步设置的路径：

```go
        package main

        import (
            "fmt"
            "net"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter7/grpc/greeter"
            "google.golang.org/grpc"
        )

        func main() {
            grpcServer := grpc.NewServer()
            greeter.RegisterGreeterServiceServer(grpcServer, 
            &Greeter{Exclaim: true})
            lis, err := net.Listen("tcp", ":4444")
            if err != nil {
                panic(err)
            }
            fmt.Println("Listening on port :4444")
            grpcServer.Serve(lis)
        }
```

1.  返回到`grpc`目录。

1.  创建一个名为`client`的新目录，并进入该目录。

1.  创建一个名为`client.go`的文件，内容如下。确保修改`greeter`导入，使用你在第 3 步设置的路径：

```go
        package main

        import (
            "context"
            "fmt"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter7/grpc/greeter"
            "google.golang.org/grpc"
        )

        func main() {
            conn, err := grpc.Dial(":4444", grpc.WithInsecure())
            if err != nil {
                panic(err)
            }
            defer conn.Close()

            client := greeter.NewGreeterServiceClient(conn)

            ctx := context.Background()
            req := greeter.GreetRequest{Greeting: "Hello", Name: 
            "Reader"}
            resp, err := client.Greet(ctx, &req)
            if err != nil {
                panic(err)
            }
            fmt.Println(resp)

            req.Greeting = "Goodbye"
            resp, err = client.Greet(ctx, &req)
            if err != nil {
                panic(err)
            }
            fmt.Println(resp)
        }
```

1.  返回到`grpc`目录。

1.  运行`go run ./server`，你会看到以下输出：

```go
$ go run ./server
Listening on port :4444
```

1.  在另一个终端中，从`grpc`目录运行`go run ./client`，你会看到以下输出：

```go
$ go run ./client
response:"Hello Reader!" 
response:"Goodbye Reader!"
```

1.  `go.mod`文件可能会被更新，顶级示例目录中现在应该存在`go.sum`文件。

1.  如果你复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 工作原理...

GRPC 服务器设置为监听端口`4444`。一旦客户端连接，它就可以向服务器发送请求并接收响应。请求、响应和支持的方法的结构由我们在第 4 步创建的`.proto`文件所决定。在实践中，当集成到 GRPC 服务器时，它们应该提供`.proto`文件，该文件可以用于自动生成客户端。

除了客户端，`protoc`命令还会为服务器生成存根，所需的一切就是填写实现细节。生成的 Go 代码还具有 JSON 标记，相同的结构可以重用于 JSON REST 服务。我们的代码设置了一个不安全的客户端。要安全地处理 GRPC，你需要使用 SSL 证书。

# 使用 twitchtv/twirp 进行 RPC

`twitchtv/twirp` RPC 框架提供了许多 GRPC 的优点，包括使用协议缓冲区（[`developers.google.com/protocol-buffers`](https://developers.google.com/protocol-buffers)）构建模型，并允许通过 HTTP 1.1 进行通信。它还可以使用 JSON 进行通信，因此可以使用`curl`命令与`twirp` RPC 服务进行通信。这个示例将实现与之前 GRPC 部分相同的`greeter`。该服务接受一个问候和一个名字，并返回句子`<greeting> <name>!`。此外，服务器可以指定是否感叹`!`或不感叹`.`。

这个示例不会探索`twitchtv/twirp`的其他功能，主要关注基本的客户端-服务器通信。有关支持的更多信息，请访问他们的 GitHub 页面（[`github.com/twitchtv/twirp`](https://github.com/twitchtv/twirp)）。

# 准备就绪

完成本章开头*技术要求*部分提到的初始设置步骤后，安装 twirp [`twitchtv.github.io/twirp/docs/install.html`](https://twitchtv.github.io/twirp/docs/install.html)，并运行以下命令：

+   `go get -u github.com/golang/protobuf/{proto,protoc-gen-go}`

+   `go get github.com/twitchtv/twirp/protoc-gen-twirp`

# 如何操作...

这些步骤涵盖了编写和运行应用程序的过程：

1.  从你的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter7/twirp`的新目录，并进入该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter7/twirp 
```

你应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter7/twirp 
```

1.  从`~/projects/go-programming-cookbook-original/chapter7/twirp`复制测试，或者将其作为练习编写一些自己的代码！

1.  创建一个名为`rpc/greeter`的目录，并进入该目录。

1.  创建一个名为`greeter.proto`的文件，内容如下：

```go
        syntax = "proto3";

        package greeter;

        service GreeterService{
            rpc Greet(GreetRequest) returns (GreetResponse) {}
        }

        message GreetRequest {
            string greeting = 1;
            string name = 2;
        }

        message GreetResponse{
            string response = 1;
        }
```

1.  返回到`twirp`目录。

1.  运行以下命令：

```go
$ protoc --proto_path=$GOPATH/src:. --twirp_out=. --go_out=. ./rpc/greeter/greeter.proto
```

1.  创建一个名为`server`的新目录，并进入该目录。

1.  创建一个名为`greeter.go`的文件，内容如下。确保修改`greeter`导入，使用你在第 3 步设置的路径：

```go
package main

import (
  "context"
  "fmt"

  "github.com/PacktPublishing/
   Go-Programming-Cookbook-Second-Edition/
   chapter7/twirp/rpc/greeter"
)

// Greeter implements the interface
// generated by protoc
type Greeter struct {
  Exclaim bool
}

// Greet implements twirp Greet
func (g *Greeter) Greet(ctx context.Context, r *greeter.GreetRequest) (*greeter.GreetResponse, error) {
  msg := fmt.Sprintf("%s %s", r.GetGreeting(), r.GetName())
  if g.Exclaim {
    msg += "!"
  } else {
    msg += "."
  }
  return &greeter.GreetResponse{Response: msg}, nil
}
```

1.  创建一个名为`server.go`的文件，内容如下。确保修改`greeter`导入以使用您在第 3 步设置的路径：

```go
package main

import (
  "fmt"
  "net/http"

  "github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter7/twirp/rpc/greeter"
)

func main() {
  server := &Greeter{}
  twirpHandler := greeter.NewGreeterServiceServer(server, nil)

  fmt.Println("Listening on port :4444")
  http.ListenAndServe(":4444", twirpHandler)
}
```

1.  导航回到`twirp`目录的上一级目录。

1.  创建一个名为`client`的新目录并导航到该目录。

1.  创建一个名为`client.go`的文件，内容如下。确保修改`greeter`导入以使用您在第 3 步设置的路径：

```go
package main

import (
  "context"
  "fmt"
  "net/http"

  "github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter7/twirp/rpc/greeter"
)

func main() {
  // you can put in a custom client for tighter controls on timeouts etc.
  client := greeter.NewGreeterServiceProtobufClient("http://localhost:4444", &http.Client{})

  ctx := context.Background()
  req := greeter.GreetRequest{Greeting: "Hello", Name: "Reader"}
  resp, err := client.Greet(ctx, &req)
  if err != nil {
    panic(err)
  }
  fmt.Println(resp)

  req.Greeting = "Goodbye"
  resp, err = client.Greet(ctx, &req)
  if err != nil {
    panic(err)
  }
  fmt.Println(resp)
}
```

1.  导航回到`twirp`目录的上一级目录。

1.  运行`go run ./server`，您将看到以下输出：

```go
$ go run ./server
Listening on port :4444
```

1.  在另一个终端中，从`twirp`目录运行`go run ./client`。您应该会看到以下输出：

```go
$ go run ./client
response:"Hello Reader." 
response:"Goodbye Reader."
```

1.  `go.mod`文件可能会被更新，`go.sum`文件现在应该存在于顶层配方目录中。

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 工作原理...

我们设置了`twitchtv/twirp` RPC 服务器监听端口`4444`。与 GRPC 一样，`protoc`可以用于为许多语言生成客户端，并且例如生成 Swagger ([`swagger.io/`](https://swagger.io/))文档。

与 GRPC 一样，我们首先将我们的模型定义为`.proto`文件，生成 Go 绑定，最后实现生成的接口。由于使用了`.proto`文件，只要您不依赖于任何框架的更高级功能，代码在 GRPC 和`twitchtv/twirp`之间相对可移植。

此外，因为`twitchtv/twirp`服务器支持 HTTP 1.1，我们可以使用`curl`进行如下操作：

```go
$ curl --request "POST" \ 
 --location "http://localhost:4444/twirp/greeter.GreeterService/Greet" \
 --header "Content-Type:application/json" \
 --data '{"greeting": "Greetings to", "name":"you"}' 

{"response":"Greetings to you."}
```


# 第八章：Go 应用程序的微服务

Go 是一个编写 Web 应用程序的绝佳选择。内置的`net/http`包结合`html/template`等包，可以实现现代完整功能的 Web 应用程序。它如此简单，以至于它鼓励为管理甚至是基本的长期运行的应用程序启动 Web 界面。尽管标准库功能齐全，但仍然有大量第三方 Web 包，涵盖从路由到全栈框架的各种功能，包括以下内容：

+   [`github.com/urfave/negroni`](https://github.com/urfave/negroni)

+   [`github.com/gin-gonic/gin`](https://github.com/gin-gonic/gin)

+   [`github.com/labstack/echo`](https://github.com/labstack/echo)

+   [`www.gorillatoolkit.org/`](http://www.gorillatoolkit.org/)

+   [`github.com/julienschmidt/httprouter`](https://github.com/julienschmidt/httprouter)

本章的食谱将侧重于处理程序、响应和请求对象以及处理中间件等概念时可能遇到的基本任务。

在本章中，将涵盖以下食谱：

+   处理 web 处理程序、请求和 ResponseWriter 实例

+   使用结构和闭包进行有状态处理程序

+   验证 Go 结构和用户输入的输入

+   渲染和内容协商

+   实现和使用中间件

+   构建一个反向代理应用程序

+   将 GRPC 导出为 JSON API

# 技术要求

为了继续本章中的所有食谱，根据以下步骤配置您的环境：

1.  从[`golang.org/doc/install`](https://golang.org/doc/install)下载并安装 Go 1.12.6 或更高版本到您的操作系统上。

1.  打开终端或控制台应用程序；创建一个项目目录，例如`~/projects/go-programming-cookbook`，并导航到该目录。所有的代码都将在这个目录中运行和修改。

1.  将最新的代码克隆到`~/projects/go-programming-cookbook-original`，或者选择从该目录工作，而不是手动输入示例，如下所示：

```go
$ git clone git@github.com:PacktPublishing/Go-Programming-Cookbook-Second-Edition.git go-programming-cookbook-original
```

1.  从[`curl.haxx.se/download.html`](https://curl.haxx.se/download.html)安装`curl`命令。

# 处理 web 处理程序、请求和 ResponseWriter 实例

Go 定义了具有以下签名的`HandlerFunc`和`Handler`接口：

```go
// HandlerFunc implements the Handler interface
type HandlerFunc func(http.ResponseWriter, *http.Request)

type Handler interface {
    ServeHTTP(http.ResponseWriter, *http.Request)
}
```

默认情况下，`net/http`包广泛使用这些类型。例如，路由可以附加到`Handler`或`HandlerFunc`接口。本教程将探讨创建`Handler`接口，监听本地端口，并在处理`http.Request`后对`http.ResponseWriter`接口执行一些操作。这应该被视为 Go Web 应用程序和 RESTful API 的基础。

# 如何做...

以下步骤涵盖了编写和运行应用程序：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter8/handlers`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter8/handlers 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter8/handlers    
```

1.  从`~/projects/go-programming-cookbook-original/chapter8/handlers`复制测试，或者使用这个作为练习来编写一些自己的代码！

1.  创建一个名为`get.go`的文件，内容如下：

```go
        package handlers

        import (
            "fmt"
            "net/http"
        )

        // HelloHandler takes a GET parameter "name" and responds
        // with Hello <name>! in plaintext
        func HelloHandler(w http.ResponseWriter, r *http.Request) {
            w.Header().Set("Content-Type", "text/plain")
            if r.Method != http.MethodGet {
                w.WriteHeader(http.StatusMethodNotAllowed)
                return
            }
            name := r.URL.Query().Get("name")

            w.WriteHeader(http.StatusOK)
            w.Write([]byte(fmt.Sprintf("Hello %s!", name)))
        }
```

1.  创建一个名为`post.go`的文件，内容如下：

```go
        package handlers

        import (
            "encoding/json"
            "net/http"
        )

        // GreetingResponse is the JSON Response that
        // GreetingHandler returns
        type GreetingResponse struct {
            Payload struct {
                Greeting string `json:"greeting,omitempty"`
                Name string `json:"name,omitempty"`
                Error string `json:"error,omitempty"`
            } `json:"payload"`
            Successful bool `json:"successful"`
        }

        // GreetingHandler returns a GreetingResponse which either has 
        // errors or a useful payload
        func GreetingHandler(w http.ResponseWriter, r *http.Request) {
            w.Header().Set("Content-Type", "application/json")
            if r.Method != http.MethodPost {
                w.WriteHeader(http.StatusMethodNotAllowed)
                return
            }
            var gr GreetingResponse
            if err := r.ParseForm(); err != nil {
                gr.Payload.Error = "bad request"
                if payload, err := json.Marshal(gr); err == nil {
                    w.Write(payload)
                }  else if err != nil {
                    w.WriteHeader(http.StatusInternalServerError)
                }
            }
            name := r.FormValue("name")
            greeting := r.FormValue("greeting")

            w.WriteHeader(http.StatusOK)
            gr.Successful = true
            gr.Payload.Name = name
            gr.Payload.Greeting = greeting
            if payload, err := json.Marshal(gr); err == nil {
               w.Write(payload)
            }
        }
```

1.  创建一个名为`example`的新目录，并导航到该目录。

1.  创建一个名为`main.go`的文件，内容如下：

```go
        package main

        import (
            "fmt"
            "net/http"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             $ chapter8/handlers"
        )

        func main() {
            http.HandleFunc("/name", handlers.HelloHandler)
            http.HandleFunc("/greeting", handlers.GreetingHandler)
            fmt.Println("Listening on port :3333")
            err := http.ListenAndServe(":3333", nil)
            panic(err)
        }
```

1.  运行`go run main.go`。

1.  您也可以运行以下命令：

```go
$ go build $ ./example
```

您应该看到以下输出：

```go
$ go run main.go
Listening on port :3333
```

1.  在一个单独的终端中，运行以下命令：

```go
$ curl "http://localhost:3333/name?name=Reader" -X GET $ curl "http://localhost:3333/greeting" -X POST -d  
 'name=Reader;greeting=Goodbye'
```

您应该看到以下输出：

```go
$ curl "http://localhost:3333/name?name=Reader" -X GET 
Hello Reader!

$ curl "http://localhost:3333/greeting" -X POST -d 'name=Reader;greeting=Goodbye' 
{"payload":{"greeting":"Goodbye","name":"Reader"},"successful":true}
```

1.  `go.mod`文件可能会被更新，顶级食谱目录中现在应该存在`go.sum`文件。

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 工作原理...

对于这个示例，我们设置了两个处理程序。第一个处理程序期望使用名为`name`的`GET`参数的`GET`请求。当我们使用`curl`时，它返回纯文本字符串`Hello <name>!`。

第二个处理程序期望使用`PostForm`请求的`POST`方法。这是如果您使用标准 HTML 表单而没有任何 AJAX 调用时会得到的结果。或者，我们可以从请求体中解析 JSON。这通常使用`json.Decoder`来完成。我建议您也尝试这个练习。最后，处理程序发送一个 JSON 格式的响应并设置所有适当的标头。

尽管所有这些都是明确写出的，但有许多方法可以使代码更简洁，包括以下方法：

+   使用[`github.com/unrolled/render`](https://github.com/unrolled/render)来处理响应

+   使用本章中提到的各种 Web 框架来解析路由参数，限制路由到特定的 HTTP 动词，处理优雅的关闭等

# 使用结构和闭包进行有状态的处理程序

由于 HTTP 处理程序函数的签名稀疏，向处理程序添加状态可能会显得棘手。例如，有多种方法可以包含数据库连接。实现这一点的两种方法是通过闭包传递状态，这对于在单个处理程序上实现灵活性非常有用，或者使用结构。

这个示例将演示两者。我们将使用一个`struct`控制器来存储一个存储接口，并创建两个由外部函数修改的单个处理程序的路由。

# 如何做...

以下步骤涵盖了编写和运行应用程序：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter8/controllers`的新目录，并进入该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter8/controllers 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter8/controllers    
```

1.  从`~/projects/go-programming-cookbook-original/chapter8/controllers`复制测试，或者将其用作编写自己代码的练习！

1.  创建一个名为`controller.go`的文件，内容如下：

```go
        package controllers

        // Controller passes state to our handlers
        type Controller struct {
            storage Storage
        }

        // New is a Controller 'constructor'
        func New(storage Storage) *Controller {
            return &Controller{
                storage: storage,
            }
        }

        // Payload is our common response
        type Payload struct {
            Value string `json:"value"`
        }
```

1.  创建一个名为`storage.go`的文件，内容如下：

```go
        package controllers

        // Storage Interface Supports Get and Put
        // of a single value
        type Storage interface {
            Get() string
            Put(string)
        }

        // MemStorage implements Storage
        type MemStorage struct {
            value string
        }

        // Get our in-memory value
        func (m *MemStorage) Get() string {
            return m.value
        }

        // Put our in-memory value
        func (m *MemStorage) Put(s string) {
            m.value = s
        }
```

1.  创建一个名为`post.go`的文件，内容如下：

```go
        package controllers

        import (
            "encoding/json"
            "net/http"
        )

        // SetValue modifies the underlying storage of the controller 
        // object
        func (c *Controller) SetValue(w http.ResponseWriter, r 
        *http.Request) {
            if r.Method != http.MethodPost {
                w.WriteHeader(http.StatusMethodNotAllowed)
                return
            }
            if err := r.ParseForm(); err != nil {
                w.WriteHeader(http.StatusInternalServerError)
                return
            }
            value := r.FormValue("value")
            c.storage.Put(value)
            w.WriteHeader(http.StatusOK)
            p := Payload{Value: value}
            if payload, err := json.Marshal(p); err == nil {
                w.Write(payload)
            } else if err != nil {
                w.WriteHeader(http.StatusInternalServerError)
            }

        }
```

1.  创建一个名为`get.go`的文件，内容如下：

```go
        package controllers

        import (
            "encoding/json"
            "net/http"
        )

        // GetValue is a closure that wraps a HandlerFunc, if 
        // UseDefault is true value will always be "default" else it'll 
        // be whatever is stored in storage
        func (c *Controller) GetValue(UseDefault bool) http.HandlerFunc 
        {
            return func(w http.ResponseWriter, r *http.Request) {
                w.Header().Set("Content-Type", "application/json")
                if r.Method != http.MethodGet {
                    w.WriteHeader(http.StatusMethodNotAllowed)
                    return
                }
                value := "default"
                if !UseDefault {
                    value = c.storage.Get()
                }
                w.WriteHeader(http.StatusOK)
                p := Payload{Value: value}
                if payload, err := json.Marshal(p); err == nil {
                    w.Write(payload)
                }
            }
        }
```

1.  创建一个名为`example`的新目录并进入该目录。

1.  创建一个名为`main.go`的文件，内容如下：

```go
        package main

        import (
            "fmt"
            "net/http"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter8/controllers"
        )

        func main() {
            storage := controllers.MemStorage{}
            c := controllers.New(&storage)
            http.HandleFunc("/get", c.GetValue(false))
            http.HandleFunc("/get/default", c.GetValue(true))
            http.HandleFunc("/set", c.SetValue)

            fmt.Println("Listening on port :3333")
            err := http.ListenAndServe(":3333", nil)
            panic(err)
        }
```

1.  运行`go run main.go`。

1.  您还可以运行以下命令：

```go
$ go build $ ./example
```

您应该看到以下输出：

```go
$ go run main.go
Listening on port :3333
```

1.  在另一个终端中，运行以下命令：

```go
$ curl "http://localhost:3333/set" -X POST -d "value=value" 
$ curl "http://localhost:3333/get" -X GET 
$ curl "http://localhost:3333/get/default" -X GET
```

您应该看到以下输出：

```go
$ curl "http://localhost:3333/set" -X POST -d "value=value"
{"value":"value"}

$ curl "http://localhost:3333/get" -X GET 
{"value":"value"}

$ curl "http://localhost:3333/get/default" -X GET 
{"value":"default"}
```

1.  `go.mod`文件可能会被更新，顶级配方目录中现在应该存在`go.sum`文件。

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 它是如何工作的...

这些策略有效是因为 Go 允许方法满足诸如`http.HandlerFunc`之类的类型化函数。通过使用结构，我们可以在`main.go`中注入各种部分，其中包括数据库连接，日志记录等。在这个示例中，我们插入了一个`Storage`接口。连接到控制器的所有处理程序都可以使用它的方法和属性。

`GetValue`方法没有`http.HandlerFunc`签名，而是返回一个。这就是我们可以使用闭包来注入状态的方式。在`main.go`中，我们定义了两个路由，一个将`UseDefault`设置为`false`，另一个将其设置为`true`。这可以在定义跨多个路由的函数时使用，或者在使用结构时，您的处理程序感觉太繁琐时使用。

# 验证 Go 结构和用户输入的输入

Web 验证可能会有问题。这个示例将探讨使用闭包来支持验证函数的易于模拟，并在初始化控制器结构时允许对验证类型的灵活性，正如前面的示例所描述的那样。

我们将对一个结构执行此验证，但不探讨如何填充这个结构。我们可以假设数据是通过解析 JSON 有效载荷、明确从表单输入中填充或其他方法填充的。

# 如何做...

以下步骤涵盖了编写和运行应用程序的过程：

1.  从你的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter8/validation`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter8/validation 
```

你应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter8/validation    
```

1.  从`~/projects/go-programming-cookbook-original/chapter8/validation`复制测试，或者利用这个机会编写一些你自己的代码！

1.  创建一个名为`controller.go`的文件，内容如下：

```go
        package validation

        // Controller holds our validation functions
        type Controller struct {
            ValidatePayload func(p *Payload) error
        }

        // New initializes a controller with our
        // local validation, it can be overwritten
        func New() *Controller {
            return &Controller{
                ValidatePayload: ValidatePayload,
            }
        }
```

1.  创建一个名为`validate.go`的文件，内容如下：

```go
        package validation

        import "errors"

        // Verror is an error that occurs
        // during validation, we can
        // return this to a user
        type Verror struct {
            error
        }

        // Payload is the value we
        // process
        type Payload struct {
            Name string `json:"name"`
            Age int `json:"age"`
        }

        // ValidatePayload is 1 implementation of
        // the closure in our controller
        func ValidatePayload(p *Payload) error {
            if p.Name == "" {
                return Verror{errors.New("name is required")}
            }

            if p.Age <= 0 || p.Age >= 120 {
                return Verror{errors.New("age is required and must be a 
                value greater than 0 and less than 120")}
            }
            return nil
        }
```

1.  创建一个名为`process.go`的文件，内容如下：

```go
        package validation

        import (
            "encoding/json"
            "fmt"
            "net/http"
        )

        // Process is a handler that validates a post payload
        func (c *Controller) Process(w http.ResponseWriter, r 
        *http.Request) {
            if r.Method != http.MethodPost {
                w.WriteHeader(http.StatusMethodNotAllowed)
                return
            }

            decoder := json.NewDecoder(r.Body)
            defer r.Body.Close()
            var p Payload

            if err := decoder.Decode(&p); err != nil {
                fmt.Println(err)
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            if err := c.ValidatePayload(&p); err != nil {
                switch err.(type) {
                case Verror:
                    w.WriteHeader(http.StatusBadRequest)
                    // pass the Verror along
                    w.Write([]byte(err.Error()))
                    return
                default:
                    w.WriteHeader(http.StatusInternalServerError)
                    return
                }
            }
        }
```

1.  创建一个名为`example`的新目录，并导航到该目录。

1.  创建一个名为`main.go`的文件，内容如下：

```go
        package main

        import (
            "fmt"
            "net/http"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter8/validation"
        )

        func main() {
            c := validation.New()
            http.HandleFunc("/", c.Process)
            fmt.Println("Listening on port :3333")
            err := http.ListenAndServe(":3333", nil)
            panic(err)
        }
```

1.  运行`go run main.go`。

1.  你也可以运行以下命令：

```go
$ go build $ ./example
```

你应该看到以下输出：

```go
$ go run main.go
Listening on port :3333
```

1.  在另一个终端中，运行以下命令：

```go
$ curl "http://localhost:3333/" -X POST -d '{}' $ curl "http://localhost:3333/" -X POST -d '{"name":"test"}' $ curl "http://localhost:3333/" -X POST -d '{"name":"test",
  "age": 5}' -v
```

你应该看到以下输出：

```go
$ curl "http://localhost:3333/" -X POST -d '{}'
name is required

$ curl "http://localhost:3333/" -X POST -d '{"name":"test"}'
age is required and must be a value greater than 0 and 
less than 120

$ curl "http://localhost:3333/" -X POST -d '{"name":"test",
"age": 5}' -v

<lots of output, should contain a 200 OK status code>
```

1.  `go.mod`文件可能会被更新，`go.sum`文件现在应该存在于顶层食谱目录中。

1.  如果你复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 它是如何工作的...

我们通过向我们的控制器结构传递一个闭包来处理验证。对于控制器可能需要验证的任何输入，我们都需要一个这样的闭包。这种方法的优势在于我们可以在运行时模拟和替换验证函数，因此测试变得更简单。此外，我们不受限于单个函数签名，可以传递诸如数据库连接之类的东西给我们的验证函数。

这个食谱展示的另一件事是返回一个名为`Verror`的类型错误。这种类型保存了可以显示给用户的验证错误消息。这种方法的一个缺点是它不能一次处理多个验证消息。通过修改`Verror`类型以允许更多状态，例如通过包含一个映射，来容纳多个验证错误，然后从我们的`ValidatePayload`函数返回，这是可能的。

# 渲染和内容协商

Web 处理程序可以返回各种内容类型；例如，它们可以返回 JSON、纯文本、图像等。在与 API 通信时，通常可以指定和接受内容类型，以澄清你将以什么格式传递数据，以及你想要接收什么数据。

这个食谱将探讨使用`unrolled/render`和一个自定义函数来协商内容类型并相应地做出响应。

# 如何做...

以下步骤涵盖了编写和运行应用程序的过程：

1.  从你的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter8/negotiate`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter8/negotiate 
```

你应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter8/negotiate    
```

1.  复制来自`~/projects/go-programming-cookbook-original/chapter8/negotiate`的测试，或者利用这个机会编写一些你自己的代码！

1.  创建一个名为`negotiate.go`的文件，内容如下：

```go
        package negotiate

        import (
            "net/http"

            "github.com/unrolled/render"
        )

        // Negotiator wraps render and does
        // some switching on ContentType
        type Negotiator struct {
            ContentType string
            *render.Render
        }

        // GetNegotiator takes a request, and figures
        // out the ContentType from the Content-Type header
        func GetNegotiator(r *http.Request) *Negotiator {
            contentType := r.Header.Get("Content-Type")

            return &Negotiator{
                ContentType: contentType,
                Render: render.New(),
            }
        }
```

1.  创建一个名为`respond.go`的文件，内容如下：

```go
        package negotiate

        import "io"
        import "github.com/unrolled/render"

        // Respond switches on Content Type to determine
        // the response
        func (n *Negotiator) Respond(w io.Writer, status int, v 
        interface{}) {
            switch n.ContentType {
                case render.ContentJSON:
                    n.Render.JSON(w, status, v)
                case render.ContentXML:
                    n.Render.XML(w, status, v)
                default:
                    n.Render.JSON(w, status, v)
                }
        }
```

1.  创建一个名为`handler.go`的文件，内容如下：

```go
        package negotiate

        import (
            "encoding/xml"
            "net/http"
        )

        // Payload defines it's layout in xml and json
        type Payload struct {
            XMLName xml.Name `xml:"payload" json:"-"`
            Status string `xml:"status" json:"status"`
        }

        // Handler gets a negotiator using the request,
        // then renders a Payload
        func Handler(w http.ResponseWriter, r *http.Request) {
            n := GetNegotiator(r)

            n.Respond(w, http.StatusOK, &Payload{Status:       
            "Successful!"})
        }
```

1.  创建一个名为`example`的新目录，并导航到该目录。

1.  创建一个名为`main.go`的文件，内容如下：

```go
        package main

        import (
            "fmt"
            "net/http"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter8/negotiate"
        )

        func main() {
            http.HandleFunc("/", negotiate.Handler)
            fmt.Println("Listening on port :3333")
            err := http.ListenAndServe(":3333", nil)
            panic(err)
        }
```

1.  运行`go run main.go`。

1.  你也可以运行以下命令：

```go
$ go build $ ./example
```

你应该看到以下输出：

```go
$ go run main.go
Listening on port :3333
```

1.  在另一个终端中，运行以下命令：

```go
$ curl "http://localhost:3333" -H "Content-Type: text/xml" $ curl "http://localhost:3333" -H "Content-Type: application/json"
```

你应该看到以下输出：

```go
$ curl "http://localhost:3333" -H "Content-Type: text/xml"
<payload><status>Successful!</status></payload> 
$ curl "http://localhost:3333" -H "Content-Type: application/json"
{"status":"Successful!"}
```

1.  `go.mod`文件可能会被更新，`go.sum`文件现在应该存在于顶层食谱目录中。

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 工作原理...

`github.com/unrolled/render`包为这个教程做了大量的工作。如果需要处理 HTML 模板等，还有大量其他选项可以输入。这个教程可以用于在通过传递各种内容类型标头来自动协商工作时，或者通过直接操作结构来演示如何解耦中间件逻辑和处理程序。

类似的模式可以应用于接受标头，但要注意这些标头通常包含多个值，您的代码将不得不考虑到这一点。

# 实现和使用中间件

Go 中用于处理程序的中间件是一个被广泛探索的领域。有各种各样的包用于处理中间件。这个教程将从头开始创建中间件，并实现一个`ApplyMiddleware`函数来链接一系列中间件。

它还将探讨在请求上下文对象中设置值并稍后使用中间件检索它们。这将通过一个非常基本的处理程序来完成，以帮助演示如何将中间件逻辑与处理程序解耦。

# 如何做...

以下步骤涵盖了编写和运行应用程序：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter8/middleware`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter8/middleware 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter8/middleware    
```

1.  复制`~/projects/go-programming-cookbook-original/chapter8/middleware`中的测试，或者将其用作编写一些自己代码的练习！

1.  创建一个名为`middleware.go`的文件，其中包含以下内容：

```go
        package middleware

        import (
            "log"
            "net/http"
            "time"
        )

        // Middleware is what all middleware functions will return
        type Middleware func(http.HandlerFunc) http.HandlerFunc

        // ApplyMiddleware will apply all middleware, the last 
        // arguments will be the
        // outer wrap for context passing purposes
        func ApplyMiddleware(h http.HandlerFunc, middleware 
        ...Middleware) http.HandlerFunc {
            applied := h
            for _, m := range middleware {
                applied = m(applied)
            }
            return applied
        }

        // Logger logs requests, this will use an id passed in via
        // SetID()
        func Logger(l *log.Logger) Middleware {
            return func(next http.HandlerFunc) http.HandlerFunc {
                return func(w http.ResponseWriter, r *http.Request) {
                    start := time.Now()
                    l.Printf("started request to %s with id %s", r.URL, 
                    GetID(r.Context()))
                    next(w, r)
                    l.Printf("completed request to %s with id %s in
                    %s", r.URL, GetID(r.Context()), time.Since(start))
                }
            }
        }
```

1.  创建一个名为`context.go`的文件，其中包含以下内容：

```go
        package middleware

        import (
            "context"
            "net/http"
            "strconv"
        )

        // ContextID is our type to retrieve our context
        // objects
        type ContextID int

        // ID is the only ID we've defined
        const ID ContextID = 0

        // SetID updates context with the id then
        // increments it
        func SetID(start int64) Middleware {
            return func(next http.HandlerFunc) http.HandlerFunc {
                return func(w http.ResponseWriter, r *http.Request) {
                    ctx := context.WithValue(r.Context(), ID, 
                    strconv.FormatInt(start, 10))
                    start++
                    r = r.WithContext(ctx)
                    next(w, r)
                }
            }
        }

        // GetID grabs an ID from a context if set
        // otherwise it returns an empty string
        func GetID(ctx context.Context) string {
            if val, ok := ctx.Value(ID).(string); ok {
                return val
            }
            return ""
        }
```

1.  创建一个名为`handler.go`的文件，其中包含以下内容：

```go
        package middleware

        import (
            "net/http"
        )

        // Handler is very basic
        func Handler(w http.ResponseWriter, r *http.Request) {
            w.WriteHeader(http.StatusOK)
            w.Write([]byte("success"))
        }
```

1.  创建一个名为`example`的新目录并导航到该目录。

1.  创建一个名为`main.go`的文件，其中包含以下内容：

```go
        package main

        import (
            "fmt"
            "log"
            "net/http"
            "os"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter8/middleware"
        )

        func main() {
            // We apply from bottom up
            h := middleware.ApplyMiddleware(
            middleware.Handler,
            middleware.Logger(log.New(os.Stdout, "", 0)),
            middleware.SetID(100),
            ) 
            http.HandleFunc("/", h)
            fmt.Println("Listening on port :3333")
            err := http.ListenAndServe(":3333", nil)
            panic(err)
        }
```

1.  运行`go run main.go`。

1.  您还可以运行以下命令：

```go
$ go build $ ./example
```

您应该看到以下输出：

```go
$ go run main.go
Listening on port :3333
```

1.  在另一个终端中，运行以下`curl`命令多次：

```go
$ curl http://localhost:3333
```

您应该看到以下输出：

```go
$ curl http://localhost:3333
success

$ curl http://localhost:3333
success

$ curl http://localhost:3333
success
```

1.  在原始的`main.go`中，您应该看到以下内容：

```go
Listening on port :3333
started request to / with id 100
completed request to / with id 100 in 52.284µs
started request to / with id 101
completed request to / with id 101 in 40.273µs
started request to / with id 102
```

1.  `go.mod`文件可能会被更新，`go.sum`文件现在应该存在于顶级教程目录中。

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 工作原理...

中间件可以用于执行简单的操作，比如日志记录、度量收集和分析。中间件也可以用于在每个请求上动态填充变量。例如，可以收集请求中的 X-header 来设置一个 ID 或生成一个 ID，就像我们在这个教程中所做的那样。另一种 ID 策略可能是为每个请求生成一个**通用唯一标识符**（**UUID**）—这样我们就可以轻松地将日志消息关联在一起，并跟踪您的请求穿越不同的应用程序，如果多个微服务参与构建响应的话。

在处理上下文值时，考虑中间件的顺序是很重要的。通常，最好不要让中间件相互依赖。例如，在这个教程中，最好在日志中间件本身生成 UUID。然而，这个教程应该作为分层中间件和在`main.go`中初始化它们的指南。

# 构建反向代理应用程序

在这个教程中，我们将开发一个反向代理应用程序。这个想法是，通过在浏览器中访问`http://localhost:3333`，所有流量将被转发到一个可配置的主机，并且响应将被转发到您的浏览器。最终结果应该是通过我们的代理应用程序在浏览器中呈现[`www.golang.org`](https://www.golang.org)。

这可以与端口转发和 SSH 隧道结合使用，以便通过中间服务器安全地访问网站。这个配方将从头开始构建一个反向代理，但这个功能也由`net/http/httputil`包提供。使用这个包，传入的请求可以通过`Director func(*http.Request)`进行修改，传出的响应可以通过`ModifyResponse func(*http.Response) error`进行修改。此外，还支持对响应进行缓冲。

# 如何做...

以下步骤涵盖了编写和运行应用程序的过程：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter8/proxy`的新目录，并进入该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter8/proxy 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter8/proxy    
```

1.  从`~/projects/go-programming-cookbook-original/chapter8/proxy`复制测试，或者将其作为练习编写一些自己的代码！

1.  创建一个名为`proxy.go`的文件，内容如下：

```go
        package proxy

        import (
            "log"
            "net/http"
        )

        // Proxy holds our configured client
        // and BaseURL to proxy to
        type Proxy struct {
            Client *http.Client
            BaseURL string
        }

        // ServeHTTP means that proxy implements the Handler interface
        // It manipulates the request, forwards it to BaseURL, then 
        // returns the response
        func (p *Proxy) ServeHTTP(w http.ResponseWriter, r 
        *http.Request) {
            if err := p.ProcessRequest(r); err != nil {
                log.Printf("error occurred during process request: %s", 
                err.Error())
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            resp, err := p.Client.Do(r)
            if err != nil {
                log.Printf("error occurred during client operation: 
                %s", err.Error())
                w.WriteHeader(http.StatusInternalServerError)
                return
            }
            defer resp.Body.Close()
            CopyResponse(w, resp)
        }
```

1.  创建一个名为`process.go`的文件，内容如下：

```go
        package proxy

        import (
            "bytes"
            "net/http"
            "net/url"
        )

        // ProcessRequest modifies the request in accordnance
        // with Proxy settings
        func (p *Proxy) ProcessRequest(r *http.Request) error {
            proxyURLRaw := p.BaseURL + r.URL.String()

            proxyURL, err := url.Parse(proxyURLRaw)
            if err != nil {
                return err
            }
            r.URL = proxyURL
            r.Host = proxyURL.Host
            r.RequestURI = ""
            return nil
        }

        // CopyResponse takes the client response and writes everything
        // to the ResponseWriter in the original handler
        func CopyResponse(w http.ResponseWriter, resp *http.Response) {
            var out bytes.Buffer
            out.ReadFrom(resp.Body)

            for key, values := range resp.Header {
                for _, value := range values {
                w.Header().Add(key, value)
                }
            }

            w.WriteHeader(resp.StatusCode)
            w.Write(out.Bytes())
        }
```

1.  创建一个名为`example`的新目录并进入。

1.  创建一个名为`main.go`的文件，内容如下：

```go
        package main

        import (
            "fmt"
            "net/http"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter8/proxy"
        )

        func main() {
            p := &proxy.Proxy{
                Client: http.DefaultClient,
                BaseURL: "https://www.golang.org",
            }
            http.Handle("/", p)
            fmt.Println("Listening on port :3333")
            err := http.ListenAndServe(":3333", nil)
            panic(err)
        }
```

1.  运行`go run main.go`。

1.  您也可以运行以下命令：

```go
$ go build $ ./example
```

您应该看到以下输出：

```go
$ go run main.go
Listening on port :3333
```

1.  将浏览器导航到`localhost:3333/`。您应该看到[`golang.org/`](https://golang.org/)网站呈现出来！

1.  `go.mod`文件可能已更新，`go.sum`文件现在应该存在于顶级配方目录中。

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 它是如何工作的...

Go 请求和响应对象在客户端和处理程序之间大部分是可共享的。这段代码使用了一个满足`Handler`接口的`Proxy`结构获取的请求。`main.go`文件使用了`Handle`而不是其他地方使用的`HandleFunc`。一旦请求可用，它就被修改为在请求中添加`Proxy.BaseURL`，然后客户端进行分发。最后，响应被复制回`ResponseWriter`接口。这包括所有标头、正文和状态。

如果需要，我们还可以添加一些额外的功能，比如基本的`auth`请求，令牌管理等。这对于代理管理 JavaScript 或其他客户端应用程序的会话非常有用。

# 将 GRPC 导出为 JSON API

在第七章*Web Clients and APIs*的*理解 GRPC 客户端*配方中，我们编写了一个基本的 GRPC 服务器和客户端。这个配方将扩展这个想法，将常见的 RPC 函数放在一个包中，并将它们包装在一个 GRPC 服务器和一个标准的 Web 处理程序中。当您的 API 希望支持两种类型的客户端，但又不想为常见功能复制代码时，这将非常有用。

# 准备工作

根据以下步骤配置您的环境：

1.  参考本章开头的*技术要求*部分中给出的步骤。

1.  安装 GRPC ([`grpc.io/docs/quickstart/go/`](https://grpc.io/docs/quickstart/go/))并运行以下命令：

+   `go get -u github.com/golang/protobuf/{proto,protoc-gen-go}`

+   `go get -u google.golang.org/grpc`

# 如何做...

以下步骤涵盖了编写和运行应用程序的过程：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter8/grpcjson`的新目录，并进入该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter8/grpcjson 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter8/grpcjson    
```

1.  从`~/projects/go-programming-cookbook-original/chapter8/grpcjson`复制测试，或者将其作为练习编写一些自己的代码！

1.  创建一个名为`keyvalue`的新目录并进入。

1.  创建一个名为`keyvalue.proto`的文件，内容如下：

```go
        syntax = "proto3";

        package keyvalue;

        service KeyValue{
            rpc Set(SetKeyValueRequest) returns (KeyValueResponse){}
            rpc Get(GetKeyValueRequest) returns (KeyValueResponse){}
        }

        message SetKeyValueRequest {
            string key = 1;
            string value = 2;
        }

        message GetKeyValueRequest{
            string key = 1;
        }

        message KeyValueResponse{
            string success = 1;
            string value = 2;
        }
```

1.  运行以下命令：

```go
$ protoc --go_out=plugins=grpc:. keyvalue.proto
```

1.  返回上一级目录。

1.  创建一个名为`internal`的新目录。

1.  创建一个名为`internal/keyvalue.go`的文件，内容如下：

```go
        package internal

        import (
            "golang.org/x/net/context"
            "sync"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter8/grpcjson/keyvalue"
            "google.golang.org/grpc"
            "google.golang.org/grpc/codes"
        )

        // KeyValue is a struct that holds a map
        type KeyValue struct {
            mutex sync.RWMutex
            m map[string]string
        }

        // NewKeyValue initializes the KeyValue struct and its map
        func NewKeyValue() *KeyValue {
            return &KeyValue{
                m: make(map[string]string),
            }
        }

        // Set sets a value to a key, then returns the value
        func (k *KeyValue) Set(ctx context.Context, r 
        *keyvalue.SetKeyValueRequest) (*keyvalue.KeyValueResponse, 
        error) {
            k.mutex.Lock()
            k.m[r.GetKey()] = r.GetValue()
            k.mutex.Unlock()
            return &keyvalue.KeyValueResponse{Value: r.GetValue()}, nil
        }

        // Get gets a value given a key, or say not found if 
        // it doesn't exist
        func (k *KeyValue) Get(ctx context.Context, r 
        *keyvalue.GetKeyValueRequest) (*keyvalue.KeyValueResponse, 
        error) {
            k.mutex.RLock()
            defer k.mutex.RUnlock()
            val, ok := k.m[r.GetKey()]
            if !ok {
                return nil, grpc.Errorf(codes.NotFound, "key not set")
            }
            return &keyvalue.KeyValueResponse{Value: val}, nil
        }
```

1.  创建一个名为`grpc`的新目录。

1.  创建一个名为`grpc/main.go`的文件，内容如下：

```go
        package main

        import (
            "fmt"
            "net"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter8/grpcjson/internal"
            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter8/grpcjson/keyvalue"
            "google.golang.org/grpc"
        )

        func main() {
            grpcServer := grpc.NewServer()
            keyvalue.RegisterKeyValueServer(grpcServer, 
            internal.NewKeyValue())
            lis, err := net.Listen("tcp", ":4444")
            if err != nil {
                panic(err)
            }
            fmt.Println("Listening on port :4444")
            grpcServer.Serve(lis)
        }
```

1.  创建一个名为`http`的新目录。

1.  创建一个名为`http/set.go`的文件，内容如下：

```go
        package main

        import (
            "encoding/json"
            "net/http"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter8/grpcjson/internal"
            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter8/grpcjson/keyvalue"
            "github.com/apex/log"
        )

        // Controller holds an internal KeyValueObject
        type Controller struct {
            *internal.KeyValue
        }

        // SetHandler wraps our GRPC Set
        func (c *Controller) SetHandler(w http.ResponseWriter, r 
        *http.Request) {
            var kv keyvalue.SetKeyValueRequest

            decoder := json.NewDecoder(r.Body)
            if err := decoder.Decode(&kv); err != nil {
                log.Errorf("failed to decode: %s", err.Error())
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            gresp, err := c.Set(r.Context(), &kv)
            if err != nil {
                log.Errorf("failed to set: %s", err.Error())
                w.WriteHeader(http.StatusInternalServerError)
                return
            }

            resp, err := json.Marshal(gresp)
            if err != nil {
                log.Errorf("failed to marshal: %s", err.Error())
                w.WriteHeader(http.StatusInternalServerError)
                return
            }
            w.WriteHeader(http.StatusOK)
            w.Write(resp)
        }
```

1.  创建一个名为`http/get.go`的文件，内容如下：

```go
        package main

        import (
            "encoding/json"
            "net/http"

            "google.golang.org/grpc"
            "google.golang.org/grpc/codes"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter8/grpcjson/keyvalue"
            "github.com/apex/log"
        )

        // GetHandler wraps our RPC Get call
        func (c *Controller) GetHandler(w http.ResponseWriter, r 
        *http.Request) {
            key := r.URL.Query().Get("key")
            kv := keyvalue.GetKeyValueRequest{Key: key}

            gresp, err := c.Get(r.Context(), &kv)
            if err != nil {
                if grpc.Code(err) == codes.NotFound {
                    w.WriteHeader(http.StatusNotFound)
                    return
                }
                log.Errorf("failed to get: %s", err.Error())
                w.WriteHeader(http.StatusInternalServerError)
                return
            }

            w.WriteHeader(http.StatusOK)
            resp, err := json.Marshal(gresp)
            if err != nil {
                log.Errorf("failed to marshal: %s", err.Error())
                w.WriteHeader(http.StatusInternalServerError)
                return
            }
            w.Write(resp)
        }
```

1.  创建一个名为`http/main.go`的文件，内容如下：

```go
        package main

        import (
            "fmt"
            "net/http"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter8/grpcjson/internal"
        )

        func main() {
            c := Controller{KeyValue: internal.NewKeyValue()}
            http.HandleFunc("/set", c.SetHandler)
            http.HandleFunc("/get", c.GetHandler)

            fmt.Println("Listening on port :3333")
            err := http.ListenAndServe(":3333", nil)
            panic(err)
        }
```

1.  运行`go run ./http`命令。您应该会看到以下输出：

```go
$ go run ./http
Listening on port :3333
```

1.  在单独的终端中，运行以下命令：

```go
$ curl "http://localhost:3333/set" -d '{"key":"test", 
 "value":"123"}' -v $ curl "http://localhost:3333/get?key=badtest" -v $ curl "http://localhost:3333/get?key=test" -v
```

您应该会看到以下输出：

```go
$ curl "http://localhost:3333/set" -d '{"key":"test", 
"value":"123"}' -v
{"value":"123"}

$ curl "http://localhost:3333/get?key=badtest" -v 
<should return a 404>

$ curl "http://localhost:3333/get?key=test" -v 
{"value":"123"}
```

1.  `go.mod`文件可能已更新，`go.sum`文件现在应该存在于顶层配方目录中。

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 工作原理...

尽管这个配方省略了客户端，但您可以复制第七章中*理解 GRPC 客户端*配方中的步骤，并且您应该会看到与我们的 curls 看到的相同的结果。`http`和`grpc`目录都使用相同的内部包。在这个包中，我们必须小心返回适当的 GRPC 错误代码，并将这些错误代码正确映射到我们的 HTTP 响应中。在这种情况下，我们使用`codes.NotFound`，将其映射到`http.StatusNotFound`。如果您需要处理多个错误，使用`switch`语句可能比`if...else`语句更合适。

您可能还注意到的另一件事是，GRPC 签名通常非常一致。它们接受一个请求并返回一个可选的响应和一个错误。如果您的 GRPC 调用足够重复，并且似乎很适合代码生成，那么可能可以创建一个通用的处理程序`shim`；最终您可能会看到类似`goadesign/goa`这样的包。
