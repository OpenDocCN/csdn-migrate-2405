# Go 分布式计算（二）

> 原文：[`zh.annas-archive.org/md5/BF0BD04A27ACABD0F3CDFCFC72870F45`](https://zh.annas-archive.org/md5/BF0BD04A27ACABD0F3CDFCFC72870F45)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：RESTful Web

在之前的章节中，我们看了 Go 语言中最重要的两个组件——goroutines 和 channels。在接下来的章节中，我们将使用 Go 构建一个分布式应用程序，了解如何为互联网或者在我们的情况下是 Web 编写应用程序非常重要。在本章中，我们将介绍使用 REST 网络协议构建 Web 应用程序的一种特定方式。我们还将学习如何与基于 REST 的 Web 应用程序进行交互。我们将按以下方式进行介绍：

+   对 HTTP 和会话的简要介绍

+   构建 REST 服务器的基础知识

+   设计一个简单的 REST 服务器

+   与 REST 服务器交互的工具

## HTTP 和会话

在本节中，我们将简要介绍 HTTP 协议及其随时间的演变。还讨论服务器如何使用 HTTP 会话跟踪用户状态。当我们尝试理解 REST 协议的工作原理时，这些知识将会派上用场。

### HTTP 的简要历史

为了更好地理解 REST 协议的优势，让我们先来了解一下 REST 网络协议出现之前互联网的使用方式。1990 年代的互联网主要用于存储和共享使用**HTTP**（**超文本传输协议**）标记的文档。对于本章来说，HTTP 可以总结如下：

+   HTTP 是一个网络通信协议，以 HTTP 请求开始，以 HTTP 响应结束。

+   早期的 HTTP 响应由纯文本文档组成，但很快 HTML 格式开始流行，因为它允许更多样式化的文档。

+   Web 浏览器带来了互联网的新时代：仅仅显示不同字体权重的文本文档已经不够了。CSS 和 JavaScript 开始出现，使这些文档可以定制化和更加交互。所有这些进步导致了我们现在所说的*web*。

+   可以使用 URL 和 HTTP 方法与 Web 服务器进行交互。有九种 HTTP 方法，但是在本书的目的中，我们只对其中的五种感兴趣：

+   `GET`：在发送简单的 HTTP 请求时使用

+   `POST`：当我们想在发送 HTTP 请求时包含有价值的信息时使用

+   `PUT`，`PATCH`和`DELETE`：从技术上讲，它们与`POST`方法相同，尽管在功能上有所不同

我们将在下一节重新讨论这些 HTTP 方法，并对它们进行更详细的探讨。

### HTTP 会话

HTTP 协议本身是无状态的；也就是说，它不知道谁在访问网页，谁可以向页面发送 POST 请求等等。在这个时期（1990 年代）的大多数 HTTP 服务器中，它们可以被视为文件服务器；也就是说，它们通过互联网提供静态文件。然而，现代的网络体验更加广泛。想象一下访问 Gmail 或 Facebook，网站知道我们是谁，我们看到的是为我们动态生成的定制内容。它们保持我们正在阅读的文章或正在撰写的邮件的“状态”。如果我们关闭浏览器一段时间后返回网站，它可以让我们回到我们离开的地方。鉴于 HTTP 协议和 HTTP 服务器是无状态的，这些网站如何跟踪所有这些内容并将它们链接回正确的用户呢？答案是 HTTP 会话。

当我们从浏览器登录网站时，我们提供凭据来识别自己。服务器回复的响应也包括一个标记，这个标记将在不久的将来用来识别我们。这个标记可以是会话 ID、cookie、认证头等形式。Web 服务器维护这些标记和相应的用户 ID 的表。在我们登录网站后，浏览器总是在每个请求中的头部发送相应的标记给服务器。因此，Web 服务器能够跟踪每个用户并向任何给定的用户显示正确的内容。服务器是如何做到这一点的呢？它在服务器端维护所有的状态信息！

## REST 协议

即使在 20 世纪 90 年代，计算机和互联网技术仍然迅速发展，而 Web 浏览器也在同时不断进化。这意味着 Web 服务器本身可以开始将一些工作转移到 Web 客户端；也就是说，Web 浏览器。慢慢地，这开始引导开发人员尝试不同的软件架构来开发 Web 应用程序。到 2010 年，REST 协议成为设计现代 Web 应用程序的最普遍方式。

**REST**（**表述状态转移协议**）首次由*Roy Fielding*在他的开创性论文中描述，题为*基于网络的软件架构的体系结构风格和设计*（[`www.ics.uci.edu/~fielding/pubs/dissertation/fielding_dissertation.pdf`](https://www.ics.uci.edu/~fielding/pubs/dissertation/fielding_dissertation.pdf)）。这种设计 Web 应用程序的方式有许多优点。它是实用的，CPU 使用效率高，网络负载小，对于不断增加的互联网流量更具扩展性等。以下是使用 REST 软件架构的一些属性和好处。

### 服务器和客户端架构

在*HTTP 会话*部分，我们描述了一个大部分工作都由服务器完成，浏览器负责将用户输入传递给服务器，解析服务器返回的 HTML 文档，并在浏览器中呈现给用户。REST 允许我们将应用程序分成服务器和客户端。服务器（后端）负责执行业务逻辑，客户端（前端）负责将用户交互传递给服务器。这可能听起来并没有太多改变；然而，REST 架构的其余属性将更加明显。

### 标准数据格式

REST 围绕着使用标准数据格式在后端和前端之间通信状态和数据。这导致了后端和前端的解耦。这意味着我们不再局限于只使用 Web 浏览器与服务器通信，这反过来意味着我们的服务器现在能够与 Web 应用程序、命令行应用程序等进行交互。REST 允许我们使用任何类型的数据格式进行通信，尽管 JSON 格式已经成为 REST 协议通信的通用语言。

### 资源

由于我们的前端和后端是分开的，我们需要在两者之间通信状态和数据。在前端，我们需要显示我们提供的服务的所有可用实体。这些实体被称为**资源**。

考虑一个提供 REST 接口（REST API）的服务器，它在我们的个人图书馆中有一本书的列表。在这种情况下，*书籍列表*是资源，我们可以在特定的端点从后端请求关于每本书的信息。对于我们的例子，端点可以是`<URL>/api/books`。`/api`前缀通常在 REST 应用程序中使用，表示我们正在与后端 URL 交互。资源通常可以被认为是数据的集合，就像数据库表的行。

### 重用 HTTP 协议

我们在前一小节*资源*中定义了端点，但是我们如何与它们交互呢？REST 是建立在 HTTP 协议之上的，并且它使用 HTTP 方法或在 REST 的情况下使用动词来与服务器交互。让我们以前面的例子`/api/books`为例，来了解它是如何使用的。

#### GET

REST 使用`GET`动词来检索特定资源类型的项目。鉴于我们有很多项目，可以检索特定资源项目以及检索所有可用的资源项目。通常通过提供项目的 id 来检索特定资源项目。以下显示了用于检索的两种`GET`形式：

+   `/api/books`：返回图书馆中所有书籍的列表

+   `/api/books/<id>`：返回图书馆中特定书籍的信息

#### POST

REST 使用`POST`动词来创建特定资源类型的新项目。资源创建可能需要额外的信息，这些信息在`POST`请求的正文中提供。作为正文的一部分提供的信息必须是 REST 服务器可以处理的数据格式。对`/api/books`进行 POST 表示我们想要向图书馆的书籍列表中添加一本新书。

#### PUT 和 PATCH

这些采用`/api/books/<id>`的形式。这些方法仅适用于已经存在的资源。它们将使用请求的正文更新给定资源的数据或新状态。`PUT`期望提供资源的新状态，包括未更改的字段。`PATCH`可以被认为是`PUT`的更轻松版本，因为我们不需要提供完整的新状态，而只需要更新的字段。

#### DELETE

REST 使用`DELETE`动词来删除特定的资源项目。它采用`/api/resource/<id>`的形式。它根据`<id>`删除特定的资源。REST 支持删除给定资源类型的所有项目，尽管这没有意义，因为现在用户可能会意外删除资源类型的所有项目。出于这个原因和许多其他原因，没有服务器实际实现这个功能。

### 可升级的组件

考虑到我们需要对 UI 进行更改，而这不会影响服务器逻辑的情况。如果网站没有根据客户端和服务器架构进行拆分，我们将不得不升级整个网站，这将是一项非常耗时的任务。由于前端和后端的拆分，我们可以只对所需的系统进行更改和升级。因此，我们可以确保最小的服务中断。

## REST 服务器的基础知识

现在我们了解了 REST 应用程序应该如何行为，让我们来构建一个吧！我们将首先构建一个简单的 Web 服务器，然后通过描述设计决策和 API 定义来设计图书 REST 服务器，最后根据设计构建 REST 服务器。

### 一个简单的 Web 服务器

Go 为我们提供了一个内置的用于构建 Web 服务器的库，`net/http`。对于我们想要在服务器上创建的每个端点，我们必须做两件事：

1.  为端点创建一个处理程序函数，接受两个参数，一个用于写入响应，另一个用于处理传入的请求。

1.  使用`net/http.HandleFunc`注册端点。

以下是一个简单的 Web 服务器，它接受所有传入的请求，将它们记录到控制台，然后返回`Hello, World!`消息。

```go
// helloServer.go 

package main 

import ( 
    "fmt" 
    "log" 
    "net/http" 
) 

func helloWorldHandler(w http.ResponseWriter, r *http.Request) { 
    msg := fmt.Sprintf("Received request [%s] for path: [%s]", r.Method, r.URL.Path) 
    log.Println(msg) 

    response := fmt.Sprintf("Hello, World! at Path: %s", r.URL.Path) 
    fmt.Fprintf(w, response) 
} 

func main() { 
    http.HandleFunc("/", helloWorldHandler) // Catch all Path 

    log.Println("Starting server at port :8080...") 
    http.ListenAndServe(":8080", nil) 
} 
```

在浏览器中请求 URL 时，以下是一些示例请求和响应：

```go
http://localhost:8080/ --> Hello, World! at Path: / 
http://localhost:8080/asdf htt--> Hello, World! at Path: /asdf 
http://localhost:8080/some-path/123 --> Hello, World! at Path: /some-path/123 
```

以下是服务器的输出：

```go
2017/10/03 13:35:46 Starting server at port :8080... 
2017/10/03 13:36:01 Received request [GET] for path: [/] 
2017/10/03 13:37:22 Received request [GET] for path: [/asdf] 
2017/10/03 13:37:40 Received request [GET] for path: [/some-path/123] 
```

请注意，即使我们提供了多个路径，它们都默认为`/`路径。

### 设计 REST API

我们已经了解了 HTTP 背后的历史和 REST 协议的核心概念。我们构建了一个简单的 Web 服务器，以展示构建 REST 服务器所需的一些服务器端代码。现在是时候利用我们迄今为止学到的一切来设计和构建一个 REST 服务器了。

我们将首先定义我们的 REST API 的数据格式，然后创建一个符合我们定义的 REST API 规范的 Web 服务器。

#### 数据格式

在这一部分，我们将描述书籍资源的格式，然后我们将开始定义每个 REST API 交互以及这些交互的预期结果。

##### 书籍资源

以下是书籍资源的基本定义。它是一个 JSON 数组，格式为`"<key>": "<value-type>"`，尽管应用中使用的实际实体将包含真实值：

```go
{ 
    "id": "string", 
    "title": "string", 
    "link": "string" 
} 
```

##### GET /api/books

这个 REST API 调用将检索书籍资源类型的所有项目的列表。在我们的示例中，响应的 JSON 格式包括书籍资源类型的数组。然而，这种返回格式并不是返回项目的唯一方式。另一种但更流行的格式包括一个带有"数据"键的 JSON 对象，其中包含实际结果和服务器可能希望在响应中发送的任何其他键。

现在让我们看一下我们在示例中将使用的简单格式：

```go
// Request 
GET "<URL>/api/books/" 

// Response 
[ 
  { 
     "id": "1", 
     "title": "book1", 
     "link": "http://link-to-book-1.com" 
   }, 
   { 
     "id": "2", 
     "title": "book2", 
     "link": "http://link-to-book-2.com" 
   } 
 ] 
```

##### GET /api/books/<id>

这种`GET`调用将基于提供的`<id>`检索单个书籍资源项目。一般来说，响应的 JSON 对象将是定义的资源类型，尽管服务器可能决定根据服务的逻辑添加或删除某些字段。对于我们的 API，我们将返回我们资源类型中定义的所有字段。

让我们看一个例子，当我们尝试检索 id 为`"1"`的书籍资源时：

```go
// Request 
GET "<URL>/api/books/1" 

// Response 
{ 
   "id": "1", 
   "title": "book1", 
   "link": "http://link-to-book-1.com" 
 } 
```

##### POST /api/books

这个 REST API 调用将创建一个新的书籍资源类型的项目。然而，为了创建一个新的项目，我们需要提供所有必要的数据。可能有不需要任何额外信息的`POST`请求。但在我们的情况下，我们需要发送诸如`title`和`link`之类的信息作为请求的负载。

在这个例子中，我们想要创建一个标题为`"book5"`，链接为`"http://link-to-book5.com"`的书籍项目。请注意，由于我们的服务器已经有两个书籍资源类型的项目，新项目将以`"3"`的 id 创建；这是根据我们服务器的实现。其他 REST 服务器可能会有不同的行为。

```go
// Request 
POST "<URL>/api/books" 

// payload 
{ 
   "title": "book5", 
   "link": "http://link-to-book-5.com" 
 } 

 // response 
 { 
    "id": "3", 
    "title": "book5", 
    "link": "http://link-to-book-5.com" 
  } 
```

##### PUT /api/books/<id>

我们将在我们的 REST API 中使用`PUT`来更新特定的资源类型。我们的 API 中定义的`PUT`对接受不完整数据的负载非常严格，也就是说，它将拒绝不完整的负载。

在这个例子中，我们将修改新创建的书籍`"3"`，并将其链接更改为指向`"http://link-to-book-15.com"`：

```go
// Request 
PUT "<URL>/api/books/3" 

// payload 
{ 
   "title": "book5", 
   "link": "http://link-to-book-15.com" 
 } 

 // response 
 { 
    "id": "3", 
    "title": "book5", 
    "link": "http://link-to-book-15.com" 
  }
```

##### DELETE /api/books/<id>

这是用于删除特定书籍资源的 REST API 调用。这种请求不需要主体，只需要书籍 id 作为 URL 的一部分，如下一个例子所示。

在这个例子中，我们将删除书籍`2`。请注意，我们不会在响应中返回任何内容；其他 REST 服务器可能会返回已删除的项目：

```go
  // Request 
  DELETE "<URL>/api/books/2" 

  // Response 
  [] 
```

##### 不成功的请求

我们可能会发送构造不良的请求、对不可用实体的请求或不完整的负载。对于所有这些情况，我们将发送相关的 HTTP 错误代码。根据服务器的实现，可能会返回单个错误代码。一些服务器返回标准的错误代码"404"，以增加安全性，不让恶意用户尝试查找他们不拥有的资源类型的项目。

#### 设计决策

我们已经定义了我们的 REST API，接下来我们想要实现服务器。在编写任何代码之前，制定我们希望服务器实现的目标非常重要。以下是服务器的一些规格：

+   我们需要提取`<id>`用于`PUT`、`DELETE`和单个资源`GET`请求。

+   我们希望记录每个传入的请求，类似于`helloWorldHandler`。

+   复制这么多的工作是繁琐的，也是不好的编码实践。我们可以利用闭包和函数文字来为我们创建新的函数，这些函数将合并前两点的任务。

+   为了保持示例简单，我们将使用`map[string]bookResource`来存储所有书籍资源的状态。所有操作将在此映射上进行。在现实世界的服务器中，我们通常会使用数据库来存储这些资源。

+   Go 服务器可以处理并发请求，这意味着我们应该确保书籍资源的映射免受竞争条件的影响。

让我们看看基于我们设计的代码可能是什么样子。

#### 书籍 API 的 REST 服务器

我们将程序分为以下部分：

```go
$ tree 
. 
├── books-handler 
│ ├── actions.go 
│ ├── common.go 
│ └── handler.go 
└── main.go 

1 directory, 5 files 
```

现在让我们看看每个文件的源代码。

##### 主要.go

`main.go`源文件主要负责组装和运行 Web 服务器的代码。实际响应 HTTP 请求的逻辑分布在其他文件中：

```go
// restServer/main.go 

package main 

import ( 
    "fmt" 
    "log" 
    "net/http" 

    booksHandler "github.com/last-ent/distributed-go/chapter4/books-handler" 
) 

func main() { 
    // Get state (map) for books available on REST server. 
    books := booksHandler.GetBooks() 
    log.Println(fmt.Sprintf("%+v", books)) 

    actionCh := make(chan booksHandler.Action) 

    // Start goroutine responsible for handling interaction with the books map 
    go booksHandler.StartBooksManager(books, actionCh) 

    http.HandleFunc("/api/books/", booksHandler.MakeHandler(booksHandler.BookHandler, "/api/books/", actionCh)) 

    log.Println("Starting server at port 8080...") 
    http.ListenAndServe(":8080", nil) 
} 
```

##### books-handler/common.go

此源文件中的代码是通用逻辑，可能会在多个请求之间共享：

通常，最好的做法是识别与特定处理程序无关的逻辑，然后将其移入`common.go`或类似的源文件，这样可以更容易找到它们并减少重复的代码。

```go
// restServer/books-handler/common.go 

package booksHandler 

import ( 
    "encoding/json" 
    "fmt" 
    "log" 
    "net/http" 
) 

// bookResource is used to hold all data needed to represent a Book resource in the books map. 
type bookResource struct { 
    Id    string 'json:"id"' 
    Title string 'json:"title"' 
    Link  string 'json:"link"' 
} 

// requestPayload is used to parse request's Payload. We ignore Id field for simplicity. 
type requestPayload struct { 
    Title string 'json:"title"' 
    Link  string 'json:"link"' 
} 

// response struct consists of all the information required to create the correct HTTP response. 
type response struct { 
    StatusCode int 
    Books      []bookResource 
} 

// Action struct is used to send data to the goroutine managing the state (map) of books. 
// RetChan allows us to send data back to the Handler function so that we can complete the HTTP request. 
type Action struct { 
    Id      string 
    Type    string 
    Payload requestPayload 
    RetChan chan<- response 
} 

// GetBooks is used to get the initial state of books represented by a map. 
func GetBooks() map[string]bookResource { 
    books := map[string]bookResource{} 
    for i := 1; i < 6; i++ { 
        id := fmt.Sprintf("%d", i) 
        books[id] = bookResource{ 
            Id:    id, 
            Title: fmt.Sprintf("Book-%s", id), 
            Link:  fmt.Sprintf("http://link-to-book%s.com", id), 
        } 
    } 
    return books 
} 

// MakeHandler shows a common pattern used reduce duplicated code. 
func MakeHandler(fn func(http.ResponseWriter, *http.Request, string, string, chan<- Action), 
    endpoint string, actionCh chan<- Action) http.HandlerFunc { 

    return func(w http.ResponseWriter, r *http.Request) { 
        path := r.URL.Path 
        method := r.Method 

        msg := fmt.Sprintf("Received request [%s] for path: [%s]", method, path) 
        log.Println(msg) 

        id := path[len(endpoint):] 
        log.Println("ID is ", id) 
        fn(w, r, id, method, actionCh) 
    } 
} 

// writeResponse uses the pattern similar to MakeHandler. 
func writeResponse(w http.ResponseWriter, resp response) { 
    var err error 
    var serializedPayload []byte 

    if len(resp.Books) == 1 { 
        serializedPayload, err = json.Marshal(resp.Books[0]) 
    } else { 
        serializedPayload, err = json.Marshal(resp.Books) 
    } 

    if err != nil { 
        writeError(w, http.StatusInternalServerError) 
        fmt.Println("Error while serializing payload: ", err) 
    } else { 
        w.Header().Set("Content-Type", "application/json") 
        w.WriteHeader(resp.StatusCode) 
        w.Write(serializedPayload) 
    } 
} 

// writeError allows us to return error message in JSON format. 
func writeError(w http.ResponseWriter, statusCode int) { 
    jsonMsg := struct { 
        Msg  string 'json:"msg"' 
        Code int    'json:"code"' 
    }{ 
        Code: statusCode, 
        Msg:  http.StatusText(statusCode), 
    } 

    if serializedPayload, err := json.Marshal(jsonMsg); err != nil { 
        http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError) 
        fmt.Println("Error while serializing payload: ", err) 
    } else { 
        w.Header().Set("Content-Type", "application/json") 
        w.WriteHeader(statusCode) 
        w.Write(serializedPayload) 
    } 
} 
```

##### books-handler/actions.go

此源文件包含处理每个 HTTP 请求方法调用的函数：

```go
// restServer/books-handler/actions.go 

package booksHandler 

import ( 
    "net/http" 
) 

// actOn{GET, POST, DELETE, PUT} functions return Response based on specific Request type. 

func actOnGET(books map[string]bookResource, act Action) { 
    // These initialized values cover the case: 
    // Request asked for an id that doesn't exist. 
    status := http.StatusNotFound 
    bookResult := []bookResource{} 

    if act.Id == "" { 

        // Request asked for all books. 
        status = http.StatusOK 
        for _, book := range books { 
            bookResult = append(bookResult, book) 
        } 
    } else if book, exists := books[act.Id]; exists { 

        // Request asked for a specific book and the id exists. 
        status = http.StatusOK 
        bookResult = []bookResource{book} 
    } 

    act.RetChan <- response{ 
        StatusCode: status, 
        Books:      bookResult, 
    } 
} 

func actOnDELETE(books map[string]bookResource, act Action) { 
    book, exists := books[act.Id] 
    delete(books, act.Id) 

    if !exists { 
        book = bookResource{} 
    } 

    // Return the deleted book if it exists else return an empty book. 
    act.RetChan <- response{ 
        StatusCode: http.StatusOK, 
        Books:      []bookResource{book}, 
    } 
} 

func actOnPUT(books map[string]bookResource, act Action) { 
    // These initialized values cover the case: 
    // Request asked for an id that doesn't exist. 
    status := http.StatusNotFound 
    bookResult := []bookResource{} 

    // If the id exists, update its values with the values from the payload. 
    if book, exists := books[act.Id]; exists { 
        book.Link = act.Payload.Link 
        book.Title = act.Payload.Title 
        books[act.Id] = book 

        status = http.StatusOK 
        bookResult = []bookResource{books[act.Id]} 
    } 

    // Return status and updated resource. 
    act.RetChan <- response{ 
        StatusCode: status, 
        Books:      bookResult, 
    } 

} 

func actOnPOST(books map[string]bookResource, act Action, newID string) { 
     // Add the new book to 'books'. 
     books[newID] = bookResource{ 
         Id:    newID, 
         Link:  act.Payload.Link, 
         Title: act.Payload.Title, 
    } 

    act.RetChan <- response{ 
        StatusCode: http.StatusCreated, 
        Books:      []bookResource{books[newID]}, 
    } 
} 
```

##### books-handler/handler.go

`handler.go`源文件包含处理和处理书籍请求所需的所有逻辑。请注意，除了包含处理 HTTP 请求的逻辑外，它还处理了服务器上书籍状态的维护：

```go
// restServer/books-handler/handler.go 

package booksHandler 

import ( 
    "encoding/json" 
    "fmt" 
    "io/ioutil" 
    "log" 
    "net/http" 
) 

// StartBooksManager starts a goroutine that changes the state of books (map). 
// Primary reason to use a goroutine instead of directly manipulating the books map is to ensure 
// that we do not have multiple requests changing books' state simultaneously. 
func StartBooksManager(books map[string]bookResource, actionCh <-chan Action) { 
    newID := len(books) 
    for { 
        select { 
        case act := <-actionCh: 
            switch act.Type { 
            case "GET": 
                actOnGET(books, act) 
            case "POST": 
                newID++ 
                newBookID := fmt.Sprintf("%d", newID) 
                actOnPOST(books, act, newBookID) 
            case "PUT": 
                actOnPUT(books, act) 
            case "DELETE": 
                actOnDELETE(books, act) 
            } 
        }  
    } 
} 

/* BookHandler is responsible for ensuring that we process only the valid HTTP Requests. 

 * GET -> id: Any 

 * POST -> id: No 
 *      -> payload: Required 

 * PUT -> id: Any 
 *     -> payload: Required 

 * DELETE -> id: Any 
*/ 
func BookHandler(w http.ResponseWriter, r *http.Request, id string, method string, actionCh chan<- Action) { 

     // Ensure that id is set only for valid requests 
     isGet := method == "GET"
     idIsSetForPost := method == "POST" && id != ""
     isPutOrPost := method == "PUT" || method == "POST"
     idIsSetForDelPut := (method == "DELETE" || method == "PUT") && id != ""
     if !isGet && !(idIsSetForPost || idIsSetForDelPut || isPutOrPost) {
         writeError(w, http.StatusMethodNotAllowed) 
         return 
     } 

     respCh := make(chan response) 
     act := Action{ 
         Id:      id, 
         Type:    method, 
         RetChan: respCh, 
     } 

     // PUT & POST require a properly formed JSON payload 
     if isPutOrPost { 
         var reqPayload requestPayload 
         body, _ := ioutil.ReadAll(r.Body) 
         defer r.Body.Close() 

         if err := json.Unmarshal(body, &reqPayload); err != nil { 
             writeError(w, http.StatusBadRequest) 
             return 
         } 

         act.Payload = reqPayload 
     } 

     // We have all the data required to process the Request. 
     // Time to update the state of books. 
     actionCh <- act 

     // Wait for respCh to return data after updating the state of books. 
     // For all successful Actions, the HTTP status code will either be 200 or 201\. 
     // Any other status code means that there was an issue with the request. 
     var resp response 
     if resp = <-respCh; resp.StatusCode > http.StatusCreated { 
         writeError(w, resp.StatusCode) 
         return 
     } 

     // We should only log the delete resource and not send it back to user 
     if method == "DELETE" { 
         log.Println(fmt.Sprintf("Resource ID %s deleted: %+v", id, resp.Books)) 
         resp = response{ 
             StatusCode: http.StatusOK, 
             Books:      []bookResource{}, 
         } 
     } 

     writeResponse(w, resp) 
 } 
```

尽管我们已经从头开始创建了一个 REST 服务器，但这并不是一个完整的 REST 服务器。为了使编写 REST 服务器成为可能，许多重要细节已被省略。但实际上，我们应该使用现有的库之一来帮助我们构建一个合适的 REST 服务器。

到目前为止一切顺利，但根据我们迄今为止看到的代码，我们如何与 REST 服务器以及基于该代码的服务器进行交互？让我们在下一节中看看这个问题。

## 如何进行 REST 调用

到目前为止，我们已经使用 Web 浏览器进行了 HTTP 请求。这适用于普通的 HTTP 服务器或对 REST 服务器进行简单的`GET`请求。但是，浏览器将无法代表我们进行其他类型的 REST 调用。

大多数 Web 应用程序使用 JavaScript、Ajax 和其他前端技术与 REST 服务器进行交互。但是，我们不必创建一个完整的 Web 前端来与 REST 服务器进行交互；我们可以利用一些工具，还可以编写程序来代替我们进行 REST 调用。

### cURL

cURL 是一个免费的命令行工具，用于在计算机网络上进行交互。它可以用于多种协议的通信，包括 HTTP、HTTPS、FTP、SCP 等。让我们对在前一节中创建的服务器进行 REST 调用。为了提高可读性，我们可以使用`jq`库。 

#### GET

现在让我们看看使用 cURL 命令进行 HTTP 请求。根据服务器的状态，进行`GET`请求可能会有不同的输出：

```go
$ # List all books on server 
$ # Note that we use '-L' flag while using cURL. 
$ # This takes care of any http redirections that might be required. 
$ curl -L localhost:8080/api/books | jq # GET CALL 
 % Total % Received % Xferd Average Speed Time Time Time Current 
 Dload Upload Total Spent Left Speed 
100 46 100 46 0 0 9721 0 --:--:-- --:--:-- --:--:-- 11500 
100 311 100 311 0 0 59589 0 --:--:-- --:--:-- --:--:-- 59589 
[ 
 { 
 "id": "3", 
 "title": "Book-3", 
 "link": "http://link-to-book3.com" 
 }, 
 { 
 "id": "4", 
 "title": "Book-4", 
 "link": "http://link-to-book4.com" 
 }, 
 { 
 "id": "5", 
 "title": "Book-5", 
 "link": "http://link-to-book5.com" 
 }, 
 { 
 "id": "1", 
 "title": "Book-1", 
 "link": "http://link-to-book1.com" 
 }, 
 { 
 "id": "2", 
 "title": "Book-2", 
 "link": "http://link-to-book2.com" 
 } 
] 

$ curl localhost:8080/api/books/3 | jq # GET a single resource. 
 % Total % Received % Xferd Average Speed Time Time Time Current 
 Dload Upload Total Spent Left Speed 
100 61 100 61 0 0 13255 0 --:--:-- --:--:-- --:--:-- 15250 
{ 
 "id": "3", 
 "title": "Book-3", 
 "link": "http://link-to-book3.com" 
} 
```

#### DELETE

假设我们有一个 id 为`"2"`的书籍，我们可以使用 cURL 进行删除，如下所示：

```go
$ # We can make other method calls by providing -X flag with method name in caps. 
$ curl -LX DELETE localhost:8080/api/books/2 | jq # DELETE a resource. 
 % Total % Received % Xferd Average Speed Time Time Time Current 
 Dload Upload Total Spent Left Speed 
100 2 100 2 0 0 337 0 --:--:-- --:--:-- --:--:-- 400 
[] 
$ curl -L localhost:8080/api/books | jq # GET all books after resource deletion. 
 % Total % Received % Xferd Average Speed Time Time Time Current 
 Dload Upload Total Spent Left Speed 
100 46 100 46 0 0 21465 0 --:--:-- --:--:-- --:--:-- 46000 
100 249 100 249 0 0 91008 0 --:--:-- --:--:-- --:--:-- 91008 
[ 
 { 
 "id": "5", 
 "title": "Book-5", 
 "link": "http://link-to-book5.com" 
 }, 
 { 
 "id": "1", 
 "title": "Book-1", 
 "link": "http://link-to-book1.com" 
 }, 
 { 
 "id": "3", 
 "title": "Book-3", 
 "link": "http://link-to-book3.com" 
 }, 
 { 
 "id": "4", 
 "title": "Book-4", 
 "link": "http://link-to-book4.com" 
 } 
] 
```

#### PUT

让我们更新具有 id 为`"4"`的现有书籍资源：

```go
$ # We can use -d flag to provide payload in a Request 
$ curl -H "Content-Type: application/json" -LX PUT -d '{"title": "New Book Title", "link": "New Link"}' localhost:8080/api/books/4 | jq 
 % Total % Received % Xferd Average Speed Time Time Time Current 
 Dload Upload Total Spent Left Speed 
100 100 100 53 100 47 13289 11785 --:--:-- --:--:-- --:--:-- 17666 
{ 
 "id": "4", 
 "title": "New Book Title", 
 "link": "New Link" 
} 
$ curl -L localhost:8080/api/books | jq # GET all books after updating a resource 
 % Total % Received % Xferd Average Speed Time Time Time Current 
 Dload Upload Total Spent Left Speed 
100 46 100 46 0 0 9886 0 --:--:-- --:--:-- --:--:-- 11500 
100 241 100 241 0 0 47024 0 --:--:-- --:--:-- --:--:-- 47024 
[ 
 { 
 "id": "1", 
 "title": "Book-1", 
 "link": "http://link-to-book1.com" 
 }, 
 { 
 "id": "3", 
 "title": "Book-3", 
 "link": "http://link-to-book3.com" 
 }, 
 { 
 "id": "4", 
 "title": "New Book Title", 
 "link": "New Link" 
 }, 
 { 
 "id": "5", 
 "title": "Book-5", 
 "link": "http://link-to-book5.com" 
 } 
] 
```

#### POST

现在我们知道如何使用 cURL 向服务器发送有效负载，让我们创建一个新的书籍资源项：

```go
$ curl -H "Content-Type: application/json" -LX POST -d '{"title":"Ultra New Book", "link": "Ultra New Link"}' localhost:8080/api/books/ | jq # POST ie., create a new resource. 
 % Total % Received % Xferd Average Speed Time Time Time Current 
 Dload Upload Total Spent Left Speed 
100 111 100 59 100 52 99k 89655 --:--:-- --:--:-- --:--:-- 59000 
{ 
 "id": "6", 
 "title": "Ultra New Book", 
 "link": "Ultra New Link" 
} 
 % Total % Received % Xferd Average Speed Time Time Time Current 
 Dload Upload Total Spent Left Speed 
100 46 100 46 0 0 8234 0 --:--:-- --:--:-- --:--:-- 9200 
100 301 100 301 0 0 46414 0 --:--:-- --:--:-- --:--:-- 46414 
[ 
 { 
 "id": "4", 
 "title": "New Book Title", 
 "link": "New Link" 
 }, 
 { 
 "id": "5", 
 "title": "Book-5", 
 "link": "http://link-to-book5.com" 
 }, 
 { 
 "id": "1", 
 "title": "Book-1", 
 "link": "http://link-to-book1.com" 
 }, 
 { 
 "id": "6", 
 "title": "Ultra New Book", 
 "link": "Ultra New Link" 
 }, 
 { 
 "id": "3", 
 "title": "Book-3", 
 "link": "http://link-to-book3.com" 
 } 
] 
```

以下是快速参考命令：

+   `curl -L localhost:8080/api/books | jq # GET CALL`

+   `curl localhost:8080/api/books/3 | jq # 获取单个资源。`

+   `curl -LX DELETE localhost:8080/api/books/2 | jq # 删除一个资源。`

+   `curl -H "Content-Type: application/json" -LX PUT -d '{"title": "New Book Title", "link": "New Link"}' localhost:8080/api/books/4 | jq`

+   `curl -H "Content-Type: application/json" -LX POST -d '{"title":"Ultra New Book", "link": "Ultra New Link"}' localhost:8080/api/books/ | jq # POST 即创建一个新资源。`

以下是服务器的控制台输出：

```go
$ go run main.go 
2017/10/09 21:07:50 map[5:{Id:5 Title:Book-5 Link:http://link-to-book5.com} 1:{Id:1 Title:Book-1 Link:http://link-to-book1.com} 2:{Id:2 Title:Book-2 Link:http://link-to-book2.com} 3:{Id:3 Title:Book-3 Link:http://link-to-book3.com} 4:{Id:4 Title:Book-4 Link:http://link-to-book4.com}] 
2017/10/09 21:07:50 Starting server at port 8080... 
2017/10/09 21:07:56 Received request [GET] for path: [/api/books/] 
2017/10/09 21:07:56 ID is 
2017/10/09 21:09:18 Received request [GET] for path: [/api/books/3] 
2017/10/09 21:09:18 ID is 3 
2017/10/09 21:11:38 Received request [DELETE] for path: [/api/books/2] 
2017/10/09 21:11:38 ID is 2 
2017/10/09 21:11:38 Resource ID 2 deleted: [{Id:2 Title:Book-2 Link:http://link-to-book2.com}] 
2017/10/09 21:12:16 Received request [GET] for path: [/api/books/] 
2017/10/09 21:12:16 ID is 
2017/10/09 21:15:22 Received request [PUT] for path: [/api/books/4] 
2017/10/09 21:15:22 ID is 4 
2017/10/09 21:16:01 Received request [GET] for path: [/api/books/] 
2017/10/09 21:16:01 ID is 
2017/10/09 21:17:07 Received request [POST] for path: [/api/books/] 
2017/10/09 21:17:07 ID is 
2017/10/09 21:17:36 Received request [GET] for path: [/api/books/] 
2017/10/09 21:17:36 ID is 
```

需要牢记的一点是，即使我们使用重定向标志`-L`，对于 POST 请求，请求体也不会被发送。我们需要确保将其发送到最终解析的端点。

这应该给我们一个如何使用 REST 客户端的基本概念。

### Postman

现在让我们看一个可以用来进行 REST 调用的基于 GUI 的工具**Postman**([`www.getpostman.com/`](https://www.getpostman.com/))。为了简洁起见，我们将看一个`GET`和一个`POST`调用。

以下屏幕截图说明了如何使用 Postman 进行`GET`请求。请注意，Postman 允许我们以易于阅读的格式查看返回的 JSON：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/a2ca97d8-66c9-4629-b037-cdf38406349c.png)

GET /api/books

以下屏幕截图显示了如何进行`POST`请求。请注意，我们可以很容易地提供一个 JSON 有效负载：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/a96d1b37-ddb5-4eb0-b640-5e525e3e100e.png)

POST /api/books

希望前面的部分和这些屏幕截图足以让我们了解如何使用 Postman。

### net/http

让我们看看如何从 Go 程序中以编程方式发送`GET`和`POST`：

```go
package main 

import ( 
    "bytes" 
    "encoding/json" 
    "fmt" 
    "io/ioutil" 
    "net/http" 
) 

type bookResource struct { 
    Id    string 'json:"id"' 
    Title string 'json:"title"' 
    Link  string 'json:"link"' 
} 

func main() { 
    // GET 
    fmt.Println("Making GET call.") 
    // It is possible that we might have error while making an HTTP request 
    // due to too many redirects or HTTP protocol error. We should check for this eventuality. 
    resp, err := http.Get("http://localhost:8080/api/books")
    if err != nil {
        fmt.Println("Error while making GET call.", err) 
        return 
    } 

    fmt.Printf("%+v\n\n", resp)

    // The response body is a data stream from the server we got the response back from. 
    // This data stream is not in a useable format yet. 
    // We need to read it from the server and convert it into a byte stream. 
    body, _ := ioutil.ReadAll(resp.Body) 
    defer resp.Body.Close() 

    var books []bookResource 
    json.Unmarshal(body, &books) 

    fmt.Println(books) 
    fmt.Println("\n") 

    // POST 
    payload, _ := json.Marshal(bookResource{ 
        Title: "New Book", 
        Link:  "http://new-book.com", 
    }) 

    fmt.Println("Making POST call.") 
    resp, err = http.Post( 
        "http://localhost:8080/api/books/", 
        "application/json", 
        bytes.NewBuffer(payload), 
    ) 
    if err != nil { 
        fmt.Println(err) 
    } 

    fmt.Printf("%+v\n\n", resp)

    body, _ = ioutil.ReadAll(resp.Body) 
    defer resp.Body.Close() 

    var book bookResource 
    json.Unmarshal(body, &book) 

    fmt.Println(book) 

    fmt.Println("\n") 
} 
```

以下是运行程序时的控制台输出：

```go
$ go run main.go 

Making GET call. 
&{Status:200 OK StatusCode:200 Proto:HTTP/1.1 ProtoMajor:1 ProtoMinor:1 Header:map[Content-Type:[application/json] Date:[Mon, 09 Oct 2017 20:07:43 GMT] Content-Length:[488]] Body:0xc4200f0040 ContentLength:488 TransferEncoding:[] Close:false Uncompressed:false Trailer:map[] Request:0xc42000a900 TLS:<nil>} 

[{2 Book-2 http://link-to-book2.com} {3 Book-3 http://link-to-book3.com} {4 Book-4 http://link-to-book4.com} {5 Book-5 http://link-to-book5.com} {6 New Book http://new-book.com} {7 New Book http://new-book.com} {8 New Book http://new-book.com} {1 Book-1 http://link-to-book1.com}] 

Making POST call. 
&{Status:201 Created StatusCode:201 Proto:HTTP/1.1 ProtoMajor:1 ProtoMinor:1 Header:map[Content-Type:[application/json] Date:[Mon, 09 Oct 2017 20:07:43 GMT] Content-Length:[58]] Body:0xc4200f0140 ContentLength:58 TransferEncoding:[] Close:false Uncompressed:false Trailer:map[] Request:0xc4200fc100 TLS:<nil>} 

{9 New Book http://new-book.com} 
```

有关`net/http`库的更多详细信息可以在[`golang.org/pkg/net/http/`](https://golang.org/pkg/net/http/)找到。

## 总结

在本章中，我们讨论了 HTTP 和会话的简要历史。接下来，我们看了 REST 协议旨在解决的问题以及它们是如何引起关注的。然后，我们深入了解了 REST 协议是什么，如何设计基于它的应用程序，如何基于我们的设计构建 REST 服务器，最后我们看了使用 cURL、Postman 和 Go 程序与 REST 服务器交互的不同方式。您可以自由选择与 REST 服务器交互的方式。但是，在本书的其余部分，我们将看到使用 cURL 与 REST 服务器交互。

现在我们已经讨论了开发分布式和面向 Web 的应用程序所必需的所有重要主题。在下一章，第五章，*介绍 Goophr*，我们可以开始讨论分布式文档索引器在概念层面上是什么，以及如何设计它，规划数据通信等等。


# 第五章：介绍 Goophr

既然我们已经对 goroutines、通道、REST 和一些用于开发 Go 应用程序的工具有了扎实的了解，让我们利用这些知识来构建一个分布式 Web 应用程序。这个应用程序的目的将是索引和搜索文档。在本章中，我们将阐述这样一个应用程序的设计结构，并且我们还将看一下我们将在项目中使用的一些剩余主题和工具。

本章可以大致分为两个部分：

+   设计概述

+   项目结构

## Goophr 是什么？

我们将构建一个应用程序来索引和搜索文档。这是我们每次使用 Google、Bing 或 DuckDuckGo 等搜索门户之一访问互联网时使用的功能。这也是一些网站借助搜索引擎提供的功能。

在接下来的几章中，我们将构建一个搜索引擎应用程序，从现有技术（如 Google、Solr 搜索引擎和 goroutines）中汲取灵感。我们的应用程序名称是对这三种技术的一种玩耍。

想象一下在任何搜索门户上搜索短语；在提交查询后，我们会得到一个包含来自我们搜索短语的术语的文本摘录的链接列表。很多时候，前几个链接往往是我们正在寻找的相关网页或文档。如何可能获得最相关文档的列表？Google 或其他搜索引擎实现这一点的方式非常复杂；他们有一个大型的计算机科学家团队不断调整搜索引擎。

我们不打算构建任何复杂的东西。通过拥有一个谦逊而实用的目标，我们可以创建一个最小但可用的搜索引擎。不过，首先让我们定义应用程序的目的和标准。

## 设计概述

既然我们已经简要描述了我们想要构建的应用程序以及构建它的原因，让我们来看看我们想要作为搜索引擎实现的功能列表：

+   它应该接受在 POST 请求中提供的文档链接并下载它们

+   它应该处理和索引下载的文档

+   它应该处理搜索查询，并以包含搜索词的摘录的文档列表作出响应

+   返回的文档列表应按文档中搜索词的出现次数较多的顺序排列

虽然我们列出了四个功能，但我们可以将应用程序分为两个主要组件：

+   **Goophr 礼宾员**：这是负责索引并返回搜索查询的文档列表的组件

+   **Goophr 图书管理员**：这是负责处理用户交互并与第一个组件交互的组件

这两个组件将作为两个 REST 服务器运行，并且所有交互都将遵循 REST 协议。因此，让我们为我们的组件定义 API 定义！在第四章中，*RESTful Web*，您注意到我们用来定义通过 REST 协议进行通信的各种 API 端点和数据定义的方法非常冗长和繁琐。如果我们有一种正式的方法来编写 API 定义，那不是更好吗？好消息是，随着 REST 协议的普及，有许多解决方案，其中一个解决方案是最广泛使用的行业标准——OpenAPI 格式。

## OpenAPI 规范

OpenAPI 让我们以标准化的方式定义 RESTful API，并且可以在不受任何特定编程语言或框架的约束下进行定义。这为我们提供了一个强大的抽象，可以定义一个 API，该 API 的初始实现可以是 Java 或 Python 中的 RESTful 服务器；同时，我们也可以将代码库移植到 Go 中，服务的行为几乎不需要或只需要进行很少的更改。

让我们列出 OpenAPI 规范的一般结构，并使用它来重新定义第四章中描述的`Books API`，*RESTful Web*。

如果我们看一下`Books API`标题，我们可以定义以下元素来描述 API：

+   我们服务器的 URL

+   关于 API 意图的基本信息

+   我们 API 中可用的路径

+   API 中每个路径可用的方法

+   请求和响应的可能描述和示例有效载荷

+   请求和响应有效载荷的模式

考虑到这些要点，让我们来看看`Books API`的 OpenAPI 规范：

```go
# openapi/books.yaml

openapi: 3.0.0
servers: 
  - url: /api 
info: 
  title: Books API 
  version: '1.0' 
  description: ; 
    API responsible for adding, reading and updating list of books. 
paths: 
  /books: 
    get: 
      description: | 
        Get list of all books 
      responses: 
        '200': 
          description: | 
            Request successfully returned list of all books 
          content: 
            application/json: 
              schema: 
                $ref: '#/components/schemas/response' 
  /books/{id}: 
    get: 
      description: | 
        Get a particular books with ID 'id' 
      responses: 
        '200': 
          description: | 
            Request was successfully completed. 
          content: 
            application/json: 
              schema: 
                $ref: '#/components/schemas/document' 
      parameters: 
        - in: query 
          name: id 
          schema: 
            type: integer 
          description: Book ID of the book to get. 
    post: 
      description: | 
        Get a particular books with ID 'id' 
      responses: 
        '200': 
          description: | 
            Request was successfully completed. 
          content: 
            application/json: 
              schema: 
                $ref: '#/components/schemas/payload' 
      requestBody: 
        content: 
          application/json: 
            schema: 
                $ref: '#/components/schemas/document' 
    put: 
      description: | 
        Update the data of a Book with ID 'id' with the payload sent in the request body. 
      responses: 
        '200': 
          description: | 
            Request was successfully completed. 
          content: 
            application/json: 
              schema: 
                $ref: '#/components/schemas/payload' 
      requestBody: 
        content: 
          application/json: 
            schema: 
                $ref: '#/components/schemas/document' 
    delete: 
      description: | 
        Get a particular books with ID 'id' 
      responses: 
        '200': 
          description: | 
            Request was successfully completed. 
      parameters: 
        - in: query 
          name: id 
          schema: 
            type: integer 
          description: Book ID of the book to get. 
components: 
  schemas: 
    response: 
      type: array 
      items: 
        $ref: '#/components/schemas/document' 

    document: 
      type: object 
      required: 
        - title 
        - link 
      properties: 
        id: 
          type: integer 
          description: Book ID 
        title: 
          type: string 
          description: Title of the book 
        link:  
          type: string 
          description: Link to the book 

    payload: 
      type: object 
      required: 
        - title 
        - link 
      properties: 
        title: 
          type: string 
          description: Title of the book 
        link:  
          type: string 
          description: Link to the book 
```

### Goophr Concierge API 定义

Goophr Concierge 是面向用户的组件，它有两个责任——索引新文档和返回查询结果。非正式地，我们可以定义 API 如下：

+   `/api/feeder`：这是用户上传文档的 API 端点

+   如果有效载荷完整且正确，POST 请求将添加新文档

+   `/api/query`：用户搜索针对此 API 端点查询的短语或术语

+   POST 请求包含带有搜索术语的有效载荷，并将返回文档列表

这个简单的 API 描述是为了我们的理解。现在让我们看看如何使用 OpenAPI 规范来制定它：

```go
# openapi/concierge.yaml

openapi: 3.0.0

servers: 
  - url: /api 
info: 
  title: Goophr Concierge API 
  version: '1.0' 
  description: > 
    API responsible for responding to user input and communicating with Goophr 
    Librarian. 
paths: 
  /feeder: 
    post: 
      description: | 
        Register new document to be indexed. 
      responses: 
        '200': 
          description: | 
            Request was successfully completed. 
          content: 
            application/json: 
              schema: 
                $ref: '#/components/schemas/response' 
        '400': 
          description: > 
            Request was not processed because payload was incomplete or 
            incorrect. 
          content: 
            application/json: 
              schema: 
                $ref: '#/components/schemas/response' 
      requestBody: 
        content: 
          application/json: 
            schema: 
              $ref: '#/components/schemas/document' 
        required: true 
  /query: 
    post: 
      description: | 
        Search query 
      responses: 
        '200': 
          description: | 
            Response consists of links to document 
          content: 
            application/json: 
              schema: 
                type: array 
                items: 
                  $ref: '#/components/schemas/document' 
      requestBody: 
        content: 
          application/json: 
            schema: 
              type: array 
              items: 
                type: string 
        required: true 
components: 
  schemas: 
    response: 
      type: object 
      properties: 
        code: 
          type: integer 
          description: Status code to send in response 
        msg: 
          type: string 
          description: Message to send in response 
    document: 
      type: object 
      required: 
        - title 
        - link 
      properties: 
        title: 
          type: string 
          description: Title of the document 
        link: 
          type: string 
          description: Link to the document
```

借助 API 描述，前面的 OpenAPI 定义应该是不言自明的。有关 OpenAPI 规范的详细信息可以在[`swagger.io/specification/`](https://swagger.io/specification/)找到。我们可以使用 Swagger 提供的工具([`editor.swagger.io/`](https://editor.swagger.io/))来更好地可视化表示我们的 API 定义。

以下是在 Swagger Editor 中查看的 Goophr Concierge OpenAPI 的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/b23d4410-fd76-4101-b6a9-2dca72407769.png)

在 Swagger Editor 上查看 OpenAPI

#### Goophr 图书管理员 API 定义

Goophr Librarian 实际上是一组文档索引的维护者，它的责任是向索引添加术语，并根据索引中可用的术语返回搜索术语的查询结果。

非正式地，我们可以定义 API 如下：

+   `/api/index`**：**Goophr Concierge 调用此 API 端点以将术语添加到实际索引

+   POST 请求将术语添加到索引

+   `/api/query`：Goophr Concierge 调用此端点来查询用户提交的搜索术语

+   POST 请求返回搜索术语的结果

以下是 Goophr 图书管理员的 OpenAPI 定义。

```go
# openapi/librarian.yaml

openapi: 3.0.0
servers: 
  - url: /api 
info: 
  title: Goophr Librarian API 
  version: '1.0' 
  description: | 
    API responsible for indexing & communicating with Goophr Concierge. 
paths: 
  /index: 
    post: 
      description: | 
        Add terms to index. 
      responses: 
        '200': 
          description: | 
            Terms were successfully added to the index. 
        '400': 
          description: > 
            Request was not processed because payload was incomplete or 
            incorrect. 
          content: 
            application/json: 
              schema: 
                $ref: '#/components/schemas/error' 
      requestBody: 
        content: 
          application/json: 
            schema: 
              $ref: '#/components/schemas/terms' 
        description: | 
          List of terms to be added to the index. 
        required: true 
  /query: 
    post: 
      description: | 
        Search for all terms in the payload. 
      responses: 
        '200': 
          description: | 
            Returns a list of all the terms along with their frequency, 
            documents the terms appear in and link to the said documents. 
          content: 
            application/json: 
              schema: 
                $ref: '#/components/schemas/results' 
        '400': 
          description: > 
            Request was not processed because payload was incomplete or 
            incorrect. 
          content: 
            application/json: 
              schema: 
                $ref: '#/components/schemas/error' 
    parameters: [] 
components: 
  schemas: 
    error: 
      type: object 
      properties: 
        msg: 
          type: string 
    term: 
      type: object 
      required: 
        - title 
        - token 
        - doc_id 
        - line_index 
        - token_index 
      properties: 
        title: 
          description: | 
            Title of the document to which the term belongs. 
          type: string 
        token: 
          description: | 
            The term to be added to the index. 
          type: string 
        doc_id: 
          description: | 
            The unique hash for each document. 
          type: string 
        line_index: 
          description: | 
            Line index at which the term occurs in the document. 
          type: integer 
        token_index: 
          description: | 
            Position of the term in the document. 
          type: integer 
    terms: 
      type: object 
      properties: 
        code: 
          type: integer 
        data: 
          type: array 
          items: 
            $ref: '#/components/schemas/term' 
    results: 
      type: object 
      properties: 
        count: 
          type: integer 
        data: 
          type: array 
          items: 
            $ref: '#/components/schemas/result' 
    result: 
      type: object 
      properties: 
        doc_id: 
          type: string 
        score: 
          type: integer
```

这两个 API 规范描述了两个组件如何相互交互，以及用户如何与它们交互。但是，这并不是完整的图片，因为即使我们只显示了两个 API 定义，实际的实现将有三个 Librarian 实例！

用户通过与 Concierge 通过`/api/feeder`和`/api/query`进行交互。Concierge 可以通过`/api/index`和`/api/query`与三个 librarian 实例进一步交互。下图显示了应用程序在广义上的外观：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/8b5f63f8-a3fa-4923-939e-b37b459c3f87.png)

Goophr 应用程序的设计

考虑到当我们需要构建一个真正的 Web 应用程序，该应用程序将被多个用户使用；在这种情况下，我们希望有多个我们的服务实例运行，以便它们可以同时为所有用户提供服务。我们可能还将我们的应用程序拆分为多个 API，并且我们需要深入了解如何设计我们的系统来处理这样的分布式工作负载。因此，为了了解如何处理这样的系统，我们将使用三个 Librarian 实例。

## 项目结构

根据上图，我们已经设计了我们的应用程序，其中包括一个 Goophr Concierge 实例和三个 Goophr Librarian 实例。为了保持我们的代码可管理，我们将把源代码分成两个主要实体和一个根级别的`docker-compose`文件：

+   `Concierge`

+   `图书管理员`

+   `docker-compose.yaml`

在第一章*，Go 的开发环境*中，我们讨论了如何创建和运行 docker 镜像。`docker run ...`对于单个镜像效果很好，但当我们想要创建一个相互交互的 docker 镜像网络时，可能会变得复杂。为了保持设置简单，我们将使用`docker-compose`（[`docs.docker.com/compose/overview/`](https://docs.docker.com/compose/overview/)）。简而言之，`docker-compose`需要一个**YAML**（**另一种标记语言**）文件，其中包含具体信息，例如要给正在运行的 docker 镜像命名，要在哪些端口上运行它们，以及要使用哪个`Dockerfile`来构建这些 docker 镜像。

以下是我们项目中将使用的`docker-compose.yaml`文件：

```go
version: '3' 

services: 
  concierge: 
    build: concierge/. 
    ports: 
      - "6060:9000" 
  a_m_librarian: 
    build: librarian/. 
    ports: 
      - "7070:9000" 
  n_z_librarian: 
      build: librarian/. 
      ports: 
        - "8080:9000" 
  others_librarian: 
      build: librarian/. 
      ports: 
        - "9090:9000"
```

请注意，`a_m_librarian`，`n_z_librarian`和`others_librarian`都是从由`librarian/Dockerfile`定义的相同 docker 镜像构建的。这比使用原始的`docker`命令启动和配置多个实例更容易。

这是我们将要开始的项目结构：

```go
$ tree . ├── concierge │ ├── api │ │ ├── feeder.go │ │ └── query.go │ ├── common │ │ ├── helpers.go │ │ └── state.go │ ├── Dockerfile │ └── main.go ├── docker-compose.yaml └── librarian ├── api │ ├── index.go │ └── query.go ├── common │ ├── helpers.go │ └── state.go ├── Dockerfile └── main.go 
```

尽管我们已经建立了一个精心设计的结构，但目前，唯一具有任何有用代码的文件是`concierge/main.go`，`concierge/Dockerfile`，`librarian/main.go`和`librarian/Dockerfile`（为了方便起见，从现在开始，我们将使用简写符号`{concierge,librarian}`/`{main.go,Dockerfile}`来表示这些文件。这种表示法受到 Bash 的启发。）

让我们来看一下`main.go`和`Dockerfile`。这两个文件对于两个组件来说几乎是相同的。为了简洁起见，我们将分别展示这两种文件，并展示它们的区别所在。

让我们从`main.go`开始：

```go
// {concierge,librarian}/main.go 
package main 

import "fmt" 

func main() { 
    fmt.Println("Hello from Concierge!")  // Or, Hello from Librarian! 
} 
```

现在让我们来看一下`Dockerfile`：

```go
# {concierge,librarian}/Dockerfile FROM golang:1.9.1 # In case of librarian, '/concierge' will be replaced with '/librarian' ADD . /go/src/github.com/last-ent/distributed-go/chapter5/goophr/concierge WORKDIR /go/src/github.com/last-ent/distributed-go/chapter5/goophr/concierge RUN go install github.com/last-ent/distributed-go/chapter5/goophr/concierge ENTRYPOINT /go/bin/concierge EXPOSE 9000 
```

如果我们运行完整的代码库，我们应该会看到类似以下的输出：

```go
$ docker-compose up --build
# ...
Creating goophr_a_m_librarian_1 ... 
Creating goophr_concierge_1 ... 
Creating goophr_m_z_librarian_1 ... 
Creating goophr_others_librarian_1 ... 
Creating goophr_a_m_librarian_1 
Creating goophr_m_z_librarian_1 
Creating goophr_others_librarian_1 
Creating goophr_others_librarian_1 ... done 
Attaching to goophr_a_m_librarian_1, goophr_m_z_librarian_1, goophr_concierge_1, goophr_others_librarian_1 
a_m_librarian_1 | Hello from Librarian! 
m_z_librarian_1 | Hello from Librarian! 
others_librarian_1 | Hello from Librarian! 
concierge_1 | Hello from Concierge! 
goophr_a_m_librarian_1 exited with code 0 
goophr_m_z_librarian_1 exited with code 0 
goophr_concierge_1 exited with code 0 
goophr_others_librarian_1 exited with code 0 
```

## 摘要

在本章中，我们首先描述了我们将在接下来的三章中构建的应用程序。然后我们将应用程序分成了两个主要组件——Goophr Concierge 和 Goophr Librarian。接下来，我们看了一下我们将在应用程序中使用的项目结构。我们还讨论了 OpenAPI，这是描述 REST API 的行业标准，并用它来定义我们的 Concierge 和 Librarian 的 API。最后，我们看了一下如何使用`docker-compose`运行我们的分布式应用程序。

在下一章中，我们将看一下 Goophr Concierge，它将与用户交互以上传文档，并响应用户的搜索查询。


# 第六章：Goophr Concierge

在前一章第五章中，*介绍 Goophr*，我们将我们的应用程序分成了两个组件：Concierge 和 Librarian。在本章中，我们将看一下 Concierge 的设计和实现。本章的主要部分如下：

+   深入了解文档馈送器和查询处理程序 API

+   解释 Concierge 的架构和逻辑流的图表

+   Concierge 的测试

## 重新审视 API 定义

让我们再次查看 Concierge 的 API 定义，并讨论定义对 API 和应用程序预期行为的传达：

```go
# openapi/concierge.yaml

openapi: 3.0.0
servers: 
  - url: /api 
info: 
  title: Goophr Concierge API 
  version: '1.0' 
  description: > 
    API responsible for responding to user input and communicating with Goophr 
    Librarian. 
paths: 
  /feeder: 
    post: 
      description: | 
        Register new document to be indexed. 
      responses: 
        '200': 
          description: | 
            Request was successfully completed. 
          content: 
            application/json: 
              schema: 
                $ref: '#/components/schemas/response' 
        '400': 
          description: > 
            Request was not processed because payload was incomplete or incorrect. 
          content: 
            application/json: 
              schema: 
                $ref: '#/components/schemas/response' 
      requestBody: 
        content: 
          application/json: 
            schema: 
              $ref: '#/components/schemas/document' 
        required: true 
  /query: 
    post: 
      description: | 
        Search query 
      responses: 
        '200': 
          description: | 
            Response consists of links to document 
          content: 
            application/json: 
              schema: 
                type: array 
                items: 
                  $ref: '#/components/schemas/document' 
      requestBody: 
        content: 
          application/json: 
            schema: 
              type: array 
              items: 
                type: string 
        required: true 
components: 
  schemas: 
    response: 
      type: object 
      properties: 
        code: 
          type: integer 
          description: Status code to send in response 
        msg: 
          type: string 
          description: Message to send in response 
    document: 
      type: object 
      required: 
        - title 
        - link 
      properties: 
        title: 
          type: string 
          description: Title of the document 
        link: 
          type: string 
          description: Link to the document 
```

根据 API 定义，我们可以说明如下：

+   所有与 Concierge 的通信都使用 JSON 格式进行。

+   Concierge 有两个端点，分别是`/api/feeder`和`/api/query`

+   `/api/feeder`：这使用`POST`方法添加新文档

+   `/api/query`：这使用`POST`方法接收搜索查询词，并返回与搜索词相关的文档列表

现在让我们详细看看每个端点。

## 文档馈送器 - REST API 端点

`/api/feeder`的主要目的是接收要索引的文档，处理它们，并将处理后的数据转发给图书管理员以添加到索引中。这意味着我们需要准确处理文档。但是，“处理文档”是什么意思呢？

它可以定义为以下一系列连续的任务：

1.  我们依赖有效载荷为我们提供标题和文档链接。我们下载链接的文档并在我们的索引中使用它。

1.  文档可以被视为一个大的文本块，可能会有多个具有相同标题的文档。我们需要能够唯一标识每个文档，并且能够轻松地检索它们。

1.  搜索查询的结果期望所提供的单词出现在文档中。这意味着我们需要从文档中提取所有单词，并跟踪单词在文档中的位置。

1.  区分“HELLO”、“hello”和“HELLO!!!”有意义吗？在它们出现的文本上下文中，它们确实传达了不同的含义。但是，对于索引来说，这取决于我们想要使索引变得多么复杂和准确。对于我们的情况，我们保持实现简单，因此我们规范化单词，也就是说，我们将单词的所有这些变体视为单个单元/令牌。此外，我们不索引代词、冠词、介词等。

对于搜索引擎来说，代词、冠词等被称为**停用词**，通常在索引中被忽略。主要原因是，虽然它们为用户提供了有价值的信息，但它们往往对索引几乎没有相关性。

1.  最后，我们想将所有这些令牌添加到由图书管理员维护的索引中。

在 Concierge 的源代码中，每个前述任务都由特定的函数处理。以下是显示每个任务的相关函数的列表：

+   任务 1：`api.FeedHandler`和`api.docProcessor`

+   任务 2：`api.docStore`和`api.lineStore`

+   任务 3 和任务 4：`api.indexProcessor`和`common.SimplifyToken`

+   任务 5：`api.indexAdder`

## 查询处理程序 - REST API 端点

同样，如果我们考虑在`/api/query`处理搜索查询的情况，我们应该能够从有效载荷中获取搜索词，从图书管理员的各个实例请求结果，处理它们，然后以搜索相关性的降序返回搜索结果给用户。但是，由于我们尚未实现图书管理员，我们将在第八章中稍后讨论此端点的实现，*部署 Goophr*，分布式搜索索引。

## 约定

Concierge 的源代码有很多组成部分。在没有任何先前理解的情况下直接跳入代码可能不是最好的方法。相反，我们将把前几节中定义的任务作为流程图呈现出来。然而，首先让我们简要看一下我们在图表和代码中使用的符号和命名约定。

### 代码约定

以下是 Concierge 中的实体：

+   **有效负载**（**p**）：这代表接收到的用于向索引添加新文档的有效负载。

+   **文档**（**d**）：这代表表示唯一文档的所有元数据。

+   **行**（**l**）：这代表文档中单行的所有元数据。

+   **标记**（**t**）：这代表文档中每个标记的所有元数据。

+   **消息**（**xMsg**）：对于给定的实体**x**，它提供了用于识别唯一实体和返回唯一实体的回调通道的信息。

+   **处理通道**（**xProcessCh**）：对于给定的实体**x**，该通道由**xProcessor** goroutine 使用来消耗和处理实体。

+   **存储**（或**数据存储**）：Concierge 还负责存储和维护系统中所有文档和行的信息。

+   **存储通道**（xStoreCh）：对于给定的实体**x**，该通道用于更新实体的存储。

+   **获取通道**（**xGetCh**或**xGetAllCh**）：这些通道由存储使用，提供一种机制来使用回调通道检索实体。

+   **done**：这是一个特殊的通道，一旦关闭，将停止所有正在运行的 goroutines。我们应该小心关闭这个通道，而不是在上面发送消息，原因是发送消息只会向一个 goroutine 发出停止信号。相反，如果我们关闭通道，所有监听该通道的 goroutines 都将收到停止消息。

让我们看一些例子，以便我们对约定有完美的理解：

+   **dStoreCh**：这是用于向文档存储添加新文档的通道

+   **dGetCh**：这是从文档存储获取单个文档的通道

### 图表约定

接下来，让我们看一下我们将在图表中使用的符号：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/32bcf0f7-1c6d-4c2c-b72a-9ba9e7398520.png)

现在，让我们通过逻辑流程图来可视化 Concierge 的逻辑。 

## 逻辑流程图

我们可以将 Concierge 的逻辑分为五个主要部分。我们将解决每个单独部分所需的逻辑流程，然后最后将它们合并在一起，以获得我们试图实现的整体情况。

### 文档处理器

首先，我们想要接受发送到端点的有效负载并开始处理文档。假设`api.FeedHandler`接受、验证并将有效负载发送到**pProcessCh**：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/a5ee380a-1d6f-440e-9360-c2fc668361c2.png)

### 文档存储

让我们来考虑一下**dStoreCh**，这是用于添加和检索文档的通道：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/9c59ee7d-56b5-4f6c-8e59-629c3aee8e6e.png)

### 索引处理器

除了添加到`docstore`中，`docProcessor`还将文档发送到`indexProcessor`，后者负责存储文档中的行并将行转换为标记：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/b6881d8b-9ad5-4e9d-a89c-7668f2375fd3.png)

### 行存储

`indexProcessor`将文档拆分为行，`lineStore`负责存储它们，并在查询时返回它们：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/809153a9-efa6-44d3-bdc8-3a91fca7456c.png)

`indexProcessor`还将行拆分为标记，并将它们添加到`iAddCh`通道。`indexAdder`负责将这些标记添加到索引（图书管理员）中。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/a70e7bec-20d6-4dd3-ab8b-66c9d0e2bb27.png)

### 综合流程图

现在我们已经定义了每个单独部分，您可能已经注意到它们相互衔接，并且它们之间有一些共享的组件。现在让我们整合所有这些流程图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/1dd32720-e188-44c8-8ee3-6308e598b06d.png)

这可能是一个很好的机会，让你自己尝试构建 Concierge。但是，请阅读以下三个设计要点，以完全了解系统。

#### 队列工作者

在综合流程图中，您可能已经注意到我们运行了四个`docProcessor`、`indexProcessor`和`indexAdder`的实例。这样做的原因是这些 goroutine 处理的任务是尴尬地并行的，也就是说，它们可以在没有副作用的情况下并行运行。这使我们能够并行处理文档，加快处理速度。

#### 单个存储

相比之下，我们将`docStore`和`lineStore`作为单个实例运行，因为我们希望为这些存储保持一致的状态。

#### 缓冲通道

对于我们代码中的几乎所有通道，我们将使用容量为 8 的缓冲通道。这样可以避免在`docProcessors`忙碌时阻塞`api.FeedHandler`端点。另外，由于队列工作者和单个存储，`lStoreCh`和`dStoreCh`的容量分别为 16。

## Concierge 源代码

现在我们已经详细讨论了 Concierge 的设计，让我们根据这些设计要点实现 Concierge。我们将在第八章，*部署 Goophr*中讨论`api/query.go`和 Dockerfile 的实现。让我们看看项目结构和源代码：

```go
$ tree 
. 
└── goophr 
    └── concierge 
        ├── api 
        │   ├── feeder.go 
        │   ├── feeder_test.go 
        │   └── query.go 
        ├── common 
        │   ├── helpers.go 
        ├── Dockerfile 
        └── main.go 

4 directories, 6 files 
```

现在让我们看看每个文件的源代码：

**main.go**：

```go
package main 

import ( 
    "net/http" 

    "github.com/last-ent/distributed-go/chapter6/goophr/concierge/api" 
    "github.com/last-ent/distributed-go/chapter6/goophr/concierge/common" 
) 

func main() { 
    common.Log("Adding API handlers...") 
    http.HandleFunc("/api/feeder", api.FeedHandler) 

    common.Log("Starting feeder...") 
    api.StartFeederSystem() 

    common.Log("Starting Goophr Concierge server on port :8080...") 
    http.ListenAndServe(":8080", nil) 
} 
```

**common/helpers.go**：

```go
package common 

import ( 
    "fmt" 
    "log" 
    "regexp" 
    "strings" 
) 

// Log is used for simple logging to console. 
func Log(msg string) { 
    log.Println("INFO - ", msg) 
} 

// Warn is used to log warning messages to console. 
func Warn(msg string) { 
    log.Println("---------------------------") 
    log.Println(fmt.Sprintf("WARN: %s", msg)) 
    log.Println("---------------------------") 
} 

var punctuations = regexp.MustCompile('^\p{P}+|\p{P}+$') 

// List of stop words that we want to ignore in our index. 
var stopWords = []string{ 
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and", "any", "are", "aren't", "as", "at", 
    "be", "because", "been", "before", "being", "below", "between", "both", "but", "by", "can't", "cannot", "could", 
    "couldn't", "did", "didn't", "do", "does", "doesn't", "doing", "don't", "down", "during", "each", "few", "for", 
    "from", "further", "had", "hadn't", "has", "hasn't", "have", "haven't", "having", "he", "he'd", "he'll", "he's", 
    "her", "here", "here's", "hers", "herself", "him", "himself", "his", "how", "how's", "i", "i'd", "i'll", "i'm", 
    "i've", "if", "in", "into", "is", "isn't", "it", "it's", "its", "itself", "let's", "me", "more", "most", "mustn't", 
    "my", "myself", "no", "nor", "not", "of", "off", "on", "once", "only", "or", "other", "ought", "our", "ours", 
    "ourselves", "out", "over", "own", "same", "shan't", "she", "she'd", "she'll", "she's", "should", "shouldn't", 
    "so", "some", "such", "than", "that", "that's", "the", "their", "theirs", "them", "themselves", "then", "there", 
    "there's", "these", "they", "they'd", "they'll", "they're", "they've", "this", "those", "through", "to", "too", 
    "under", "until", "up", "very", "was", "wasn't", "we", "we'd", "we'll", "we're", "we've", "were", "weren't", "what", 
    "what's", "when", "when's", "where", "where's", "which", "while", "who", "who's", "whom", "why", "why's", "with", 
    "won't", "would", "wouldn't", "you", "you'd", "you'll", "you're", "you've", "your", "yours", "yourself", "yourselves"} 

// SimplifyToken is responsible to normalizing a string token and 
// also checks whether the token should be indexed or not. 
func SimplifyToken(token string) (string, bool) { 
    simpleToken := strings.ToLower(punctuations.ReplaceAllString(token, "")) 

    for _, stopWord := range stopWords { 
        if stopWord == simpleToken { 
            return "", false 
        } 
    } 

    return simpleToken, true 
} 
```

**api/feeder.go**：

```go
package api 

import ( 
    "crypto/sha1" 
    "encoding/json" 
    "fmt" 
    "io/ioutil" 
    "net/http" 
    "strings" 
    "time" 

    "github.com/last-ent/distributed-go/chapter6/goophr/concierge/common" 
) 

type payload struct { 
    URL   string 'json:"url"' 
    Title string 'json:"title"' 
} 

type document struct { 
    Doc   string 'json:"-"' 
    Title string 'json:"title"' 
    DocID string 'json:"DocID"'

} 

type token struct { 
    Line   string 'json:"-"' 
    Token  string 'json:"token"' 
    Title  string 'json:"title"' 
    DocID  string 'json:"doc_id"' 
    LIndex int    'json:"line_index"' 
    Index  int    'json:"token_index"' 
} 

type dMsg struct { 
    DocID string 
    Ch    chan document 
} 

type lMsg struct { 
    LIndex int 
    DocID  string 
    Ch     chan string 
} 

type lMeta struct { 
    LIndex int 
    DocID  string 
    Line   string 
} 

type dAllMsg struct { 
    Ch chan []document 
} 

// done signals all listening goroutines to stop. 
var done chan bool 

// dGetCh is used to retrieve a single document from store. 
var dGetCh chan dMsg 

// lGetCh is used to retrieve a single line from store. 
var lGetCh chan lMsg 

// lStoreCh is used to put a line into store. 
var lStoreCh chan lMeta 

// iAddCh is used to add token to index (Librarian). 
var iAddCh chan token 

// dStoreCh is used to put a document into store. 
var dStoreCh chan document 

// dProcessCh is used to process a document and convert it to tokens. 
var dProcessCh chan document 

// dGetAllCh is used to retrieve all documents in store. 
var dGetAllCh chan dAllMsg 

// pProcessCh is used to process the /feeder's payload and start the indexing process. 
var pProcessCh chan payload 

// StartFeederSystem initializes all channels and starts all goroutines. 
// We are using a standard function instead of 'init()' 
// because we don't want the channels & goroutines to be initialized during testing. 
// Unless explicitly required by a particular test. 
func StartFeederSystem() { 
    done = make(chan bool) 

    dGetCh = make(chan dMsg, 8) 
    dGetAllCh = make(chan dAllMsg) 

    iAddCh = make(chan token, 8) 
    pProcessCh = make(chan payload, 8) 

    dStoreCh = make(chan document, 8) 
    dProcessCh = make(chan document, 8) 
    lGetCh = make(chan lMsg) 
    lStoreCh = make(chan lMeta, 8) 

    for i := 0; i < 4; i++ { 
        go indexAdder(iAddCh, done) 
        go docProcessor(pProcessCh, dStoreCh, dProcessCh, done) 
        go indexProcessor(dProcessCh, lStoreCh, iAddCh, done) 
    } 

    go docStore(dStoreCh, dGetCh, dGetAllCh, done) 
    go lineStore(lStoreCh, lGetCh, done) 
} 

// indexAdder adds token to index (Librarian). 
func indexAdder(ch chan token, done chan bool) { 
    for { 
        select { 
        case tok := <-ch: 
            fmt.Println("adding to librarian:", tok.Token) 

        case <-done: 
            common.Log("Exiting indexAdder.") 
            return 
        } 
    } 
} 

// lineStore maintains a catalog of all lines for all documents being indexed. 
func lineStore(ch chan lMeta, callback chan lMsg, done chan bool) { 
    store := map[string]string{} 
    for { 
        select { 
        case line := <-ch: 
            id := fmt.Sprintf("%s-%d", line.DocID, line.LIndex) 
            store[id] = line.Line 

        case ch := <-callback: 
            line := "" 
            id := fmt.Sprintf("%s-%d", ch.DocID, ch.LIndex) 
            if l, exists := store[id]; exists { 
                line = l 
            } 
            ch.Ch <- line 
        case <-done: 
            common.Log("Exiting docStore.") 
            return 
        } 
    } 
} 

// indexProcessor is responsible for converting a document into tokens for indexing. 
func indexProcessor(ch chan document, lStoreCh chan lMeta, iAddCh chan token, done chan bool) { 
    for { 
        select { 
        case doc := <-ch: 
            docLines := strings.Split(doc.Doc, "\n") 

            lin := 0 
            for _, line := range docLines { 
                if strings.TrimSpace(line) == "" { 
                    continue 
                } 

                lStoreCh <- lMeta{ 
                    LIndex: lin, 
                    Line:   line, 
                    DocID:  doc.DocID, 
                } 

                index := 0 
                words := strings.Fields(line) 
                for _, word := range words { 
                    if tok, valid := common.SimplifyToken(word); valid { 
                        iAddCh <- token{ 
                            Token:  tok, 
                            LIndex: lin, 
                            Line:   line, 
                            Index:  index, 
                            DocID:  doc.DocID, 
                            Title:  doc.Title, 
                        } 
                        index++ 
                    } 
                } 
                lin++ 
            } 

        case <-done: 
            common.Log("Exiting indexProcessor.") 
            return 
        } 
    } 
} 

// docStore maintains a catalog of all documents being indexed. 
func docStore(add chan document, get chan dMsg, dGetAllCh chan dAllMsg, done chan bool) { 
    store := map[string]document{} 

    for { 
        select { 
        case doc := <-add: 
            store[doc.DocID] = doc 
        case m := <-get: 
            m.Ch <- store[m.DocID] 
        case ch := <-dGetAllCh: 
            docs := []document{} 
            for _, doc := range store { 
                docs = append(docs, doc) 
            } 
            ch.Ch <- docs 
        case <-done: 
            common.Log("Exiting docStore.") 
            return 
        } 
    } 
} 

// docProcessor processes new document payloads. 
func docProcessor(in chan payload, dStoreCh chan document, dProcessCh chan document, done chan bool) { 
    for { 
        select { 
        case newDoc := <-in: 
            var err error 
            doc := "" 

            if doc, err = getFile(newDoc.URL); err != nil { 
                common.Warn(err.Error()) 
                continue 
            } 

            titleID := getTitleHash(newDoc.Title) 
            msg := document{ 
                Doc:   doc, 
                DocID: titleID, 
                Title: newDoc.Title, 
            } 

            dStoreCh <- msg 
            dProcessCh <- msg 
        case <-done: 
            common.Log("Exiting docProcessor.") 
            return 
        } 
    } 
} 

// getTitleHash returns a new hash ID everytime it is called. 
// Based on: https://gobyexample.com/sha1-hashes

func getTitleHash(title string) string {

    hash := sha1.New() 
    title = strings.ToLower(title) 

    str := fmt.Sprintf("%s-%s", time.Now(), title) 
    hash.Write([]byte(str)) 

    hByte := hash.Sum(nil) 

    return fmt.Sprintf("%x", hByte) 
} 

// getFile returns file content after retrieving it from URL. 
func getFile(URL string) (string, error) { 
    var res *http.Response 
    var err error 

    if res, err = http.Get(URL); err != nil { 
        errMsg := fmt.Errorf("Unable to retrieve URL: %s.\nError: %s", URL, err) 

        return "", errMsg 

    } 
    if res.StatusCode > 200 { 
        errMsg := fmt.Errorf("Unable to retrieve URL: %s.\nStatus Code: %d", URL, res.StatusCode) 

        return "", errMsg 
    } 

    body, err := ioutil.ReadAll(res.Body) 
    defer res.Body.Close() 

    if err != nil { 
        errMsg := fmt.Errorf("Error while reading response: URL: %s.\nError: %s", URL, res.StatusCode, err.Error()) 

        return "", errMsg 
    } 

    return string(body), nil 
} 

// FeedHandler start processing the payload which contains the file to index. 
func FeedHandler(w http.ResponseWriter, r *http.Request) { 
    if r.Method == "GET" { 
        ch := make(chan []document) 
        dGetAllCh <- dAllMsg{Ch: ch} 
        docs := <-ch 
        close(ch) 

        if serializedPayload, err := json.Marshal(docs); err == nil { 
            w.Write(serializedPayload) 
        } else { 
            common.Warn("Unable to serialize all docs: " + err.Error()) 
            w.WriteHeader(http.StatusInternalServerError) 
            w.Write([]byte('{"code": 500, "msg": "Error occurred while trying to retrieve documents."}')) 
        } 
        return 
    } else if r.Method != "POST" { 
        w.WriteHeader(http.StatusMethodNotAllowed) 
        w.Write([]byte('{"code": 405, "msg": "Method Not Allowed."}')) 
        return 
    } 

    decoder := json.NewDecoder(r.Body) 
    defer r.Body.Close() 

    var newDoc payload 
    decoder.Decode(&newDoc) 
    pProcessCh <- newDoc 

    w.Write([]byte('{"code": 200, "msg": "Request is being processed."}')) 
} 
```

**api/feeder_test.go**：

```go
package api 

import ( 
    "fmt" 
    "net/http" 
    "net/http/httptest" 
    "testing" 
) 

func TestGetTitleHash(t *testing.T) { 

    h1 := getTitleHash("A-Title") 
    h2 := getTitleHash("Diff Title") 
    hDup := getTitleHash("A-Title") 

    for _, tc := range []struct { 
        name     string 
        hashes   []string 
        expected bool 
    }{ 
        {"Different Titles", []string{h1, h2}, false}, 
        {"Duplicate Titles", []string{h1, hDup}, false}, 
        {"Same hashes", []string{h2, h2}, true}, 
    } { 
        t.Run(tc.name, func(t *testing.T) { 
            actual := tc.hashes[0] == tc.hashes[1] 
            if actual != tc.expected { 
                t.Error(actual, tc.expected, tc.hashes) 
            } 
        }) 
    } 
} 

func TestGetFile(t *testing.T) { 
    doc := "Server returned text!" 
    testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { 
        w.Write([]byte(doc)) 
    })) 
    defer testServer.Close() 

    rDoc, err := getFile(testServer.URL) 
    if err != nil { 
        t.Error("Error while retrieving document", err) 
    } 
    if doc != rDoc { 
        t.Error(doc, "!=", rDoc) 
    } 
} 

func TestIndexProcessor(t *testing.T) { 
    ch1 := make(chan document, 1) 
    ch2 := make(chan lMeta, 1) 
    ch3 := make(chan token, 3) 
    done := make(chan bool) 

    go indexProcessor(ch1, ch2, ch3, done) 

    ch1 <- document{ 
        DocID: "a-hash", 
        Title: "a-title", 
        Doc:   "Golang Programming rocks!", 
    } 

    for i, tc := range []string{ 
        "golang", "programming", "rocks", 
    } { 
        t.Run(fmt.Sprintf("Testing if '%s' is returned. at index: %d", tc, i), func(t *testing.T) { 
            tok := <-ch3 
            if tok.Token != tc { 
                t.Error(tok.Token, "!=", tc) 
            } 
            if tok.Index != i { 
                t.Error(tok.Index, "!=", i) 
            } 
        }) 
    } 
    close(done) 

} 
```

### 运行测试

在`api/feeder_test.go`中，我们有三个主要的测试用例场景：

+   测试是否为每个新文档生成了唯一的哈希值

+   测试发送到`/api/feeder`端点的有效负载是否返回预期的文档内容

+   测试以确保文档的索引工作正常

在运行测试后，以下是预期的输出：

```go
    $ go test -v ./... 
    ? github.com/last-ent/distributed-go/chapter6/goophr/concierge [no test files] 
    === RUN TestGetTitleHash 
    === RUN TestGetTitleHash/Different_Titles 
    === RUN TestGetTitleHash/Duplicate_Titles 
    === RUN TestGetTitleHash/Same_hashes 
    --- PASS: TestGetTitleHash (0.00s) 
    --- PASS: TestGetTitleHash/Different_Titles (0.00s) 
    --- PASS: TestGetTitleHash/Duplicate_Titles (0.00s) 
    --- PASS: TestGetTitleHash/Same_hashes (0.00s) 
    === RUN TestGetFile 
    --- PASS: TestGetFile (0.00s) 
    === RUN TestIndexProcessor 
    === RUN TestIndexProcessor/Testing_if_'golang'_is_returned._at_index:_1 
    === RUN TestIndexProcessor/Testing_if_'programming'_is_returned._at_index:_2 
    === RUN TestIndexProcessor/Testing_if_'rocks'_is_returned._at_index:_3 
    --- PASS: TestIndexProcessor (0.00s) 
    --- PASS: TestIndexProcessor/Testing_if_'golang'_is_returned._at_index:_1 (0.00s) 
    --- PASS: TestIndexProcessor/Testing_if_'programming'_is_returned._at_index:_2 (0.00s) 
    --- PASS: TestIndexProcessor/Testing_if_'rocks'_is_returned._at_index:_3 (0.00s) 
    PASS 
    ok github.com/last-ent/distributed-go/chapter6/goophr/concierge/api 0.004s
    ? github.com/last-ent/distributed-go/chapter6/goophr/concierge/common [no test files] 

```

### Concierge 服务器

让我们尝试将书籍*《黑客：计算机革命的英雄》*发布到 Concierge 端点`/api/feeder`。我们需要在另一个终端窗口中运行 Concierge 服务器：

```go
    $ curl -X POST -d '{"title": "Hackers: Heroes of Computer Revolution", "url": "http://www.gutenberg.org/cache/epub/729/pg729.txt"}' http://localhost:8080/api/feeder | jq 
     % Total % Received % Xferd Average Speed Time Time Time Current
     Dload Upload Total Spent Left Speed
    100 162 100 51 100 111 51 111 0:00:01 --:--:-- 0:00:01 54000
    {
     "code": 200,
     "msg": "Request is being processed."
    }
```

接下来，让我们看看服务器上会发生什么：

```go
    $ go run main.go
    2017/11/18 21:05:57 INFO - Adding API handlers...
    2017/11/18 21:05:57 INFO - Starting feeder...
    2017/11/18 21:05:57 INFO - Starting Goophr Concierge server on port :8080...
    // ...
    adding to librarian: gutenberg-tm 
    adding to librarian: including 
    adding to librarian: make 
    adding to librarian: u.s 
    adding to librarian: project 
    adding to librarian: gutenberg 
    /...

```

## 摘要

在本章中，我们深入研究了 Concierge 的`feeder`组件。我们设计了系统，并使用逻辑流程图来理解代码的各个部分是如何交互的。接下来，我们用测试和一个真实的例子来测试我们的代码。

在下一章，第七章，*Goophr 图书管理员*中，我们将深入探讨 Goophr 图书管理员的设计和实现。
