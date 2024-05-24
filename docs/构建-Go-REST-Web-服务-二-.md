# 构建 Go REST Web 服务（二）

> 原文：[`zh.annas-archive.org/md5/57EDF27484D8AB35B253814EEB7E5A77`](https://zh.annas-archive.org/md5/57EDF27484D8AB35B253814EEB7E5A77)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：使用流行的 Go 框架简化 RESTful 服务

在本章中，我们将涵盖使用框架简化构建 REST 服务相关的主题。首先，我们将快速了解 go-restful，一个 REST API 创建框架，然后转向一个名为`Gin`的框架。我们将在本章尝试构建一个地铁 API。我们将讨论的框架是完整的 Web 框架，也可以用来在短时间内创建 REST API。在本章中，我们将大量讨论资源和 REST 动词。我们将尝试将一个名为`Sqlite3`的小型数据库与我们的 API 集成。最后，我们将检查`Revel.go`，看看如何用它原型化我们的 REST API。

总的来说，本章我们将涵盖的主题如下：

+   如何在 Go 中使用 SQLite3

+   使用 go-restful 包创建 REST API

+   介绍用于创建 REST API 的 Gin 框架

+   介绍 Revel.go 用于创建 REST API

+   构建 CRUD 操作的基础知识

# 获取代码

您可以从[`github.com/narenaryan/gorestful/tree/master/chapter4`](https://github.com/narenaryan/gorestful/tree/master/chapter4)获取本章的代码示例。本章的示例以项目的形式而不是单个程序的形式呈现。因此，将相应的目录复制到您的`GOPATH`中以正确运行代码示例。

# go-restful，一个用于创建 REST API 的框架

`go-restful`是一个用于在 Go 中构建 REST 风格 Web 服务的包。REST，正如我们在前面的部分中讨论的，要求开发人员遵循一组设计协议。我们已经讨论了 REST 动词应该如何定义以及它们对资源的影响。

使用`go-restful`，我们可以将 API 处理程序的逻辑分离并附加 REST 动词。这样做的好处是，通过查看代码，清楚地告诉我们正在创建什么 API。在进入示例之前，我们需要为`go-restful`的 REST API 安装一个名为 SQLite3 的数据库。安装步骤如下：

+   在 Ubuntu 上，运行以下命令：

```go
 apt-get install sqlite3 libsqlite3-dev
```

+   在 OS X 上，您可以使用`brew`命令安装 SQLite3：

```go
 brew install sqlite3
```

+   现在，使用以下`get`命令安装`go-restful`包：

```go
 go get github.com/emicklei/go-restful
```

我们已经准备好了。首先，让我们编写一个简单的程序，展示`go-restful`在几行代码中可以做什么。让我们创建一个简单的 ping 服务器，将服务器时间回显给客户端：

```go
package main
import (
    "fmt"
    "github.com/emicklei/go-restful"
    "io"
    "net/http"
    "time"
)
func main() {
    // Create a web service
    webservice := new(restful.WebService)
    // Create a route and attach it to handler in the service
    webservice.Route(webservice.GET("/ping").To(pingTime))
    // Add the service to application
    restful.Add(webservice)
    http.ListenAndServe(":8000", nil)
}
func pingTime(req *restful.Request, resp *restful.Response) {
    // Write to the response
   io.WriteString(resp, fmt.Sprintf("%s", time.Now()))
}
```

如果我们运行这个程序：

```go
go run basicExample.go
```

服务器将在本地主机的端口`8000`上运行。因此，我们可以使用 curl 请求或浏览器来查看`GET`请求的输出：

```go
curl -X GET "http://localhost:8000/ping"
2017-06-06 07:37:26.238146296 +0530 IST
```

在上述程序中，我们导入了`go-restful`库，并使用`restful.WebService`结构的新实例创建了一个新的服务。接下来，我们可以使用以下语句创建一个 REST 动词：

```go
webservice.GET("/ping")
```

我们可以附加一个函数处理程序来执行这个动词；`pingTime`就是这样一个函数。这些链接的函数被传递给`Route`函数以创建一个路由器。然后是以下重要的语句：

```go
restful.Add(webservice)
```

这将注册新创建的`webservice`到`go-restful`。如果您注意到，我们没有将任何`ServeMux`对象传递给`http.ListenServe`函数；`go-restful`会处理它。这里的主要概念是使用基于资源的 REST API 创建`go-restful`。从基本示例开始，让我们构建一些实际的东西。

假设你的城市正在建设新的地铁，并且你需要为其他开发人员开发一个 REST API 来消费并相应地创建一个应用程序。我们将在本章中创建这样一个 API，并使用各种框架来展示实现。在此之前，对于**创建、读取、更新、删除**（**CRUD**）操作，我们应该知道如何使用 Go 代码查询或将它们插入到 SQLite 数据库中。

# CRUD 操作和 SQLite3 基础知识

所有的 SQLite3 操作都将使用一个名为`go-sqlite3`的库来完成。我们可以使用以下命令安装该包：

```go
go get github.com/mattn/go-sqlite3
```

这个库的特殊之处在于它使用了 Go 的内部`sql`包。我们通常导入`database/sql`并使用`sql`在数据库（这里是 SQLite3）上执行数据库查询：

```go
import "database/sql"
```

现在，我们可以创建一个数据库驱动程序，然后使用`Query`方法在其上执行 SQL 命令：

`sqliteFundamentals.go`:

```go
package main
import (
    "database/sql"
    "log"
    _ "github.com/mattn/go-sqlite3"
)
// Book is a placeholder for book
type Book struct {
    id int
    name string
    author string
}
func main() {
    db, err := sql.Open("sqlite3", "./books.db")
    log.Println(db)
    if err != nil {
        log.Println(err)
    }
    // Create table
    statement, err := db.Prepare("CREATE TABLE IF NOT EXISTS books (id
INTEGER PRIMARY KEY, isbn INTEGER, author VARCHAR(64), name VARCHAR(64) NULL)")
    if err != nil {
        log.Println("Error in creating table")
    } else {
        log.Println("Successfully created table books!")
    }
    statement.Exec()
    // Create
    statement, _ = db.Prepare("INSERT INTO books (name, author, isbn) VALUES (?, ?, ?)")
    statement.Exec("A Tale of Two Cities", "Charles Dickens", 140430547)
    log.Println("Inserted the book into database!")
    // Read
    rows, _ := db.Query("SELECT id, name, author FROM books")
    var tempBook Book
    for rows.Next() {
        rows.Scan(&tempBook.id, &tempBook.name, &tempBook.author)
        log.Printf("ID:%d, Book:%s, Author:%s\n", tempBook.id,
tempBook.name, tempBook.author)
    }
    // Update
    statement, _ = db.Prepare("update books set name=? where id=?")
    statement.Exec("The Tale of Two Cities", 1)
    log.Println("Successfully updated the book in database!")
    //Delete
    statement, _ = db.Prepare("delete from books where id=?")
    statement.Exec(1)
    log.Println("Successfully deleted the book in database!")
}
```

这个程序解释了如何在 SQL 数据库上执行 CRUD 操作。目前，数据库是 SQLite3。让我们使用以下命令运行它：

```go
go run sqliteFundamentals.go
```

输出如下，打印所有的日志语句：

```go
2017/06/10 08:04:31 Successfully created table books!
2017/06/10 08:04:31 Inserted the book into database!
2017/06/10 08:04:31 ID:1, Book:A Tale of Two Cities, Author:Charles Dickens
2017/06/10 08:04:31 Successfully updated the book in database!
2017/06/10 08:04:31 Successfully deleted the book in database!
```

这个程序在 Windows 和 Linux 上都可以正常运行。在 Go 版本低于 1.8.1 的情况下，你可能会在 macOS X 上遇到问题，比如*Signal Killed*。这是因为 Xcode 版本的问题，请记住这一点。

关于程序，我们首先导入`database/sql`和`go-sqlite3`。然后，我们使用`sql.Open()`函数在文件系统上打开一个`db`文件。它接受两个参数，数据库类型和文件名。如果出现问题，它会返回一个错误，否则返回一个数据库驱动程序。在`sql`库中，为了避免 SQL 注入漏洞，该包提供了一个名为`Prepare`的函数：

```go
statement, err := db.Prepare("CREATE TABLE IF NOT EXISTS books (id INTEGER PRIMARY KEY, isbn INTEGER, author VARCHAR(64), name VARCHAR(64) NULL)")
```

前面的语句只是创建了一个语句，没有填充任何细节。实际传递给 SQL 查询的数据使用语句中的`Exec`函数。例如，在前面的代码片段中，我们使用了：

```go
statement, _ = db.Prepare("INSERT INTO books (name, author, isbn) VALUES (?, ?, ?)")
statement.Exec("A Tale of Two Cities", "Charles Dickens", 140430547)
```

如果你传递了不正确的值，比如导致 SQL 注入的字符串，驱动程序会立即拒绝 SQL 操作。要从数据库中获取数据，使用`Query`方法。它返回一个迭代器，使用`Next`方法返回匹配查询的所有行。我们应该在循环中使用该迭代器进行处理，如下面的代码所示：

```go
rows, _ := db.Query("SELECT id, name, author FROM books")
var tempBook Book
for rows.Next() {
     rows.Scan(&tempBook.id, &tempBook.name, &tempBook.author)
     log.Printf("ID:%d, Book:%s, Author:%s\n", tempBook.id, tempBook.name, tempBook.author)
}
```

如果我们需要向`SELECT`语句传递条件，那么你应该准备一个语句，然后将通配符(?)数据传递给它。

# 使用 go-restful 构建地铁 API

让我们利用前一节学到的知识，为我们在前一节谈到的城市地铁项目创建一个 API。路线图如下：

1.  设计 REST API 文档。

1.  为数据库创建模型。

1.  实现 API 逻辑。

# 设计规范

在创建任何 API 之前，我们应该知道 API 的规范是什么样的，以文档的形式。我们在前几章中展示了一些例子，包括 URL 缩短器 API 设计文档。让我们尝试为这个地铁项目创建一个。看一下下面的表格：

| **HTTP 动词** | **路径** | **操作** | **资源** |
| --- | --- | --- | --- |
| `POST` | `/v1/train` (details as JSON body) | 创建 | 火车 |
| `POST` | `/v1/station` (details as JSON body) | 创建 | 站点 |
| `GET` | `/v1/train/id`  | 读取 | 火车 |
| `GET` | `/v1/station/id` | 读取 | 站点 |
| `POST` | `/v1/schedule` (source and destination) | 创建 | 路线 |

我们还可以包括`UPDATE`和`DELETE`方法。通过实现前面的设计，用户可以很容易地自行实现它们。

# 创建数据库模型

让我们编写一些 SQL 字符串，为前面的火车、站点和路线资源创建表。我们将为这个 API 创建一个项目布局。项目布局将如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/bd044302-d60b-436b-b223-7ea7454c6d0e.png)

我们在`$GOPATH/src/github.com/user/`中创建我们的项目。这里，用户是`narenaryan`，`railAPI`是我们的项目源，`dbutils`是我们自己的处理数据库初始化实用函数的包。让我们从`dbutils/models.go`文件开始。我将在`models.go`文件中为火车、站点和时间表各添加三个模型：

```go
package dbutils

const train = `
      CREATE TABLE IF NOT EXISTS train (
           ID INTEGER PRIMARY KEY AUTOINCREMENT,
           DRIVER_NAME VARCHAR(64) NULL,
           OPERATING_STATUS BOOLEAN
        )
`

const station = `
        CREATE TABLE IF NOT EXISTS station (
          ID INTEGER PRIMARY KEY AUTOINCREMENT,
          NAME VARCHAR(64) NULL,
          OPENING_TIME TIME NULL,
          CLOSING_TIME TIME NULL
        )
`
const schedule = `
        CREATE TABLE IF NOT EXISTS schedule (
          ID INTEGER PRIMARY KEY AUTOINCREMENT,
          TRAIN_ID INT,
          STATION_ID INT,
          ARRIVAL_TIME TIME,
          FOREIGN KEY (TRAIN_ID) REFERENCES train(ID),
          FOREIGN KEY (STATION_ID) REFERENCES station(ID)
        )
`
```

这些都是用反引号（`` ` ``）字符括起来的普通多行字符串。该时刻表保存了在给定时间到达特定车站的列车的信息。在这里，火车和车站是时间表的外键。对于train，与之相关的细节是列。包名是`dbutils`，当我们提到包名时，包中的所有Go程序都可以共享导出的变量和函数，而不需要实际导入。

现在，让我们在`init-tables.go`文件中添加代码来初始化（创建表）数据库：

```go

package dbutils
import "log"
import "database/sql"
func Initialize(dbDriver *sql.DB) {
    statement, driverError := dbDriver.Prepare(train)
    if driverError != nil {
        log.Println(driverError)
    }
    // 创建火车表
    _, statementError := statement.Exec()
    if statementError != nil {
        log.Println("Table already exists!")
    }
    statement, _ = dbDriver.Prepare(station)
    statement.Exec()
    statement, _ = dbDriver.Prepare(schedule)
    statement.Exec()
    log.Println("All tables created/initialized successfully!")
}

```

我们导入`database/sql`以将参数类型传递给函数。函数中的所有其他语句与我们在上述代码中给出的 SQLite3 示例类似。它只是在 SQLite3 数据库中创建了三个表。我们的主程序应该将数据库驱动程序传递给此函数。如果你观察这里，我们没有导入 train、station 和 schedule。但是，由于此文件位于`db utils`包中，`models.go`中的变量是可访问的。

现在我们的初始包已经完成。你可以使用以下命令为此包构建对象代码：

```go

go build github.com/narenaryan/dbutils

```

直到我们创建并运行我们的主程序才有用。所以，让我们编写一个简单的主程序，从`dbutils`包导入`Initialize`函数。让我们将文件命名为`main.go`：

```go

package main
import (
    "database/sql"
    "log"
    _ "github.com/mattn/go-sqlite3"
    "github.com/narenaryan/dbutils"
)
func main() {
    // 连接到数据库
    db, err := sql.Open("sqlite3", "./railapi.db")
    if err != nil {
        log.Println("Driver creation failed!")
    }
    // 创建表
    dbutils.Initialize(db)
}

```

并使用以下命令从`railAPI`目录运行程序：

```go

go run main.go

```

你看到的输出应该类似于以下内容：

```go

2017/06/10 14:05:36 所有表格成功创建/初始化！

```

在上述程序中，我们添加了创建数据库驱动程序的代码，并将表创建任务传递给了`dbutils`包中的`Initialize`函数。我们可以直接在主程序中完成这个任务，但是将逻辑分解成多个包和组件是很好的。现在，我们将扩展这个简单的布局，使用`go-restful`包创建一个 API。API 应该实现我们的 API 设计文档中的所有函数。

当我们运行我们的主程序时，上述目录树图片中的`railapi.db`文件将被创建。如果数据库文件不存在，SQLite3 将负责创建数据库文件。SQLite3 数据库是简单的文件。你可以使用`$ sqlite3 file_name`命令进入 SQLite shell。

让我们将主程序修改为一个新的程序。我们将逐步进行，并在此示例中了解如何使用`go-restful`构建 REST 服务。首先，向程序中添加必要的导入：

```go

package main
import (
    "database/sql"
    "encoding/json"
    "log"
    "net/http"
    "time"
    "github.com/emicklei/go-restful"
    _ "github.com/mattn/go-sqlite3"
    "github.com/narenaryan/dbutils"
)

```

我们需要两个外部包，`go-restful`和`go-sqlite3`，用于构建 API 逻辑。第一个用于处理程序，第二个用于添加持久性特性。`dbutils`是我们之前创建的。`time`和`net/http`包用于一般任务。

尽管 SQLite 数据库表中给出了具体的列名称，在 GO 编程中，我们需要一些结构体来处理数据进出数据库。我们需要为所有模型定义数据持有者，所以下面我们将定义它们。看一下以下代码片段：

```go

// DB Driver visible to whole program
var DB *sql.DB
// TrainResource is the model for holding rail information
type TrainResource struct {
    ID int
    DriverName string
    OperatingStatus bool
}
// StationResource holds information about locations
type StationResource struct {
    ID int
    Name string
    OpeningTime time.Time
    ClosingTime time.Time
}
// ScheduleResource links both trains and stations
type ScheduleResource struct {
    ID int
    TrainID int
    StationID int
    ArrivalTime time.Time
}

```

`DB`变量被分配为保存全局数据库驱动程序。上面的所有结构体都是 SQL 中数据库模型的确切表示。Go 的`time.Time`结构体类型实际上可以保存数据库中的`TIME`字段。

现在是真正的`go-restful`实现。我们需要为我们的 API 在`go-restful`中创建一个容器。然后，我们应该将 Web 服务注册到该容器中。让我们编写`Register`函数，如下面的代码片段所示：

```go

// Register adds paths and routes to container
func (t *TrainResource) Register(container *restful.Container) {
    ws := new(restful.WebService)
    ws.Path("/v1/trains").
    Consumes(restful.MIME_JSON).
    Produces(restful.MIME_JSON) // you can specify this per route as well
    ws.Route(ws.GET("/{train-id}").To(t.getTrain))
    ws.Route(ws.POST("").To(t.createTrain))
    ws.Route(ws.DELETE("/{train-id}").To(t.removeTrain))
    container.Add(ws)
}

```

在`go-restful`中，Web 服务主要基于资源工作。所以在这里，我们定义了一个名为`Register`的函数在`TrainResource`上，接受容器作为参数。我们创建了一个新的`WebService`并为其添加路径。路径是 URL 端点，路由是附加到函数处理程序的路径参数或查询参数。`ws`是用于提供`Train`资源的 Web 服务。我们将三个 REST 方法，即`GET`、`POST`和`DELETE`分别附加到三个函数处理程序上，分别是`getTrain`、`createTrain`和`removeTrain`：

```go

Path("/v1/trains").
Consumes(restful.MIME_JSON).
Produces(restful.MIME_JSON)

```

这些语句表明 API 将只接受请求中的`Content-Type`为 application/JSON。对于所有其他类型，它会自动返回 415--媒体不支持错误。返回的响应会自动转换为漂亮的 JSON 格式。我们还可以有一个格式列表，比如 XML、JSON 等等。`go-restful`提供了这个功能。

现在，让我们定义函数处理程序：

```go

// GET http://localhost:8000/v1/trains/1
func (t TrainResource) getTrain(request *restful.Request, response *restful.Response) {
    id := request.PathParameter("train-id")
    err := DB.QueryRow("select ID, DRIVER_NAME, OPERATING_STATUS FROM train where id=?", id).Scan(&t.ID, &t.DriverName, &t.OperatingStatus)
    if err != nil {
        log.Println(err)
        response.AddHeader("Content-Type", "text/plain")
        response.WriteErrorString(http.StatusNotFound, "Train could not be found.")
    } else {
        response.WriteEntity(t)
    }
}
// POST http://localhost:8000/v1/trains
func (t TrainResource) createTrain(request *restful.Request, response *restful.Response) {
    log.Println(request.Request.Body)
    decoder := json.NewDecoder(request.Request.Body)
    var b TrainResource
    err := decoder.Decode(&b)
    log.Println(b.DriverName, b.OperatingStatus)
    // Error handling is obvious here. So omitting...
    statement, _ := DB.Prepare("insert into train (DRIVER_NAME, OPERATING_STATUS) values (?, ?)")
    result, err := statement.Exec(b.DriverName, b.OperatingStatus)
    if err == nil {
        newID, _ := result.LastInsertId()
        b.ID = int(newID)
        response.WriteHeaderAndEntity(http.StatusCreated, b)
    } else {
        response.AddHeader("Content-Type", "text/plain")
        response.WriteErrorString(http.StatusInternalServerError, err.Error())
    }
}
// DELETE http://localhost:8000/v1/trains/1
func (t TrainResource) removeTrain(request *restful.Request, response *restful.Response) {
    id := request.PathParameter("train-id")
    statement, _ := DB.Prepare("delete from train where id=?")
    _, err := statement.Exec(id)
    if err == nil {
        response.WriteHeader(http.StatusOK)
    } else {
        response.AddHeader("Content-Type", "text/plain")
        response.WriteErrorString(http.StatusInternalServerError, err.Error())
    }
}

```

所有这些 REST 方法都在`TimeResource`结构的实例上定义。谈到`GET`处理程序，它将`Request`和`Response`作为其参数传递。可以使用`request.PathParameter`函数获取路径参数。传递给它的参数将与我们在前面的代码段中添加的路由保持一致。也就是说，`train-id`将被返回到处理程序中，以便我们可以剥离它并将其用作从我们的 SQLite 数据库中获取记录的条件。

在`POST`处理程序函数中，我们使用 JSON 包的`NewDecoder`函数解析请求体。`go-restful`没有一个函数可以解析客户端发布的原始数据。有函数可用于剥离查询参数和表单参数，但这个缺失了。所以，我们编写了自己的逻辑来剥离和解析 JSON 主体，并使用这些结果将数据插入我们的 SQLite 数据库中。该处理程序正在为请求中提供的细节创建一个`db`记录。

如果您理解前两个处理程序，`DELETE`函数就很明显了。我们使用`DB.Prepare`创建一个`DELETE` SQL 命令，并返回 201 状态 OK，告诉我们删除操作成功了。否则，我们将实际错误作为服务器错误发送回去。现在，让我们编写主函数处理程序，这是我们程序的入口点：

```go

func main() {
    var err error
    DB, err = sql.Open("sqlite3", "./railapi.db")
    if err != nil {
        log.Println("Driver creation failed!")
    }
    dbutils.Initialize(DB)
    wsContainer := restful.NewContainer()
    wsContainer.Router(restful.CurlyRouter{})
    t := TrainResource{}
    t.Register(wsContainer)
    log.Printf("start listening on localhost:8000")
    server := &http.Server{Addr: ":8000", Handler: wsContainer}
    log.Fatal(server.ListenAndServe())
}

```

这里的前四行执行与数据库相关的工作。然后，我们使用`restful.NewContainer`创建一个新的容器。然后，我们使用称为`CurlyRouter`的路由器（它允许我们在路径中使用`{train_id}`语法来设置路由）来为我们的容器设置路由。接下来，我们创建了`TimeResource`结构的实例，并将该容器传递给`Register`方法。该容器确实可以充当 HTTP 处理程序；因此，我们可以轻松地将其传递给`http.Server`。

使用 `request.QueryParameter` 从 HTTP 请求中获取查询参数在`go-restful`处理程序中。

此代码可在 GitHub 仓库中找到。现在，当我们在`$GOPATH/src/github.com/narenaryan`目录中运行`main.go`文件时，我们会看到这个：

```go

go run railAPI/main.go

```

并进行 curl `POST`请求创建一个火车：

```go

curl -X POST \
    http://localhost:8000/v1/trains \
    -H 'cache-control: no-cache' \
    -H 'content-type: application/json' \
    -d '{"driverName": "Menaka", "operatingStatus": true}'

```

这会创建一个带有驾驶员和操作状态详细信息的新火车。响应是新创建的分配了火车`ID`的资源：

```go

{
    "ID": 1,
    "DriverName": "Menaka",
    "OperatingStatus": true
}

```

现在，让我们进行一个 curl 请求来检查`GET`：

```go

CURL -X GET "http://localhost:8000/v1/trains/1"

```

您将看到以下 JSON 输出：

```go

{
    "ID": 1,
    "DriverName": "Menaka",
    "OperatingStatus": true
}

```

可以对发布的数据和返回的 JSON 使用相同的名称，但为了显示两个操作之间的区别，使用了不同的变量名称。现在，使用`DELETE`API 调用删除我们在前面代码片段中创建的资源：

```go

CURL -X DELETE "http://localhost:8000/v1/trains/1"

```

如果操作成功，它不会返回任何响应体，而是返回`Status 200 ok`。现在，如果我们尝试对`ID`为 1 的火车进行`GET`操作，它会返回以下响应：

```go

Train could not be found.

```

这些实现可以扩展到`PUT`和`PATCH`。我们需要在`Register`方法中添加两个额外的路由，并定义相应的处理程序。在这里，我们为`Train`资源创建了一个 web 服务。类似地，还可以为`Station`和`Schedule`表上的 CRUD 操作创建 web 服务。这项任务就留给读者去探索。

`go-restful`是一个轻量级的库，在创建 RESTful 服务时具有强大的功能。主题是将资源（模型）转换成可消费的 API。使用其他繁重的框架可能会加快开发速度，但因为代码包装的原因，API 可能会变得更慢。`go-restful`是一个用于 API 创建的精简且底层的包。

`go-restful` 还提供了对使用**swagger**文档化 REST API 的内置支持。它是一个运行并生成我们构建的 REST API 文档模板的工具。通过将其与基于`go-restful`的 web 服务集成，我们可以实时生成文档。欲了解更多信息，请访问[github.com/emicklei/go-restful-swagger12](https://github.com/emicklei/go-restful-swagger12)。

# 使用 Gin 框架构建 RESTful API

`Gin-gonic`是基于`httprouter`的框架。我们在第二章*处理我们的 REST 服务的路由*中学习了`httprouter`。它是一个 HTTP 多路复用器，类似于 Gorilla Mux，但更快。 `Gin`允许以清晰的方式创建 REST 服务的高级 API。 `Gin`将自己与另一个名为`martini`的 web 框架进行比较。所有 web 框架都允许我们做更多的事情，如模板化和 web 服务器设计，除了服务创建。使用以下命令安装`Gin`包：

```go

go get gopkg.in/gin-gonic/gin.v1

```

让我们写一个简单的 hello world 程序在`Gin`中熟悉`Gin`的构造。文件名是`ginBasic.go`：

```go

package main
import (
    "time"
    "github.com/gin-gonic/gin"
)
func main() {
r := gin.Default()
    /* GET takes a route and a handler function
    Handler takes the gin context object
    */
    r.GET("/pingTime", func(c *gin.Context) {
        // JSON serializer is available on gin context
        c.JSON(200, gin.H{
            "serverTime": time.Now().UTC(),
        })
    })
    r.Run(":8000") // 在 0.0.0.0:8080 上监听并提供服务
}

```

这个简单的服务器尝试实现一个向客户端提供 UTC 服务器时间的服务。我们在第三章*使用中间件和 RPC 工作*中实现了一个这样的服务。但在这里，如果你看，`Gin`允许你用几行代码做很多事情；所有的样板细节都被省去了。来到前面的程序，我们用`gin.Default`函数创建了一个路由器。然后，我们附加了与 REST 动词相对应的路由，就像在`go-restful`中做的那样；一个到函数处理程序的路由。然后，我们通过传递要运行的端口来调用`Run`函数。默认端口将是`8080`。

`c`是保存单个请求信息的`gin.Context`。我们可以使用`context.JSON`函数将数据序列化为 JSON，然后发送回客户端。现在，如果我们运行并查看前面的程序：

```go

go run ginExamples/ginBasic.go

```

发出一个 curl 请求：

```go

curl -X GET "http://localhost:8000/pingTime"

Output
=======
{"serverTime":"2017-06-11T03:59:44.135062688Z"}

```

与此同时，我们运行`Gin`服务器的控制台上漂亮地呈现了调试消息：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/54d2bbb0-6c1c-466d-b187-1828e5283490.png)

这是显示端点、请求的延迟和 REST 方法的 Apache 风格的调试日志。

为了在生产模式下运行`Gin`，设置`GIN_MODE = release`环境变量。然后控制台输出将被静音，日志文件可用于监视日志。

现在，让我们在`Gin`中编写我们的 Rail API，以展示如何使用`Gin`框架实现完全相同的东西。我将使用相同的项目布局，将我的新项目命名为`railAPIGin`，并使用`dbutils`如它所在。首先，让我们准备好我们程序的导入：

```go

package main
import (
    "database/sql"
    "log"
    "net/http"
    "github.com/gin-gonic/gin"
    _ "github.com/mattn/go-sqlite3"
    "github.com/narenaryan/dbutils"
)

```

我们导入了`sqlite3`和`dbutils`用于与数据库相关的操作。我们导入了`gin`用于创建我们的 API 服务器。`net/http`在提供与响应一起发送的直观状态代码方面很有用。看一下下面的代码片段：

```go

// DB Driver visible to whole program
var DB *sql.DB
// StationResource holds information about locations
type StationResource struct {
    ID int `json:"id"`
    Name string `json:"name"`
    OpeningTime string `json:"opening_time"`
    ClosingTime string `json:"closing_time"`
}

```

我们创建了一个数据库驱动程序，该驱动程序对所有处理程序函数都可用。 `StationResource`是我们从请求体和来自数据库的数据解码而来的 JSON 的占位符。如果你注意到了，它与`go-restful`的示例略有不同。现在，让我们编写实现`GET`、`POST`和`DELETE`方法的`station`资源的处理程序：

```go

// GetStation returns the station detail
    func GetStation(c *gin.Context) {
    var station StationResource
    id := c.Param("station_id")
    err := DB.QueryRow("select ID, NAME, CAST(OPENING_TIME as CHAR), CAST(CLOSING_TIME as CHAR) from station where id=?", id).Scan(&station.ID, &station.Name, &station.OpeningTime, &station.ClosingTime)
    if err != nil {
        log.Println(err)
        c.JSON(500, gin.H{
            "error": err.Error(),
        })
    } else {
        c.JSON(200, gin.H{
        "result": station,
        })
    }
}
// CreateStation handles the POST
func CreateStation(c *gin.Context) {
    var station StationResource
    // Parse the body into our resrource
    if err := c.BindJSON(&station); err == nil {
        // Format Time to Go time format
        statement, _ := DB.Prepare("insert into station (NAME, OPENING_TIME, CLOSING_TIME) values (?, ?, ?)")
        result, _ := statement.</span>Exec(station.Name, station.OpeningTime, station.ClosingTime)
        if err == nil {
            newID, _ := result.LastInsertId()
            station.ID = int(newID)
            c.JSON(http.StatusOK, gin.H{
                "result": station,
            })
        } else {
            c.String(http.StatusInternalServerError, err.Error())
        }
    } else {
        c.String(http.StatusInternalServerError, err.Error())
    }
}
// RemoveStation handles the removing of resource
func RemoveStation(c *gin.Context) {
    id := c.Param("station-id")
    statement, _ := DB.Prepare("delete from station where id=?")
    _, err := statement.Exec(id)
    if err != nil {
        log.Println(err)
        c.JSON(500, gin.H{
            "error": err.Error(),
        })
    } else {
        c.String(http.StatusOK, "")
    }
}

```

在`GetStation`中，我们使用`c.Param`来剥离`station_id`路径参数。之后，我们使用该 ID 从 SQLite3 站点表中检索数据库记录。如果您仔细观察，SQL 查询有点不同。我们使用`CAST`方法将 SQL `TIME`字段检索为 Go 可以正确消耗的字符串。如果删除类型转换，将引发恐慌错误，因为我们尝试在运行时将`TIME`字段加载到 Go 字符串中。为了给您一个概念，`TIME`字段看起来像*8:00:00*，*17:31:12*，等等。接下来，如果没有错误，我们将使用`gin.H`方法返回结果。

在`CreateStation`中，我们试图执行插入查询。但在此之前，为了从`POST`请求的主体中获取数据，我们使用了一个名为`c.BindJSON`的函数。这个函数将数据加载到传递的结构体中。这意味着站点结构将加载来自主体提供的数据。这就是为什么`StationResource`具有 JSON 推断字符串来告诉期望的键值是什么。例如，这是`StationResource`结构的一个字段，带有推断字符串。

```go

ID int `json:"id"`

```

在收集数据后，我们正在准备一个数据库插入语句并执行它。结果是插入记录的 ID。我们使用该 ID 将站点详细信息发送回客户端。在`RemoveStation`中，我们执行`DELETE` SQL 查询。如果操作成功，则返回`200 OK`状态。否则，我们会发送适当的原因给`500 Internal Server Error`。

现在来看主程序，它首先运行数据库逻辑以确保表已创建。然后，它尝试创建`Gin`路由器并向其添加路由：

```go

func main() {
    var err error
    DB, err = sql.Open("sqlite3", "./railapi.db")
    if err != nil {
        log.Println("Driver creation failed!")
    }
    dbutils.Initialize(DB)
    r := gin.Default()
    // Add routes to REST verbs
    r.GET("/v1/stations/:station_id", GetStation)
    r.POST("/v1/stations", CreateStation)
    r.DELETE("/v1/stations/:station_id", RemoveStation)
    r.Run(":8000") // 默认监听并在 0.0.0.0:8080 上提供服务
}

```

我们正在使用`Gin`路由器注册`GET`、`POST`和`DELETE`路由。然后，我们将路由和处理程序传递给它们。最后，我们使用 Gin 的`Run`函数以`8000`作为端口启动服务器。运行前述程序，如下所示：

```go

go run railAPIGin/main.go

```

现在，我们可以通过执行`POST`请求来插入新记录：

```go

curl -X POST \
    http://localhost:8000/v1/stations \
    -H 'cache-control: no-cache' \
    -H 'content-type: application/json' \
    -d '{"name":"Brooklyn", "opening_time":"8:12:00", "closing_time":"18:23:00"}'

```

它返回：

```go

{"result":{"id":1,"name":"Brooklyn","opening_time":"8:12:00","closing_time":"18:23:00"}}

```

现在尝试使用`GET`获取详细信息：

```go

CURL -X GET "http://10.102.78.140:8000/v1/stations/1"

Output
======
{"result":{"id":1,"name":"Brooklyn","opening_time":"8:12:00","closing_time":"18:23:00"}}

```

我们也可以使用以下命令删除站点记录：

```go

CURL -X DELETE "http://10.102.78.140:8000/v1/stations/1"

```

它返回`200 OK`状态，确认资源已成功删除。正如我们已经讨论的那样，`Gin`提供了直观的调试功能，显示附加的处理程序，并使用颜色突出显示延迟和 REST 动词：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/c1f2942f-5dfc-4fda-b9d3-7a9470ca687d.png)

例如，`200`是绿色的，`404`是黄色的，`DELETE`是红色的，等等。`Gin`提供了许多其他功能，如路由的分类、重定向和中间件函数。

如果您要快速创建 REST Web 服务，请使用`Gin`框架。您还可以将其用于许多其他用途，如静态文件服务等。请记住，它是一个完整的 Web 框架。在 Gin 中获取查询参数，请使用以下方法在`Gin`上下文对象上：`c.Query("param")`。

# 使用 Revel.go 构建一个 RESTful API

Revel.go 也是一个像 Python 的 Django 一样完整的 Web 框架。它比 Gin 还要早，并被称为高生产力的 Web 框架。它是一个异步的、模块化的、无状态的框架。与 `go-restful` 和 `Gin` 框架不同，Revel 直接生成了一个可用的脚手架。

使用以下命令安装`Revel.go`：

```go

go get github.com/revel/revel

```

为了运行脚手架工具，我们应该安装另一个附加包：

```go

go get github.com/revel/cmd/revel

```

确保 `$GOPATH/bin` 在您的 `PATH` 变量中。一些外部包将二进制文件安装在 `$GOPATH/bin` 目录中。如果在路径中，我们可以在系统范围内访问可执行文件。在这里，Revel 将安装一个名为`revel`的二进制文件。在 Ubuntu 或 macOS X 上，您可以使用以下命令执行：

```go

export PATH=$PATH:$GOPATH/bin

```

将上面的内容添加到 `~/.bashrc` 以保存设置。在 Windows 上，您需要直接调用可执行文件的位置。现在我们已经准备好开始使用 Revel 了。让我们在 `github.com/narenaryan` 中创建一个名为 `railAPIRevel` 的新项目：

```go

revel new railAPIRevel

```

这样就可以在不写一行代码的情况下创建一个项目脚手架。这就是 Web 框架在快速原型设计中的抽象方式。Revel 项目布局树看起来像这样：

```go

conf/         Configuration directory
app.conf      Main app configuration file
routes        路由定义文件
app/          应用程序源
init.go       拦截器注册
controllers/  这里放置应用程序控制器
views/        模板目录
messages/     消息文件
public/       公共静态资产
css/          CSS 文件
js/           Javascript 文件
images/       图像文件
tests/        测试套件

```

在所有那些样板目录中，有三个重要的东西用于创建一个 API。那是：

+   `app/controllers`

+   `conf/app.conf`

+   `conf/routes`

控制器是执行 API 逻辑的逻辑容器。`app.conf` 允许我们设置 `host`、`port`、`dev` 模式/生产模式等。`routes` 定义了端点、REST 动词和函数处理程序（这里是控制器的函数）。这意味着在控制器中定义一个函数，并在路由文件中将其附加到路由上。

让我们使用我们之前看到的 `go-restful` 的相同例子，为列车创建一个 API。但由于冗余，我们将删除数据库逻辑。稍后我们将看到如何使用 Revel 为 API 构建 `GET`、`POST` 和 `DELETE` 操作。现在，将路由文件修改为这样：

```go

# 路由配置
#
# 此文件定义了所有应用程序路由（优先级较高的路由优先）
#

module:testrunner
# module:jobs

GET /v1/trains/:train-id App.GetTrain
POST /v1/trains App.CreateTrain
DELETE /v1/trains/:train-id App.RemoveTrain

```

语法可能看起来有点新。这是一个配置文件，我们只需以这种格式定义一个路由：

```go

VERB END_POINT HANDLER

```

我们还没有定义处理程序。在端点中，路径参数使用`:param` 注释进行访问。这意味着对于文件中的 `GET` 请求，`train-id` 将作为 `path` 参数传递。现在，转到 `controllers` 文件夹，并将 `app.go` 文件中的现有控制器修改为这样：

```go

package controllers
import (
    "log"
    "net/http"
    "strconv"
    "github.com/revel/revel"
)
type App struct {
    *revel.Controller
}
// TrainResource 是用于保存铁路信息的模型
type TrainResource struct {
    ID int `json:"id"`
    DriverName string `json:"driver_name"`
    OperatingStatus bool `json:"operating_status"`
}
// GetTrain 处理对火车资源的 GET
func (c App) GetTrain() revel.Result {
    var train TrainResource
    // 从路径参数中获取值。
    id := c.Params.Route.Get("train-id")
    // 使用此 ID 从数据库查询并填充 train 表....
    train.ID，_ = strconv.Atoi（id）
    train.DriverName = "Logan" // 来自数据库
    train.OperatingStatus = true // 来自数据库
    c.Response.Status = http.StatusOK
    return c.RenderJSON(train)
}
// CreateTrain 处理对火车资源的 POST
func (c App) CreateTrain() revel.Result {
    var train TrainResource
    c.Params.BindJSON(&train)
    // 使用 train.DriverName 和 train.OperatingStatus 插入到 train 表中....
    train.ID = 2
    c.Response.Status = http.StatusCreated
    return c.RenderJSON(train)
}
// RemoveTrain 实现对火车资源的 DELETE
func (c App) RemoveTrain() revel.Result {
    id := c.Params.Route.Get("train-id")
    // 使用 ID 从 train 表中删除记录....
    log.Println("成功删除资源：", id)
    c.Response.Status = http.StatusOK
    return c.RenderText("")
}

```

我们在文件 `app.go` 中创建了 API 处理程序。这些处理程序的名称应与我们在路由文件中提到的名称匹配。我们可以使用带有 `*revel.Controller` 作为其成员的结构创建一个 Revel 控制器。然后，我们可以向其附加任意数量的处理程序。控制器保存了传入 HTTP 请求的信息，因此我们可以在处理程序中使用信息，如查询参数、路径参数、JSON 主体、表单数据等。

我们正在定义 `TrainResource` 作为一个数据持有者。在 `GetTrain` 中，我们使用 `c.Params.Route.Get` 函数获取路径参数。该函数的参数是我们在路由文件中指定的路径参数（这里是 `train-id`）。该值将是一个字符串。我们需要将其转换为 `Int` 类型以与 `train.ID` 进行映射。然后，我们使用 `c.Response.Status` 变量（而不是函数）将响应状态设置为 `200 OK`。`c.RenderJSON` 接受一个结构体并将其转换为 JSON 主体。

在 `CreateTrain` 中，我们添加了 `POST` 请求逻辑。我们创建了一个新的 `TrainResource` 结构体，并将其传递给一个名为 `c.Params.BindJSON` 的函数。`BindJSON` 的作用是从 JSON `POST` 主体中提取参数，并尝试在结构体中查找匹配的字段并填充它们。当我们将 Go 结构体编组为 JSON 时，字段名将按原样转换为键。但是，如果我们将 `jason:"id"` 字符串格式附加到任何结构字段上，它明确表示从该结构编组的 JSON 应具有键 `id`，而不是 **ID**。在使用 JSON 时，这是 Go 中的一个良好做法。然后，我们向 HTTP 响应添加了一个 201 创建的状态。我们返回火车结构体，它将在内部转换为 JSON。

`RemoveTrain` 处理程序逻辑与 `GET` 类似。一个微妙的区别是没有发送任何内容。正如我们之前提到的，数据库 CRUD 逻辑在上述示例中被省略。读者可以通过观察我们在 `go-restful` 和 `Gin` 部分所做的工作来尝试添加 SQLite3 逻辑。

最后，默认端口号是 `9000`，Revel 服务器运行的配置更改端口号在 `conf/app.conf` 文件中。让我们遵循在 `8000` 上运行我们的应用程序的传统。因此，将文件的 `http` 端口部分修改为以下内容。这告诉 Revel 服务器在不同的端口上运行：

```go

......

# 要监听的 IP 地址。
http.addr = "0.0.0.0"
# 要监听的端口。
http.port = 8000 # 从 9000 更改为 8000 或任何端口
# 是否使用 SSL。
http.ssl = false
......

```

现在，我们可以使用以下命令运行 Revel API 服务器：

```go

revel run github.com/narenaryan/railAPIRevel

```

我们的应用服务器在 `http://localhost:8000` 上启动。现在，让我们进行一些 API 请求：

```go

CURL -X GET "http://10.102.78.140:8000/v1/trains/1"

output
=======
{
    "id": 1,
    "driver_name": "Logan",
    "operating_status": true
}

```

`POST` 请求：


```go

curl -X POST \
    http://10.102.78.140:8000/v1/trains \
    -H 'cache-control: no-cache' \
    -H 'content-type: application/json' \
    -d '{"driver_name":"Magneto", "operating_status": true}'

output
======
{
    "id": 2,
    "driver_name": "Magneto",
    "operating_status": true
}

```

`DELETE`与`GET`相同，但不返回主体。这里，代码是为了展示如何处理请求和响应。请记住，Revel 不仅仅是一个简单的 API 框架。它是一个类似于 Django（Python）或 Ruby on Rails 的完整的 Web 框架。我们在 Revel 中内置了模板，测试和许多其他功能。

确保为`GOPATH/user`创建一个新的 Revel 项目。否则，当运行项目时，Revel 命令行工具可能找不到项目。

我们在本章中看到的所有 Web 框架都支持中间件。 `go-restful`将其中间件命名为`Filters`，而`Gin`将其命名为自定义中间件。 Revel 将其中间件拦截器。中间件在函数处理程序之前和之后分别读取或写入请求和响应。在第三章中，*使用中间件和 RPC*，我们将更多地讨论中间件。

# 摘要

在本章中，我们尝试使用 Go 中的一些 Web 框架构建了一个地铁轨道 API。最受欢迎的是`go-restful`，`Gin Gonic`和`Revel.go`。我们首先学习了如何在 Go 应用程序中进行第一个数据库集成。我们选择了 SQLite3，并尝试使用`go-sqlite3`库编写了一个示例应用程序。

接下来，我们探索了`go-restful`，并详细了解了如何创建路由和处理程序。`go-restful`具有在资源之上构建 API 的概念。它提供了一种直观的方式来创建可以消耗和产生各种格式（如 XML 和 JSON）的 API。我们使用火车作为资源，并构建了一个在数据库上执行 CRUD 操作的 API。我们解释了为什么`go-restful`轻量级，并且可以用来创建低延迟的 API。接下来，我们看到了`Gin`框架，并尝试重复相同的 API，但是创建了一个围绕车站资源的 API。我们看到了如何在 SQL 数据库时间字段中存储时间。我们建议使用`Gin`来快速原型化您的 API。

最后，我们尝试使用`Revel.go`网络框架在火车资源上创建另一个 API。我们开始创建一个项目，检查了目录结构，然后继续编写一些服务（没有`db`集成）。我们还看到了如何运行应用程序并使用配置文件更改端口。

本章的主题是为您提供一些创建 RESTful API 的精彩框架。每个框架可能有不同的做事方式，选择您感到舒适的那个。当您需要一个端到端的网络应用程序（模板和用户界面）时，请使用`Revel.go`，当您需要快速创建 REST 服务时，请使用`Gin`，当 API 的性能至关重要时，请使用`go-rest`。


# 第五章：使用 MongoDB 和 Go 创建 REST API

在本章中，我们将介绍名为`MongoDB`的 NoSQL 数据库。我们将学习`MongoDB`如何适用于现代 Web 服务。我们将首先学习有关`MongoDB`集合和文档的知识。我们将尝试使用`MongoDB`作为数据库创建一个示例 API。在这个过程中，我们将使用一个名为`mgo`的驱动程序包。然后，我们将尝试为电子商务 REST 服务设计一个文档模型。

基本上，我们将讨论以下主题：

+   安装和使用 MongoDB

+   使用 Mongo shell

+   使用 MongoDB 作为数据库构建 REST API

+   数据库索引的基础知识

+   设计电子商务文档模型

# 获取代码

您可以从[`github.com/narenaryan/gorestful/tree/master/chapter5`](https://github.com/narenaryan/gorestful/tree/master/chapter5)获取本章的代码示例。本章的示例是单个程序和项目的组合。因此，将相应的目录复制到您的`GOPATH`中，以正确运行代码示例。

# MongoDB 简介

**MongoDB**是一种受到全球开发人员青睐的流行 NoSQL 数据库。它不同于传统的关系型数据库，如 MySQL、PostgreSQL 和 SQLite3。与其他数据库相比，MongoDB 的主要区别在于在互联网流量增加时易于扩展。它还将 JSON 作为其数据模型，这使我们可以直接将 JSON 存储到数据库中。

许多大公司，如 Expedia、Comcast 和 Metlife，都在 MongoDB 上构建了他们的应用程序。它已经被证明是现代互联网业务中的重要组成部分。MongoDB 将数据存储在文档中；可以将其视为 SQL 数据库中的行。所有 MongoDB 文档都存储在一个集合中，而集合就是表（类比 SQL）。IMDB 电影的一个示例文档如下：

```go
{
  _id: 5,
  name: 'Star Trek',
  year: 2009,
  directors: ['J.J. Abrams'],
  writers: ['Roberto Orci', 'Alex Kurtzman'],
  boxOffice: {
     budget:150000000,
     gross:257704099
  }
}
```

MongoDB 相对于关系型数据库的主要优势是：

+   易于建模（无模式）

+   可以利用查询功能

+   文档结构适合现代 Web 应用程序（JSON）

+   比关系型数据库更具可扩展性

# 安装 MongoDB 并使用 shell

MongoDB 可以轻松安装在任何平台上。在 Ubuntu 16.04 上，我们需要在运行`apt-get`命令之前执行一些进程：

```go
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 0C49F3730359A14518585931BC711F9BA15703C6 
 echo "deb [ arch=amd64,arm64 ] http://repo.mongodb.org/apt/ubuntu xenial/mongodb-org/3.4 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-3.4.list

sudo apt-get update && sudo apt-get install mongodb-org
```

它将在最后一步要求确认安装；按*Y*。安装完成后，我们需要使用以下命令启动 MongoDB 守护进程：

```go
systemctl start mongod
```

所有前面的命令都需要由 root 用户运行。如果用户不是 root 用户，请在每个命令前使用`sudo`关键字。

我们还可以从网站手动下载 MongoDB，并使用`~/mongodb/bin/mongod/`命令运行服务器。为此，我们需要创建一个 init 脚本，因为如果关闭终端，服务器将被关闭。我们还可以使用`nohup`在后台运行服务器。通常最好使用`apt-get`进行安装。

要在 macOS X 上安装 MongoDB，请使用 Homebrew 软件。我们可以使用以下命令轻松安装它：

```go
brew install mongodb
```

之后，我们需要创建 MongoDB 存储其数据库的`db`目录：

```go
mkdir -p /data/db
```

然后，使用`chown`更改该文件的权限：

```go
chown -R `id -un` /data/db
```

现在我们已经准备好了 MongoDB。我们可以在终端窗口中使用以下命令运行它，这将启动 MongoDB 守护进程：

```go
mongod
```

请查看以下截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/c03be89e-caf0-4908-b354-18561320761a.png)

在 Windows 上，我们可以手动从网站下载安装程序二进制文件，并通过将安装的`bin`目录添加到`PATH`变量中来启动它。然后，我们可以使用`mongod`命令运行它。

# 使用 Mongo shell

每当我们开始使用 MongoDB 时，我们应该先玩一会儿。查找可用的数据库、集合、文档等可以使用一个名为 Mongo shell 的简单工具。这个 shell 是与我们在前面部分提到的安装步骤一起打包的。我们需要使用以下命令启动它：

```go
mongo
```

参考以下截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/22b8e49f-16bd-40a6-add0-135f45be6284.png)

如果您看到这个屏幕，一切都进行得很顺利。如果您遇到任何错误，服务器没有运行或者有其他问题。对于故障排除，您可以查看官方 MongoDB 故障排除指南[`docs.mongodb.com/manual/faq/diagnostics`](https://docs.mongodb.com/manual/faq/diagnostics/)。客户端提供了有关 MongoDB 版本和其他警告的信息。要查看所有可用的 shell 命令，请使用`help`命令。

现在我们已经准备好了。让我们创建一个名为`movies`的新集合，并将前面的示例文档插入其中。默认情况下，数据库将是一个测试数据库。您可以使用`use`命令切换到一个新的数据库：

```go
> show databases
```

它显示所有可用的数据库。默认情况下，`admin`，`test`和`local`是三个可用的数据库。为了创建一个新的数据库，只需使用`use db_name`：

```go
> use appdb
```

这将把当前数据库切换到`appdb`数据库。如果您尝试查看可用的数据库，它不会显示出来，因为 MongoDB 只有在插入数据时（第一个集合或文档）才会创建数据库。因此，现在我们可以通过从 shell 中插入一个文档来创建一个新的集合。然后，我们可以使用以下命令将前面的《星际迷航》电影记录插入到名为`movies`的集合中：

```go
> db.movies.insertOne({ _id: 5, name: 'Star Trek', year: 2009, directors: ['J.J. Abrams'], writers: ['Roberto Orci', 'Alex Kurtzman'], boxOffice: { budget:150000000, gross:257704099 } } )
{ 
 "acknowledged" : true,
 "insertedId" : 5 
}
```

您插入的 JSON 具有名为`_id`的 ID。我们可以在插入文档时提供它，或者 MongoDB 可以为您自动插入一个。在 SQL 数据库中，我们使用*自动递增*以及一个`ID`模式来递增`ID`字段。在这里，MongoDB 生成一个唯一的哈希`ID`而不是一个序列。让我们再插入一个关于`黑暗骑士`的文档，但这次让我们不传递`_id`字段：

```go
> db.movies.insertOne({ name: 'The Dark Knight ', year: 2008, directors: ['Christopher Nolan'], writers: ['Jonathan Nolan', 'Christopher Nolan'], boxOffice: { budget:185000000, gross:533316061 } } )> db.movies.insertOne({ name: 'The Dark Knight ', year: 2008, directors: ['Christopher Nolan'], writers: ['Jonathan Nolan', 'Christopher Nolan'], boxOffice: { budget:185000000, gross:533316061 } } )
{ 
 "acknowledged" : true,
 "insertedId" : ObjectId("59574125bf7a73d140d5ba4a")
}
```

如果您观察到确认的 JSON 响应，`insertId`现在已经更改为非常长的`59574125bf7a73d140d5ba4a`。这是 MongoDB 生成的唯一哈希。现在，让我们看看我们集合中的所有文档。我们还可以使用`insertMany`函数一次插入一批文档：

```go
> db.movies.find()

{ "_id" : 5, "name" : "Star Trek", "year" : 2009, "directors" : [ "J.J. Abrams" ], "writers" : [ "Roberto Orci", "Alex Kurtzman" ], "boxOffice" : { "budget" : 150000000, "gross" : 257704099 } }
{ "_id" : ObjectId("59574125bf7a73d140d5ba4a"), "name" : "The Dark Knight ", "year" : 2008, "directors" : [ "Christopher Nolan" ], "writers" : [ "Jonathan Nolan", "Christopher Nolan" ], "boxOffice" : { "budget" : 185000000, "gross" : 533316061 } }
```

在 movies 集合上使用`find`函数返回集合中所有匹配的文档。为了返回单个文档，使用`findOne`函数。它从多个结果中返回最新的文档：

```go
> db.movies.findOne()

{ "_id" : 5, "name" : "Star Trek", "year" : 2009, "directors" : [ "J.J. Abrams" ], "writers" : [ "Roberto Orci", "Alex Kurtzman" ], "boxOffice" : { "budget" : 150000000, "gross" : 257704099 }}
```

我们如何根据一些条件获取文档？这意味着查询。在 MongoDB 中查询被称为过滤数据并返回结果。如果我们需要过滤发布于 2008 年的电影，那么我们可以这样做：

```go
> db.movies.find({year: {$eq: 2008}})

{ "_id" : ObjectId("59574125bf7a73d140d5ba4a"), "name" : "The Dark Knight ", "year" : 2008, "directors" : [ "Christopher Nolan" ], "writers" : [ "Jonathan Nolan", "Christopher Nolan" ], "boxOffice" : { "budget" : 185000000, "gross" : 533316061 } }
```

前面 mongo 语句中的过滤查询是：

```go
{year: {$eq: 2008}}
```

这说明搜索条件是*年份*，值应该是*2008*。`$eq`被称为过滤操作符，它有助于关联字段和数据之间的条件。它相当于 SQL 中的`=`操作符。在 SQL 中，等效的查询可以写成：

```go
SELECT * FROM movies WHERE year=2008;
```

我们可以简化上次编写的 mongo 查询语句为：

```go
> db.movies.find({year: 2008})
```

这个查询和上面的 mongo 查询是一样的，返回相同的一组文档。前一种语法使用了`$eq`，这是一个查询操作符。从现在开始，让我们简单地称之为*操作符*。其他操作符有：

| **操作符** | **功能** |
| --- | --- |
| `$lt` | 小于 |
| `$gt` | 大于 |
| `$in` | 在 |
| `$lte` | 小于或等于 |
| `$ne` | 不等于 |

现在，让我们对自己提出一个问题。我们想获取所有预算超过 1.5 亿美元的文档。我们如何使用之前获得的知识进行过滤？看一下以下代码片段：

```go
> db.movies.find({'boxOffice.budget': {$gt: 150000000}})

{ "_id" : ObjectId("59574125bf7a73d140d5ba4a"), "name" : "The Dark Knight ", "year" : 2008, "directors" : [ "Christopher Nolan" ], "writers" : [ "Jonathan Nolan", "Christopher Nolan" ], "boxOffice" : { "budget" : 185000000, "gross" : 533316061 } }
```

如果您注意到，我们使用`boxOffice.budget`在 JSON 中访问了 budget 键。MongoDB 的美妙之处在于它允许我们以很大的自由查询 JSON。在获取文档时，我们不能给条件添加两个或更多的操作符吗？是的，我们可以！让我们找到数据库中 2009 年发布的预算超过 1.5 亿美元的所有电影：

```go
> db.movies.find({'boxOffice.budget': {$gt: 150000000}, year: 2009})
```

这返回了空值，因为我们没有任何符合给定条件的文档。逗号分隔的字段实际上与`AND`操作结合在一起。现在，让我们放宽条件，找到 2009 年发布的电影或预算超过$150,000,000 的电影：

```go
> db.movies.find({$or: [{'boxOffice.budget': {$gt: 150000000}}, {year: 2009}]})

{ "_id" : 5, "name" : "Star Trek", "year" : 2009, "directors" : [ "J.J. Abrams" ], "writers" : [ "Roberto Orci", "Alex Kurtzman" ], "boxOffice" : { "budget" : 150000000, "gross" : 257704099 } }
{ "_id" : ObjectId("59574125bf7a73d140d5ba4a"), "name" : "The Dark Knight ", "year" : 2008, "directors" : [ "Christopher Nolan" ], "writers" : [ "Jonathan Nolan", "Christopher Nolan" ], "boxOffice" : { "budget" : 185000000, "gross" : 533316061 } }
```

在这里，查询有点不同。我们使用了一个称为`$or`的运算符来查找两个条件的谓词。结果将是获取文档的条件。`$or`需要分配给一个包含 JSON 条件对象列表的列表。由于 JSON 可以嵌套，条件也可以嵌套。这种查询方式对于来自 SQL 背景的人来说可能是新的。MongoDB 团队设计它用于直观地过滤数据。我们还可以使用运算符轻松地在 MongoDB 中编写高级查询，例如内连接、外连接、嵌套查询等。

不知不觉中，我们已经完成了 CRUD 中的三个操作。我们看到了如何创建数据库和集合。然后，我们使用过滤器插入文档并读取它们。现在是删除操作的时候了。我们可以使用`deleteOne`和`deleteMany`函数从给定的集合中删除文档：

```go
> db.movies.deleteOne({"_id": ObjectId("59574125bf7a73d140d5ba4a")})
{ "acknowledged" : true, "deletedCount" : 1 }
```

传递给**`deleteOne`**函数的参数是过滤条件，类似于读操作。所有匹配给定条件的文档都将从集合中删除。响应中有一个很好的确认消息，其中包含被删除的文档数量。

前面的所有部分都讨论了 MongoDB 的基础知识，但是使用的是执行 JavaScript 语句的 shell。手动从 shell 执行`db`语句并不是很有用。我们需要使用驱动程序在 Go 中调用 Mongo DB 的 API。在接下来的部分中，我们将看到一个名为`mgo`的驱动程序包。官方的 MongoDB 驱动程序包括 Python、Java 和 Ruby 等语言。Go 的`mgo`驱动程序是一个第三方软件包。

# 介绍`mgo`，一个用于 Go 的 MongoDB 驱动程序

`mgo`是一个丰富的 MongoDB 驱动程序，它方便开发人员编写应用程序，与 MongoDB 进行通信，而无需使用 Mongo shell。使用`mgo`驱动程序，Go 应用程序可以轻松地与 MongoDB 进行所有 CRUD 操作。这是一个开源实现，可以自由使用和修改。由 Labix 维护。我们可以将其视为 MongoDB API 的包装器。安装该软件包非常简单，请参考以下命令：

```go
go get gopkg.in/mgo.v2
```

这将在`$GOPATH`中安装软件包。现在，我们可以在我们的 Go 程序中引用该软件包，如下所示：

```go
import "gopkg.in/mgo.v2"
```

让我们编写一个简单的程序，与 MongoDB 通信并插入`The Dark Knight`电影记录：

```go
package main

import (
        "fmt"
        "log"

        mgo "gopkg.in/mgo.v2"
        "gopkg.in/mgo.v2/bson"
)

// Movie holds a movie data
type Movie struct {
        Name      string   `bson:"name"`
        Year      string   `bson:"year"`
        Directors []string `bson:"directors"`
        Writers   []string `bson:"writers"`
        BoxOffice `bson:"boxOffice"`
}

// BoxOffice is nested in Movie
type BoxOffice struct {
        Budget uint64 `bson:"budget"`
        Gross  uint64 `bson:"gross"`
}

func main() {
        session, err := mgo.Dial("127.0.0.1")
        if err != nil {
                panic(err)
        }
        defer session.Close()

        c := session.DB("appdb").C("movies")

        // Create a movie
        darkNight := &Movie{
                Name:      "The Dark Knight",
                Year:      "2008",
                Directors: []string{"Christopher Nolan"},
                Writers:   []string{"Jonathan Nolan", "Christopher Nolan"},
                BoxOffice: BoxOffice{
                        Budget: 185000000,
                        Gross:  533316061,
                },
        }

        // Insert into MongoDB
        err = c.Insert(darkNight)
        if err != nil {
                log.Fatal(err)
        }

        // Now query the movie back
        result := Movie{}
        // bson.M is used for nested fields
        err = c.Find(bson.M{"boxOffice.budget": bson.M{"$gt": 150000000}}).One(&result)
        if err != nil {
                log.Fatal(err)
        }

        fmt.Println("Movie:", result.Name)
}
```

如果您观察代码，我们导入了`mgo`软件包以及`bson`软件包。接下来，我们创建了模型我们的 JSON 要插入到数据库中的结构。在主函数中，我们使用**`mgo.Dial`**函数创建了一个会话。之后，我们使用链式方式的`DB`和`C`函数获取了一个集合：

```go
c := session.DB("appdb").C("movies")
```

这里，`c`代表集合。我们正在从`appdb`中获取 movies 集合。然后，我们通过填充数据创建了一个结构对象。接下来，我们在`c`集合上使用**`Insert`**函数将`darkNight`数据插入集合中。该函数还可以接受一系列结构对象，以插入一批电影。然后，我们在集合上使用**`Find`**函数来读取具有给定条件的电影。在这里，与我们在 shell 中使用的条件不同，查询条件（查询）的形成也不同。由于 Go 不是 JavaScript shell，我们需要一个可以将普通过滤查询转换为 MongoDB 可理解查询的转换器。`mgo`软件包中的**`bson.M`**函数就是为此而设计的：

```go
bson.M{"year": "2008"}
```

但是，如果我们需要使用运算符执行高级查询怎么办？我们可以通过用`bson.M`函数替换普通的 JSON 语法来实现这一点。我们可以使用以下查询从数据库中找到预算超过$150,000,000 的电影：

```go
bson.M{"boxOffice.budget": bson.M{"$gt": 150000000}}
```

如果将此与 shell 命令进行对比，我们只需在 JSON 查询前面添加`bson.M`，然后将其余查询按原样编写。操作符号应该在这里是一个字符串（`"$gt"`）。

在结构定义中还有一个值得注意的事情是，我们为每个字段添加了`bson:identifier`标签。没有这个标签，Go 会将 BoxOffice 存储为 boxoffice。因此，为了让 Go 保持 CamelCase，我们添加了这些标签。现在，让我们运行这个程序并查看输出：

```go
go run mgoIntro.go
```

输出如下：

```go
Movie: The Dark Knight
```

查询结果可以存储在一个新的结构中，并可以序列化为 JSON 供客户端使用。

# 使用 Gorilla Mux 和 MongoDB 构建 RESTful API

在之前的章节中，我们探讨了构建 RESTful API 的所有可能方式。我们首先研究了 HTTP 路由器，然后是 web 框架。但作为个人选择，为了使我们的 API 轻量化，我们更喜欢 Gorilla Mux 作为默认选择，以及`mgo`作为 MongoDB 驱动程序。在本节中，我们将构建一个完整的电影 API，其中包括数据库和 HTTP 路由器的端到端集成。我们看到了如何使用 Go 和 MongoDB 创建新资源并检索它。利用这些知识，让我们编写这个程序：

```go
package main

import (
        "encoding/json"
        "io/ioutil"
        "log"
        "net/http"
        "time"

        "github.com/gorilla/mux"
        mgo "gopkg.in/mgo.v2"
        "gopkg.in/mgo.v2/bson"
)

// DB stores the database session imformation. Needs to be initialized once
type DB struct {
        session    *mgo.Session
        collection *mgo.Collection
}

type Movie struct {
        ID        bson.ObjectId `json:"id" bson:"_id,omitempty"`
        Name      string        `json:"name" bson:"name"`
        Year      string        `json:"year" bson:"year"`
        Directors []string      `json:"directors" bson:"directors"`
        Writers   []string      `json:"writers" bson:"writers"`
        BoxOffice BoxOffice     `json:"boxOffice" bson:"boxOffice"`
}

type BoxOffice struct {
        Budget uint64 `json:"budget" bson:"budget"`
        Gross  uint64 `json:"gross" bson:"gross"`
}

// GetMovie fetches a movie with a given ID
func (db *DB) GetMovie(w http.ResponseWriter, r *http.Request) {
        vars := mux.Vars(r)
        w.WriteHeader(http.StatusOK)
        var movie Movie
        err := db.collection.Find(bson.M{"_id": bson.ObjectIdHex(vars["id"])}).One(&movie)
        if err != nil {
                w.Write([]byte(err.Error()))
        } else {
                w.Header().Set("Content-Type", "application/json")
                response, _ := json.Marshal(movie)
                w.Write(response)
        }

}

// PostMovie adds a new movie to our MongoDB collection
func (db *DB) PostMovie(w http.ResponseWriter, r *http.Request) {
        var movie Movie
        postBody, _ := ioutil.ReadAll(r.Body)
        json.Unmarshal(postBody, &movie)
        // Create a Hash ID to insert
        movie.ID = bson.NewObjectId()
        err := db.collection.Insert(movie)
        if err != nil {
                w.Write([]byte(err.Error()))
        } else {
                w.Header().Set("Content-Type", "application/json")
                response, _ := json.Marshal(movie)
                w.Write(response)
        }
}

func main() {
        session, err := mgo.Dial("127.0.0.1")
        c := session.DB("appdb").C("movies")
        db := &DB{session: session, collection: c}
        if err != nil {
                panic(err)
        }
        defer session.Close()
        // Create a new router
        r := mux.NewRouter()
        // Attach an elegant path with handler
        r.HandleFunc("/v1/movies/{id:[a-zA-Z0-9]*}", db.GetMovie).Methods("GET")
        r.HandleFunc("/v1/movies", db.PostMovie).Methods("POST")
        srv := &http.Server{
                Handler: r,
                Addr:    "127.0.0.1:8000",
                // Good practice: enforce timeouts for servers you create!
                WriteTimeout: 15 * time.Second,
                ReadTimeout:  15 * time.Second,
        }
        log.Fatal(srv.ListenAndServe())
}
```

让我们将这个程序命名为`movieAPI.go`并运行它：

```go
go run movieAPI.go
```

接下来，我们可以使用 curl 或 Postman 发出`POST` API 请求来创建一个新的电影：

```go
curl -X POST \
 http://localhost:8000/v1/movies \
 -H 'cache-control: no-cache' \
 -H 'content-type: application/json' \
 -H 'postman-token: 6ef9507e-65b3-c3dd-4748-3a2a3e055c9c' \
 -d '{ "name" : "The Dark Knight", "year" : "2008", "directors" : [ "Christopher Nolan" ], "writers" : [ "Jonathan Nolan", "Christopher Nolan" ], "boxOffice" : { "budget" : 185000000, "gross" : 533316061 }
}'
```

这将返回以下响应：

```go
{"id":"5958be2a057d926f089a9700","name":"The Dark Knight","year":"2008","directors":["Christopher Nolan"],"writers":["Jonathan Nolan","Christopher Nolan"],"boxOffice":{"budget":185000000,"gross":533316061}}
```

我们的电影已成功创建。这里返回的 ID 是由`mgo`包生成的。MongoDB 希望驱动程序提供唯一的 ID。如果没有提供，那么`Db`会自己创建一个。现在，让我们使用 curl 发出一个`GET` API 请求：

```go
curl -X GET \
 http://localhost:8000/v1/movies/5958be2a057d926f089a9700 \
 -H 'cache-control: no-cache' \
 -H 'postman-token: 00282916-e7f8-5977-ea34-d8f89aeb43e2'
```

它返回了我们在创建资源时得到的相同数据：

```go
{"id":"5958be2a057d926f089a9700","name":"The Dark Knight","year":"2008","directors":["Christopher Nolan"],"writers":["Jonathan Nolan","Christopher Nolan"],"boxOffice":{"budget":185000000,"gross":533316061}}
```

在前面的程序中发生了很多事情。我们将在接下来的章节中详细解释。

在前面的程序中，为了简单起见，`PostMovie`中跳过了为操作分配正确状态代码的微不足道的逻辑。读者可以随意修改程序，为操作添加正确的状态代码（200 OK，201 Created 等）。

首先，我们导入程序所需的必要包。我们导入了`mgo`和`bson`用于与 MongoDB 相关的实现，Gorilla Mux 用于 HTTP 路由编码/JSON，以及 ioutil 用于在 HTTP 请求的生命周期中读取和写入 JSON。

然后，我们创建了一个名为**`DB`**的结构，用于存储 MongoDB 的 session 和 collection 信息。我们需要这个结构，以便拥有全局 session，并在多个地方使用它，而不是创建一个新的 session（客户端连接）。看一下以下代码片段：

```go
// DB stores the database session imformation. Needs to be initialized once 
type DB struct {
   session *mgo.Session 
   collection *mgo.Collection 
}
```

我们需要这样做是因为 Mux 的多个 HTTP 处理程序需要这些信息。这是一种简单的将通用数据附加到不同函数的技巧。在 Go 中，我们可以创建一个结构，并向其添加函数，以便在函数中访问结构中的数据。然后，我们声明了存储电影嵌套 JSON 信息的结构。在 Go 中，为了创建嵌套的 JSON 结构，我们应该嵌套结构。

接下来，我们在`DB`结构上定义了两个函数。我们将在后面使用这两个函数作为 Gorilla Mux 路由器的处理程序。这两个函数可以访问 session 和 collection 信息，而无需创建新的 session。**`GetMovie`**处理程序从 MongoDB 读取数据，并将 JSON 返回给客户端。**`PostMovie`**在名为`moviex`的集合中在数据库中创建一个新资源（这里是电影）。

现在，来到主函数，我们在这里创建了 session 和 collection。`session`将在整个程序的生命周期内保持不变。但如果需要，处理函数可以通过使用`session`变量来覆盖 collection。这使我们能够编写可重用的数据库参数。然后，我们创建了一个新的路由器，并使用**`HandleFunc`**附加了处理函数和路由。然后，我们创建了一个在 localhost 的`8000`端口上运行的服务器。

在`PostMovie`中，我们使用`mgo`函数的**`bson.NewObjectId()`**创建一个新的哈希 ID。这个函数每次调用时都会返回一个新的哈希。然后我们将其传递给我们插入到数据库中的结构。我们使用**`collection.Insert`** moviefunction 在集合中插入一个文档。如果出现问题，这将返回一个错误。为了发送一条消息回去，我们使用`json.Marshal`对一个结构进行编组。如果你仔细观察`Movie`结构的结构，它是这样的：

```go
type Movie struct {
  ID        bson.ObjectId `json:"id" bson:"_id,omitempty"`
  Name      string        `json:"name" bson:"name"`
  Year      string        `json:"year" bson:"year"`
  Directors []string      `json:"directors" bson:"directors"`
  Writers   []string      `json:"writers" bson:"writers"`
  BoxOffice BoxOffice     `json:"boxOffice" bson:"boxOffice"`
}
```

右侧的标识符``json:"id" bson:"_id,omitempty"``是一个辅助工具，用于在对结构执行编组或解组时显示序列化的方式。`bson`标签显示了如何将字段插入到 MongoDB 中。`json`显示了我们的 HTTP 处理程序应该从客户端接收和发送数据的格式。

在`GetMovie`中，我们使用`Mux.vars`映射来获取作为路径参数传递的 ID。我们不能直接将 ID 传递给 MongoDB，因为它期望的是 BSON 对象而不是普通字符串。为了实现这一点，我们使用**`bson.ObjectIdHex`**函数。一旦我们得到了给定 ID 的电影，它将被加载到结构对象中。接下来，我们使用**`json.Marshal`**函数将其序列化为 JSON，并将其发送回客户端。我们可以很容易地向前面的代码中添加`PUT`（更新）和`DELETE`方法。我们只需要定义另外两个处理程序，如下所示：

```go
// UpdateMovie modifies the data of given resource
func (db *DB) UpdateMovie(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    var movie Movie
    putBody, _ := ioutil.ReadAll(r.Body)
    json.Unmarshal(putBody, &movie)
    // Create an Hash ID to insert
    err := db.collection.Update(bson.M{"_id": bson.ObjectIdHex(vars["id"])}, bson.M{"$set": &movie})
    if err != nil {
      w.WriteHeader(http.StatusOK)
      w.Write([]byte(err.Error()))
    } else {
      w.Header().Set("Content-Type", "text")
      w.Write([]byte("Updated succesfully!"))
    }
}

// DeleteMovie removes the data from the db
func (db *DB) DeleteMovie(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    // Create an Hash ID to insert
    err := db.collection.Remove(bson.M{"_id": bson.ObjectIdHex(vars["id"])})
    if err != nil {
      w.WriteHeader(http.StatusOK)
      w.Write([]byte(err.Error()))
    } else {
      w.Header().Set("Content-Type", "text")
      w.Write([]byte("Deleted succesfully!"))
    }
}
```

这种方法与`mgo`的 DB 方法完全相同。在这里，我们使用了`Update`和`Remove`函数。由于这些不重要，我们可以只向客户端发送状态而不发送正文。为了使这些处理程序处于活动状态，我们需要在前面程序的主块中添加这两行：

```go
r.HandleFunc("/v1/movies/{id:[a-zA-Z0-9]*}", db.UpdateMovie).Methods("PUT")
r.HandleFunc("/v1/movies/{id:[a-zA-Z0-9]*}", db.DeleteMovie).Methods("DELETE")
```

这些添加的完整代码可以在`chapter5/movieAPI_updated.go`文件中找到。

# 通过索引提高查询性能

我们都知道，在阅读一本书时，索引非常重要。当我们试图在书中搜索一个主题时，我们首先翻阅索引页。如果找到索引，然后我们去到该主题的具体页码。但这里有一个缺点。我们为了这种索引而使用了额外的页面。同样，当我们查询某些内容时，MongoDB 需要遍历所有文档。如果文档存储了重要字段的索引，它可以快速地将数据返回给我们。与此同时，我们浪费了额外的空间来进行索引。

在计算领域，B 树是一个重要的数据结构，用于实现索引，因为它可以对节点进行分类。通过遍历该树，我们可以在较少的步骤中找到我们需要的数据。我们可以使用 MongoDB 提供的`createIndex`函数来创建索引。让我们以学生和他们在考试中的分数为例。我们将更频繁地进行`GET`操作，并对分数进行排序。这种情况下的索引可以用以下形式来可视化。看一下下面的图表：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/b04cf3da-323c-4ca5-81d2-67fd41c87303.png)

这是 MongoDB 网站提供的官方示例。由于频繁使用，分数是要进行索引的字段。一旦进行了索引，数据库就会在二叉树中存储每个文档的地址。每当有人查询这个字段时，它会检查范围运算符（在这种情况下是`$lt`），遍历二叉树，并以更短的步骤获取文档的地址。由于分数被索引，排序操作的成本较低。因此，数据库返回排序（升序或降序）结果所需的时间更短。

回到我们之前的电影 API 示例，我们可以为数据创建索引。默认情况下，所有`_id`字段都被索引，这里使用 mongo shell 来展示。以前，我们将年份字段视为字符串。让我们将其修改为整数并进行索引。使用`mongo`命令启动 mongo shell。使用一个新的 mongo 数据库并将一个文档插入其中：

```go
> db.movies.insertOne({ name: 'Star Trek',   year: 2009,   directors: ['J.J. Abrams'],   writers: ['Roberto Orci', 'Alex Kurtzman'],   boxOffice: {      budget:150000000,      gross:257704099   } } )
{ 
 "acknowledged" : true,
 "insertedId" : ObjectId("595a6cc01226e5fdf52026a1")
}
```

再插入一个类似的不同数据的文档：

```go
> db.movies.insertOne({ name: 'The Dark Knight ', year: 2008, directors: ['Christopher Nolan'], writers: ['Jonathan Nolan', 'Christopher Nolan'], boxOffice: { budget:185000000, gross:533316061 } } )
{ 
 "acknowledged" : true,
 "insertedId" : ObjectId("59603d3b0f41ead96110cf4f")
}
```

现在，让我们使用`createIndex`函数为年份添加索引：

```go
db.movies.createIndex({year: 1})
```

这一行为检索数据库记录添加了魔力。现在，所有与年份相关的查询都利用了索引：

```go
> db.movies.find({year: {$lt: 2010}})
{ "_id" : ObjectId("5957397f4e5c31eb7a9ed48f"), "name" : "Star Trek", "year" : 2009, "directors" : [ "J.J. Abrams" ], "writers" : [ "Roberto Orci", "Alex Kurtzman" ], "boxOffice" : { "budget" : 150000000, "gross" : 257704099 } }
{ "_id" : ObjectId("59603d3b0f41ead96110cf4f"), "name" : "The Dark Knight ", "year" : 2008, "directors" : [ "Christopher Nolan" ], "writers" : [ "Jonathan Nolan", "Christopher Nolan" ], "boxOffice" : { "budget" : 185000000, "gross" : 533316061 } }
```

查询结果没有区别。但是通过索引，`MongoDB`文档的查找机制已经发生了变化。对于大量文档，这可能会大大减少查找时间。

索引是有成本的。如果索引没有正确地进行，一些查询在不同字段上运行得非常慢。在 MongoDB 中，我们还可以有复合索引，可以索引多个字段。

为了查看查询的执行时间，请在`query`函数之后使用`explain`函数。例如，`db.movies.find({year: {$lt: 2010}}).explain("executionStats")`。这将解释查询的获胜计划，以毫秒为单位的时间，使用的索引等等。

使用`explain`函数查看索引和非索引数据的性能。

# 设计电子商务数据文档模型

到目前为止，我们已经看到了如何与 MongoDB 交互，并为我们的 REST API 执行 CRUD 操作。在这里，我们将定义一个可以由 MongoDB 实现的真实世界 JSON 文档。让我们为电子商务问题的 JSON 设计提出设计。这五个组件对于任何电子商务设计都是必不可少的：

+   产品

+   客户/用户

+   类别

+   订单

+   回顾

让我们看看每个组件的模式：

产品：

```go
{
    _id: ObjectId("59603d3b0f41ead96110cf4f"),
    sku: 1022,
    slug: "highlander-shirt-223",
    name: "Highlander casual shirt",
    description: "A nice looking casual shirt for men",
    details: {
      model_number: 235476,
      manufacturer: "HighLander",
      color: "light blue",
      mfg_date: new Date(2017, 4, 8),
      size: 40 
    },
    reviews: 3,
    pricing: {
      cost: 23,
      retail: 29
    },
    categories: {
      ObjectId("3d3b10f41efad96g110vcf4f"),
      ObjectId("603d3eb0ft41ead96110cf4f")
    },
    tags: ["shirts", "men", "clothing"],
    reviews: {
      ObjectId("3bd310f41efad96g110vcf4f"),
      ObjectId("f4e603d3eb0ft41ead96110c"),
      ObjectId("96g3bd310f41efad110vcf4g")
    }
}
```

类别：

```go
{
    _id: ObjectId("6d3b56900f41ead96110cf4f"),
    name: "Casual Shirts",
    description: "All casual shirts for men",
    slug: "casual-shirts",
    parent_categories: [{
      slug: "home"
      name: "Home",
      _id: ObjectId("3d3b10f41efad96g110vcf4f"),
    }, 
    {
      slug: "shirts"
      name: "Shirts",
      _id: ObjectId("603d3eb0ft41ead96110cf4f"),
    }]
}
```

用户：

```go
{
  _id: ObjectId("4fcf3eb0ft41ead96110"),
  username: "John",
  email_address: "john.p@gmail.com",
  password: "5kj64k56hdfjkhdfkgdf98g79df7g9dfg",
  first_name: "John",
  last_name: "Pauling",
  address_multiple: [{
    type: "home"
    street: "601 Sherwood Ave",
    city: "San Bernardino",
    state: "California",
    pincode: 94565
  }, 
  {
    type: "work"
    street: "241 Indian Spring St",
    city: "Pittsburg",
    state: "California",
    pincode: 94565
  }] ,
  payments: {
    name: "Paypal",
    auth: {
      token: "dfghjvbsclka76asdadn89"
    }
  }
}
```

顺序：

```go
{
  _id: ObjectId(),
  user: ObjectId("4fcf3eb0ft41ead96110"),
  state: "cart",
  item_queue: [{
    item: ObjectId("59603d3b0f41ead96110cf4f"),
    quantity: 1,
    cost: 23
  }],
  shipping_address: {
    type: "work"
    street: "241 Indian Spring St",
    city: "Pittsburg",
    state: "California",
    pincode: 94565
  },
  total: 23, 
}
```

回顾：

```go
{
  _id: ObjectId("5tcf3eb0ft41ead96110"),
  product: ObjectId("4fcf3eb0ft41ead96110"),
  posted_date: new Date(2017, 2, 6),
  title: "Overall satisfied with product",
  body: "The product is good and durable. After dry wash, the color hasn't changed much",
  user: ObjectId(),
  rating: 4,
  upvotes: 3,
  downvotes: 0,
  upvoters: [ObjectId("41ea5tcf3eb0ftd9233476hg"),
             ObjectId("507f1f77bcf86cd799439011"),
             ObjectId("54f113fffba522406c9cc20f")
            ],
  downvoters: []
}
```

所有前述的模式都是为了让人了解如何设计电子商务 REST 服务。最终数据中应包含所有必要的字段。

请注意，前述的 JSON 不是真正的 JSON，而是 Mongo shell 中使用的形式。在创建服务时请注意这种差异。提供模式是为了让读者看到电子商务关系数据的设计方式。

由于我们已经定义了模式，读者可以进行编码练习。您能否利用我们在本章开头部分获得的知识来创建一个符合前述模式的 REST 服务？无论如何，我们将在接下来的章节中在其他数据库中实现这个模型。

# 总结

首先，我们从介绍 MongoDB 及其如何解决现代 Web 问题开始了本章。MongoDB 是一种与传统关系数据库不同的 NoSQL 数据库。然后，我们学习了如何在所有平台上安装 MongoDB 以及如何启动 Mongo 服务器。然后我们探索了 Mongo shell 的特性。Mongo shell 是一个用于快速检查或执行 CRUD 操作以及许多其他操作的工具。我们看了查询的操作符符号。接下来我们介绍了 Go 的 MongoDB 驱动程序`mgo`并学习了它的用法。我们使用`mgo`和 MongoDB 创建了一个持久的电影 API。我们看到了如何将 Go 结构映射到 JSON 文档。

在 MongoDB 中，并非所有查询都是高效的。因此，为了提高查询性能，我们看到了通过索引机制来减少文档获取时间的方法，通过将文档按 B 树的顺序排列。我们看到了如何使用`explain`命令来测量查询的执行时间。最后，我们通过提供 BSON（Mongo shell 的 JSON）来设计了一个电子商务文档。


# 第六章：使用协议缓冲区和 GRPC

在本章中，我们将进入协议缓冲区的世界。我们将发现使用协议缓冲区而不是 JSON 的好处，以及何时使用两者。我们将使用 Google 的`proto`库来编译协议缓冲区。我们将尝试使用协议缓冲区编写一些可以与 Go 或其他应用程序（如 Python、NodeJS 等）通信的 Web 服务。然后，我们将解释 GRPC，一种高级简化的 RPC 形式。我们将学习 GRPC 和协议缓冲区如何帮助我们构建可以被任何客户端消费的服务。我们还将讨论 HTTP/2 及其优势，以及其在普通 HTTP/1.1 基于 JSON 的服务上的优势。

简而言之，我们将涵盖以下主题：

+   协议缓冲区介绍

+   协议缓冲区的格式

+   协议缓冲区的编译过程

+   GRPC，一个现代的 RPC 库

+   使用 GRPC 进行双向流

# 获取代码

您可以从[`github.com/narenaryan/gorestful/tree/master/chapter6`](https://github.com/narenaryan/gorestful/tree/master/chapter6)获取本章的代码示例。本章的示例是单个程序和项目的组合。因此，请将相应的目录复制到您的`GOPATH`中，以正确运行代码示例。

# 协议缓冲区介绍

HTTP/1.1 是 Web 社区采用的标准。近年来，由于其优势，HTTP/2 变得更加流行。使用 HTTP/2 的一些好处包括：

+   通过 TLS（HTTPS）加密数据

+   头部压缩

+   单个 TCP 连接

+   回退到 HTTP/1.1

+   所有主要浏览器的支持

谷歌关于协议缓冲区的技术定义是：

协议缓冲区是一种灵活、高效、自动化的序列化结构化数据的机制 - 想象一下 XML，但更小、更快、更简单。您只需定义一次您希望数据结构化的方式，然后您可以使用特殊生成的源代码轻松地将您的结构化数据写入和从各种数据流中读取，并使用各种语言。您甚至可以更新数据结构，而不会破坏针对“旧”格式编译的已部署程序。

在 Go 中，协议缓冲区与 HTTP/2 结合在一起。它们是一种类似 JSON 但严格类型化的格式，只能从客户端到服务器理解。首先，我们将了解为什么存在 protobufs（协议缓冲区的简称）以及如何使用它们。

协议缓冲区在序列化结构化数据方面比 JSON/XML 有许多优势，例如：

+   它们更简单

+   它们的大小是 JSON/XML 的 3 到 10 倍

+   它们快 20 到 100 倍

+   它们不太模棱两可

+   它们生成易于以编程方式使用的数据访问类

# 协议缓冲区语言

协议缓冲区是具有极简语法的文件。我们编译协议缓冲区，目标文件将为编程语言生成。例如，在 Go 中，编译后的文件将是一个`.go`文件，其中包含映射 protobuf 文件的结构。在 Java 中，将创建一个类文件。将协议缓冲区视为具有特定顺序的数据的骨架。在跳入实际代码之前，我们需要了解类型。为了使事情变得更容易，我将首先展示 JSON 及其在协议缓冲区中的等效内容。然后，我们将实施一个实例。

在这里，我们将使用**proto3**作为我们的协议缓冲区版本。版本之间存在细微差异，但最新版本已经发布并进行了改进。

有许多类型的协议缓冲区元素。其中一些是：

+   标量值

+   枚举

+   默认值

+   嵌套值

+   未知类型

首先，让我们看看如何在协议缓冲区中定义消息类型。在这里，我们尝试定义一个简单的网络接口消息：

```go
syntax 'proto3';

message NetworkInterface {
  int index = 1;
  int mtu = 2;
  string name = 3;
  string hardwareaddr = 4;
}
```

语法可能看起来很新。在前面的代码中，我们正在定义一个名为`NetworkInterface`的消息类型。它有四个字段：*index*、*最大传输单元（MTU）*、*名称*和*硬件地址（MAC）*。如果我们希望在 JSON 中写入相同的内容，它将如下所示：

```go
{
   "networkInterface": {
       "index" : 0,
       "mtu" : 68,
       "name": "eth0",
       "hardwareAddr": "00:A0:C9:14:C8:29"
   }
}
```

字段名称已更改以符合 JSON 样式指南，但本质和结构是相同的。但是，在 protobuf 文件中给字段分配的顺序号（1,2,3,4）是什么？它们是序列化和反序列化协议缓冲区数据在两个系统之间的顺序标签。这类似于提示协议缓冲区编码/解码系统按照特定顺序分别写入/读取数据。当上述 protobuf 文件被编译并生成编程语言目标时，协议缓冲区消息将被转换为 Go 结构，并且字段将填充为空的默认值。

# 标量值

我们为`networkInterface`消息中的字段分配的类型是标量类型。这些类型类似于 Go 类型，并且与它们完全匹配。对于其他编程语言，它们将转换为相应的类型。Protobuf 是为 Go 设计的，因此大多数类型（如`int`，`int32`，`int64`，`string`和`bool`）完全相同，但有一些不同。它们是：

| **Go 类型** | **Protobuf 类型** |
| --- | --- |
| float32 | float |
| float64 | double |
| uint32 | fixed32 |
| uint64 | fixed64 |
| []byte | bytes |

在定义 protbuf 文件中的消息时，应该牢记这些事情。除此之外，我们可以自由地使用其他 Go 类型作为普通标量类型。**默认值**是如果用户没有为这些标量值分配值，则将填充这些类型的值。我们都知道在任何给定的编程语言中，变量是被定义和赋值的。定义为变量分配内存，赋值为变量填充值。类比地，我们在前面的消息中定义的标量字段将被分配默认值。让我们看看给定类型的默认值：

| **Protobuf 类型** | **默认值** |
| --- | --- |
| 字符串 | "" |
| bytes | 空字节[] |
| bool | false |
| int，int32，int64，float，double | 0 |
| enum | 0 |

由于协议缓冲区使用数据结构在端系统之间达成协议，因此在 JSON 中不需要为键占用额外的空间。

# 枚举和重复字段

枚举为给定元素集提供数字的排序。默认值的顺序是从零到 n。因此，在协议缓冲区消息中，我们可以有一个枚举类型。让我们看一个`enum`的例子：

```go
syntax 'proto3';

message Schedule{
  enum Days{
     SUNDAY = 0;
     MONDAY = 1;
     TUESDAY = 2;
     WEDNESDAY = 3;
     THURSDAY = 4;
     FRIDAY = 5;
     SATURDAY = 6;
  }
}
```

如果我们需要为多个枚举成员分配相同的值怎么办。Protobuf3 允许使用名为**allow aliases**的选项来为两个不同的成员分配相同的值。例如：

```go
enum EnumAllowingAlias {
  option allow_alias = true;
  UNKNOWN = 0;
  STARTED = 1;
  RUNNING = 1;
}
```

在这里，`STARTED`和`RUNNING`都有一个`1`标签。这意味着数据中两者可以具有相同的值。如果我们尝试删除重复的值，我们还应该删除`allow_alias`选项。否则，proto 编译器会抛出错误（我们很快将看到 proto 编译器是什么）。

`Repeated`字段是协议缓冲区消息中表示项目列表的字段。在 JSON 中，对于给定的键，我们有一系列元素。同样，重复字段允许我们定义特定类型的元素的数组/列表：

```go
message Site{
   string url = 1;
   int latency = 2;
   repeated string proxies = 3;
}
```

在上述代码中，第三个字段是一个重复字段，这意味着它是一个代理的数组/列表。该值可以是诸如["100.104.112.10", "100.104.112.12"]之类的内容。除了重复字段，我们还可以使用其他消息作为类型。这类似于嵌套的 JSON。例如，看一下以下代码：

```go
{
  outerJSON: {
      outerKey1: val1,
      innerJSON: {
         innerKey1: val2
      }
  }
}
```

我们看到`innerJSON`嵌套在`outerJSON`的成员之一。我们如何在 protobuf 中建模相同的事物？我们可以使用嵌套消息来做到这一点，如下面的代码所示：

```go
message Site {
  string url = 1;
  int latency = 2;
  repeated Proxy proxies = 3;
}

message Proxy {
  string url = 1;
  int latency = 2;
}
```

在这里，我们将`Proxy`类型嵌套到`Site`中。我们很快将看到一个包含所有这些类型字段的真实示例。

# 使用 protoc 编译协议缓冲区

到目前为止，我们已经讨论了如何编写协议缓冲区文件，该文件以前是用 JSON 或其他数据格式编写的。但是，我们如何将其实际集成到我们的程序中呢？请记住，协议缓冲区是数据格式，不仅仅是数据格式。它们是各种系统之间的通信格式，类似于 JSON。这是我们在 Go 程序中使用 protobuf 的实际步骤：

1.  安装`protoc`命令行工具和`proto`库。

1.  编写一个带有`.proto`扩展名的 protobuf 文件。

1.  将其编译为目标编程语言（这里是 Go）。

1.  从生成的目标文件中导入结构并序列化数据。

1.  在远程机器上，接收序列化数据并将其解码为结构或类。

看一下下面的图表：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/6db67127-8a0c-4e2e-b2c9-b4ae112087c7.jpg)

第一步是在我们的机器上安装`protobuf`编译器。为此，请从[`github.com/google/protobuf/releases`](https://github.com/google/protobuf/releases)下载`protobuf`包。在 macOS X 上，我们可以使用此命令安装`protobuf`：

```go
brew install protobuf
```

在 Ubuntu 或 Linux 上，我们可以将`protoc`复制到`/usr/bin`文件夹中：

```go
# Make sure you grab the latest version
curl -OL https://github.com/google/protobuf/releases/download/v3.3.0/protoc-3.3.0-linux-x86_64.zip
# Unzip
unzip protoc-3.3.0-linux-x86_64.zip -d protoc3
# Move only protoc* to /usr/bin/
sudo mv protoc3/bin/protoc /usr/bin/protoc
```

在 Windows 上，我们可以从[`github.com/google/protobuf/releases/download/v3.3.0/protoc-3.3.0-win32.zip`](https://github.com/google/protobuf/releases/download/v3.3.0/protoc-3.3.0-win32.zip)复制可执行文件（`.exe`）到`PATH`环境变量。让我们编写一个简单的协议缓冲区来说明如何编译和使用目标文件中的结构。使用以下命令在`$GOPATH/src/github.com/narenaryan`（这是我们 Go 项目的位置）中创建一个名为`protofiles`的文件夹：

```go
mkdir $GOPATH/src/github.com/narenaryan/protofiles
```

在这里，创建一个名为`person.proto`的文件，它模拟了一个人的信息。向其中添加一些消息，如下面的代码片段所示：

```go
syntax = "proto3";
package protofiles;

message Person {
  string name = 1;
  int32 id = 2;  // Unique ID number for this person.
  string email = 3;

  enum PhoneType {
    MOBILE = 0;
    HOME = 1;
    WORK = 2;
  }

  message PhoneNumber {
    string number = 1;
    PhoneType type = 2;
  }

  repeated PhoneNumber phones = 4;
}

// Our address book file is just one of these.
message AddressBook {
  repeated Person people = 1;
}
```

我们创建了两个主要消息，称为`AddressBook`和`Person`。`AddressBook`有一个人员列表。`Person`有`name`、`id`、`email`和`phone Number`。在第二行，我们将包声明为`protofiles`，如下所示：

```go
package protofiles;
```

这告诉编译器将生成的文件添加到给定包名称的相关位置。Go 不能直接使用这个`.proto`文件。我们需要将其编译为有效的 Go 文件。编译后，此包名称`protofiles`将用于设置输出文件（在本例中为 Go）的包。要编译此协议缓冲区文件，请转到`protofiles`目录并运行此命令：

```go
protoc --go_out=. *.proto
```

此命令将给定的协议缓冲区文件转换为具有相同名称的 Go 文件。运行此命令后，您将看到在同一目录中创建了一个新文件：

```go
[16:20:27] naren:protofiles git:(master*) $ ls -l
total 24
-rw-r--r-- 1 naren staff 5657 Jul 15 16:20 person.pb.go
-rw-r--r--@ 1 naren staff 433 Jul 15 15:58 person.proto
```

新文件名为`person.pb.go`。如果我们打开并检查此文件，它包含以下重要块：

```go
........
type Person_PhoneType int32

const (
  Person_MOBILE Person_PhoneType = 0
  Person_HOME   Person_PhoneType = 1
  Person_WORK   Person_PhoneType = 2
)

var Person_PhoneType_name = map[int32]string{
  0: "MOBILE",
  1: "HOME",
  2: "WORK",
}
var Person_PhoneType_value = map[string]int32{
  "MOBILE": 0,
  "HOME":   1,
  "WORK":   2,
}
.......
```

这只是该文件的一部分。将为给定的结构（如`Person`和`AddressBook`）创建许多 getter 和 setter 方法。此代码是自动生成的。我们需要在主程序中使用此代码来创建协议缓冲区字符串。现在，让我们创建一个名为`protobufs`的新目录。其中包含使用`person.pb.go`文件中的`Person`结构的`main.go`文件：

```go
mkdir $GOPATH/src/github.com/narenaryan/protobufs
```

现在，为了让 Go 将结构序列化为协议二进制格式，我们需要安装 Go proto 驱动程序。使用`go get`命令安装它：

```go
go get github.com/golang/protobuf/proto
```

之后，让我们编写`main.go`：

```go
package main

import (
  "fmt"

  "github.com/golang/protobuf/proto"
  pb "github.com/narenaryan/protofiles"
)

func main() {
  p := &pb.Person{
    Id:    1234,
    Name:  "Roger F",
    Email: "rf@example.com",
    Phones: []*pb.Person_PhoneNumber{
      {Number: "555-4321", Type: pb.Person_HOME},
    },
  }

  p1 := &pb.Person{}
  body, _ := proto.Marshal(p)
  _ = proto.Unmarshal(body, p1)
  fmt.Println("Original struct loaded from proto file:", p, "\n")
  fmt.Println("Marshaled proto data: ", body, "\n")
  fmt.Println("Unmarshaled struct: ", p1)
}
```

我们从`protofiles`包中导入**协议缓冲区**（**pb**）。在`proto files`中，有一些结构映射到给定的协议缓冲区。我们使用`Person`结构并对其进行初始化。然后，我们使用`proto.Marshal`函数对结构进行序列化。如果我们运行这个程序，输出如下：

```go
go run main.go
Original struct loaded from proto file: name:"Roger F" id:1234 email:"rf@example.com" phones:<number:"555-4321" type:HOME >

Marshaled proto data: [10 7 82 111 103 101 114 32 70 16 210 9 26 14 114 102 64 101 120 97 109 112 108 101 46 99 111 109 34 12 10 8 53 53 53 45 52 51 50 49 16 1]

Unmarshaled struct: name:"Roger F" id:1234 email:"rf@example.com" phones:<number:"555-4321" type:HOME >
```

序列化数据的第二个输出并不直观，因为`proto`库将数据序列化为二进制字节。协议缓冲区在 Go 中的另一个好处是，通过编译 proto 文件生成的结构体可以用于实时生成 JSON。让我们修改前面的例子。将其命名为`main_json.go`： 

```go
package main

import (
  "fmt"

  "encoding/json"
  pb "github.com/narenaryan/protofiles"
)

func main() {
  p := &pb.Person{
    Id:    1234,
    Name:  "Roger F",
    Email: "rf@example.com",
    Phones: []*pb.Person_PhoneNumber{
      {Number: "555-4321", Type: pb.Person_HOME},
    },
  }
  body, _ := json.Marshal(p)
  fmt.Println(string(body))
}
```

如果我们运行这个程序，它会打印一个 JSON 字符串，可以发送给任何能理解 JSON 的客户端：

```go
go run main_json.go

{"name":"Roger F","id":1234,"email":"rf@example.com","phones":[{"number":"555-4321","type":1}]}
```

任何其他语言或平台都可以轻松加载这个 JSON 字符串并立即使用数据。那么，使用协议缓冲区而不是 JSON 有什么好处呢？首先，协议缓冲区旨在使两个后端系统以更小的开销进行通信。由于二进制的大小比文本小，协议缓冲区序列化的数据比 JSON 的大小小。

通过使用协议缓冲区，我们可以将 JSON 和协议缓冲区格式映射到 Go 结构。这通过在转换一个格式到另一个格式时实现了两全其美。

但是，协议缓冲区只是一种数据格式。如果我们不进行通信，它们就没有任何重要性。因此，在这里，协议缓冲区用于以 RPC 的形式在两个端系统之间传递消息。我们看到了 RPC 是如何工作的，并且在前几章中还创建了 RPC 客户端和服务器。现在，我们将扩展这些知识，使用**Google 远程过程调用**（**GRPC**）与协议缓冲区来扩展我们的微服务通信。在这种情况下，服务器和客户端可以以协议缓冲区格式进行通信。

# GRPC 简介

GRPC 是一种在两个系统之间发送和接收消息的传输机制。这两个系统通常是服务器和客户端。正如我们在前几章中所描述的，RPC 可以在 Go 中实现以传输 JSON。我们称之为 JSON RPC 服务。同样，Google RPC 专门设计用于以协议缓冲区的形式传输数据。

GRPC 使服务创建变得简单而优雅。它提供了一套不错的 API 来定义服务并开始运行它们。在本节中，我们将主要关注如何创建 GRPC 服务并使用它。GRPC 的主要优势是它可以被多种编程语言理解。协议缓冲区提供了一个通用的数据结构。因此，这种组合使各种技术堆栈和系统之间能够无缝通信。这是分布式计算的核心概念。

Square、Netflix 等公司利用 GRPC 来扩展其庞大的流量服务。Google 的前产品经理 Andrew Jessup 在一次会议上表示，在 Google，每天处理数十亿次 GRPC 调用。如果任何商业组织需要采用 Google 的做法，它也可以通过对服务进行调整来处理流量需求。

在编写服务之前，我们需要安装`grpc` Go 库和`protoc-gen`插件。使用以下命令安装它们：

```go
go get google.golang.org/grpc
go get -u github.com/golang/protobuf/protoc-gen-go
```

GRPC 相对于传统的 HTTP/REST/JSON 架构具有以下优势：

+   GRPC 使用 HTTP/2，这是一种二进制协议

+   HTTP/2 中可以进行头部压缩，这意味着开销更小

+   我们可以在一个连接上复用多个请求

+   使用协议缓冲区进行数据的严格类型化

+   可以进行请求或响应的流式传输，而不是请求/响应事务

看一下下面的图表：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/8c77a0c5-6a5f-452f-b00f-d52b9b258101.jpg)

图表清楚地显示了任何后端系统或移动应用都可以通过发送协议缓冲区请求直接与 GRPC 服务器通信。让我们使用 GRPC 和协议缓冲区在 Go 中编写一个货币交易服务。在这里，我们将展示客户端和服务器的实现方式。步骤如下：

1.  为服务和消息创建协议缓冲区文件。

1.  编译协议缓冲区文件。

1.  使用生成的 Go 包创建一个 GRPC 服务器。

1.  创建一个与服务器通信的 GRPC 客户端。

对于这个项目，在你的 Go 工作空间中创建一个名为`datafiles`的文件夹（这里是`$GOPATH/src/github.com/narenaryan/`）：

```go
mkdir grpc_example
cd grpc_example
mkdir datafiles
```

在其中创建一个名为`transaction.proto`的文件，其中定义了消息和一个服务。我们很快将看到服务是什么：

```go
syntax = "proto3";
package datafiles;

message TransactionRequest {
   string from = 1;
   string to = 2;
   float amount = 3;
}

message TransactionResponse {
  bool confirmation = 1;
}

service MoneyTransaction {
    rpc MakeTransaction(TransactionRequest) returns (TransactionResponse) {}
}
```

这是服务器上的一个最简单的协议缓冲文件，用于货币交易。我们已经在 proto 文件中看到了关于消息关键字的信息。最后一个关键字`service`对我们来说是新的。`service`告诉 GRPC 将其视为服务，并且所有的 RPC 方法将作为实现此服务的服务器的接口。实现 Go 接口的结构体应该实现所有的函数。现在，让我们编译这个文件：

```go
protoc -I datafiles/ datafiles/transaction.proto --go_out=plugins=grpc:datafiles
```

这个命令比我们之前使用的命令稍微长一些。这是因为这里我们使用了`protoc-gen-go`插件。该命令简单地表示使用数据文件作为协议文件的输入目录，并使用相同的目录输出目标 Go 文件。现在，如果我们查看文件系统，将会有两个文件：

```go
-rw-r--r-- 1 naren staff 6215 Jul 16 17:28 transaction.pb.go
-rw-r--r-- 1 naren staff 294 Jul 16 17:28 transaction.proto
```

现在，在`$GOPATH/src/github.com/narenaryan/grpc_example`中创建另外两个目录，用于服务器和客户端逻辑。服务器实现了从 proto 文件生成的接口：

```go
mkdir grpcServer grpcClient
```

现在，将一个名为`server.go`的文件添加到`grpcServer`目录中，该文件实现了交易服务：

```go
package main

import (
  "log"
  "net"

  pb "github.com/narenaryan/grpc_example/datafiles"
  "golang.org/x/net/context"
  "google.golang.org/grpc"
  "google.golang.org/grpc/reflection"
)

const (
  port = ":50051"
)

// server is used to create MoneyTransactionServer.
type server struct{}

// MakeTransaction implements MoneyTransactionServer.MakeTransaction
func (s *server) MakeTransaction(ctx context.Context, in *pb.TransactionRequest) (*pb.TransactionResponse, error) {
  log.Printf("Got request for money Transfer....")
  log.Printf("Amount: %f, From A/c:%s, To A/c:%s", in.Amount, in.From, in.To)
  // Do database logic here....
  return &pb.TransactionResponse{Confirmation: true}, nil
}

func main() {
  lis, err := net.Listen("tcp", port)
  if err != nil {
    log.Fatalf("Failed to listen: %v", err)
  }
  s := grpc.NewServer()
  pb.RegisterMoneyTransactionServer(s, &server{})
  // Register reflection service on gRPC server.
  reflection.Register(s)
  if err := s.Serve(lis); err != nil {
    log.Fatalf("Failed to serve: %v", err)
  }
}
```

在前面的文件中发生了很多事情。首先，我们导入了所有必要的导入项。这里的新导入项是`context`和`reflection`。Context 用于创建一个`context`变量，它在 RPC 请求的整个生命周期内存在。这两个库都被 GRPC 用于其内部函数。

在解释下一节之前，如果我们打开生成的`transaction.pb.go`文件，我们可以清楚地看到有两件重要的事情：

+   `RegisterMoneyTransactionServer`函数

+   `MakeTransaction`函数作为`MoneyTransactionServer`接口的一部分。

为了实现一个服务，我们需要这两个东西：`MakeTransaction`用于实际的服务功能，以及`RegisterMoneyTransactionServer`用于注册服务（即创建一个在端口上运行的 RPC 服务器）。

`MakeTransaction`的`in`变量具有 RPC 请求的详细信息。它基本上是一个映射到我们在协议缓冲文件中定义的`TransactionRequest`消息的结构。从`MakeTransaction`返回的是`TransactionResponse`。这个函数签名与我们最初在协议缓冲文件中定义的函数签名匹配：

```go
rpc MakeTransaction(TransactionRequest) returns (TransactionResponse) {}
```

现在，让我们编写一个客户端。我们可以用任何编程语言编写客户端（或）服务器，但是在这里，我们为了理解 Go GRPC API，同时编写了一个客户端和服务器。在`grpcClient`目录中添加一个名为`client.go`的文件：

```go
package main

import (
  "log"

  pb "github.com/narenaryan/grpc_example/datafiles"
  "golang.org/x/net/context"
  "google.golang.org/grpc"
)

const (
  address = "localhost:50051"
)

func main() {
  // Set up a connection to the server.
  conn, err := grpc.Dial(address, grpc.WithInsecure())
  if err != nil {
    log.Fatalf("Did not connect: %v", err)
  }
  defer conn.Close()
  c := pb.NewMoneyTransactionClient(conn)

  // Prepare data. Get this from clients like Frontend or App
  from := "1234"
  to := "5678"
  amount := float32(1250.75)

  // Contact the server and print out its response.
  r, err := c.MakeTransaction(context.Background(), &pb.TransactionRequest{From: from,
    To: to, Amount: amount})
  if err != nil {
    log.Fatalf("Could not transact: %v", err)
  }
  log.Printf("Transaction confirmed: %t", r.Confirmation)
}
```

这个客户端也使用了`grpc`包。它使用一个名为`context.Background()`的空上下文传递给`MakeTransaction`函数。函数的第二个参数是`TransactionRequest`结构体：

```go
&pb.TransactionRequest{From: from, To: to, Amount: amount}
```

它与我们在上一节讨论的理论明显相符。现在，让我们运行它并查看输出。打开一个新的控制台，并使用以下命令运行 GRPC 服务器：

```go
go run $GOPATH/src/github.com/narenaryan/grpc_example/grpcServer/server.go
```

TCP 服务器开始监听端口`50051`。现在，打开另一个终端/Shell，并启动与该服务器通信的客户端程序：

```go
go run $GOPATH/src/github.com/narenaryan/grpc_example/grpcClient/client.go
```

它打印出成功交易的输出：

```go
2017/07/16 19:13:16 Transaction confirmed: true
```

同时，服务器将此消息记录到控制台中：

```go
2017/07/16 19:13:16 Amount: 1250.750000, From A/c:1234, To A/c:5678
```

在这里，客户端向 GRPC 服务器发出了一个请求，并传递了`From A/c`号码、`To A/c`号码和`Amount`的详细信息。服务器接收这些详细信息，处理它们，并发送一个回复，表示一切正常。

由于我在我的机器上运行代码示例，我在[github.com](https://github.com/)下有`narenaryan`作为项目目录。您可以用任何其他名称替换它。

# 使用 GRPC 进行双向流

GRPC 相对于传统的 HTTP/1.1 的主要优势在于它使用单个 TCP 连接在服务器和客户端之间发送和接收多个消息。我们之前看到了资金交易的示例。另一个现实世界的用例是出租车上安装的 GPS。在这里，出租车是客户端，它沿着路线发送其地理位置到服务器。最后，服务器可以根据点之间的时间和总距离计算总费用。

另一个这样的用例是当服务器需要在执行某些处理时通知客户端。这被称为服务器推送模型。当客户端仅请求一次时，服务器可以发送一系列结果。这与轮询不同，轮询中客户端每次都会请求。当需要执行一系列耗时步骤时，这可能很有用。GRPC 客户端可以将该作业升级到 GRPC 服务器。然后，服务器花费时间并将消息传递回客户端，客户端读取并执行有用的操作。让我们实现这个。

这个概念类似于 WebSockets，但适用于任何类型的平台。创建一个名为`serverPush`的项目：

```go
mkdir $GOPATH/src/github.com/narenaryan/serverPush
mkdir $GOPATH/src/github.com/narenaryan/serverPush/datafiles
```

现在，在`datafiles`中编写一个与之前类似的协议缓冲区：

```go
syntax = "proto3";
package datafiles;

message TransactionRequest {
   string from = 1;
   string to = 2;
   float amount = 3;
}

message TransactionResponse {
  string status = 1;
  int32 step = 2;
  string description = 3;
}

service MoneyTransaction {
    rpc MakeTransaction(TransactionRequest) returns (stream TransactionResponse) {}
}
```

在协议缓冲区文件中定义了两个消息和一个服务。令人兴奋的部分在于服务中，我们返回的是一个流而不是一个普通的响应：

```go
rpc MakeTransaction(TransactionRequest) returns (stream TransactionResponse) {}
```

该项目的用例是：*客户端向服务器发送资金转账请求，服务器执行一些任务，并将这些步骤详细信息作为一系列响应发送回服务器*。现在，让我们编译 proto 文件：

```go
protoc -I datafiles/ datafiles/transaction.proto --go_out=plugins=grpc:datafiles
```

这将在`datafiles`目录中创建一个名为`transaction.pb.go`的新文件。我们将在服务器和客户端程序中使用此文件中的定义，我们将很快创建。现在，让我们编写 GRPC 服务器代码。由于引入了流，这段代码与之前的示例有些不同：

```go
mkdir $GOPATH/src/github.com/narenaryan/serverPush/grpcServer
vi $GOPATH/src/github.com/narenaryan/serverPush/grpcServer/server.go
```

现在，将此程序添加到文件中：

```go
package main

import (
  "fmt"
  "log"
  "net"
  "time"

  pb "github.com/narenaryan/serverPush/datafiles"
  "google.golang.org/grpc"
  "google.golang.org/grpc/reflection"
)

const (
  port      = ":50051"
  noOfSteps = 3
)

// server is used to create MoneyTransactionServer.
type server struct{}

// MakeTransaction implements MoneyTransactionServer.MakeTransaction
func (s *server) MakeTransaction(in *pb.TransactionRequest, stream pb.MoneyTransaction_MakeTransactionServer) error {
  log.Printf("Got request for money transfer....")
  log.Printf("Amount: $%f, From A/c:%s, To A/c:%s", in.Amount, in.From, in.To)
  // Send streams here
  for i := 0; i < noOfSteps; i++ {
    // Simulating I/O or Computation process using sleep........
    // Usually this will be saving money transfer details in DB or
    // talk to the third party API
    time.Sleep(time.Second * 2)
    // Once task is done, send the successful message back to the client
    if err := stream.Send(&pb.TransactionResponse{Status: "good",
      Step:        int32(i),
      Description: fmt.Sprintf("Description of step %d", int32(i))}); err != nil {
      log.Fatalf("%v.Send(%v) = %v", stream, "status", err)
    }
  }
  log.Printf("Successfully transfered amount $%v from %v to %v", in.Amount, in.From, in.To)
  return nil
}

func main() {
  lis, err := net.Listen("tcp", port)
  if err != nil {
    log.Fatalf("Failed to listen: %v", err)
  }
  // Create a new GRPC Server
  s := grpc.NewServer()
  // Register it with Proto service
  pb.RegisterMoneyTransactionServer(s, &server{})
  // Register reflection service on gRPC server.
  reflection.Register(s)
  if err := s.Serve(lis); err != nil {
    log.Fatalf("Failed to serve: %v", err)
  }
}
```

`MakeTransaction`是我们感兴趣的函数。它以请求和流作为参数。在函数中，我们循环执行步骤的次数（这里是三次），并执行计算。服务器使用`time.Sleep`函数模拟模拟 I/O 或计算：

```go
stream.Send()
```

这个函数从服务器向客户端发送一个流式响应。现在，让我们编写客户端程序。这也与我们在前面的代码中看到的基本 GRPC 客户端有些不同。为客户端程序创建一个新目录：

```go
mkdir $GOPATH/src/github.com/narenaryan/serverPush/grpcClient
vi $GOPATH/src/github.com/narenaryan/serverPush/grpcClient/cilent.go
```

现在，在该文件中开始编写客户端逻辑：

```go
package main

import (
  "io"
  "log"

  pb "github.com/narenaryan/serverPush/datafiles"
  "golang.org/x/net/context"
  "google.golang.org/grpc"
)

const (
  address = "localhost:50051"
)

// ReceiveStream listens to the stream contents and use them
func ReceiveStream(client pb.MoneyTransactionClient, request *pb.TransactionRequest) {
  log.Println("Started listening to the server stream!")
  stream, err := client.MakeTransaction(context.Background(), request)
  if err != nil {
    log.Fatalf("%v.MakeTransaction(_) = _, %v", client, err)
  }
  // Listen to the stream of messages
  for {
    response, err := stream.Recv()
    if err == io.EOF {
      // If there are no more messages, get out of loop
      break
    }
    if err != nil {
      log.Fatalf("%v.MakeTransaction(_) = _, %v", client, err)
    }
    log.Printf("Status: %v, Operation: %v", response.Status, response.Description)
  }
}

func main() {
  // Set up a connection to the server.
  conn, err := grpc.Dial(address, grpc.WithInsecure())
  if err != nil {
    log.Fatalf("Did not connect: %v", err)
  }
  defer conn.Close()
  client := pb.NewMoneyTransactionClient(conn)

  // Prepare data. Get this from clients like Front-end or Android App
  from := "1234"
  to := "5678"
  amount := float32(1250.75)

  // Contact the server and print out its response.
  ReceiveStream(client, &pb.TransactionRequest{From: from,
    To: to, Amount: amount})
}
```

在这里，`ReceiveStream`是我们为了发送请求和接收一系列消息而编写的自定义函数。它接受两个参数：`MoneyTransactionClient`和`TransactionRequest`。它使用第一个参数创建一个流并开始监听它。当服务器耗尽所有消息时，客户端将停止监听并终止。然后，如果客户端尝试接收消息，将返回一个`io.EOF`错误。我们正在记录从 GRPC 服务器收集的响应。第二个参数`TransactionRequest`用于第一次向服务器发送请求。现在，运行它将使我们更清楚。在终端一上，运行 GRPC 服务器：

```go
go run $GOPATH/src/github.com/narenaryan/serverPush/grpcServer/server.go
```

它将继续监听传入的请求。现在，在第二个终端上运行客户端以查看操作：

```go
go run $GOPATH/src/github.com/narenaryan/serverPush/grpcClient/client.go
```

这将在控制台上输出以下内容：

```go
2017/07/16 15:08:15 Started listening to the server stream!
2017/07/16 15:08:17 Status: good, Operation: Description of step 0
2017/07/16 15:08:19 Status: good, Operation: Description of step 1
2017/07/16 15:08:21 Status: good, Operation: Description of step 2
```

同时，服务器还在终端一上记录自己的消息：

```go
2017/07/16 15:08:15 Got request for money Transfer....
2017/07/16 15:08:15 Amount: $1250.750000, From A/c:1234, To A/c:5678
2017/07/16 15:08:21 Successfully transfered amount $1250.75 from 1234 to 5678
```

这个过程与服务器同步进行。客户端保持活动状态，直到所有流式消息都被发送回来。服务器可以同时处理任意数量的客户端。每个客户端请求被视为一个独立的实体。这是服务器发送一系列响应的示例。还有其他情况可以使用协议缓冲区和 GRPC 实现：

+   客户端发送流式请求，以从服务器获取最终响应。

+   客户端和服务器都同时发送流式请求和响应

官方的 GRPC 团队在 GitHub 上提供了一个很好的出租车路线示例。您可以查看它以了解双向流的功能。

[`github.com/grpc/grpc-go/tree/master/examples/route_guide`](https://github.com/grpc/grpc-go/tree/master/examples/route_guide)。

# 总结

在本章中，我们从理解协议缓冲的基础知识开始我们的旅程。然后，我们遇到了协议缓冲语言，它有许多类型，如标量、枚举和重复类型。我们看到了 JSON 和协议缓冲之间的一些类比。我们了解了为什么协议缓冲比纯 JSON 数据格式更节省内存。我们通过模拟网络接口定义了一个样本协议缓冲。`message`关键字用于在协议缓冲中定义消息。

接下来，我们安装了`protoc`编译器来编译我们用协议缓冲语言编写的文件。然后，我们看到如何编译`.proto`文件以生成一个`.go`文件。这个 Go 文件包含了主程序消耗的所有结构和接口。接下来，我们为一个地址簿和人员编写了一个协议缓冲。我们看到了如何使用`grpc.Marshal`将 Go 结构序列化为二进制可传输数据。我们还发现，在 Go 中，协议缓冲与 JSON 之间的转换非常容易实现。

然后，我们转向了使用协议缓冲的谷歌 RPC 技术 GRPC。我们看到了 HTTP/2 和 GRPC 的好处。然后，我们定义了一个 GRPC 服务和协议缓冲形式的数据。接下来，我们实现了一个 GRPC 服务器和 GRPC，关于从`.proto`生成的文件。

GRPC 提供了双向和多路传输机制。这意味着它可以使用单个 TCP 连接进行所有消息传输。我们实现了一个这样的场景，客户端向服务器发送消息，服务器回复一系列消息。
