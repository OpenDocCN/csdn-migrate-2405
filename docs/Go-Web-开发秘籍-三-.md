# Go Web 开发秘籍（三）

> 原文：[`zh.annas-archive.org/md5/6712F93A50A8E516D2DB7024F42646AC`](https://zh.annas-archive.org/md5/6712F93A50A8E516D2DB7024F42646AC)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：使用 SQL 和 NoSQL 数据库

在本章中，我们将涵盖以下内容：

+   集成 MySQL 和 Go

+   在 MySQL 中创建您的第一条记录

+   从 MySQL 中读取记录

+   更新您的第一条记录在 MySQL 中

+   从 MySQL 中删除您的第一条记录

+   集成 MongoDB 和 Go

+   在 MongoDB 中创建您的第一个文档

+   从 MongoDB 中读取文档

+   在 MongoDB 中更新您的第一个文档

+   从 MongoDB 中删除您的第一个文档

# 介绍

每当我们想要持久保存数据时，我们总是期待将其保存在数据库中，主要分为两类——**SQL**和**NoSQL**。每个类别下都有许多可以根据业务用例使用的数据库，因为每个数据库都具有不同的特性并且服务于不同的目的。

在本章中，我们将把 Go Web 应用程序与最著名的开源数据库——**MySQL**和**MongoDB**集成，并学习在它们上执行 CRUD 操作。由于我们将使用 MySQL 和 MongoDB，我假设这两个数据库都已安装并在您的本地机器上运行。

# 集成 MySQL 和 Go

假设您是一名开发人员，并且希望将应用程序数据保存在 MySQL 数据库中。作为第一步，您必须在应用程序和 MySQL 之间建立连接，我们将在本示例中介绍。

# 准备就绪...

通过执行以下命令验证本地端口`3306`上是否安装并运行了 MySQL：

```go
$ ps -ef | grep 3306
```

这应该返回以下响应：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/53efed06-d9a0-4f73-b865-85ba8e619fb7.png)

还要登录到 MySQL 数据库并创建一个 mydb 数据库，执行如下截图中显示的命令：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/04132684-d375-44e4-88cc-dd91026a9a36.png)

# 如何做...

1.  使用`go get`命令安装`github.com/go-sql-driver/mysql`包，如下所示：

```go
$ go get github.com/go-sql-driver/mysql
```

1.  创建`connect-mysql.go`。然后我们连接到 MySQL 数据库并执行`SELECT`查询以获取当前数据库名称，如下所示：

```go
package main
import 
(
  "database/sql"
  "fmt"
  "log"
  "net/http"
  "github.com/go-sql-driver/mysql"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
  DRIVER_NAME = "mysql"
  DATA_SOURCE_NAME = "root:password@/mydb"
)
var db *sql.DB
var connectionError error
func init() 
{
  db, connectionError = sql.Open(DRIVER_NAME, DATA_SOURCE_NAME)
  if connectionError != nil 
  {
    log.Fatal("error connecting to database :: ", connectionError)
  }
}
func getCurrentDb(w http.ResponseWriter, r *http.Request) 
{
  rows, err := db.Query("SELECT DATABASE() as db")
  if err != nil 
  {
    log.Print("error executing query :: ", err)
    return
  }
  var db string
  for rows.Next() 
  {
    rows.Scan(&db)
  }
  fmt.Fprintf(w, "Current Database is :: %s", db)
}
func main() 
{
  http.HandleFunc("/", getCurrentDb)
  defer db.Close()
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, nil)
  if err != nil 
  {
    log.Fatal("error starting http server :: ", err)
    return
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run connect-mysql.go
```

# 它是如何工作的...

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`。

浏览到`http://localhost:8080/`将返回当前数据库名称，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/ec5b9a53-7f99-40b2-91f4-d38bc84233d3.png)

让我们了解我们编写的程序：

1.  使用`import ("database/sql" "fmt" "log" "net/http" _ "github.com/go-sql-driver/mysql")`，我们导入了`github.com/go-sql-driver/mysql`以进行副作用或初始化，使用下划线在导入语句前面明确表示。

1.  使用`var db *sql.DB`，我们声明了一个私有的`DB`实例。

根据项目大小，您可以全局声明一个 DB 实例，使用处理程序将其注入为依赖项，或将连接池指针放入`x/net/context`中。

1.  接下来，我们定义了一个`init()`函数，在其中我们连接到数据库并将数据库驱动程序名称和数据源传递给它。

1.  然后，我们定义了一个`getCurrentDb`处理程序，基本上在数据库上执行选择查询以获取当前数据库名称，遍历记录，将其值复制到变量中，最终将其写入 HTTP 响应流。

# 在 MySQL 中创建您的第一条记录

在数据库中创建或保存记录需要我们编写 SQL 查询并执行它们，实现**对象关系映射**（**ORM**），或实现数据映射技术。

在这个示例中，我们将编写一个 SQL 查询，并使用`database/sql`包执行它来创建一条记录。为了实现这一点，您还可以使用 Go 中许多第三方库中可用的任何库来实现 ORM，例如`https://github.com/jinzhu/gorm`，`https://github.com/go-gorp/gorp`和`https://github.com/jirfag/go-queryset`。

# 准备就绪...

由于我们在上一个示例中已经与 MySQL 数据库建立了连接，我们将扩展它以执行 SQL 查询来创建一条记录。

在创建记录之前，我们必须在 MySQL 数据库中创建一个表，我们将通过执行以下截图中显示的命令来完成：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/0cf3005e-2549-4802-b109-2d2c18bc9a27.png)

# 操作步骤…

1.  使用`go get`命令安装`github.com/go-sql-driver/mysql`和`github.com/gorilla/mux`包，如下所示：

```go
$ go get github.com/go-sql-driver/mysql
$ go get github.com/gorilla/mux
```

1.  创建`create-record-mysql.go`。然后我们连接到 MySQL 数据库并执行 INSERT 查询以创建员工记录，如下所示：

```go
package main
import 
(
  "database/sql"
  "fmt"
  "log"
  "net/http"
  "strconv"
  "github.com/go-sql-driver/mysql"
  "github.com/gorilla/mux"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
  DRIVER_NAME = "mysql"
  DATA_SOURCE_NAME = "root:password@/mydb"
)
var db *sql.DB
var connectionError error
func init() 
{
  db, connectionError = sql.Open(DRIVER_NAME, DATA_SOURCE_NAME)
  if connectionError != nil 
  {
    log.Fatal("error connecting to database : ", connectionError)
  }
}
func createRecord(w http.ResponseWriter, r *http.Request) 
{
  vals := r.URL.Query()
  name, ok := vals["name"]
  if ok 
  {
    log.Print("going to insert record in database for name : ",
    name[0])
    stmt, err := db.Prepare("INSERT employee SET name=?")
    if err != nil 
    {
      log.Print("error preparing query :: ", err)
      return
    }
    result, err := stmt.Exec(name[0])
    if err != nil 
    {
      log.Print("error executing query :: ", err)
      return
    }
    id, err := result.LastInsertId()
    fmt.Fprintf(w, "Last Inserted Record Id is :: %s",
    strconv.FormatInt(id, 10))
  } 
  else 
  {
    fmt.Fprintf(w, "Error occurred while creating record in 
    database for name :: %s", name[0])
  }
}
func main() 
{
  router := mux.NewRouter()
  router.HandleFunc("/employee/create", createRecord).
  Methods("POST")
  defer db.Close()
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, router)
  if err != nil 
  {
    log.Fatal("error starting http server : ", err)
    return
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run create-record-mysql.go
```

# 工作原理…

运行程序后，HTTP 服务器将在本地监听端口`8080`。

从命令行执行`POST`请求以创建员工记录，将会给出最后创建的记录的 ID：

```go
$ curl -X POST http://localhost:8080/employee/create?name=foo
Last created record id is :: 1
```

让我们理解我们编写的程序：

1.  使用`import ("database/sql" "fmt" "log" "net/http" "strconv" _ "github.com/go-sql-driver/mysql" "github.com/gorilla/mux")`，我们导入了`github.com/gorilla/mux`来创建一个 Gorilla Mux 路由器，并初始化了 Go MySQL 驱动，导入了`github.com/go-sql-driver/mysql`包。

1.  接下来，我们定义了一个`createRecord`处理程序，它从请求中获取姓名，将其分配给本地变量名，准备一个带有姓名占位符的`INSERT`语句，该占位符将动态替换为姓名，执行该语句，并最终将最后创建的 ID 写入 HTTP 响应流。

# 从 MySQL 中读取记录

在上一个示例中，我们在 MySQL 数据库中创建了一个员工记录。现在，在这个示例中，我们将学习如何通过执行 SQL 查询来读取它。

# 操作步骤…

1.  使用`go get`命令安装`github.com/go-sql-driver/mysql`和`github.com/gorilla/mux`包，如下所示：

```go
$ go get github.com/go-sql-driver/mysql
$ go get github.com/gorilla/mux
```

1.  创建`read-record-mysql.go`，在其中我们连接到 MySQL 数据库，执行`SELECT`查询以获取数据库中的所有员工，遍历记录，将其值复制到结构体中，将所有记录添加到列表中，并将其写入 HTTP 响应流，如下所示：

```go
package main
import 
(
  "database/sql" "encoding/json"
  "log"
  "net/http"
  "github.com/go-sql-driver/mysql"
  "github.com/gorilla/mux"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
  DRIVER_NAME = "mysql"
  DATA_SOURCE_NAME = "root:password@/mydb"
)
var db *sql.DB
var connectionError error
func init() 
{
  db, connectionError = sql.Open(DRIVER_NAME, DATA_SOURCE_NAME)
  if connectionError != nil 
  {
    log.Fatal("error connecting to database :: ", connectionError)
  }
}
type Employee struct 
{
  Id int `json:"uid"`
  Name string `json:"name"`
}
func readRecords(w http.ResponseWriter, r *http.Request) 
{
  log.Print("reading records from database")
  rows, err := db.Query("SELECT * FROM employee")
  if err != nil 
  {
    log.Print("error occurred while executing select 
    query :: ",err)
    return
  }
  employees := []Employee{}
  for rows.Next() 
  {
    var uid int
    var name string
    err = rows.Scan(&uid, &name)
    employee := Employee{Id: uid, Name: name}
    employees = append(employees, employee)
  }
  json.NewEncoder(w).Encode(employees)
}
func main() 
{
  router := mux.NewRouter()
  router.HandleFunc("/employees", readRecords).Methods("GET")
  defer db.Close()
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, router)
  if err != nil 
  {
    log.Fatal("error starting http server :: ", err)
    return
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run read-record-mysql.go
```

# 工作原理…

运行程序后，HTTP 服务器将在本地监听端口`8080`。

浏览到`http://localhost:8080/employees`将列出员工表中的所有记录，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/c289af02-53f5-42d2-8b78-582b369e93fa.png)

让我们看一下我们编写的程序：

1.  使用`import ("database/sql" "encoding/json" "log" "net/http" _ "github.com/go-sql-driver/mysql" "github.com/gorilla/mux")`，我们导入了一个额外的包`encoding/json`，它有助于将 Go 数据结构编组为`JSON`。

1.  接下来，我们声明了 Go 数据结构`Person`，它具有`Id`和`Name`字段。

请记住，在类型定义中字段名称应以大写字母开头，否则可能会出现错误。

1.  接下来，我们定义了一个`readRecords`处理程序，它查询数据库以获取员工表中的所有记录，遍历记录，将其值复制到结构体中，将所有记录添加到列表中，将对象列表编组为 JSON，并将其写入 HTTP 响应流。

# 在 MySQL 中更新您的第一个记录

考虑这样一个情景，你在数据库中创建了一个员工的记录，包括姓名、部门、地址等所有细节，一段时间后员工更换了部门。在这种情况下，我们必须在数据库中更新他们的部门，以便他们的详细信息在整个组织中保持同步，这可以通过`SQL UPDATE`语句实现，在这个示例中，我们将学习如何在 Go 中实现它。

# 操作步骤…

1.  使用`go get`命令安装`github.com/go-sql-driver/mysql`和`github.com/gorilla/mux`包，如下所示：

```go
$ go get github.com/go-sql-driver/mysql
$ go get github.com/gorilla/mux
```

1.  创建`update-record-mysql.go`。然后我们连接到 MySQL 数据库，更新员工的姓名，然后将更新的记录数量写入数据库到 HTTP 响应流中，如下所示：

```go
package main
import 
(
  "database/sql"
  "fmt"
  "log"
  "net/http" 
  "github.com/go-sql-driver/mysql"
  "github.com/gorilla/mux"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
  DRIVER_NAME = "mysql"
  DATA_SOURCE_NAME = "root:password@/mydb"
)
var db *sql.DB
var connectionError error 
func init() 
{
  db, connectionError = sql.Open(DRIVER_NAME, DATA_SOURCE_NAME)
  if connectionError != nil 
  {
    log.Fatal("error connecting to database :: ", connectionError)
  }
}
type Employee struct 
{
  Id   int    `json:"uid"`
  Name string `json:"name"`
}
func updateRecord(w http.ResponseWriter, r *http.Request) 
{
  vars := mux.Vars(r)
  id := vars["id"]
  vals := r.URL.Query()
  name, ok := vals["name"]
  if ok 
  {
    log.Print("going to update record in database 
    for id :: ", id)
    stmt, err := db.Prepare("UPDATE employee SET name=? 
    where uid=?")
    if err != nil 
    {
      log.Print("error occurred while preparing query :: ", err)
      return
    }
    result, err := stmt.Exec(name[0], id)
    if err != nil 
    {
      log.Print("error occurred while executing query :: ", err)
      return
    }
    rowsAffected, err := result.RowsAffected()
    fmt.Fprintf(w, "Number of rows updated in database 
    are :: %d",rowsAffected)
  } 
  else 
  {
    fmt.Fprintf(w, "Error occurred while updating record in 
    database for id :: %s", id)
  }
}
func main() 
{
  router := mux.NewRouter()
  router.HandleFunc("/employee/update/{id}",
  updateRecord).Methods("PUT")
  defer db.Close()
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, router)
  if err != nil 
  {
    log.Fatal("error starting http server :: ", err)
    return
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run update-record-mysql.go
```

# 工作原理…

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`。

接下来，从命令行执行`PUT`请求以更新 ID 为`1`的员工记录将给出数据库中更新的记录数作为响应：

```go
$ curl -X PUT http://localhost:8080/employee/update/1?name\=bar
Number of rows updated in database are :: 1
```

让我们看一下我们编写的程序：

1.  我们定义了一个`updateRecord`处理程序，它以 URL 路径变量路径中要更新的 ID 和请求变量中的新名称作为输入，准备一个带有名称和 UID 占位符的`update`语句，该占位符将动态替换，执行该语句，获取执行结果中更新的行数，并将其写入 HTTP 响应流。

1.  接下来，我们注册了一个`updateRecord`处理程序，用于处理`gorilla/mux`路由器中`/employee/update/{id}`的 URL 模式的每个`PUT`请求，并在从`main()`函数返回时使用`defer db.Close()`语句关闭数据库。

# 从 MySQL 中删除您的第一条记录

考虑这样一个情景，员工已经离开组织，您想要从数据库中撤销他们的详细信息。在这种情况下，我们可以使用`SQL DELETE`语句，我们将在本教程中介绍。

# 如何做到这一点...

1.  使用`go get`命令安装`github.com/go-sql-driver/mysql`和`github.com/gorilla/mux`包，如下所示：

```go
$ go get github.com/go-sql-driver/mysql
$ go get github.com/gorilla/mux
```

1.  创建`delete-record-mysql.go`。然后我们连接到 MySQL 数据库，从数据库中删除员工的名称，并将从数据库中删除的记录数写入 HTTP 响应流，如下所示：

```go
package main
import 
(
  "database/sql"
  "fmt"
  "log"
  "net/http"
  "github.com/go-sql-driver/mysql"
  "github.com/gorilla/mux"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
  DRIVER_NAME = "mysql"
  DATA_SOURCE_NAME = "root:password@/mydb"
)
var db *sql.DB
var connectionError error
func init() 
{
  db, connectionError = sql.Open(DRIVER_NAME, DATA_SOURCE_NAME)
  if connectionError != nil 
  {
    log.Fatal("error connecting to database :: ", connectionError)
  }
}
func deleteRecord(w http.ResponseWriter, r *http.Request) 
{
  vals := r.URL.Query()
  name, ok := vals["name"]
  if ok 
  {
    log.Print("going to delete record in database for 
    name :: ", name[0])
    stmt, err := db.Prepare("DELETE from employee where name=?")
    if err != nil 
    {
      log.Print("error occurred while preparing query :: ", err)
      return
    }
    result, err := stmt.Exec(name[0])
    if err != nil 
    {
      log.Print("error occurred while executing query :: ", err)
      return
    }
    rowsAffected, err := result.RowsAffected()
    fmt.Fprintf(w, "Number of rows deleted in database are :: %d",
    rowsAffected)
  } 
  else 
  {
    fmt.Fprintf(w, "Error occurred while deleting record in 
    database for name %s", name[0])
  }
}
func main() 
{
  router := mux.NewRouter()
  router.HandleFunc("/employee/delete",
  deleteRecord).Methods("DELETE")
  defer db.Close()
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, router)
  if err != nil 
  {
    log.Fatal("error starting http server :: ", err)
    return
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run delete-record-mysql.go
```

# 它是如何工作的...

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`。

接下来，从命令行执行`DELETE`请求以删除名称为`bar`的员工将给出从数据库中删除的记录数：

```go
$ curl -X DELETE http://localhost:8080/employee/delete?name\=bar
Number of rows deleted in database are :: 1
```

让我们看一下我们编写的程序：

1.  我们定义了一个`deleteRecord`处理程序，它以请求变量中要从数据库中删除的名称作为输入，准备一个带有名称占位符的`DELETE`语句，该占位符将动态替换，执行该语句，获取执行结果中删除的行数，并将其写入 HTTP 响应流。

1.  接下来，我们注册了一个`deleteRecord`处理程序，用于处理`gorilla/mux`路由器中`/employee/delete`的 URL 模式的每个`DELETE`请求，并在从`main()`函数返回时使用`defer db.Close()`语句关闭数据库。

# 集成 MongoDB 和 Go

每当您想要在 MongoDB 数据库中持久保存数据时，您必须采取的第一步是在数据库和您的 Web 应用程序之间建立连接，在本教程中，我们将使用 Go 中最著名和常用的 MongoDB 驱动程序之一`gopkg.in/mgo.v2`。

# 准备就绪...

通过执行以下命令验证`MongoDB`是否安装并在本地端口`27017`上运行：

```go
$ mongo
```

这应该返回以下响应：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/063c04f9-4a03-455a-b1f7-723eba8828e7.png)

# 如何做到这一点...

1.  使用`go get`命令安装`gopkg.in/mgo.v`包，如下所示：

```go
$ go get gopkg.in/mgo.v
```

1.  创建`connect-mongodb.go`。然后我们连接到`MongoDB`数据库，从集群中获取所有数据库名称，并将它们写入 HTTP 响应流，如下所示：

```go
package main
import 
(
  "fmt"
  "log"
  "net/http"
  "strings"
  mgo "gopkg.in/mgo.v2"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
  MONGO_DB_URL = "127.0.0.1"
)
var session *mgo.Session
var connectionError error
func init() 
{
  session, connectionError = mgo.Dial(MONGO_DB_URL)
  if connectionError != nil 
  {
    log.Fatal("error connecting to database :: ", connectionError)
  }
  session.SetMode(mgo.Monotonic, true)
}
func getDbNames(w http.ResponseWriter, r *http.Request) 
{
  db, err := session.DatabaseNames()
  if err != nil 
  {
    log.Print("error getting database names :: ", err)
    return
  }
  fmt.Fprintf(w, "Databases names are :: %s", strings.Join
  (db, ", "))
}
func main() 
{
  http.HandleFunc("/", getDbNames)
  defer session.Close()
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, nil)
  if err != nil 
  {
    log.Fatal("error starting http server :: ", err)
    return
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run connect-mongodb.go
```

# 它是如何工作的...

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`。

浏览到`http://localhost:8080/`将列出 MongoDB 集群中存在的所有数据库的名称，并显示如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/d3f544b8-eaf5-4716-8018-51e858236b81.png)

让我们看一下我们编写的程序：

1.  使用`import（"fmt" "log" "net/http" "strings" mgo

"gopkg.in/mgo.v2"）`，我们导入了`gopkg.in/mgo.v2`并使用`mgo`作为包别名。

1.  使用`var session *mgo.Session`，我们声明了私有的 MongoDB`Session`实例，它作为与数据库的通信会话。

1.  使用`var connectionError error`，我们声明了一个私有的`error`对象。

1.  接下来，我们定义了`init()`函数，在这里我们连接到 MongoDB，传递主机为`127.0.0.1`，这意味着 MongoDB 和应用程序都在同一台机器上的端口`27017`上运行，可选择将会话切换到单调行为，以便在同一会话中的顺序查询中读取的数据将是一致的，并且在会话中进行的修改将在随后的查询中被观察到。

如果你的 MongoDB 运行在除`27017`之外的端口上，那么你必须传递主机和端口，用冒号分隔，如：`mgo.Dial("localhost:27018")`。

1.  接下来，我们定义了一个`getDbNames`处理程序，它基本上从 MongoDB 集群中获取所有数据库名称，并将它们作为逗号分隔的字符串写入 HTTP 响应流。

# 在 MongoDB 中创建你的第一个文档

在这个示例中，我们将学习如何在数据库中创建一个 BSON 文档（JSON 样式文档的二进制编码序列化），使用 Go 的 MongoDB 驱动程序（[gopkg.in/mgo.v2](http://gopkg.in/mgo.v2)）。

# 如何做...

1.  使用以下命令，安装`gopkg.in/mgo.v2`和`github.com/gorilla/mux`包：

```go
$ go get gopkg.in/mgo.v2
$ go get github.com/gorilla/mux
```

1.  创建`create-record-mongodb.go`。然后我们连接到 MongoDB 数据库，创建一个包含两个字段（ID 和姓名）的员工文档，并将最后创建的文档 ID 写入 HTTP 响应流，如下所示：

```go
package main
import 
(
  "fmt"
  "log"
  "net/http"
  "strconv"
  "github.com/gorilla/mux"
  mgo "gopkg.in/mgo.v2"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
  MONGO_DB_URL = "127.0.0.1"
)
var session *mgo.Session
var connectionError error
type Employee struct 
{
  Id int `json:"uid"`
  Name string `json:"name"`
}
func init() 
{
  session, connectionError = mgo.Dial(MONGO_DB_URL)
  if connectionError != nil 
  {
    log.Fatal("error connecting to database :: ", connectionError)
  }
  session.SetMode(mgo.Monotonic, true)
}
func createDocument(w http.ResponseWriter, r *http.Request) 
{
  vals := r.URL.Query()
  name, nameOk := vals["name"]
  id, idOk := vals["id"]
  if nameOk && idOk 
  {
    employeeId, err := strconv.Atoi(id[0])
    if err != nil 
    {
      log.Print("error converting string id to int :: ", err)
      return
    }
    log.Print("going to insert document in database for name 
    :: ", name[0])
    collection := session.DB("mydb").C("employee")
    err = collection.Insert(&Employee{employeeId, name[0]})
    if err != nil 
    {
      log.Print("error occurred while inserting document in 
      database :: ", err)
      return
    }
    fmt.Fprintf(w, "Last created document id is :: %s", id[0])
  } 
  else 
  {
    fmt.Fprintf(w, "Error occurred while creating document in
    database for name :: %s", name[0])
  }
}
func main() 
{
  router := mux.NewRouter()
  router.HandleFunc("/employee/create",
  createDocument).Methods("POST")
  defer session.Close()
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, router)
  if err != nil 
  {
    log.Fatal("error starting http server :: ", err)
    return
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run create-record-mongodb.go
```

# 它是如何工作的...

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`。

接下来，执行以下命令行中的`POST`请求来创建一个员工文档将会给你在 MongoDB 中创建的文档的 ID：

```go
$ curl -X POST http://localhost:8080/employee/create?name=foo\&id=1
Last created document id is :: 1
```

让我们来看一下我们编写的程序：

1.  使用`import ("fmt" "log" "net/http" "strconv" "github.com/gorilla/mux" mgo "gopkg.in/mgo.v2")`，我们导入了`github.com/gorilla/mux`来创建一个 Gorilla Mux 路由器，以及`gopkg.in/mgo.v2`，包别名为`mgo`，它将作为 MongoDB 驱动程序。

1.  接下来，我们定义了一个`createDocument`处理程序，它从 HTTP 请求中获取员工的姓名和 ID。因为请求变量的类型是`string`，我们将`string`类型的变量 ID 转换为`int`类型。然后，我们从 MongoDB 获取员工集合，并调用`collection.Insert`处理程序将`Employee`结构类型的实例保存到数据库中。

# 从 MongoDB 中读取文档

在上一个示例中，我们在 MongoDB 中创建了一个 BSON 文档。现在，在这个示例中，我们将学习如何使用`gopkg.in/mgo.v2/bson`包来读取它，该包有助于查询 MongoDB 集合。

# 如何做...

1.  使用以下命令，安装`gopkg.in/mgo.v2`、`gopkg.in/mgo.v2/bson`和`github.com/gorilla/mux`包：

```go
$ go get gopkg.in/mgo.v2
$ go get gopkg.in/mgo.v2/bson
$ go get github.com/gorilla/mux
```

1.  创建`read-record-mongodb.go`。然后我们连接到 MongoDB 数据库，读取员工集合中的所有文档，将列表编组为 JSON，并将其写入 HTTP 响应流，如下所示：

```go
package main
import 
(
  "encoding/json"
  "log"
  "net/http"
  "github.com/gorilla/mux"
  mgo "gopkg.in/mgo.v2"
  "gopkg.in/mgo.v2/bson"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
  MONGO_DB_URL = "127.0.0.1"
)
var session *mgo.Session
var connectionError error
func init() 
{
  session, connectionError = mgo.Dial(MONGO_DB_URL)
  if connectionError != nil 
  {
    log.Fatal("error connecting to database :: ", connectionError)
  }
  session.SetMode(mgo.Monotonic, true)
}
type Employee struct 
{
  Id int `json:"uid"`
  Name string `json:"name"`
}
func readDocuments(w http.ResponseWriter, r *http.Request) 
{
  log.Print("reading documents from database")
  var employees []Employee
  collection := session.DB("mydb").C("employee")
  err := collection.Find(bson.M{}).All(&employees)
  if err != nil 
  {
    log.Print("error occurred while reading documents from 
    database :: ", err)
    return
  }
  json.NewEncoder(w).Encode(employees)
}
func main() 
{
  router := mux.NewRouter()
  router.HandleFunc("/employees", readDocuments).Methods("GET")
  defer session.Close()
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, router)
  if err != nil 
  {
    log.Fatal("error starting http server :: ", err)
    return
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run read-record-mongodb.go
```

# 它是如何工作的...

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`。

接下来，浏览到`http://localhost:8080/employees`将会给你 MongoDB 员工集合中所有员工的列表：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/76fe5abd-4e48-4d30-aa23-d97d15b85a61.png)

让我们来看一下我们在程序中引入的更改：

1.  使用`import ("encoding/json" "log" "net/http" "github.com/gorilla/mux" mgo "gopkg.in/mgo.v2" "gopkg.in/mgo.v2/bson")`，我们导入了额外的`gopkg.in/mgo.v2/bson`包，它是 Go 的 BSON 规范，以及`encoding/json`包，我们用它来将我们从 MongoDB 获取的对象列表编组为`JSON`。

1.  接下来，我们定义了一个`readDocuments`处理程序，在这里我们首先从 MongoDB 获取员工集合，查询其中的所有文档，遍历文档将其映射到`Employee`结构的数组中，最后将其编组为`JSON`。

# 在 MongoDB 中更新您的第一个文档

一旦创建了一个 BSON 文档，我们可能需要更新其中的一些字段。在这种情况下，我们必须在 MongoDB 集合上执行`update/upsert`查询，这将在本教程中介绍。

# 如何做…

1.  使用`go get`命令安装`gopkg.in/mgo.v2`、`gopkg.in/mgo.v2/bson`和`github.com/gorilla/mux`包，如下所示：

```go
$ go get gopkg.in/mgo.v2
$ go get gopkg.in/mgo.v2/bson
$ go get github.com/gorilla/mux
```

1.  创建`update-record-mongodb.go`。然后我们连接到 MongoDB 数据库，更新 ID 的员工的名称，并将在 HTTP 响应流中写入在 MongoDB 中更新的记录数量，如下所示：

```go
package main
import 
(
  "fmt"
  "log"
  "net/http"
  "strconv"
  "github.com/gorilla/mux"
  mgo "gopkg.in/mgo.v2"
  "gopkg.in/mgo.v2/bson"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
  MONGO_DB_URL = "127.0.0.1"
)
var session *mgo.Session
var connectionError error
type Employee struct 
{
  Id int `json:"uid"`
  Name string `json:"name"`
}
func init() 
{
  session, connectionError = mgo.Dial(MONGO_DB_URL)
  if connectionError != nil 
  {
    log.Fatal("error connecting to database :: ", 
    connectionError)
  }
  session.SetMode(mgo.Monotonic, true)
}
func updateDocument(w http.ResponseWriter, r *http.Request) 
{
  vars := mux.Vars(r)
  id := vars["id"]
  vals := r.URL.Query()
  name, ok := vals["name"]
  if ok 
  {
    employeeId, err := strconv.Atoi(id)
    if err != nil 
    {
      log.Print("error converting string id to int :: ", err)
      return
    }
    log.Print("going to update document in database 
    for id :: ", id)
    collection := session.DB("mydb").C("employee")
    var changeInfo *mgo.ChangeInfo
    changeInfo, err = collection.Upsert(bson.M{"id": employeeId},
    &Employee{employeeId, name[0]})
    if err != nil 
    {
      log.Print("error occurred while updating record in 
      database :: ", err)
      return
    }
    fmt.Fprintf(w, "Number of documents updated in database 
    are :: %d", changeInfo.Updated)
  } 
  else 
  {
    fmt.Fprintf(w, "Error occurred while updating document
    in database for id :: %s", id)
  }
}
func main() 
{
  router := mux.NewRouter()
  router.HandleFunc("/employee/update/{id}",
  updateDocument).Methods("PUT")
  defer session.Close()
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, router)
  if err != nil 
  {
    log.Fatal("error starting http server :: ", err)
    return
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run update-record-mongodb.go
```

# 它是如何工作的…

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`。

接下来，通过命令行执行`PUT`请求来更新员工文档，如下所示，将会给出在 MongoDB 中更新的文档数量：

```go
$ curl -X PUT http://localhost:8080/employee/update/1\?name\=bar
Number of documents updated in database are :: 1
```

让我们来看一下我们写的程序：

1.  我们定义了一个`updateDocument`处理程序，它从 URL 路径变量中获取要在 MongoDB 中更新的 ID 和作为 HTTP 请求变量的新名称。由于请求变量是字符串类型，我们将`string`类型的变量 ID 转换为`int`类型。然后，我们从 MongoDB 获取员工集合，并调用`collection.Upsert`处理程序，以插入（如果不存在）或更新具有新名称的员工文档的 ID。

1.  接下来，我们注册了一个`updateDocument`处理程序，用于处理`/employee/update/{id}`的 URL 模式，对于每个使用`gorilla/mux`路由器的`PUT`请求，并在我们从`main()`函数返回时使用`defer session.Close()`语句关闭 MongoDB 会话。

# 从 MongoDB 中删除您的第一个文档

每当我们想要清理数据库或删除不再需要的文档时，我们可以使用 Go 的 MongoDB 驱动程序（[gopkg.in/mgo.v2](http://gopkg.in/mgo.v2)）轻松地删除它们，这将在本教程中介绍。

# 如何做…

1.  使用`go get`命令安装`gopkg.in/mgo.v2`、`gopkg.in/mgo.v2/bson`和`github.com/gorilla/mux`包，如下所示：

```go
$ go get gopkg.in/mgo.v2
$ go get gopkg.in/mgo.v2/bson
$ go get github.com/gorilla/mux
```

1.  创建`delete-record-mongodb.go`。然后我们连接到 MongoDB，从数据库中获取要删除的员工的名称作为 HTTP 请求变量，获取命名集合，并按如下方式删除文档：

```go
package main
import 
(
  "fmt"
  "log"
  "net/http"
  "github.com/gorilla/mux"
  mgo "gopkg.in/mgo.v2"
  "gopkg.in/mgo.v2/bson"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
  MONGO_DB_URL = "127.0.0.1"
)
var session *mgo.Session
var connectionError error
type Employee struct 
{
  Id int `json:"uid"`
  Name string `json:"name"`
}
func init() 
{
  session, connectionError = mgo.Dial(MONGO_DB_URL)
  if connectionError != nil 
  {
    log.Fatal("error connecting to database :: ", 
    connectionError)
  }
  session.SetMode(mgo.Monotonic, true)
}
func deleteDocument(w http.ResponseWriter, r *http.Request) 
{
  vals := r.URL.Query()
  name, ok := vals["name"]
  if ok 
  {
    log.Print("going to delete document in database for 
    name :: ", name[0])
    collection := session.DB("mydb").C("employee")
    removeErr := collection.Remove(bson.M{"name": name[0]})
    if removeErr != nil 
    {
      log.Print("error removing document from 
      database :: ", removeErr)
      return
    }
    fmt.Fprintf(w, "Document with name %s is deleted from 
    database", name[0])
  } 
  else 
  {
    fmt.Fprintf(w, "Error occurred while deleting document 
    in database for name :: %s", name[0])
  }
}
func main() 
{
  router := mux.NewRouter()
  router.HandleFunc("/employee/delete",
  deleteDocument).Methods("DELETE")
  defer session.Close()
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, router)
  if err != nil 
  {
    log.Fatal("error starting http server :: ", err)
    return
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run delete-record-mongodb.go
```

# 它是如何工作的…

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`。

接下来，通过命令行执行`DELETE`请求来删除 BSON 文档，如下所示，将会给出从数据库中删除的文档的名称：

```go
$ curl -X DELETE http://localhost:8080/employee/delete?name\=bar
Document with name bar is deleted from database
```

让我们来看一下我们写的程序：

1.  我们定义了一个`deleteDocument`处理程序，它从 MongoDB 获取要删除的名称作为请求变量，从 MongoDB 获取员工集合，并调用`collection.Remove`处理程序来删除给定名称的文档。

1.  然后，我们注册了一个`deleteDocument`处理程序，用于处理`/employee/delete`的 URL 模式，对于每个使用`gorilla/mux`路由器的`DELETE`请求，并在我们从`main()`函数返回时使用`defer session.Close()`语句关闭 MongoDB 会话。


# 第六章：使用 Micro 编写 Go 中的微服务-微服务工具包

在本章中，我们将涵盖以下内容：

+   创建您的第一个协议缓冲

+   启动微服务发现客户端

+   创建您的第一个微服务

+   创建您的第二个微服务

+   创建您的微服务 API

+   使用命令行界面和 Web UI 与微服务进行交互

# 介绍

随着组织现在转向 DevOps，微服务也开始变得流行起来。由于这些服务具有独立的性质，并且可以用任何语言开发，这使得组织能够专注于它们的开发。通过掌握本章涵盖的概念，我们将能够以相当简单的方式使用 Go Micro 编写微服务。

在本章中，我们将首先编写协议缓冲。然后我们将学习如何启动 Consul，这是一个微服务发现客户端，最终转向创建微服务并通过命令行和 Web 仪表板与它们进行交互。

# 创建您的第一个协议缓冲

协议缓冲是 Go 支持的一种灵活、高效和自动化的编码和序列化结构化数据的机制。在本教程中，我们将学习如何编写我们的第一个协议缓冲。

# 准备就绪…

1.  验证是否通过执行以下命令安装了`protoc`：

```go
$ protoc --version
 libprotoc 3.3.2
```

1.  通过以下方式安装`protobuf`：

```go
$ git clone https://github.com/google/protobuf
$ cd protobuf
$ ./autogen.sh
$ ./configure
$ make
$ make check
$ make install
```

# 如何做…

1.  在`proto`目录中创建`hello.proto`并定义一个名为`Say`的`service`接口，其中包含两种数据类型-`Request`和`Response`，如下所示：

```go
syntax = "proto3";
service Say 
{
  rpc Hello(Request) returns (Response) {}
}
message Request 
{
  string name = 1;
}
message Response 
{
  string msg = 1;
}
```

1.  使用以下命令编译`hello.proto`：

```go
$ protoc --go_out=plugins=micro:. hello.proto
```

# 它是如何工作的…

一旦命令成功执行，`hello.pb.go`将在`proto`目录中创建，其外观如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/e6c3c506-21d5-499e-8258-e1c595f129fb.png)

让我们了解我们编写的`.proto`文件：

+   `syntax = "proto3";`：在这里，我们指定我们使用`proto3`语法，这使得编译器了解协议缓冲必须使用版本 3 进行编译。如果我们不明确指定语法，则编译器会假定我们使用`proto2`。

+   `service Say { rpc Hello(Request) returns (Response) {} }`：在这里，我们定义了一个名为`Say`的 RPC 服务和一个接受`Request`并返回`Response`的`Hello`方法。

+   `message Request { string name = 1; }`：在这里，我们定义了具有`name`字段的`Request`数据类型。

+   `message Response { string msg = 1; }`：在这里，我们定义了具有`msg`字段的`Response`数据类型。

# 启动微服务发现客户端

在部署了多个服务的微服务架构中，服务发现客户端帮助应用程序找到它们依赖的服务，可以通过 DNS 或 HTTP 进行。当我们谈论服务发现客户端时，最常见和著名的之一是 HashiCorp 的`Consul`，我们将在本教程中启动它。

# 准备就绪…

通过执行以下命令验证是否安装了`Consul`：

```go
$ consul version
 Consul v0.8.5
 Protocol 2 spoken by default, understands 2 to 3 (agent will automatically use protocol >2 when speaking to compatible agents)
```

# 如何做…

通过执行以下命令以服务器模式启动`consul agent`：

```go
$ consul agent -dev
```

# 它是如何工作的…

一旦命令成功执行，Consul 代理将以服务器模式运行，给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/a92cdd9a-1d8a-4f8c-9590-403457ed9e18.png)

我们还可以通过执行以下命令列出 Consul 集群的成员：

```go
$ consul members
```

这将给我们以下结果：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/49a2e1e2-9503-4260-8d73-c53721654e1b.png)

由于 Consul 可以在服务器模式或客户端模式下运行，至少需要一个服务器，为了保持最低限度的设置，我们已经以服务器模式启动了我们的代理，尽管这并不推荐，因为在故障情况下存在数据丢失的可能性。

此外，浏览到`http://localhost:8500/ui/`将显示 Consul Web UI，我们可以在其中查看所有服务和节点，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/7204b5d2-47f8-41b7-a5eb-1f7bee423eec.png)

# 创建您的第一个微服务

微服务只是作为唯一进程运行并通过明确定义的轻量级机制进行通信以服务于业务目标的代码片段，我们将在这个示例中使用`https://github.com/micro/micro`编写，尽管还有许多其他库可用，如`https://github.com/go-kit/kit`和`https://github.com/grpc/grpc-go`，它们具有相同的目的。

# 准备就绪…

1.  通过执行以下命令启动`consul agent`：

```go
$ consul agent -dev
```

1.  通过执行以下命令安装和运行`micro`：

```go
$ go get github.com/micro/micro
$ micro api
 2018/02/06 00:03:36 Registering RPC Handler at /rpc
 2018/02/06 00:03:36 Registering API Default Handler at /
 2018/02/06 00:03:36 Listening on [::]:8080
 2018/02/06 00:03:36 Listening on [::]:54814
 2018/02/06 00:03:36 Broker Listening on [::]:54815
 2018/02/06 00:03:36 Registering node: go.micro.api-a6a82a54-0aaf-11e8-8d64-685b35d52676
```

# 如何做…

1.  通过执行命令`$ mkdir services && cd services && touch first-greeting-service.go`在`services`目录中创建`first-greeting-service.go`。

1.  将以下内容复制到`first-greeting-service.go`：

```go
package main
import 
(
  "log"
  "time"
  hello "../proto"
  "github.com/micro/go-micro"
)
type Say struct{}
func (s *Say) Hello(ctx context.Context, req *hello.Request, 
rsp *hello.Response) error 
{
  log.Print("Received Say.Hello request - first greeting service")
  rsp.Msg = "Hello " + req.Name
  return nil
}
func main() 
{
  service := micro.NewService
  (
    micro.Name("go.micro.service.greeter"),
    micro.RegisterTTL(time.Second*30),
    micro.RegisterInterval(time.Second*10),
  )
  service.Init()
  hello.RegisterSayHandler(service.Server(), new(Say))
  if err := service.Run(); err != nil 
  {
    log.Fatal("error starting service : ", err)
    return
  }
}
```

一切就绪后，目录结构应如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/ed19fcaf-f4ff-4c02-aab8-a6df9c1da93d.png)

1.  转到`services`目录并使用以下命令运行程序：

```go
$ go run first-greeting-service.go
```

# 它是如何工作的…

一旦我们运行程序，RPC 服务器将在本地监听端口`8080`。

接下来，从命令行执行`POST`请求，如下所示：

```go
$ curl -X POST -H 'Content-Type: application/json' -d '{"service": "go.micro.service.greeter", "method": "Say.Hello", "request": {"name": "Arpit Aggarwal"}}' http://localhost:8080/rpc
```

这将使我们从服务器获得 Hello，然后是名称作为响应，如下所示的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/e40538e4-a0ce-4817-8c4e-24a2c9b8b33c.png)

查看`first-greeting-service.go`的日志将向我们展示请求是由第一个问候服务提供的，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/f0b1e3d4-0295-44c0-a864-5fff2aec62b4.png)

让我们看一下我们编写的程序：

+   使用`import ("log" "time" hello "../proto" "github.com/micro/go-micro" "golang.org/x/net/context")`，我们导入了`"hello "../proto"`，一个包含协议缓冲区源代码和已编译协议缓冲区后缀`.pb.go`的目录。此外，我们导入了`github.com/micro/go-micro`包，其中包含编写微服务所需的所有库。

+   接下来，我们定义了一个`main()`处理程序，在其中使用`micro.NewService()`创建一个名为`go.micro.service.greeter`的新服务，初始化它，注册处理程序，并最终启动它。

# 创建您的第二个微服务

在这个示例中，我们将使用`go-micro`创建另一个微服务，它是`first-greeting-service.go`的副本，除了在控制台上打印的日志消息之外，它演示了两个具有相同名称的服务的客户端负载平衡的概念。

# 如何做…

1.  通过执行命令`$ cd services && touch second-greeting-service.go`在`services`目录中创建`second-greeting-service.go`。

1.  将以下内容复制到`second-greeting-service.go`：

```go
package main
import 
(
  "context"
  "log"
  "time"
  hello "../proto"
  "github.com/micro/go-micro"
)
type Say struct{}
func (s *Say) Hello(ctx context.Context, req *hello.Request, 
rsp *hello.Response) error 
{
  log.Print("Received Say.Hello request - second greeting
  service")
  rsp.Msg = "Hello " + req.Name
  return nil
}
func main() 
{
  service := micro.NewService
  (
    micro.Name("go.micro.service.greeter"),
    micro.RegisterTTL(time.Second*30),
    micro.RegisterInterval(time.Second*10),
  )
  service.Init()
  hello.RegisterSayHandler(service.Server(), new(Say))
  if err := service.Run(); err != nil 
  {
    log.Fatal("error starting service : ", err)
    return
  }
}
```

一切就绪后，目录结构应如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/f9dc5e14-ac7d-451b-94a5-0ff6ec6eca55.png)

1.  转到`services`目录并使用以下命令运行程序：

```go
$ go run second-greeting-service.go
```

# 它是如何工作的…

一旦我们运行程序，RPC 服务器将在本地监听端口`8080`。

接下来，从命令行执行`POST`请求，如下所示：

```go
$ curl -X POST -H 'Content-Type: application/json' -d '{"service": "go.micro.service.greeter", "method": "Say.Hello", "request": {"name": "Arpit Aggarwal"}}' http://localhost:8080/rpc
```

这将使我们从服务器获得 Hello，然后是名称作为响应，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/4575909c-9536-4bdb-b86e-cd1b65b10d01.png)

查看`second-greeting-service.go`的日志将向我们展示请求是由第二个问候服务提供的：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/ea73a7c0-7ec3-46ad-8bc9-e7743f1a47b4.png)

现在，如果我们再次执行`POST`请求，它将在`first-greeting-service.go`控制台中打印日志，这是因为 Go Micro 提供的智能客户端负载平衡构建在发现之上的服务。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/054f15ff-427a-4a86-bd7e-b9b08c09b102.png)

# 创建您的 Micro API

到目前为止，我们已经通过名称显式调用了后端服务和访问它的方法。在这个示例中，我们将学习如何使用 Go Micro API 访问服务，该 API 实现了 API 网关模式，提供了微服务的单一入口点。使用 Go Micro API 的优势在于它通过 HTTP 提供服务，并使用 HTTP 处理程序动态路由到适当的后端服务。

# 准备就绪…

通过执行以下命令在单独的终端中启动 `consul agent`、`micro API`、`first-greeting-service.go` 和 `second-greeting-service.go`：

```go
$ consul agent -dev
$ micro api
$ go run first-greeting-service.go
$ go run second-greeting-service.go
```

# 操作步骤…

1.  通过执行命令 `$ mkdir api && cd api && touch greeting-api.go` 在 `api` 目录中创建 `greeting-api.go`。

1.  将以下内容复制到 `greeting-api.go`：

```go
package main
import 
(
  "context"
  "encoding/json"
  "log"
  "strings"
  hello "../proto"
  "github.com/micro/go-micro"
  api "github.com/micro/micro/api/proto"
)
type Say struct 
{
  Client hello.SayClient
}
func (s *Say) Hello(ctx context.Context, req *api.Request, 
rsp *api.Response) error 
{
  log.Print("Received Say.Hello request - Micro Greeter API")
  name, ok := req.Get["name"]
  if ok 
  {
    response, err := s.Client.Hello
    (
      ctx, &hello.Request
      {
        Name: strings.Join(name.Values, " "),
      }
    )
    if err != nil 
    {
      return err
    }
    message, _ := json.Marshal
    (
      map[string]string
      {
        "message": response.Msg,
      }
    )
    rsp.Body = string(message)
  }
  return nil
}
func main() 
{
  service := micro.NewService
  (
    micro.Name("go.micro.api.greeter"),
  )
  service.Init()
  service.Server().Handle
  (
    service.Server().NewHandler
    (
      &Say{Client: hello.NewSayClient("go.micro.service.
      greeter", service.Client())},
    ),
  )
  if err := service.Run(); err != nil 
  {
    log.Fatal("error starting micro api : ", err)
    return
  }
}
```

一切就绪后，目录结构应该如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/d5987017-7916-4937-b535-e7dc02a41da8.png)

1.  转到 `api` 目录并使用以下命令运行程序：

```go
$ go run greeting-api.go
```

# 工作原理…

一旦我们运行程序，HTTP 服务器将在本地监听端口 `8080`。

接下来，按照以下步骤浏览至 `http://localhost:8080/greeter/say/hello?name=Arpit+Aggarwal`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/3da80faa-0f64-491e-8b1c-f1783f6c1355.png)

这将给出响应 Hello，后跟作为 HTTP 请求变量接收到的名称。此外，查看 `second-greeting-service.go` 的日志将显示请求是由第二个问候服务提供的，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/ffe18d8b-281f-4b8d-a22f-6a764c882ccb.png)

现在，如果我们再次执行 `GET` 请求，它将在 `first-greeting-service.go` 控制台中打印日志，这是因为 Go Micro 提供的发现功能上构建的服务的智能客户端负载平衡：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/41a961ff-1753-4825-bccf-869524273f25.png)

# 使用命令行界面和 web UI 与微服务交互

到目前为止，我们已经使用命令行执行了 `GET` 和 `POST` HTTP 请求来访问服务。这也可以通过 Go Micro web 用户界面来实现。我们只需要启动 `micro web`，这将在本示例中介绍。

# 操作步骤…

1.  使用以下命令安装 `go get github.com/micro/micro` 包：

```go
$ go get github.com/micro/micro
```

1.  使用以下命令运行 web UI：

```go
$ micro web
```

# 工作原理…

一旦命令成功执行，浏览至 `http://localhost:8082/registry` 将列出所有已注册的服务，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/b2a878e4-9849-4592-83bc-120587f5a12b.png)

使用 web UI 查询我们的 `greeter` 服务，请求为 `{"name" : "Arpit Aggarwal"}`，将会得到响应 `{"msg": "Hello Arpit Aggarwal"} `：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/900737b2-6989-4e39-b4d2-632c3494285c.png)

使用 `CLI` 命令查询相同的 `greeter` 服务，命令为 `query go.micro.service.greeter Say.Hello {"name" : "Arpit Aggarwal"}`，将会得到响应 `{"msg": "Hello Arpit Aggarwal"}`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/cb86a401-112a-4f99-8c58-88b27c501957.png)


# 第七章：在 Go 中使用 WebSocket

在本章中，我们将涵盖以下示例：

+   创建你的第一个 WebSocket 服务器

+   创建你的第一个 WebSocket 客户端

+   调试你的第一个本地 WebSocket 服务器

+   调试你的第一个远程 WebSocket 服务器

+   单元测试你的第一个 WebSocket 服务器

# 介绍

WebSocket 提供了服务器和客户端之间的双向、单一套接字、全双工连接，使实时通信比其他方式如长轮询和服务器发送事件更加高效。

使用 WebSocket，客户端和服务器可以独立通信，每个都能在初始握手后同时发送和接收信息，重复使用从客户端到服务器和服务器到客户端的相同连接，最终大大减少延迟和服务器负载，使 Web 应用程序能够以最有效的方式执行现代任务。WebSocket 协议得到大多数主流浏览器的支持，包括 Google Chrome、Microsoft Edge、Internet Explorer、Firefox、Safari 和 Opera。因此没有兼容性问题。

在本章中，我们将学习如何创建 WebSocket 服务器和客户端，编写单元测试并调试运行在本地或远程的服务器。

# 创建你的第一个 WebSocket 服务器

在这个示例中，我们将学习如何编写一个 WebSocket 服务器，它是一个 TCP 应用程序，监听在端口`8080`上，允许连接的客户端彼此发送消息。

# 如何做…

1.  使用`go get`命令安装`github.com/gorilla/websocket`包，如下所示：

```go
$ go get github.com/gorilla/websocket
```

1.  创建`websocket-server.go`，我们将在其中将 HTTP 请求升级为 WebSocket，从客户端读取 JSON 消息，并将其广播给所有连接的客户端，如下所示：

```go
package main 
import 
(
  "log"
  "net/http"
  "github.com/gorilla/websocket"
)
var clients = make(map[*websocket.Conn]bool)
var broadcast = make(chan Message) 
var upgrader = websocket.Upgrader{}
type Message struct 
{
  Message string `json:"message"`
}
func HandleClients(w http.ResponseWriter, r *http.Request) 
{
  go broadcastMessagesToClients()
  websocket, err := upgrader.Upgrade(w, r, nil)
  if err != nil 
  {
    log.Fatal("error upgrading GET request to a 
    websocket :: ", err)
  }
  defer websocket.Close()
  clients[websocket] = true
  for 
  {
    var message Message
    err := websocket.ReadJSON(&message)
    if err != nil 
    {
      log.Printf("error occurred while reading 
      message : %v", err)
      delete(clients, websocket)
      break
    }
    broadcast <- message
  }
}
func main() 
{
  http.HandleFunc
  (
    "/", func(w http.ResponseWriter, 
    r *http.Request) 
    {
      http.ServeFile(w, r, "index.html")
    }
  )
  http.HandleFunc("/echo", HandleClients)
  err := http.ListenAndServe(":8080", nil)
  if err != nil 
  {
    log.Fatal("error starting http server :: ", err)
    return
  }
}
func broadcastMessagesToClients() 
{
  for 
  {
    message := <-broadcast
    for client := range clients 
    {
      err := client.WriteJSON(message)
      if err != nil 
      {
        log.Printf("error occurred while writing 
        message to client: %v", err)
        client.Close()
        delete(clients, client)
      }
    }
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run websocket-server.go
```

# 工作原理…

一旦我们运行程序，WebSocket 服务器将在本地监听端口`8080`。

让我们了解我们编写的程序：

1.  我们使用了`import ("log" "net/http" "github.com/gorilla/websocket")`，这是一个预处理命令，告诉 Go 编译器包括所有来自`log`、`net/http`和`github.com/gorilla/websocket`包的文件。

1.  使用`var clients = make(map[*websocket.Conn]bool)`，我们创建了一个表示连接到 WebSocket 服务器的客户端的映射，KeyType 为 WebSocket 连接对象，ValueType 为布尔值。

1.  使用`var broadcast = make(chan Message)`，我们创建了一个通道，所有接收到的消息都会被写入其中。

1.  接下来，我们定义了一个`HandleClients`处理程序，当收到`HTTP GET`请求时，将其升级为`WebSocket`，将客户端注册到套接字服务器，读取请求的 JSON 消息，并将其写入广播通道。

1.  然后，我们定义了一个 Go 函数`broadcastMessagesToClients`，它抓取写入广播通道的消息，并将其发送给当前连接到 WebSocket 服务器的每个客户端。

# 创建你的第一个 WebSocket 客户端

在这个示例中，我们将创建一个简单的客户端来开始 WebSocket 握手过程。客户端将向 WebSocket 服务器发送一个相当标准的`HTTP GET`请求，服务器通过响应中的 Upgrade 头将其升级。

# 如何做…

1.  创建`index.html`，我们将在页面加载时打开到非安全 WebSocket 服务器的连接，如下所示：

```go
<html>
  <title>WebSocket Server</title>
  <input id="input" type="text" />
  <button onclick="send()">Send</button>
  <pre id="output"></pre>
  <script>
    var input = document.getElementById("input");
    var output = document.getElementById("output");
    var socket = new WebSocket("ws://" + window.
    location.host + "/echo");
    socket.onopen = function () 
    {
      output.innerHTML += "Status: Connected\n";
    };
    socket.onmessage = function (e) 
    {
      output.innerHTML += "Message from Server: " + 
      e.data + "\n";
    };
    function send() 
    {
      socket.send
      (
        JSON.stringify
        (
          {
            message: input.value
          }
        )
      );
      input.value = "";
    }
  </script>
</html>
```

一切就绪后，目录结构应该如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/b629829f-2f75-49d2-8adb-f5d85f9f16bd.png)

1.  使用以下命令运行程序：

```go
$ go run websocket-server.go
```

# 工作原理…

一旦我们运行程序，WebSocket 服务器将在本地监听端口`8080`。

浏览到`http://localhost:8080`将显示带有文本框和发送按钮的 WebSocket 客户端页面，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/e7d52e7d-4a4c-4d38-8d18-78eec80c5f2f.png)

# 调试你的第一个本地 WebSocket 服务器

调试 Web 应用程序是开发人员学习的最重要的技能之一，因为它有助于识别问题、隔离问题的来源，然后要么纠正问题，要么确定解决问题的方法。在这个示例中，我们将学习如何使用 GoLand IDE 调试在本地运行的 WebSocket 服务器。

# 准备...

本示例假定您已经安装并配置了 GoLand IDE 以在您的机器上运行 Go 应用程序。

# 如何做...

1.  单击 GoLand IDE 中的 Open Project 以打开我们在以前的示例中编写的`websocket-server.go`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/7e8fc02a-a5b9-4612-bd22-b277ce9efc6a.png)

1.  一旦项目打开，单击 Edit Configurations，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/866d4acf-d5df-4ba7-885f-66fd01e84caf.png)

1.  通过单击+号显示如下截图所示的 Add New Configuration 来选择 Add New Configuration：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/9154d8b8-a857-4792-9ff3-d93bd660994a.png)

1.  选择 Go Build，将配置重命名为`WebSocket Local Debug`，将运行类型更改为目录，然后单击应用和确定，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/5e252651-72a4-4c00-b3bb-d5a40c2387f7.png)

1.  放置一些断点并单击调试按钮：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/79998142-500c-478a-bcc1-3fb007247706.png)

# 它是如何工作的...

一旦我们运行程序，WebSocket 服务器将在本地以调试模式启动，监听端口`8080`。

浏览到`http://localhost:8080`将显示带有文本框和发送按钮的 WebSocket 客户端页面，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/9c61dcbe-8aeb-4f39-bd23-ec1f7378dc5f.png)

输入文本并单击发送按钮，以查看程序执行停在我们在 GoLand IDE 中放置的断点处，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/d8e39ac7-c56e-4cd3-b842-6932d2cac0fc.png)

# 调试您的第一个远程 WebSocket 服务器

在以前的示例中，我们学习了如何调试在本地运行的 WebSocket 服务器。在这个示例中，我们将学习如何在另一台或远程机器上调试它。

这些步骤与我们在以前的示例中所采取的步骤基本相同，只是在调试配置部分，我们将把本地主机更改为远程机器 IP 或 DNS，并启动 Delve 服务器，这是 Go 编程语言在远程机器上的调试器。

# 如何做...

1.  通过单击 Edit Configurations...添加另一个配置，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/176fe105-a87d-4df3-96e0-a9c3ad856881.png)

1.  单击+号添加新配置，然后选择 Go Remote：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/6af1b410-d858-4f26-969d-68705cc23442.png)

1.  将调试配置重命名为`WebSocket Remote Debug`，将主机更改为`remote-machine-IP`或`DNS`，然后单击应用和确定，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/75309b82-08d3-4bb3-afb8-5c7b07107460.png)

1.  通过执行以下命令在目标或远程机器上运行无头 Delve 服务器：

```go
dlv debug --headless --listen=:2345 --api-version=2
```

上述命令将启动一个监听端口`2345`的 API 服务器。

1.  选择 WebSocket Remote Debug 配置，然后单击调试按钮：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/6651b141-4aa4-4637-a6b5-29486425d23c.png)

# 它是如何工作的...

浏览到远程可用的 WebSocket 客户端页面，输入一些文本，然后单击发送按钮，以查看程序执行停在我们放置的断点处：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/f98f24a1-bba5-40ed-9a83-7d4b65a51286.png)

# 单元测试您的第一个 WebSocket 服务器

单元测试或测试驱动开发有助于开发人员设计松散耦合的代码，重点放在代码的可重用性上。它还帮助我们意识到何时停止编码并快速进行更改。

在这个示例中，我们将学习如何为我们在以前的示例中已经编写的 WebSocket 服务器编写单元测试。

参见*创建您的第一个 WebSocket 服务器*示例。

# 如何做...

1.  使用`go get`命令安装`github.com/gorilla/websocket`和`github.com/stretchr/testify/assert`包，如下所示：

```go
$ go get github.com/gorilla/websocket
$ go get github.com/stretchr/testify/assert
```

1.  创建`websocket-server_test.go`，我们将在其中创建一个测试服务器，使用 Gorilla 客户端连接到它，并最终读取和编写消息以测试连接，如下所示：

```go
package main
import 
(
  "net/http"
  "net/http/httptest"
  "strings"
  "testing"
  "github.com/gorilla/websocket"
  "github.com/stretchr/testify/assert"
)
func TestWebSocketServer(t *testing.T) 
{
  server := httptest.NewServer(http.HandlerFunc
  (HandleClients))
  defer server.Close()
  u := "ws" + strings.TrimPrefix(server.URL, "http")
  socket, _, err := websocket.DefaultDialer.Dial(u, nil)
  if err != nil 
  {
    t.Fatalf("%v", err)
  }
  defer socket.Close()
  m := Message{Message: "hello"}
  if err := socket.WriteJSON(&m); err != nil 
  {
    t.Fatalf("%v", err)
  }
  var message Message
  err = socket.ReadJSON(&message)
  if err != nil 
  {
    t.Fatalf("%v", err)
  }
  assert.Equal(t, "hello", message.Message, "they 
  should be equal")
}
```

# 工作原理…

从命令行执行`go test`如下：

```go
$ go test websocket-server_test.go websocket-server.go
ok  command-line-arguments 0.048s
```

它将给我们响应`ok`，这意味着测试已成功编译和执行。

让我们看看当 Go 测试失败时会是什么样子。将`assert`语句中的预期输出更改为其他内容。在以下示例中，`hello`已更改为`hi`：

```go
...
assert.Equal(t, "hi", message.Message, "they should be equal")
...
```

通过运行`go test`命令再次执行测试：

```go
$ go test websocket-server_test.go websocket-server.go
```

它将给我们失败的响应，以及如下截图所示的错误跟踪：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/a6465f59-e243-47f4-b1da-a7e5dc4233bd.png)


# 第八章：使用 Go Web 应用程序框架-Beego

在本章中，我们将涵盖以下内容：

+   使用 Beego 创建你的第一个项目

+   创建你的第一个控制器和路由器

+   创建你的第一个视图

+   创建你的第一个会话变量

+   创建你的第一个过滤器

+   在 Beego 中处理 HTTP 错误

+   在 Beego 中实现缓存

+   监视 Beego 应用程序

+   在本地机器上部署 Beego 应用程序

+   使用 Nginx 部署 Beego 应用程序

# 介绍

无论何时我们开发一个应用程序，Web 应用程序框架都是必不可少的，因为它通过消除编写大量重复代码的需要并提供模型、API 和其他元素等功能，显著加快和简化了我们的工作。使用应用程序框架，我们可以享受其架构模式的好处，并加速应用程序的开发。

一种流行的 Web 应用程序框架类型是**模型-视图-控制器**（**MVC**），Go 语言有许多 MVC 框架可用，如 Revel、Utron 和 Beego。

在本章中，我们将学习 Beego，这是一个最受欢迎和常用的 Web MVC 框架之一。我们将从创建项目开始，然后转向创建控制器、视图和过滤器。我们还将看看如何实现缓存，监视和部署应用程序。

# 使用 Beego 创建你的第一个项目

开始一个项目的第一件事是设置其基本架构。在 Beego 中，可以使用一个叫做`bee`的工具轻松实现这一点，我们将在这个示例中介绍。

# 如何做…

1.  使用`go get`命令安装`github.com/beego/bee`包，如下所示：

```go
$ go get github.com/beego/bee
```

1.  打开终端到你的`$GOPATH/src`目录，并使用`bee new`命令创建一个项目，如下所示：

```go
$ cd $GOPATH/src
$ bee new my-first-beego-project
```

一旦命令成功执行，它将创建一个新的 Beego 项目，并在控制台上的创建步骤将如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/a8194ce7-d255-4723-b99f-c570e1fdeb92.png)

1.  转到新创建的项目路径，输入`bee run`编译和运行项目，如下所示：

```go
$ cd $GOPATH/src/my-first-beego-project
$ bee run
```

一旦命令成功执行，`bee`将构建项目并启动应用程序，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/edc1967e-3c91-4b9e-ae04-4f85abd4cb87.png)

# 它是如何工作的…

一旦命令成功执行，Web 应用程序将在默认的 Beego 端口`8080`上运行，并浏览`http://localhost:8080/`将呈现应用程序的欢迎页面，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/34d6133d-8cb1-476f-af60-3dccfa850c63.png)

# 创建你的第一个控制器和路由器

Web 应用程序的一个主要组件是控制器，它充当视图和模型之间的协调者，并处理用户的请求，这可能是按钮点击、菜单选择或 HTTP `GET`和`POST`请求。在这个示例中，我们将学习如何在 Beego 中创建一个控制器。

# 如何做…

1.  转到`$GOPATH/src/my-first-beego-project/controllers`并创建`firstcontroller.go`，如下所示：

```go
package controllers
import "github.com/astaxie/beego"
type FirstController struct 
{
  beego.Controller
}
type Employee struct 
{
  Id int `json:"id"`
  FirstName string `json:"firstName"`
  LastName string `json:"lastName"`
}
type Employees []Employee
var employees []Employee
func init() 
{
  employees = Employees
  {
    Employee{Id: 1, FirstName: "Foo", LastName: "Bar"},
    Employee{Id: 2, FirstName: "Baz", LastName: "Qux"},
  }
}
func (this *FirstController) GetEmployees() 
{
  this.Ctx.ResponseWriter.WriteHeader(200)
  this.Data["json"] = employees
  this.ServeJSON()
}
```

1.  转到`$GOPATH/src/my-first-beego-project/routers`并编辑`router.go`以添加`GET`映射`/employees`，由`FirstController`中定义的`GetEmployees`处理程序处理，如下所示：

```go
package routers
import 
(
  "my-first-beego-project/controllers"
  "github.com/astaxie/beego"
)
func init() 
{
  beego.Router("/", &controllers.MainController{})
  beego.Router("/employees", &controllers.FirstController{},
  "get:GetEmployees")
}
```

1.  使用以下命令运行项目：

```go
$ bee run
```

# 它是如何工作的…

一旦命令成功执行，Web 应用程序将在默认的 Beego 端口`8080`上运行。

接下来，从命令行执行`GET`请求将给你列出所有员工的列表：

```go
$ curl -X GET http://localhost:8080/employees
[
 {
 "id": 1,
 "firstName": "Foo",
 "lastName": "Bar"
 },
 {
 "id": 2,
 "firstName": "Baz",
 "lastName": "Qux"
 }
]
```

让我们理解我们编写的程序：

+   导入“github.com/astaxie/beego”：在这里，我们导入了 Beego。

+   `type FirstController struct { beego.Controller }`：在这里，我们定义了`FirstController`结构类型，它包含了一个匿名的`beego.Controller`类型的结构字段，因此`FirstController`自动获取了`beego.Controller`的所有方法。

+   `func (this *FirstController) GetEmployees() { this.Ctx.ResponseWriter.WriteHeader(200) this.Data["json"] = employees this.ServeJSON() }`：在这里，我们定义了`GetEmployees`处理程序，它将为 URL 模式`/employees`的每个`GET`请求执行。

在 Go 中，以大写字母开头的函数或处理程序是导出函数，这意味着它们是公共的，并且可以在程序外部使用。这就是我们在程序中定义所有函数时都使用大写字母而不是驼峰命名法的原因。

# 创建你的第一个视图

视图是模型的可视表示。它通过模型访问数据，并指定数据应该如何呈现。当模型发生变化时，它保持其呈现的一致性，这可以通过推模型或拉模型来实现。在推模型中，视图向模型注册自己以获取更改通知，而在拉模型中，视图负责在需要检索最新数据时调用模型。在本示例中，我们将学习如何创建我们的第一个视图来呈现员工列表。

# 如何做…

1.  移动到`$GOPATH/src/my-first-beego-project/views`并创建`dashboard.tpl`，并复制以下内容：

```go
<!DOCTYPE html>
<html>
  <body>
    <table border= "1" style="width:100%;">
      {{range .employees}}
      <tr>
        <td>{{.Id}}</td>
        <td>{{.FirstName}}</td>
        <td>{{.LastName}}</td>
      </tr>
      {{end}}
    </table>
  </body>
</html>
```

1.  移动到`$GOPATH/src/my-first-beego-project/controllers`并编辑`firstcontroller.go`，添加`Dashboard`处理程序，如下所示：

```go
package controllers
import "github.com/astaxie/beego"
type FirstController struct 
{
  beego.Controller
}
type Employee struct 
{
  Id int `json:"id"`
  FirstName string `json:"firstName"`
  LastName string `json:"lastName"`
}
type Employees []Employee
var employees []Employee
func init() 
{
  employees = Employees
  {
    Employee{Id: 1, FirstName: "Foo", LastName: "Bar"},
    Employee{Id: 2, FirstName: "Baz", LastName: "Qux"},
  }
}
...
func (this *FirstController) Dashbaord() 
{
  this.Data["employees"] = employees
  this.TplName = "dashboard.tpl"
}
```

1.  移动到`$GOPATH/src/my-first-beego-project/routers`并编辑`router.go`，添加`GET`映射`/dashboard`，由`FirstController`中定义的`Dashboard`处理程序处理，如下所示：

```go
package routers
import 
(
  "my-first-beego-project/controllers"
  "github.com/astaxie/beego"
)
func init() 
{
  beego.Router("/", &controllers.MainController{})
  beego.Router("/employees", &controllers.FirstController{},
  "get:GetEmployees")
  beego.Router("/dashboard", &controllers.FirstController{},
  "get:Dashbaord")
}

```

1.  使用以下命令运行项目：

```go
$ bee run
```

# 它是如何工作的…

一旦命令成功执行，Web 应用程序将在默认的 Beego 端口`8080`上运行。

浏览`http://localhost:8080/dashboard`将呈现员工仪表板，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/bb36f8f2-6852-4f28-8e3f-6778731ecb60.png)

# 创建你的第一个会话变量

每当我们需要将用户数据从一个 HTTP 请求传递到另一个 HTTP 请求时，我们可以使用 HTTP 会话，我们将在本示例中介绍。

# 准备好…

此示例假定您已经在本地端口`6379`上安装并运行了`Redis`。

# 如何做…

1.  使用`go get`命令安装`github.com/astaxie/beego/session/redis`包，如下所示：

```go
$ go get -u github.com/astaxie/beego/session/redis
```

1.  移动到`$GOPATH/src/my-first-beego-project/controllers`并创建`sessioncontroller.go`，在这里我们将定义处理程序，确保只有经过身份验证的用户才能查看主页，如下所示：

```go
package controllers 
import "github.com/astaxie/beego"
type SessionController struct 
{
  beego.Controller
}
func (this *SessionController) Home() 
{
  isAuthenticated := this.GetSession("authenticated")
  if isAuthenticated == nil || isAuthenticated == false 
  {
    this.Ctx.WriteString("You are unauthorized to 
    view the page.")
    return
  }
  this.Ctx.ResponseWriter.WriteHeader(200)
  this.Ctx.WriteString("Home Page")
}
func (this *SessionController) Login() 
{
  this.SetSession("authenticated", true)
  this.Ctx.ResponseWriter.WriteHeader(200)
  this.Ctx.WriteString("You have successfully logged in.")
}
func (this *SessionController) Logout() 
{
  this.SetSession("authenticated", false)
  this.Ctx.ResponseWriter.WriteHeader(200)
  this.Ctx.WriteString("You have successfully logged out.")
}
```

1.  移动到`$GOPATH/src/my-first-beego-project/routers`并编辑`router.go`，添加`GET`映射`/home`，`/login`和`/logout`，分别由`FirstController`中定义的`Home`，`Login`和`Logout`处理程序处理，如下所示：

```go
package routers
import 
(
  "my-first-beego-project/controllers"
  "github.com/astaxie/beego"
)
func init() 
{
  beego.Router("/", &controllers.MainController{})
  beego.Router("/employees", &controllers.FirstController{},
  "get:GetEmployees")
  beego.Router("/dashboard", &controllers.FirstController{}, 
  "get:Dashbaord")
  beego.Router("/home", &controllers.SessionController{},
  "get:Home")
  beego.Router("/login", &controllers.SessionController{}, 
  "get:Login")
  beego.Router("/logout", &controllers.SessionController{}, 
  "get:Logout")
}
```

1.  移动到`$GOPATH/src/my-first-beego-project`并编辑`main.go`，导入`github.com/astaxie/beego/session/redis`，如下所示：

```go
package main
import 
(
  _ "my-first-beego-project/routers"
  "github.com/astaxie/beego"
  _ "github.com/astaxie/beego/session/redis"
)
func main() 
{
  beego.BConfig.WebConfig.DirectoryIndex = true
  beego.BConfig.WebConfig.StaticDir["/swagger"] = "swagger"
  beego.Run()
}
```

1.  在`$GOPATH/src/my-first-beego-project/conf/app.conf`中打开`session`的使用，如下所示：

```go
SessionOn = true
SessionProvider = "redis"
SessionProviderConfig = "127.0.0.1:6379"
```

1.  使用以下命令运行程序：

```go
$ bee run 
```

# 它是如何工作的…

一旦命令成功执行，Web 应用程序将在默认的 Beego 端口`8080`上运行。

接下来，我们将执行一些命令来看会话是如何工作的。首先，我们将通过执行以下命令访问`/home`：

```go
$ curl -X GET http://localhost:8080/home 
```

这将导致我们从服务器收到未经授权的访问消息：

```go
You are unauthorized to view the page.
```

显然，我们无法访问它，因为我们必须首先登录到应用程序，这将创建一个`beegosessionID`。现在让我们通过执行以下命令登录到应用程序：

```go
$ curl -X GET -i http://localhost:8080/login
```

这将导致服务器返回以下响应：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/6ddd6d86-c388-4b8b-bcb9-bb0a801be17d.png)

现在我们将使用作为`/login`请求的一部分创建的 cookie`beegosessionID`来访问`/home`，如下所示：

```go
$ curl --cookie "beegosessionID=6e1c6f60141811f1371d7ea044f1c194" http://localhost:8080/home Home Page
```

# 创建你的第一个过滤器

有时，我们可能希望在调用操作方法之前或之后执行逻辑。在这种情况下，我们使用过滤器，我们将在本示例中介绍。

过滤器基本上是封装常见功能或横切关注点的处理程序。我们只需定义它们一次，然后将它们应用于不同的控制器和操作方法。

# 操作步骤…

1.  使用`go get`命令安装`github.com/astaxie/beego/context`包，如下所示：

```go
$ go get github.com/astaxie/beego/context
```

1.  移动到`$GOPATH/src/my-first-beego-project/filters`并创建`firstfilter.go`，在`Controller`之前运行，并记录 IP 地址和当前时间戳，如下所示：

```go
package filters 
import 
(
  "fmt"
  "time"
  "github.com/astaxie/beego/context"
)
var LogManager = func(ctx *context.Context) 
{ 
  fmt.Println("IP :: " + ctx.Request.RemoteAddr + ", 
  Time :: " + time.Now().Format(time.RFC850))
}
```

1.  移动到`$GOPATH/src/my-first-beego-project/routers`并编辑`router.go`以添加`GET`映射`/*`，将由`LogManager`过滤器处理，如下所示：

```go
package routers 
import 
(
  "my-first-beego-project/controllers"
  "my-first-beego-project/filters"
  "github.com/astaxie/beego"
)
func init() 
{
  beego.Router("/", &controllers.MainController{})
  ...
  beego.InsertFilter("/*", beego.BeforeRouter, 
  filters.LogManager)
}
```

1.  使用以下命令运行程序：

```go
$ bee run
```

# 工作原理…

一旦命令成功执行，Web 应用程序将在默认的 Beego 端口`8080`上运行。

接下来，我们将执行一个请求，通过执行以下命令获取所有员工：

```go
$ curl -X GET http://localhost:8080/employees
[
 {
 "id": 1,
 "firstName": "Foo",
 "lastName": "Bar"
 },
 {
 "id": 2,
 "firstName": "Baz",
 "lastName": "Qux"
 }
]
```

一旦命令成功执行，我们可以在控制台的应用程序日志中看到打印的 IP 和时间戳，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/5f17dd63-8b1e-4118-a2fa-686a57917a47.png)

使用`beego.InsertFilter("/*", beego.BeforeRouter, filters.LogManager)`，我们在应用程序中插入了一个过滤器，该过滤器在找到路由器之前执行 URL 模式`/*`，并由`LogManager`处理。类似于`beego.BeforeRouter`，还有四个其他位置可以放置过滤器：`beego.BeforeStatic`，`beego.BeforeExec`，`beego.AfterExec`和`beego.FinishRouter`。

# 在 Beego 中处理 HTTP 错误

错误处理是 Web 应用程序设计中最重要的方面之一，因为它在两个方面有所帮助。首先，它以相对友好的方式让应用程序用户知道出了问题，他们应该联系技术支持部门或者应该通知技术支持部门的人员。其次，它允许程序员添加一些细节来帮助调试问题。在本示例中，我们将学习如何在 Beego 中实现错误处理。

# 操作步骤…

1.  移动到`$GOPATH/src/my-first-beego-project/controllers`并创建`errorcontroller.go`，在其中我们将定义处理`404`和`500` HTTP 错误的处理程序，以及处理应用程序中任何通用错误的处理程序，如下所示：

```go
package controllers
import "github.com/astaxie/beego"
type ErrorController struct 
{
  beego.Controller
}
func (c *ErrorController) Error404() 
{
  c.Data["content"] = "Page Not Found"
  c.TplName = "404.tpl"
}
func (c *ErrorController) Error500() 
{
  c.Data["content"] = "Internal Server Error"
  c.TplName = "500.tpl"
}
func (c *ErrorController) ErrorGeneric() 
{
  c.Data["content"] = "Some Error Occurred"
  c.TplName = "genericerror.tpl"
}
```

1.  移动到`$GOPATH/src/my-first-beego-project/controllers`并编辑`firstcontroller.go`以添加`GetEmployee`处理程序，该处理程序将从 HTTP 请求参数中获取 ID，从静态员工数组中获取员工详细信息，并将其作为响应返回，或者如果请求的 ID 不存在，则抛出通用错误，如下所示：

```go
package controllers
import "github.com/astaxie/beego"
type FirstController struct 
{
  beego.Controller
}
type Employee struct 
{
  Id int `json:"id"`
  FirstName string `json:"firstName"`
  LastName string `json:"lastName"`
}
type Employees []Employee
var employees []Employee
func init() 
{
  employees = Employees
  {
    Employee{Id: 1, FirstName: "Foo", LastName: "Bar"},
    Employee{Id: 2, FirstName: "Baz", LastName: "Qux"},
  }
}
...
func (this *FirstController) GetEmployee() 
{
  var id int
  this.Ctx.Input.Bind(&id, "id")
  var isEmployeeExist bool
  var emps []Employee
  for _, employee := range employees 
  {
    if employee.Id == id 
    {
      emps = append(emps, Employee{Id: employee.Id, 
      FirstName: employee.FirstName, LastName: 
      employee.LastName})
      isEmployeeExist = true
      break
    }
  }
  if !isEmployeeExist 
  {
    this.Abort("Generic")
  } 
  else 
  {
    this.Data["employees"] = emps
    this.TplName = "dashboard.tpl"
  }
}
```

1.  移动到`$GOPATH/src/my-first-beego-project/views`并创建`genericerror.tpl`，内容如下：

```go
<!DOCTYPE html>
<html>
  <body>
    {{.content}}
  </body>
</html>
```

1.  使用以下命令运行程序：

```go
$ bee run 
```

# 工作原理…

一旦命令成功执行，Web 应用程序将在默认的 Beego 端口`8080`上运行。

接下来，浏览`http://localhost:8080/employee?id=2`将会给出员工的详细信息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/46d2b6f4-a78c-46ce-b33c-653bf5346abe.png)

当浏览`http://localhost:8080/employee?id=4`时：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/15fa193a-8f0a-4154-b574-38c885b00a10.png)

它将给出错误消息，如“发生了一些错误”。这是因为我们要求获取 ID 为`4`的员工的详细信息，而在静态员工数组中不存在，因此服务器抛出通用错误，由`errorcontroller.go`中定义的`ErrorGeneric`处理程序处理。

# 在 Beego 中实现缓存

在 Web 应用程序中缓存数据有时是必要的，以避免反复请求数据库或外部服务的静态数据。在本示例中，我们将学习如何在 Beego 应用程序中实现缓存。

Beego 支持四种缓存提供程序：`file`，`Memcache`，`memory`和`Redis`。在本示例中，我们将使用框架默认的`memory`缓存提供程序。

# 操作步骤…

1.  使用`go get`命令安装`github.com/astaxie/beego/cache`包，如下所示：

```go
$ go get github.com/astaxie/beego/cache
```

1.  移动到`$GOPATH/src/my-first-beego-project/controllers`并创建`cachecontroller.go`，在其中我们将定义`GetFromCache`处理程序，该处理程序将从缓存中获取键的值并将其写入 HTTP 响应，如下所示：

```go
package controllers
import 
(
  "fmt"
  "time"
  "github.com/astaxie/beego"
  "github.com/astaxie/beego/cache"
)
type CacheController struct 
{
  beego.Controller
}
var beegoCache cache.Cache
var err error
func init() 
{
  beegoCache, err = cache.NewCache("memory",
  `{"interval":60}`)
  beegoCache.Put("foo", "bar", 100000*time.Second)
}
func (this *CacheController) GetFromCache() 
{
  foo := beegoCache.Get("foo")
  this.Ctx.WriteString("Hello " + fmt.Sprintf("%v", foo))
}
```

1.  移动到`$GOPATH/src/my-first-beego-project/routers`并编辑`router.go`以添加`GET`映射`/getFromCache`，该映射将由`CacheController`中定义的`GetFromCache`处理程序处理，如下所示：

```go
package routers
import 
(
  "my-first-beego-project/controllers"
  "my-first-beego-project/filters"
  "github.com/astaxie/beego"
)
func init() 
{
  beego.Router("/", &controllers.MainController{})
  ... 
  beego.Router("/getFromCache", &controllers.
  CacheController{}, "get:GetFromCache")
}
```

1.  使用以下命令运行程序：

```go
$ bee run
```

# 它是如何工作的…

一旦命令成功执行，Web 应用程序将在默认的 Beego 端口`8080`上运行。

在应用程序启动时，将使用名称为`foo`且值为`bar`的键添加到缓存中。接下来，浏览`http://localhost:8080/getFromCache`将从缓存中读取`foo`键值，将其附加到 Hello，并在浏览器上显示，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/35ad2340-26fa-41f7-9b3b-dd7c9c2d5056.png)

# 监控 Beego 应用程序

一旦 Beego 应用程序启动并运行，我们可以轻松地通过其管理仪表板监视应用程序请求统计信息、性能、健康检查、任务和配置状态。我们将在本教程中学习如何做到这一点。

# 如何做到这一点…

1.  通过在`$GOPATH/src/my-first-beego-project/conf/app.conf`中添加`EnableAdmin = true`来启用应用程序实时监视，如下所示：

```go
appname = my-first-beego-project
...
EnableAdmin = true
..
```

可选地，通过在`$GOPATH/src/my-first-beego-project/conf/app.conf`中添加字段来更改其监听的端口：

```go
AdminAddr = "localhost"
AdminPort = 8088
```

1.  使用以下命令运行程序：

```go
$ bee run
```

# 它是如何工作的…

一旦命令成功执行，Web 应用程序将在默认的 Beego 端口`8080`上运行，并且浏览`http://localhost:8088/`将呈现管理仪表板，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/c53d95cd-edbc-432a-b968-96b5e9211ce8.png)

浏览`http://localhost:8088/qps`将显示应用程序的请求统计信息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/b9affdd6-bf38-4319-8855-584efdaf1be2.png)

# 在本地机器上部署 Beego 应用程序

一旦应用程序开发结束，我们必须部署它以供最终用户使用，这可以在本地或远程进行。在本教程中，我们将学习如何在本地机器上部署我们的 Beego 应用程序。

# 如何做到这一点…

1.  因为`bee`创建的应用程序默认处于开发模式，并且在公共服务器上运行应用程序时，始终以生产模式运行应用程序是最佳实践，因此我们必须在`$GOPATH/src/my-first-beego-project/conf/app.conf`中将`RunMode`更改为`prod`，如下所示：

```go
beego.RunMode = "prod"
```

1.  通过执行以下命令将静态文件、配置文件和模板作为 Beego 应用程序的字节码文件的一部分包含在一个单独的目录中：

```go
$ mkdir $GOPATH/my-first-beego-app-deployment
$ cp my-first-beego-project $GOPATH/my-first-beego-app-deployment
$ cp -fr views $GOPATH/my-first-beego-app-deployment
$ cp -fr static $GOPATH/my-first-beego-app-deployment
$ cp -fr conf $GOPATH/my-first-beego-app-deployment
```

1.  移动到`$GOPATH/my-first-beego-app-deployment`并使用`nohup`命令将应用程序作为后台进程运行，如下所示：

```go
$ cd $GOPATH/my-first-beego-app-deployment
$ nohup ./my-first-beego-project &
```

# 它是如何工作的…

一旦命令成功执行，Web 应用程序将在默认的 Beego 端口`8080`上运行，浏览`http://localhost:8080/`将呈现应用程序的欢迎页面，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/4d67d510-d668-4788-b5fe-53b2f4d307bb.png)

# 使用 Nginx 部署 Beego 应用程序

在上一个教程中，我们学习了如何在本地运行 Beego 应用程序。在本教程中，我们将使用`Nginx`部署相同的应用程序。

# 准备就绪…

这个教程假设您已经安装并在端口`80`上运行了`Nginx`。对我来说，它安装在`/Users/ArpitAggarwal/nginx`。

# 如何做到这一点…

1.  打开`/Users/ArpitAggarwal/nginx/conf/nginx.conf`中的 Nginx 配置文件，并将`server`下的`location`块替换为以下内容：

```go
location / 
{
 # root html;
 # index index.html index.htm;
 proxy_pass http://localhost:8080/;
}
```

1.  通过执行以下命令启动 Nginx：

```go
$ cd /Users/ArpitAggarwal/nginx/sbin
$ ./nginx
```

1.  通过执行以下命令运行 Beego 应用程序：

```go
$ bee run
```

# 它是如何工作的…

一旦命令成功执行，浏览`http://localhost:80/`将呈现应用程序的欢迎页面，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/9ca23b43-cd30-4fb7-8c77-33a1e83f9530.png)
