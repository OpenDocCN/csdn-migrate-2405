# 构建 Go REST Web 服务（三）

> 原文：[`zh.annas-archive.org/md5/57EDF27484D8AB35B253814EEB7E5A77`](https://zh.annas-archive.org/md5/57EDF27484D8AB35B253814EEB7E5A77)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：使用 PostgreSQL、JSON 和 Go 进行工作

在本章中，我们将从宏观角度看 SQL。在之前的章节中，我们讨论了 SQLite3，这是一个用于快速原型设计的小型数据库。但是，当涉及到生产级应用程序时，人们更喜欢 MySQL 或 PostgreSQL。在 Web 应用程序领域，两者都经过了充分验证。首先，我们将讨论 PostgreSQL 的内部，然后转向在 Go 中编写数据库模型。然后，我们将尝试通过一个实例来实现 URL 缩短服务。

在本章中，我们将涵盖以下主题：

+   介绍 PostgreSQL 数据库

+   安装 PostgreSQL 并创建用户和数据库

+   了解`pq`，Go 中的数据库驱动程序

+   使用 PostgreSQL 和 Base62 算法实现 URL 缩短服务

+   探索 PostgreSQL 中的 JSON 存储

+   介绍`gorm`，Go 的强大 ORM

+   实施电子商务 REST API

# 获取代码

您可以在以下网址找到本章的代码示例：[`github.com/narenaryan/gorestful/tree/master/chapter7`](https://github.com/narenaryan/gorestful/tree/master/chapter7)。在上一章中，我们讨论了协议缓冲区和 GRPC。但是在这里，我们回到了使用 JSON 的 REST API，并看看 PostgreSQL 如何补充 JSON。

# 安装 PostgreSQL 数据库

PostgreSQL 是一个可以安装在多个平台上的开源数据库。在 Ubuntu 上，可以使用以下命令进行安装：

将存储库添加到软件包列表中：

```go

sudo sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt/ `lsb_release -cs`-pgdg main" >> /etc/apt/sources.list.d/pgdg.list' 
wget -q https://www.postgresql.org/media/keys/ACCC4CF8.asc -O - | sudo apt-key add -

```

要更新软件包列表：

```go

sudo apt-get update
apt-get install postgresql postgresql-contrib
```

这将在 Ubuntu 机器上安装数据库并在端口`5432`上启动服务器。现在，为了进入数据库 shell，使用以下命令。PostgreSQL 创建一个名为`postgres`的默认用户以登录。看一下以下命令：

```go
sudo su - postgres
```

现在用户可以访问数据库。使用`psql`命令启动 PostgreSQL shell：

```go
psql
```

这表明 PostgreSQL 与其他类似数据库（如 MySQL 或 SQLite3）相比，采用了不同的进入 shell 的方法。在 Windows 上，通过单击二进制安装程序文件来进行安装。这是一个基于 GUI 的安装，应提供超级用户的端口和密码。安装数据库后，我们可以使用**pgAdmin3**工具进行检查。macOS X 的设置与 Ubuntu 类似，只是安装是通过 Homebrew 完成的。看一下以下命令：

```go
brew install postgresql
```

然后，通过使用以下命令使数据库服务器在系统重新启动时运行：

```go
pg_ctl -D /usr/local/var/postgres start && brew services start postgresql
```

现在，PostgreSQL 服务器开始运行，并且可以在 macOS X 上存储和检索数据。

# 在 PostgreSQL 中添加用户和数据库

现在，我们应该知道如何创建新用户和数据库。为此，我们将以 Ubuntu/Mac 为一般示例。我们在一个名为`psql`的 shell 中执行此操作。使用`\?`命令可以在`psql`中看到所有可用命令。为了进入`psql`，首先切换到`postgres`用户。在 Ubuntu 上，您可以使用以下命令来执行：

```go
sudo su postgres
```

现在，它将我们转换为一个名为`postgres`的用户。然后，使用`psql`命令启动`psql` shell。如果在其中输入`\?`，您将看到所有可用命令的输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/a59458f4-5721-4fac-906b-ce4696b696f1.png)

要列出所有可用用户及其权限，您将在 shell 帮助的`Informational`部分中找到一个命令，即：

```go
\du - List roles
```

角色是授予用户的访问权限。列表中的默认角色是`postgres`：

```go
postgres=# \du

 List of roles 
 Role name |      Attributes               | Member of 
-----------+------------------------------------------------------------+-----------
 postgres | Superuser, Create role, Create DB, Replication, Bypass RLS | {}
```

上述命令列出了角色（用户）及其属性（角色允许执行的操作）和其他选项。要添加新用户，我们只需输入此`psql`命令：

```go
CREATE ROLE naren with LOGIN PASSWORD 'passme123';
```

这将创建一个名为`naren`的新用户和密码`passme123.`现在，使用以下命令为用户授予创建数据库和进一步角色的权限：

```go
ALTER USER naren CREATEDB, CREATEROLE;
```

要删除用户，只需在相同上下文中使用`DROP`命令：

```go
DROP ROLE naren;
```

不要尝试更改默认`postgres`用户的密码。它旨在成为一个 sudo 帐户，不应该作为普通用户保留。相反，创建一个角色并为其分配所需的权限。

现在我们知道如何创建一个角色。让我们看看一些更多的 CRUD 命令，这些命令实际上是我们在其他关系数据库中看到的 SQL 命令。看一下下表：

| **操作** | **SQL 命令** |
| --- | --- |
| 创建数据库 |

```go
CREATE DATABASE mydb;
```

|

| 创建表 |
| --- |

```go
CREATE TABLE products (
    product_no integer,
    name text,
    price numeric
);
```

|

| 插入到表中 |
| --- |

```go
INSERT INTO products VALUES (1, 'Rice', 5.99);
```

|

| 更新表 |
| --- |

```go
UPDATE products SET price = 10 WHERE price = 5.99;
```

|

| 从表中删除 |
| --- |

```go
DELETE FROM products WHERE price = 5.99;
```

|

现在，让我们从 Go 中看看如何与 PostgreSQL 交流，并尝试使用一个简单的例子来执行前面的操作。

# pq，一个纯 PostgreSQL 数据库驱动程序

在之前的章节中，当我们处理 SQLite3 时，我们使用了一个名为`go-sqlite3`的外部库。同样，有一个数据库驱动程序库可用于连接 Go 和 PostgreSQL。该库称为`pq`。我们可以使用以下命令安装该库：

```go
go get github.com/lib/pq
```

获得这个库之后，我们需要以与 SQLite3 相似的方式使用它。API 将与 Go 的`database/sql`包一致。为了创建一个新表，我们应该初始化 DB。要创建一个新数据库，只需在`psql` shell 中输入以下命令，如下所示；这是一次性的事情：

```go
CREATE DATABASE mydb;
```

现在，我们将编写一个小的代码示例，解释了`pq`驱动程序的用法。在你的`$GOPATH`中创建一个名为`models`的目录。在这里，我的`GOPATH`是`/home/naren/workspace/`。与前几章中的所有示例一样，我们将在`src/`目录中创建我们的包和应用程序源代码：

```go
mkdir github.com/narenaryan/src/models
```

现在，添加一个名为`web_urls.go`的文件。这个文件将包含表创建逻辑：

```go
package models

import (
        "database/sql"
        "log"
        _ "github.com/lib/pq"
)

func InitDB() (*sql.DB, error) {
        var err error
        db, err := sql.Open("postgres", "postgres://naren:passme123@localhost/mydb?sslmode=disable")
        if err != nil {
                return nil, err
        } else {
                // Create model for our URL service
                stmt, err := db.Prepare("CREATE TABLE WEB_URL(ID SERIAL PRIMARY KEY, URL TEXT NOT NULL);")
                if err != nil {
                        log.Println(err)
                        return nil, err
                }
                res, err := stmt.Exec()
                log.Println(res)
                if err != nil {
                        log.Println(err)
                        return nil, err
                }
                return db, nil
        }
}
```

我们在这里导入了`pq`库。我们使用`sql.Open`函数来启动一个新的数据库连接池。如果你观察连接字符串，它由多个部分组成。看一下下图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/c5cf7c9a-a38f-4642-a72b-54de1f5c7c41.png)

连接字符串应该包括数据库类型、`username:password`对、数据库服务器 IP 和 sslmode 设置。然后我们创建一个名为`web_url`的表。所有的错误处理程序都在那里，以指定如果出现问题。`InitDB`函数将数据库连接对象返回给导入该函数的任何程序。让我们编写主程序来使用这个包：

```go
package main

import (
       "log"
      "github.com/narenaryan/models"
)

func main() {
  db, err := models.InitDB()
  if err != nil {
    log.Println(db)
  }
}
```

该程序导入了`models`包，并使用了其中的`InitDB`函数。我们只是打印了数据库连接，这将是一个地址。如果你运行程序，你会看到对象的地址被打印出来：

```go
go run main.go
```

这将在`mydb`数据库中创建一个`web_url`表。我们可以通过进入`psql` shell 并输入以下内容来交叉检查：

```go
\c mydb \dt
```

它将用户连接到`mydb`数据库并列出所有可用的表，如下面的代码片段所示：

```go
You are now connected to database "mydb" as user "postgres".
 List of relations
 Schema | Name | Type | Owner
--------+---------+-------+-------
 public | web_url | table | naren
(1 row)
```

在 PostgreSQL 中，AUTO INCREMENT 类型需要在为表创建提供模式时替换为 SERIAL。

# 使用 Postgres 和 pq 实现 URL 缩短服务

让我们编写 URL 缩短服务来解释我们在前一节讨论的所有概念。在那之前，让我们设计一个实现 Base62 算法的包，其中包括编码/解码函数。URL 缩短技术需要 Base62 算法来将长 URL 转换为短 URL，反之亦然。然后，我们编写一个实例来展示这种编码是如何工作的。在`GOPATH`中创建一个名为`base62`的目录：

```go
mkdir $GOPATH/src/github.com/narenaryan/base62
```

现在，添加一个名为`encodeutils.go`的文件，其中包含我们的编码和解码函数。

# 定义 Base62 算法

我们在前几章中看到了 Base62 算法的工作原理。这是该算法的坚实实现。这个逻辑是纯数学的，可以在网上找到。看一下下面的代码：

```go
package base62

import (
     "math"
     "strings"
)

const base = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const b = 62

// Function encodes the given database ID to a base62 string
func ToBase62(num int) string{
    r := num % b
    res := string(base[r])
    div := num / b
    q := int(math.Floor(float64(div)))

    for q != 0 {
        r = q % b
        temp := q / b
        q = int(math.Floor(float64(temp)))
        res = string(base[int(r)]) + res
    }

    return string(res)
}

// Function decodes a given base62 string to datbase ID
func ToBase10(str string) int{
    res := 0
    for _, r := range str {
        res = (b * res) + strings.Index(base, string(r))
    }
    return res
}
```

在上述程序中，我们定义了两个名为`ToBase62`和`ToBase10`的函数。第一个函数接受一个整数并生成一个`base62`字符串，而后一个函数则反转了这个效果；也就是说，它接受一个`base62`字符串并给出原始数字。为了说明这一点，让我们创建一个简单的程序，使用这两个函数来展示编码/解码：

```go
vi $GOPATH/src/github.com/narenaryan/usebase62.go
```

将以下内容添加到其中：

```go
package main

import (
      "log"
      base62 "github.com/narenaryan/base62"
)

func main() {
  x := 100
  base62String := base62.ToBase62(x)
  log.Println(base62String)
  normalNumber := base62.ToBase10(base62String)
  log.Println(normalNumber)
}
```

在这里，我们使用了`base62`包中的函数，并尝试查看输出。如果我们使用以下命令运行这个程序（从`$GOPATH/src/github.com/narenaryan`）：

```go
go run usebase62.go
```

它打印出：

```go
2017/08/07 23:00:05 1C
2017/08/07 23:00:05 100
```

`100`的`base62`编码是`1C`。这是因为索引 100 在我们的`base62`逻辑中缩小为`1C`：

```go
const base = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
```

原始数字将用于映射此基本字符串中的字符。然后，将数字除以 62 以找出下一个字符。这种算法的美妙之处在于为每个给定的数字创建一个独特的、更短的字符串。我们使用这种技术将数据库 ID 传递到`ToBase62`算法中，并得到一个更短的字符串。每当 URL 缩短请求到达我们的服务器时，它应执行以下步骤：

1.  将 URL 存储在数据库中，并获取插入记录的 ID。

1.  将此 ID 作为 API 响应传递给客户端。

1.  每当客户端加载缩短的 URL 时，它会访问我们的 API 服务器。

1.  然后 API 服务器将短 URL 转换回数据库 ID，并从原始 URL 中获取记录。

1.  最后，客户端可以使用此 URL 重定向到原始站点。

我们将在这里编写一个 Go 项目，实现上述步骤。让我们组成程序。我正在为我们的项目创建一个目录结构。我们从前面的示例中获取处理编码/解码`base62`和数据库逻辑的文件。目录结构如下：

```go
urlshortener
├── main.go
├── models
│   └── models.go
└── utils
 └── encodeutils.go

2 directories, 3 files
```

将此目录复制到`$GOPATH/src/github.com/narenaryan`。再次小心。用你的用户名替换`narenaryan`。从前面的示例中复制`encodeutils.go`和`models.go`。然后，开始编写主程序：

```go
package main

import (
    "database/sql"
    "encoding/json"
    "io/ioutil"
    "log"
    "net/http"
    "time"

    "github.com/gorilla/mux"
    _ "github.com/lib/pq"
    "github.com/narenaryan/urlshortener/models"
    base62 "github.com/narenaryan/urlshortener/utils"
)

// DB stores the database session imformation. Needs to be initialized once
type DBClient struct {
  db *sql.DB
}

// Model the record struct
type Record struct {
  ID  int    `json:"id"`
  URL string `json:"url"`
}

// GetOriginalURL fetches the original URL for the given encoded(short) string
func (driver *DBClient) GetOriginalURL(w http.ResponseWriter, r *http.Request) {
  var url string
  vars := mux.Vars(r)
  // Get ID from base62 string
  id := base62.ToBase10(vars["encoded_string"])
  err := driver.db.QueryRow("SELECT url FROM web_url WHERE id = $1", id).Scan(&url)
  // Handle response details
  if err != nil {
    w.Write([]byte(err.Error()))
  } else {
    w.WriteHeader(http.StatusOK)
    w.Header().Set("Content-Type", "application/json")
    responseMap := map[string]interface{}{"url": url}
    response, _ := json.Marshal(responseMap)
    w.Write(response)
  }
}

// GenerateShortURL adds URL to DB and gives back shortened string
func (driver *DBClient) GenerateShortURL(w http.ResponseWriter, r *http.Request) {
  var id int
  var record Record
  postBody, _ := ioutil.ReadAll(r.Body)
  json.Unmarshal(postBody, &record)
  err := driver.db.QueryRow("INSERT INTO web_url(url) VALUES($1) RETURNING id", record.URL).Scan(&id)
  responseMap := map[string]interface{}{"encoded_string": base62.ToBase62(id)}
  if err != nil {
    w.Write([]byte(err.Error()))
  } else {
    w.Header().Set("Content-Type", "application/json")
    response, _ := json.Marshal(responseMap)
    w.Write(response)
  }
}

func main() {
  db, err := models.InitDB()
  if err != nil {
    panic(err)
  }
  dbclient := &DBClient{db: db}
  if err != nil {
    panic(err)
  }
  defer db.Close()
  // Create a new router
  r := mux.NewRouter()
  // Attach an elegant path with handler
  r.HandleFunc("/v1/short/{encoded_string:[a-zA-Z0-9]*}", dbclient.GetOriginalURL).Methods("GET")
  r.HandleFunc("/v1/short", dbclient.GenerateShortURL).Methods("POST")
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

首先，我们导入了`postgres`库和其他必要的库。我们从模型中导入了数据库会话。接下来，我们导入了我们的编码/解码 base62 算法来实现我们的逻辑：

```go
// DB stores the database session imformation. Needs to be initialized once
type DBClient struct {
  db *sql.DB
}

// Model the record struct
type Record struct {
  ID  int    `json:"id"`
  URL string `json:"url"`
}
```

需要`DBClient`以便在各种函数之间传递数据库驱动程序。记录是类似于插入数据库的记录的结构。我们在我们的代码中定义了两个函数`GenerateShortURL`和`GetOriginalURL`，用于将 URL 添加到数据库，然后从数据库中获取它。正如我们已经解释了 URL 缩短的内部技术，使用此服务的客户端将得到必要的响应。让我们在跳入更多细节之前运行程序并查看输出：

```go
go run $GOPATH/src/github.com/narenaryan/urlshortener/main.go
```

如果您的`$GOPATH/bin`已经在系统的`PATH`变量中，我们可以首先安装二进制文件，然后像这样运行它：

```go
go install github.com/narenaryan/urlshortener/main.go
```

然后只是程序名称：

```go
urlshortener
```

最好的做法是安装二进制文件，因为它可以在整个系统中使用。但对于较小的程序，我们可以通过访问程序的目录来运行`main.go`。

现在它运行 HTTP 服务器并开始收集 URL 缩短服务的请求。打开控制台并输入以下 CURL 命令：

```go
curl -X POST \
 http://localhost:8000/v1/short \
 -H 'cache-control: no-cache' \
 -H 'content-type: application/json' \
 -d '{
 "url": "https://www.forbes.com/forbes/welcome/?toURL=https://www.forbes.com/sites/karstenstrauss/2017/04/20/the-highest-paying-jobs-in-tech-in-2017/&refURL=https://www.google.co.in/&referrer=https://www.google.co.in/"
}'
```

它返回缩短的字符串：

```go
{
  "encoded_string": "1"
}
```

编码的字符串只是`"1"`。Base62 算法从`1`开始分配更短的字符串，直到组合字母数字。现在，如果我们需要检索原始 URL，我们可以执行`GET`请求：

```go
curl -X GET \
 http://localhost:8000/v1/short/1 \
 -H 'cache-control: no-cache' \
```

它返回以下 JSON：

```go
{   
"url":"https://www.forbes.com/forbes/welcome/?toURL=https://www.forbes.com/sites/karstenstrauss/2017/04/20/the-highest-paying-jobs-in-tech-in-2017/\u0026refURL=https://www.google.co.in/\u0026referrer=https://www.google.co.in/"}
```

因此，服务可以使用此结果将用户重定向到原始 URL（站点）。在这里，生成的字符串不取决于 URL 的长度，因为只有数据库 ID 是编码的标准。

在 PostgreSQL 中需要向`INSERT` SQL 命令添加`RETURNING`关键字以获取最后插入的数据库 ID。这在 MySQL 或 SQLite3 的`INSERT INTO web_url( ) VALUES($1) RETURNING id, record.URL`中并非如此。这个 DB 查询返回最后插入记录的 ID。如果我们去掉`RETURNING`关键字，查询将返回空。

# 在 PostgreSQL 中探索 JSON 存储

**PostgreSQL >9.2**有一个突出的功能 9.2" dbid="254735"叫做 JSON 存储。PostgreSQL 引入了一种新的数据类型来存储 JSON 数据。PostgreSQL 允许用户插入一个`jsonb`字段类型，它保存 JSON 字符串。它在对结构更加灵活的真实世界数据进行建模时非常有用。PostgreSQL 通过允许我们存储 JSON 字符串以及关系类型来发挥了最佳的作用。

在本节中，我们将尝试实现我们在前几章中为电子商务网站定义的一些 JSON 模型。但在这里，我们将使用 JSON 字段在 PostgreSQL 中存储和检索项目。对于访问 PostgreSQL 的 JSON 存储，普通的`pq`库非常繁琐。因此，为了更好地处理它，我们可以使用一个称为**GORM**的**对象关系映射器**（**ORM**）。

# GORM，Go 的强大 ORM

这个 ORM 具有`database/sql`包中可以执行的所有操作的 API。我们可以使用这个命令安装 GORM：

```go
go get -u github.com/jinzhu/gorm
```

有关此 ORM 的完整文档，请访问[`jinzhu.me/gorm/`](http://jinzhu.me/gorm/)。让我们编写一个实现用户和订单类型 JSON 模型的程序。用户可以下订单。我们将使用我们在上一章中定义的模型。我们可以在`$GOPATH/src/github.com/narenaryan`中创建一个名为`jsonstore`的新目录，并在其中为我们的模型创建一个新目录：

```go
mkdir jsonstore
mkdir jsonstore/models
touch jsonstore/models/models.go
```

现在，将`models.go`文件编辑为：

```go
package models

import (
  "github.com/jinzhu/gorm"
  _ "github.com/lib/pq"
)

type User struct {
  gorm.Model
  Orders []Order
  Data string `sql:"type:JSONB NOT NULL DEFAULT '{}'::JSONB" json:"-"`
}

type Order struct {
  gorm.Model
  User User
  Data string `sql:"type:JSONB NOT NULL DEFAULT '{}'::JSONB"`
}

// GORM creates tables with plural names. Use this to suppress it
func (User) TableName() string {
  return "user"
}

func (Order) TableName() string {
  return "order"
}

func InitDB() (*gorm.DB, error) {
  var err error
  db, err := gorm.Open("postgres", "postgres://naren:passme123@localhost/mydb?sslmode=disable")
  if err != nil {
    return nil, err
  } else {
    /*
    // The below AutoMigrate is equivalent to this
    if !db.HasTable("user") {
      db.CreateTable(&User{})
    }

    if !db.HasTable("order") {
      db.CreateTable(&Order{})        
    }
    */
    db.AutoMigrate(&User{}, &Order{})
    return db, nil
  }
}
```

这看起来与我们在本章前面定义的模型类似。在这里，对我们来说有很多新的东西。我们在 GORM 中创建的每个模型（表）都应该表示为一个结构。这就是我们创建了两个结构，`User`和`Order`的原因。第一行应该是`gorm.Model`。其他字段是表的字段。默认情况下，将创建一个递增的 ID。在之前的 URL 缩短器模型中，我们在操作之前手动检查表的存在。但在这里，有一个函数：

```go
db.AutoMigrate(&User{}, &Order{})
```

这个函数为作为参数传递的结构创建表。它确保如果表已经存在，它会跳过创建。如果你仔细观察，我们为这些结构添加了一个函数，`TableName`。默认情况下，GORM 创建的所有表名都是复数名（`User`的`users`被创建）。为了强制它创建给定的名称，我们需要覆盖该函数。另一个有趣的事情是，在结构中，我们使用了一个叫做`Data`的字段。它的类型是：

```go
`sql:"type:JSONB NOT NULL DEFAULT '{}'::JSONB" json:"-"`
```

是的，它是一个`jsonb`类型的字符串。我们现在将其类型添加为`string.PostgreSQL`，GORM 会处理它。然后我们将数据库连接返回给导入`models`包的人。 

# 实现电子商务 REST API

在开始之前，让我们设计 API 规范表，其中显示了各种 URL 终端的 REST API 签名。请参考以下表：

| **终端** | **方法** | **描述** |
| --- | --- | --- |
| `/v1/user/id` | `GET` | 使用 ID 获取用户 |
| `/v1/user` | `POST` | 创建新用户 |
| `/v1/user?first_name=NAME` | `GET` | 通过给定的名字获取所有用户 |
| `/v1/order/id` | `GET` | 获取具有给定 ID 的订单 |
| `/v1/order` | `POST` | 创建新订单 |

现在我们来到主程序；让我们向我们的`jsonstore`项目添加一个文件。在这个程序中，我们将尝试实现前三个终端。我们建议读者将剩下的两个终端的实现作为一个作业。看一下以下命令：

```go
touch jsonstore/main.go
```

程序结构遵循我们到目前为止看到的所有程序的相同风格。我们使用 Gorilla Mux 作为我们的 HTTP 路由器，并将数据库驱动程序导入到我们的程序中：

```go
package main

import (
  "encoding/json"
  "io/ioutil"
  "log"
  "net/http"
  "time"

  "github.com/gorilla/mux"
  "github.com/jinzhu/gorm"
    _ "github.com/lib/pq"
  "github.com/narenaryan/jsonstore/models"
)

// DB stores the database session imformation. Needs to be initialized once
type DBClient struct {
  db *gorm.DB
}

// UserResponse is the response to be send back for User
type UserResponse struct {
  User models.User `json:"user"`
  Data interface{} `json:"data"`
}

// GetUsersByFirstName fetches the original URL for the given encoded(short) string
func (driver *DBClient) GetUsersByFirstName(w http.ResponseWriter, r *http.Request) {
  var users []models.User
  name := r.FormValue("first_name")
  // Handle response details
  var query = "select * from \"user\" where data->>'first_name'=?"
  driver.db.Raw(query, name).Scan(&users)
  w.WriteHeader(http.StatusOK)
  w.Header().Set("Content-Type", "application/json")
  //responseMap := map[string]interface{}{"url": ""}
  respJSON, _ := json.Marshal(users)
  w.Write(respJSON)
}

// GetUser fetches the original URL for the given encoded(short) string
func (driver *DBClient) GetUser(w http.ResponseWriter, r *http.Request) {
  var user = models.User{}
  vars := mux.Vars(r)
  // Handle response details
  driver.db.First(&user, vars["id"])
  var userData interface{}
  // Unmarshal JSON string to interface
  json.Unmarshal([]byte(user.Data), &userData)
  var response = UserResponse{User: user, Data: userData}
  w.WriteHeader(http.StatusOK)
  w.Header().Set("Content-Type", "application/json")
  //responseMap := map[string]interface{}{"url": ""}
  respJSON, _ := json.Marshal(response)
  w.Write(respJSON)
}

// PostUser adds URL to DB and gives back shortened string
func (driver *DBClient) PostUser(w http.ResponseWriter, r *http.Request) {
  var user = models.User{}
  postBody, _ := ioutil.ReadAll(r.Body)
  user.Data = string(postBody)
  driver.db.Save(&user)
  responseMap := map[string]interface{}{"id": user.ID}
  var err string = ""
  if err != "" {
    w.Write([]byte("yes"))
  } else {
    w.Header().Set("Content-Type", "application/json")
    response, _ := json.Marshal(responseMap)
    w.Write(response)
  }
}

func main() {
  db, err := models.InitDB()
  if err != nil {
    panic(err)
  }
  dbclient := &DBClient{db: db}
  if err != nil {
    panic(err)
  }
  defer db.Close()
  // Create a new router
  r := mux.NewRouter()
  // Attach an elegant path with handler
  r.HandleFunc("/v1/user/{id:[a-zA-Z0-9]*}", dbclient.GetUser).Methods("GET")
  r.HandleFunc("/v1/user", dbclient.PostUser).Methods("POST")
  r.HandleFunc("/v1/user", dbclient.GetUsersByFirstName).Methods("GET")
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

这里有三个重要的方面：

+   我们用 GORM 驱动程序替换了传统的驱动程序

+   使用 GORM 函数进行 CRUD 操作

+   我们将 JSON 插入到 PostgreSQL 中，并在 JSON 字段中检索结果

让我们详细解释所有的元素。首先，我们导入了所有必要的包。有趣的是：

```go
  "github.com/jinzhu/gorm"
   _ "github.com/lib/pq"
  "github.com/narenaryan/jsonstore/models"
```

GORM 在内部在某种程度上使用了`database/sql`包。我们从我们在前面的代码中创建的包中导入了模型。接下来，我们创建了三个函数，实现了前三个 API 规范。它们是`GetUsersByFirstName`，`GetUser`和`PostUser`。每个函数都继承了数据库驱动程序，并作为`main`函数中 URL 端点的处理程序函数传递：

```go
 r.HandleFunc("/v1/user/{id:[a-zA-Z0-9]*}", dbclient.GetUser).Methods("GET")
 r.HandleFunc("/v1/user", dbclient.PostUser).Methods("POST")
 r.HandleFunc("/v1/user", dbclient.GetUsersByFirstName).Methods("GET")
```

现在，如果我们进入第一个函数，这很简单，这些语句会吸引我们的注意：

```go
driver.db.First(&user, vars["id"])
```

上述语句告诉数据库从具有给定第二参数`ID`的数据库中获取第一条记录。它将返回的数据填充到`user`结构中。我们在`GetUser`中使用`UserResponse`而不是`User`结构，因为`User`包含数据字段，它是一个字符串。但是，为了向客户端返回完整和正确的 JSON，我们需要将数据转换为一个适当的结构，然后进行编组：

```go
// UserResponse is the response to be send back for User
type UserResponse struct {
  User models.User `json:"user"`
  Data interface{} `json:"data"`
}
```

在这里，我们创建了一个可以容纳任何 JSON 数据的空接口。当我们使用驱动程序调用第一个函数时，用户结构具有一个数据字段，它是一个字符串。我们需要将该字符串转换为一个结构，然后将其与`UserResponse`中的其他详细信息一起发送。现在让我们看看这个过程。使用以下命令运行程序：

```go
go run jsonstore/main.go
```

并制作一些 CURL 命令来查看 API 响应：

创建用户：

```go
curl -X POST \
  http://localhost:8000/v1/user \
  -H 'cache-control: no-cache' \
  -H 'content-type: application/json' \
  -d '{
     "username": "naren",
     "email_address": "narenarya@live.com",
     "first_name": "Naren",
     "last_name": "Arya"
}'
```

它返回了在数据库中插入的记录：

```go
{
  "id": 1
}
```

现在，如果我们`GET`插入记录的详细信息：

```go
curl -X GET http://localhost:8000/v1/user/1 
```

它返回有关用户的所有详细信息：

```go
{"user":{"ID":1,"CreatedAt":"2017-08-27T11:55:02.974371+05:30","UpdatedAt":"2017-08-27T11:55:02.974371+05:30","DeletedAt":null,"Orders":null},"data":{"email_address":"narenarya@live.com","first_name":"Naren","last_name":"Arya","username":"naren"}}
```

插入一条记录以检查名字 API：

```go
curl -X POST \
  http://localhost:8000/v1/user \
  -H 'cache-control: no-cache' \
  -H 'content-type: application/json' \
  -d '{
     "username": "nareny",
     "email_address": "naren.yellavula@gmail.com",
     "first_name": "Naren",
     "last_name": "Yellavula"
}'
```

这插入了我们的第二条记录。让我们测试我们的第三个 API，`GetUsersByFirstName`：

```go
curl -X GET 'http://localhost:8000/v1/user?first_name=Naren' 
```

这将返回所有具有给定名字的用户：

```go
[{"ID":1,"CreatedAt":"2017-08-27T11:55:02.974371+05:30","UpdatedAt":"2017-08-27T11:55:02.974371+05:30","DeletedAt":null,"Orders":null},{"ID":2,"CreatedAt":"2017-08-27T11:59:41.84332+05:30","UpdatedAt":"2017-08-27T11:59:41.84332+05:30","DeletedAt":null,"Orders":null}]
```

这个项目的核心宗旨是展示如何从 PostgreSQL 中存储和检索 JSON。这里的特殊之处在于，我们查询了 JSON 字段，而不是`User`表中的普通字段。

记住，PostgreSQL 将其用户存储在一个名为 user 的表中。如果要创建一个新的用户表，请使用`"user"`（双引号）。即使在检索时也要使用双引号。否则，数据库将获取内部用户详细信息。

`SELECT * FROM "user"; // 正确的方式`

`SELECT * FROM user; // 错误的方式。它获取数据库用户`

这结束了我们对 PostgreSQL 的旅程。在 Postgres 中还有很多可以探索的地方。它通过允许我们在同一张表中存储关系型数据和 JSON 数据，将两者的优点发挥到了极致。

# 摘要

在本章中，我们通过安装 PostgreSQL 开始了我们的旅程。我们正式介绍了 PostgreSQL，并尝试看到所有可能的 CRUD 操作的 SQL 查询。然后我们看到了如何在 PostgreSQL 中添加用户和数据库。然后我们安装并解释了`pq`，这是 Go 语言的 Postgres 驱动程序。我们解释了驱动程序 API 如何执行原始的 SQL 查询。

然后是 URL 缩短服务的实现部分；该 REST 服务接受原始 URL 并返回缩短的字符串。它还接受缩短的 URL 并返回原始 URL。我们编写了一个示例程序来说明支持我们服务的 Base62 算法。我们随后在我们的服务中利用了这个算法，并创建了一个 REST API。

GORM 是 Go 语言中众所周知的对象关系映射器。使用 ORM，可以轻松管理数据库操作。GORM 提供了一些有用的函数，比如`AutoMigrate`（如果不存在则创建表），用于在传统的`database/sql`驱动程序上编写直观的 Go 代码。

PostgreSQL 还允许在 9.2 版本之后存储 JSON（称为 JSON 存储）。它允许开发人员以 JSON 格式获得关系数据库的好处。我们可以在 JSON 字段上创建索引，对 JSON 字段进行查询等。我们使用 GORM 为我们在前几章中定义的电子商务模型实现了 REST API。PostgreSQL 是一个成熟的、开源的关系数据库，可以满足我们的企业需求。Go 语言的驱动程序支持非常出色，包括`pq`和`gorm`。


# 第八章：使用 Go 构建 REST API 客户端和单元测试

在本章中，我们将深入讨论 Go 客户端应用程序的工作原理。我们将探索`grequests`，这是一个类似 Python 请求的库，允许我们从 Go 代码中进行 API 调用。然后，我们将编写一个使用 GitHub API 的客户端软件。在此过程中，我们将尝试了解两个名为`cli`和`cobra`的出色库。在掌握了这些基础知识后，我们将尝试使用这些知识在命令行上编写 API 测试工具。然后我们将了解 Redis，这是一个内存数据库，我们可以用它来缓存 API 响应以备份数据。

在本章中，我们将涵盖以下主题：

+   什么是客户端软件？

+   Go 中编写命令行工具的基础知识

+   介绍`grequests`，Go 中类似 Python 请求的库

+   从 Go 客户端检查 GitHub REST API

+   在 Go 中创建 API 客户端

+   缓存 API 以备后用

+   为 API 创建一个单元测试工具

# 获取代码

您可以在 GitHub 存储库链接[`github.com/narenaryan/gorestful/tree/master/chapter8`](https://github.com/narenaryan/gorestful/tree/master/chapter8)中获取本章的代码示例。本章包含单个程序和项目的组合示例。因此，请将相应的目录复制到您的`GOPATH`中，以正确运行代码示例。对于 URL 缩短服务的单元测试的最后一个示例，测试可在[`github.com/narenaryan/gorestful/tree/master/chapter7`](https://github.com/narenaryan/gorestful/tree/master/chapter7)中找到。

# 构建 REST API 客户端的计划

到目前为止，我们主要关注编写服务器端 REST API。基本上，它们是服务器程序。在一些情况下，例如 GRPC，我们还需要客户端。但是真正的客户端程序会从用户那里获取输入并执行一些逻辑。要使用 Go 客户端，我们应该了解 Go 中的`flag`库。在此之前，我们应该知道如何从 Go 程序中对 API 进行请求。在之前的章节中，我们假设客户端可以是 CURL、浏览器、Postman 等。但是我们如何从 Go 中消费 API 呢？

命令行工具与 Web 用户界面一样重要，用于执行系统任务。在**企业对企业**（**B2B**）公司中，软件打包为单个二进制文件，而不是多个不同的部分。作为 Go 开发人员，您应该知道如何实现为命令行编写应用程序的目标。然后，可以利用这些知识轻松而优雅地创建与 REST API 相关的 Web 客户端。

# Go 中编写命令行工具的基础知识

Go 提供了一个名为`flag`的基本库。它指的是命令行标志。由于它已经打包在 Go 发行版中，因此无需外部安装任何内容。我们可以看到编写命令行工具的绝对基础知识。`flag`包具有多个函数，例如`Int`和`String`，用于处理作为命令行标志给定的输入。假设我们需要从用户那里获取一个名称并将其打印回控制台。我们使用`flag.String`方法，如下面的代码片段所示：

```go
import "flag"
var name = flag.String("name", "No Namer", "your wonderful name")
```

让我们写一个简短的程序以获得清晰的细节。在您的`$GOPATH/src/github.com/narenaryan`中创建一个名为`flagExample.go`的文件，并添加以下内容：

```go
package main

import (
  "flag"
  "log"
  )

var name = flag.String("name", "stranger", "your wonderful name")

func main(){
  flag.Parse()
  log.Printf("Hello %s, Welcome to the command line world", *name)
}
```

在这个程序中，我们创建了一个名为`name`的标志。它是一个字符串指针。`flag.String`接受三个参数。第一个是参数的名称。第二个和第三个是该标志的默认值和帮助文本。然后我们要求程序解析所有标志指针。当我们运行程序时，它实际上会将值从命令行填充到相应的变量中。要访问指针的值，我们使用`*`。首先构建，然后使用以下命令运行程序：

```go
go build flagExample.go
```

这将在相同的目录中创建一个二进制文件。我们可以像运行普通可执行文件一样运行它：

```go
./flagExample
```

它给出以下输出：

```go
Hello stranger, Welcome to the command line world
```

在这里，我们没有给出名为`name`的参数。但是我们已经为该参数分配了默认值。Go 的标志获取默认值并继续。现在，为了查看可用的选项并了解它们，可以请求帮助：

```go
./flagExample -h

Output
========
Usage of ./flagExample:
 -name string
 your wonderful name (default "stranger") 
```

这就是我们将帮助文本作为标志命令的第三个参数的原因。

在 Windows 中，当我们构建一个`.go`文件时，将生成`flagExample.exe`。之后，我们可以通过调用程序名称从命令行运行该程序。

现在尝试添加参数，它会打印给定的名称：

```go
./flagExample -name Albert
(or)
./flagExample -name=Albert
```

这两个参数都可以正常工作，给出输出：

```go
Hello Albert, Welcome to the command line world
```

如果我们需要收集多个参数，我们需要修改前面的程序为：

```go
package main

import (
  "flag"
  "log"
  )

var name = flag.String("name", "stranger", "your wonderful name")
var age = flag.Int("age", 0, "your graceful age")

func main(){
  flag.Parse()
  log.Printf("Hello %s (%d years), Welcome to the command line world", *name, *age)
}
```

这需要两个参数，只是另一种类型的额外添加。如果我们运行这个，我们会看到输出：

```go
./flagExampleMultiParam -name Albert -age 24

Hello Albert (24 years), Welcome to the command line world
```

这正是我们所期望的。我们可以将变量绑定到解析输出，而不是使用指针。这种绑定是通过`init()`函数完成的，无论主函数是否存在，它都会在 Go 程序中运行：

```go
var name String 
func init() {
  flag.IntVar(&name, "name", "stranger", "your wonderful name")
}
```

这样，值将直接传递并存储在变量中。使用`init()`函数完全重写前面的程序如下所示：

`initFlag.go`：

```go
package main

import (
  "flag"
  "log"
  )

var name string
var age int

func init() {
  flag.StringVar(&name, "name", "stranger", "your wonderful name")
  flag.IntVar(&age, "age", 0, "your graceful age")
}

func main(){
  flag.Parse()
  log.Printf("Hello %s (%d years), Welcome to the command line world", name, age)
}
```

输出与前面的程序完全相同。在这里，我们可以直接将数据加载到我们的变量中，而不是使用指针。

在 Go 中，执行从`main`程序开始。但是 Go 程序可以有任意数量的`init`函数。如果一个包中有`init`函数，它将被执行。

这个`flag`库非常基础。但是为了编写高级客户端应用程序，我们需要借助该库。在下一节中，我们将看看这样一个库。

# CLI - 用于构建美观客户端的库

这是在玩`flag`包后 Go 开发人员的下一步。它提供了一个直观的 API，可以轻松创建命令行应用程序。它允许我们收集参数和标志。对于设计复杂的应用程序来说，这可能非常方便。要安装该包，请使用以下命令：

```go
go get github.com/urfave/cli
```

之后，让我们编写一个与前面程序完全相同的程序：

`cli/cliBasic.go`：

```go
package main

import (
  "log"
  "os"

  "github.com/urfave/cli"
)

func main() {
  // Create new app
  app := cli.NewApp()

  // add flags with three arguments
  app.Flags = []cli.Flag {
    cli.StringFlag{
      Name: "name",
      Value: "stranger",
      Usage: "your wonderful name",
    },
    cli.IntFlag{
      Name: "age",
      Value: 0,
      Usage: "your graceful age",
    },
  }
  // This function parses and brings data in cli.Context struct
  app.Action = func(c *cli.Context) error {
    // c.String, c.Int looks for value of given flag
    log.Printf("Hello %s (%d years), Welcome to the command line world", c.String("name"), c.Int("age"))
    return nil
  }
  // Pass os.Args to cli app to parse content
  app.Run(os.Args)
}
```

这比之前的程序更长，但更具表现力。我们使用`cli.NewApp`函数创建了一个新的应用程序。它创建了一个新的结构。我们需要将一些参数附加到这个结构。它们是`Flags`结构和`Action`函数。`Flags`结构是一个列表，定义了该应用程序的所有可能的标志。`Flag`的结构来自**GoDoc** ([`godoc.org/github.com/urfave/cli#Flag`](https://godoc.org/github.com/urfave/cli#Flag))：

```go
type Flag interface {
    fmt.Stringer
    // Apply Flag settings to the given flag set
    Apply(*flag.FlagSet)
    GetName() string
}
```

内置的结构，如`StringFlag`和`IntFlag`，实现了`Flag`接口。`Name`，`Value`和`Usage`都很简单。它们类似于`flag`包中使用的那些。`Action`函数接受`cli.Context`参数。该上下文对象包含有关标志和命令行参数的所有信息。我们可以使用它们并对它们应用逻辑。`c.String`，`c.Int`和其他函数用于查找标志变量。例如，在前面的程序中，`c.String("name")`获取了一个名为`name`的标志变量。该程序与以前的程序运行相同：

```go
go build cli/cliBasic.go
```

# 在 CLI 中收集命令行参数

命令行参数和标志之间存在区别。以下图表清楚地说明了它们之间的区别：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/aaebeab6-0adf-407a-87a8-5c2b5e00dd03.jpg)

假设我们有一个名为 storeMarks 的命令行应用程序，用于保存学生的成绩。它有一个标志（称为`save`）来指定是否应将详细信息推送到数据库。给定的参数是学生的姓名和实际成绩。我们已经看到如何在程序中收集标志值。在本节中，我们将看到如何以富有表现力的方式收集程序参数。

为了收集参数，我们使用`c.Args`函数，其中`c`是`Action`函数的`cli`上下文。创建一个名为`cli`的目录，并添加一个新程序`cli/storeMarks.go`：

```go
package main

import (
  "github.com/urfave/cli"
  "log"
  "os"
)

func main() {
  app := cli.NewApp()
  // define flags
  app.Flags = []cli.Flag{
    cli.StringFlag{
      Name:  "save",
      Value: "no",
      Usage: "Should save to database (yes/no)",
    },
  }

  app.Version = "1.0"
  // define action
  app.Action = func(c *cli.Context) error {
    var args []string
    if c.NArg() > 0 {
      // Fetch arguments in a array
      args = c.Args()
      personName := args[0]
      marks := args[1:len(args)]
      log.Println("Person: ", personName)
      log.Println("marks", marks)
    }
    // check the flag value
    if c.String("save") == "no" {
      log.Println("Skipping saving to the database")
    } else {
      // Add database logic here
      log.Println("Saving to the database", args)
    }
    return nil
  }

  app.Run(os.Args)
}
```

`c.Args`保存了我们输入的所有参数。由于我们知道参数的顺序，我们推断第一个参数是名称，其余的值是分数。我们正在检查一个名为`save`的标志，以确定是否将这些详细信息保存在数据库中（这里我们没有数据库逻辑，为简单起见）。`app.Version`设置了工具的版本。其他所有内容与上一个程序相同。

让我们运行这个程序，看看输出：

```go
go build cli/storeMarks.go
```

运行程序：

```go
./storeMarks --save=yes Albert 89 85 97

2017/09/02 21:02:02 Person: Albert
2017/09/02 21:02:02 marks [89 85 97]
2017/09/02 21:02:02 Saving to the database [Albert 89 85 97]
```

如果我们不给出任何标志，默认值是`save=no`：

```go
./storeMarks Albert 89 85 97

2017/09/02 21:02:59 Person: Albert
2017/09/02 21:02:59 marks [89 85 97]
2017/09/02 21:02:59 Skipping saving to the database
```

到目前为止一切看起来都很好。但是当用户需要时，该工具如何显示帮助？`cli`库已经为给定的应用程序创建了一个很好的帮助部分。输入任何这些命令，帮助文本将被自动生成：

+   `./storeMarks -h`（或）

+   `./storeMarks -help`（或）

+   `./storeMarks --help`

+   `./storeMarks help`

一个很好的帮助部分出现了，像这样显示版本详细信息和可用标志（全局选项）、命令和参数：

```go
NAME:
 storeMarks - A new cli application

USAGE:
 storeMarks [global options] command [command options] [arguments...]

VERSION:
 1.0

COMMANDS:
 help, h Shows a list of commands or help for one command

GLOBAL OPTIONS:
 --save value Should save to database (yes/no) (default: "no")
 --help, -h show help
 --version, -v print the version
```

这实际上使构建客户端应用程序变得更容易。它比内部的`flag`包更快、更直观。

命令行工具是在构建程序后生成的二进制文件。它们需要以选项运行。这就像任何系统程序一样，不再与 Go 编译器相关

# grequests - 用于 Go 的 REST API 包

Python 的开发人员知道`Requests`库。这是一个干净、简短的库，不包括在 Python 的标准库中。Go 包`grequests`受到该库的启发。它提供了一组简单的函数，使用这些函数我们可以从 Go 代码中进行 API 请求，如`GET`、`POST`、`PUT`和`DELETE`。使用`grequests`允许我们封装内置的 HTTP 请求和响应。要为 Go 安装`grequests`包，请运行以下命令：

```go
go get -u github.com/levigross/grequests
```

现在，看一下这个基本程序，演示了使用`grequests`库向 REST API 发出`GET`请求。在 Go 源目录中创建一个名为`grequests`的目录，并添加一个名为`basicRequest.go`的文件，如下面的代码片段所示：

```go
package main

import (
  "github.com/levigross/grequests"
  "log"
)

func main() {
  resp, err := grequests.Get("http://httpbin.org/get", nil)
  // You can modify the request by passing an optional RequestOptions struct
  if err != nil {
    log.Fatalln("Unable to make request: ", err)
  }
  log.Println(resp.String())
}
```

`grequests`包具有执行所有 REST 操作的方法。上面的程序使用了包中的`Get`函数。它接受两个函数参数。第一个是 API 的 URL，第二个是请求参数对象。由于我们没有传递任何请求参数，这里的第二个参数是`nil`。`resp`是从请求返回的，它有一个名为`String()`的函数，返回响应体：

```go
go run grequests/basicRequest.go
```

输出是`httpbin`返回的 JSON 响应：

```go
{
  "args": {},
  "headers": {
    "Accept-Encoding": "gzip",
    "Connection": "close",
    "Host": "httpbin.org",
    "User-Agent": "GRequests/0.10"
  },
  "origin": "116.75.82.9",
  "url": "http://httpbin.org/get"
}
```

# grequests 的 API 概述

在`grequests`中探索的最重要的事情不是 HTTP 函数，而是`RequestOptions`结构。这是一个非常大的结构，包含有关 API 方法类型的各种信息。如果 REST 方法是`GET`，`RequestOptions`将包含`Params`属性。如果方法是`POST`，该结构将具有`Data`属性。每当我们发出请求，我们都会得到一个响应。让我们看看响应的结构。根据官方文档，响应如下所示：

```go
type Response struct {
    Ok bool
    Error error
    RawResponse *http.Response
    StatusCode int
    Header http.Header
}
```

响应的`Ok`属性保存了有关请求是否成功的信息。如果出现问题，错误将填入`Error`属性。`RawResponse`是 Go HTTP 响应，将被`grequests`响应的其他函数使用。`StatusCode`和`Header`分别存储响应的状态代码和头部详细信息。`Response`中有一些有用的函数：

+   JSON

+   XML

+   String

+   Bytes

可以通过将空接口传递给函数来调用获取的响应，如`grequests/jsonRequest.go`：

```go
package main

import (
  "github.com/levigross/grequests"
  "log"
)

func main() {
  resp, err := grequests.Get("http://httpbin.org/get", nil)
  // You can modify the request by passing an optional RequestOptions struct
  if err != nil {
    log.Fatalln("Unable to make request: ", err)
  }
  var returnData map[string]interface{}
  resp.JSON(&returnData)
  log.Println(returnData)

}
```

我们声明了一个接口来保存 JSON 值。然后使用`resp.JSON`函数填充了`returnData`（空接口）。该程序打印地图而不是纯粹的 JSON。

# 熟悉 GitHub REST API

GitHub 提供了一个很好的 REST API 供用户使用。它通过 API 向客户端开放有关用户、存储库、存储库统计等数据。当前稳定版本为 v3。API 文档可以在[`developer.github.com/v3/`](https://developer.github.com/v3/)找到。API 的根端点是：

```go
curl https://api.github.com
```

其他 API 将添加到此基本 API 中。现在让我们看看如何进行一些查询并获取与各种元素相关的数据。对于未经身份验证的用户，速率限制为 60/小时，而对于传递`client_id`（可以从 GitHub 帐户获取）的客户端，速率限制为 5,000/小时。

如果您有 GitHub 帐户（如果没有，建议您创建一个），您可以在您的个人资料|个人访问令牌区域或通过访问[`github.com/settings/tokens`](https://github.com/settings/tokens)找到访问令牌。使用`Generate new token`按钮创建一个新的访问令牌。它要求各种权限和资源类型。全部选中。将生成一个新的字符串。将其保存到某个私人位置。我们生成的令牌可以用于访问 GitHub API（以获得更长的速率限制）。

下一步是将访问令牌保存到环境变量**`GITHUB_TOKEN`**中。为此，请打开您的**`~/.profile`**或**`~/.bashrc`**文件，并将其添加为最后一行：

```go
export GITHUB_TOKEN=YOUR_GITHUB_ACCESS_TOKEN
```

`YOUR_GITHUB_ACCESS_TOKEN`是之前从 GitHub 帐户生成并保存的。让我们创建一个程序来获取给定用户的所有存储库。创建一个名为`githubAPI`的新目录，并创建一个名为`getRepos.go`的程序文件：

```go
package main

import (
  "github.com/levigross/grequests"
  "log"
  "os"
)

var GITHUB_TOKEN = os.Getenv("GITHUB_TOKEN")
var requestOptions = &grequests.RequestOptions{Auth: []string{GITHUB_TOKEN, "x-oauth-basic"}}

type Repo struct {
  ID int `json:"id"`
  Name string `json:"name"`
  FullName string  `json:"full_name"`
  Forks int `json:"forks"`
  Private bool `json:"private"`
}

func getStats(url string) *grequests.Response{
  resp, err := grequests.Get(url, requestOptions)
  // You can modify the request by passing an optional RequestOptions struct
  if err != nil {
    log.Fatalln("Unable to make request: ", err)
  }
  return resp
}

func main() {
  var repos []Repo
  var repoUrl = "https://api.github.com/users/torvalds/repos"
  resp := getStats(repoUrl)
  resp.JSON(&repos)
  log.Println(repos)
}
```

运行程序，您将看到以下输出：

```go
2017/09/03 17:59:41 [{79171906 libdc-for-dirk torvalds/libdc-for-dirk 10 false} {2325298 linux torvalds/linux 18274 false} {78665021 subsurface-for-dirk torvalds/subsurface-for-dirk 16 false} {86106493 test-tlb torvalds/test-tlb 25 false}]
```

打印输出不是 JSON，而是 Go `Repo` `struct`的列表。前面的程序说明了我们如何查询 GitHub API 并将数据加载到我们的自定义结构中：

```go
type Repo struct {
  ID int `json:"id"`
  Name string `json:"name"`
  FullName string  `json:"full_name"`
  Forks int `json:"forks"`
  Private bool `json:"private"`
}
```

这是我们用于保存存储库详细信息的结构。返回的 JSON 有许多字段，但为简单起见，我们只是从中摘取了一些重要字段：

```go
var GITHUB_TOKEN = os.Getenv("GITHUB_TOKEN")
var requestOptions = &grequests.RequestOptions{Auth: []string{GITHUB_TOKEN, "x-oauth-basic"}}
```

在第一行，我们正在获取名为`GITHUB_TOKEN`的环境变量。`os.Getenv`函数通过给定的名称返回环境变量的值。为了使 GitHub 假定`GET`请求的来源，我们应该设置身份验证。为此，将参数传递给`RequestOptions`结构。该参数应该是用户名和密码的列表。

# 创建一个 CLI 工具作为 GitHub REST API 的 API 客户端

在查看了这个例子之后，我们能够轻松地从我们的 Go 客户端访问 GitHub API。到目前为止，我们可以结合本章学到的两种技术，来设计一个使用 GitHub API 的命令行工具。让我们创建一个新的命令行应用程序，其中：

+   提供按用户名获取存储库详细信息的选项

+   使用给定描述将任何文件上传到 GitHub gists（文本片段）

+   使用个人访问令牌进行身份验证

Gists 是 GitHub 提供的存储文本内容的片段。有关更多详细信息，请访问[`gist.github.com`](https://gist.github.com)。

在`githubAPI`目录中创建一个名为**`gitTool.go`**的程序。这将是前面程序规范的逻辑：

```go
package main

import (
  "encoding/json"
  "fmt"
  "github.com/levigross/grequests"
  "github.com/urfave/cli"
  "io/ioutil"
  "log"
  "os"
)

var GITHUB_TOKEN = os.Getenv("GITHUB_TOKEN")
var requestOptions = &grequests.RequestOptions{Auth: []string{GITHUB_TOKEN, "x-oauth-basic"}}

// Struct for holding response of repositories fetch API
type Repo struct {
  ID       int    `json:"id"`
  Name     string `json:"name"`
  FullName string `json:"full_name"`
  Forks    int    `json:"forks"`
  Private  bool   `json:"private"`
}

// Structs for modelling JSON body in create Gist
type File struct {
  Content string `json:"content"`
}

type Gist struct {
  Description string          `json:"description"`
  Public      bool            `json:"public"`
  Files       map[string]File `json:"files"`
}

// Fetches the repos for the given Github users
func getStats(url string) *grequests.Response {
  resp, err := grequests.Get(url, requestOptions)
  // you can modify the request by passing an optional RequestOptions struct
  if err != nil {
    log.Fatalln("Unable to make request: ", err)
  }
  return resp
}

// Reads the files provided and creates Gist on github
func createGist(url string, args []string) *grequests.Response {
  // get first teo arguments
  description := args[0]
  // remaining arguments are file names with path
  var fileContents = make(map[string]File)
  for i := 1; i < len(args); i++ {
    dat, err := ioutil.ReadFile(args[i])
    if err != nil {
      log.Println("Please check the filenames. Absolute path (or) same directory are allowed")
      return nil
    }
    var file File
    file.Content = string(dat)
    fileContents[args[i]] = file
  }
  var gist = Gist{Description: description, Public: true, Files: fileContents}
  var postBody, _ = json.Marshal(gist)
  var requestOptions_copy = requestOptions
  // Add data to JSON field
  requestOptions_copy.JSON = string(postBody)
  // make a Post request to Github
  resp, err := grequests.Post(url, requestOptions_copy)
  if err != nil {
    log.Println("Create request failed for Github API")
  }
  return resp
}

func main() {
  app := cli.NewApp()
  // define command for our client
  app.Commands = []cli.Command{
    {
      Name:    "fetch",
      Aliases: []string{"f"},
      Usage:   "Fetch the repo details with user. [Usage]: goTool fetch user",
      Action: func(c *cli.Context) error {
        if c.NArg() > 0 {
          // Github API Logic
          var repos []Repo
          user := c.Args()[0]
          var repoUrl = fmt.Sprintf("https://api.github.com/users/%s/repos", user)
          resp := getStats(repoUrl)
          resp.JSON(&repos)
          log.Println(repos)
        } else {
          log.Println("Please give a username. See -h to see help")
        }
        return nil
      },
    },
    {
      Name:    "create",
      Aliases: []string{"c"},
      Usage:   "Creates a gist from the given text. [Usage]: goTool name 'description' sample.txt",
      Action: func(c *cli.Context) error {
        if c.NArg() > 1 {
          // Github API Logic
          args := c.Args()
          var postUrl = "https://api.github.com/gists"
          resp := createGist(postUrl, args)
          log.Println(resp.String())
        } else {
          log.Println("Please give sufficient arguments. See -h to see help")
        }
        return nil
      },
    },
  }

  app.Version = "1.0"
  app.Run(os.Args)
}
```

在深入解释细节之前，让我们运行程序。这清楚地说明了我们如何实现该程序：

```go
go build githubAPI/gitTool.go
```

它在相同的目录中创建一个二进制文件。如果您键入`./gitTool -h`，它会显示：

```go
NAME:
 gitTool - A new cli application

USAGE:
 gitTool [global options] command [command options] [arguments...]

VERSION:
 1.0

COMMANDS:
 fetch, f Fetch the repo details with user. [Usage]: goTool fetch user
 create, c Creates a gist from the given text. [Usage]: goTool name 'description' sample.txt
 help, h Shows a list of commands or help for one command

GLOBAL OPTIONS:
 --help, -h show help
 --version, -v print the version
```

如果您查看帮助命令，有两个命令，`fetch`和`create`。`fetch`获取给定用户的存储库，`create`创建一个带有提供的文件的`gist`。让我们在程序的相同目录中创建两个示例文件，以测试`create`命令：

```go
echo 'I am sample1 file text' > githubAPI/sample1.txt
echo 'I am sample2 file text' > githubAPI/sample2.txt
```

使用第一个命令运行该工具：

```go
./gitTool f torvalds
```

它返回所有属于伟大的 Linus Torvalds 的存储库。日志消息打印填充的结构：

```go
[{79171906 libdc-for-dirk torvalds/libdc-for-dirk 10 false} {2325298 linux torvalds/linux 18310 false} {78665021 subsurface-for-dirk torvalds/subsurface-for-dirk 16 false} {86106493 test-tlb torvalds/test-tlb 25 false}]
```

现在，让我们检查第二个命令。它使用给定的描述和一组文件作为参数创建`gist`：

```go
./gitTool c "I am doing well" sample1.txt sample2.txt
```

它返回有关创建的`gist`的 JSON 详细信息。这是一个非常冗长的 JSON，所以这里跳过输出。然后，打开您的[gist.github.com](https://gist.github.com/)帐户，您将看到创建的`gist`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/ff1620ca-8fee-48f9-8bec-ebc3d694ef84.png)

现在，来解释一下，我们首先导入`grequests`以进行 API 调用和`cli`以构建命令行工具。其他导入是必要的，以便读取文件，记录到控制台和编码 JSON。然后我们定义了三个结构：`Repo`，`File`和`Gist`。GitHub 的`gists` API 需要 JSON 数据来创建：

```go
{
  "description": "the description for this gist",
  "public": true,
  "files": {
    "file1.txt": {
      "content": "String file contents"
    }
  }
}
```

`grequests`的`POST`请求使用具有`Data`作为字段的`requestOptions`。但它的签名是`Map[string]string]`，这不足以创建前面的结构。`grequests`允许我们传递任何结构的 JSON 字符串到 API。我们创建了结构，以便数据可以填充并编组成适当的 JSON 以使`POST`请求成功。

然后，我们创建了两个函数：`getStats`（返回给定用户的所有存储库详细信息）和`createGist`（使用给定的描述和文件名创建新的`gist`文件）。第二个函数更有趣。我们正在传递一个 URL 进行`POST`请求，描述和`file_names`以`args`数组的形式。然后，我们正在迭代每个文件并获取内容。我们正在调整我们的结构，以便`POST`请求的最终 JSON 主体将具有相同的结构。最后，我们使用具有我们的 JSON 的**`requestOptions`**进行`POST`请求。

这样，我们结合了两个库来构建一个可以执行任何任务的 API 客户端。Go 的美妙之处在于我们可以将最终的二进制文件中包含命令行工具的逻辑和调用逻辑的 REST API。

对于任何 Go 程序来说，要很快读懂，首先要遵循`main`函数，然后进入其他函数。这样，我们可以遇到导入的包及其 API。

# 使用 Redis 缓存 API 数据

**Redis**是一个可以存储键/值对的内存数据库。它最适合缓存使用案例，其中我们需要临时存储信息，但对于大量流量。例如，像 BBC 和 The Guardian 这样的网站在仪表板上显示最新文章。他们的流量很大，如果从数据库中获取文档（文章），他们需要一直维护一个庞大的数据库集群。由于给定的一组文章不会改变（至少几个小时），BBC 可以维护一个保存文章的缓存。当第一个客户访问页面时，从数据库中获取副本，发送到浏览器，并放入 Redis 缓存中。下次客户出现时，BBC 应用服务器从 Redis 中读取内容，而不是去数据库。由于 Redis 运行在主内存中，延迟得到减少。客户可以看到他的页面在一瞬间加载。网络上的基准测试可以更多地告诉我们网站如何有效地优化其内容。

如果 Redis 中的数据不再相关怎么办？（例如，BBC 更新了其头条新闻。）Redis 提供了一种在其中存储的`keys:values`过期的方法。我们可以运行一个调度程序，当过期时间过去时更新 Redis。

同样，我们可以为给定请求（`GET`）缓存第三方 API 的响应。我们需要这样做，因为像 GitHub 这样的第三方系统给了我们一个速率限制（告诉我们要保守）。对于给定的`GET URL`，我们可以将`URL`作为键，`Response`作为值进行存储。在下次给出相同请求时（在键过期之前），只需从 Redis 中提取响应，而不是访问 GitHub 服务器。这种方法也适用于我们的 REST API。最频繁和不变的 REST API 可以被缓存，以减少对主数据库的负载。

Go 有一个很棒的库可以与 Redis 通信。它是[`github.com/go-redis/redis`](https://github.com/go-redis/redis)。这是一个众所周知的库，许多开发人员建议您使用。下图很好地说明了这个概念：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/4ec5f6f5-dcf7-4cc9-b427-14e8ce28865e.jpg)

这里需要注意的一个问题是 API 的过期。实时 API 不应该被缓存，因为它具有动态性。缓存为我们带来了性能优化，但也带来了一些麻烦。在进行缓存时要小心。全球有许多更好的实践方法。请仔细阅读它们，以了解各种架构。

# 为我们的 URL 缩短服务创建一个单元测试工具

在上一章中，我们创建了一个 URL 缩短服务。我们之前工作的 URL 缩短器项目的结构如下：

```go
├── main.go
├── models
│   └── models.go
└── utils
    └── encodeutils.go

2 directories, 3 files
```

在`main.go`文件中，我们创建了两个 API 处理程序：一个用于`GET`，一个用于`POST`。我们将为这两个处理程序编写单元测试。在项目的根目录中添加一个名为`main_test.go`的文件：

```go
touch main_test.go
```

为了测试我们的 API，我们需要测试我们的 API 处理程序：

```go
package main_test

import (
  "testing"
  "net/http"
)

func TestGetOriginalURL(t *testing.T) {
  // make a dummy reques
  response, err := http.Get("http://localhost:8000/v1/short/1")

    if http.StatusOK != response.StatusCode {
      t.Errorf("Expected response code %d. Got %d\n", http.StatusOK, response.StatusCode)
    }

    if err != nil {
      t.Errorf("Encountered an error:", err)
    }
}
```

Go 中有一个名为`testing`的测试包。它允许我们创建一些断言，并让我们进行通过或失败的测试。我们正在通过进行简单的 HTTP 请求来测试 API `TestGetOriginalURL`。确保数据库中至少插入了一条记录。数据库连接的高级测试主题超出了本书的范围。我们可以在项目目录中使用 Go test 命令进行测试。

# 摘要

我们从理解客户端软件开始我们的章节：软件客户端的工作原理以及我们如何创建一些。我们了解了编写命令行应用程序的基础知识。CLI 是一个第三方包，可以让我们创建漂亮的命令行应用程序。安装后，我们看到了如何通过工具收集命令行参数。我们还探讨了 CLI 应用程序中的命令和标志。接下来，我们研究了`grequests`，这是一个类似于 Python requests 的包，用于从 Go 代码中进行 API 请求。我们看到了如何从客户端程序中进行`GET`、`POST`等请求。

接下来，我们探讨了 GitHub API 如何获取仓库等详细信息。有了这两个概念的知识，我们开发了一个客户端，列出了给定用户的仓库，并创建了一个`gist`（GitHub 上的文本文件）。我们介绍了 Redis 架构，说明了缓存如何帮助处理速率限制的 API。最后，我们为上一章中创建的 URL 缩短服务编写了一个单元测试。


# 第九章：使用微服务扩展我们的 REST API

在概念上，构建 REST API 很容易。但是将它们扩展以接受大量流量是一个挑战。到目前为止，我们已经研究了创建 REST API 结构和示例 REST API 的细节。在本章中，我们将探索 Go Kit，这是一个用于构建微服务的精彩的、符合惯例的 Go 软件包。这是微服务时代，创业公司在短时间内就成为企业。微服务架构允许公司快速并行迭代。我们将从定义微服务开始，然后通过创建 REST 风格的微服务来了解 Go Kit。

在本章中，我们将涵盖以下主题：

+   单体和微服务之间的区别

+   微服务的需求

+   介绍 Go Kit，一个 Go 语言的微服务工具包

+   使用 Go Kit 创建 REST API

+   为 API 添加日志记录

+   为 API 添加仪表板

# 获取代码

您可以在 GitHub 存储库链接[`github.com/narenaryan/gorestful/tree/master/chapter9`](https://github.com/narenaryan/gorestful/tree/master/chapter9)中获取本章的代码示例。在上一章中，我们讨论了 Go API 客户端。在这里，我们回到了具有微服务架构的 REST API。

# 什么是微服务？

什么是微服务？这是企业世界向计算世界提出的问题。由于团队规模较大，公司准备采用微服务来分解任务。微服务架构用粒度服务取代了传统的单体，并通过某种协议相互通信。

微服务为以下方面带来了好处：

+   如果团队很大，人们可以在应用程序的各个部分上工作

+   新开发人员很容易适应

+   采用最佳实践，如**持续集成**（**CI**）和**持续交付**（**CD**）

+   易于替换的松散耦合架构软件

在单体应用程序（传统应用程序）中，一个巨大的服务器通过多路复用计算能力来服务传入的请求。这很好，因为我们在一个地方拥有一切，比如应用服务器、数据库和其他东西。但它也有缺点。当软件出现问题时，一切都会出现问题。此外，开发人员需要设置整个应用程序来开发一个小部分。

单体应用程序的缺点清单可能包括：

+   紧密耦合的架构

+   单点故障

+   添加新功能和组件的速度

+   工作的碎片化仅限于团队

+   持续部署非常困难，因为需要推送整个应用程序

查看单体应用程序时，整个堆栈被视为单个实体。如果数据库出现故障，应用程序也会出现故障。如果代码中的错误导致软件应用程序崩溃，与客户端的整个连接也会中断。这实际上导致了微服务的出现。

让我们来看一个场景。Bob 经营的公司使用传统的**面向服务的架构**（**SOA**），开发人员全天候工作以添加新功能。如果有发布，人们需要对每个小组件的代码进行全面测试。当所有更改完成时，项目从开发转移到测试。下一条街上的另一家公司由 Alice 经营，使用微服务架构。Alice 公司的所有软件开发人员都在个别服务上工作，这些服务通过连续的构建流水线进行测试，并且通知非常迅速。开发人员通过彼此的 REST/RPC API 交流以添加新功能。与 Bob 的开发人员相比，他们可以轻松地将其堆栈从一种技术转移到另一种技术。这个例子表明了 Alice 公司的灵活性和速度比 Bob 公司更大。

微服务还创建了一个允许我们使用容器（docker 等）的平台。在微服务中，编排和服务发现对于跟踪松散耦合的元素非常重要。诸如 Kubernetes 之类的工具用于管理 docker 容器。通常，为微服务拥有一个 docker 容器是一个很好的做法。服务发现是在飞行中自动检测 IP 地址和其他详细信息。这消除了硬编码微服务需要相互协商的东西的潜在威胁。

# 单体架构与微服务

行业专家建议将软件应用程序作为单体架构开始，然后逐步将其拆分为微服务。这实际上帮助我们专注于应用程序交付，而不是研究微服务模式。一旦产品稳定下来，开发人员应该找到一种松散耦合功能的方法。看一下下面的图表：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/a7355ea1-d2ba-4a9d-b60b-b49dac855c81.jpg)

这张图描述了单体架构和微服务架构的结构。单体架构将所有内容包裹在洋葱形式中。它被称为紧密耦合的系统。相比之下，微服务是独立的，易于替换和修改。每个微服务可以通过各种传输机制（如 HTTP 和 RPC）相互通信。格式可以是 JSON 或协议缓冲区。

# Go Kit，用于构建微服务的包

在企业世界中，人们了解 Netflix 的 Eureka 和 Java 社区的 Spring Boot。在 Go 中，一个试图达到那个实现水平的包显然是**Go kit**。这是一个用于构建微服务的工具包。

它具有 Go 风格的添加服务的方式，这让我们感觉良好。它带有一个添加微服务的过程。在接下来的章节中，我们将看到如何按照 Go Kit 定义的步骤创建微服务。它主要由许多层组成。在 Go Kit 中，有三个层，请求和响应在其中流动：

+   **传输层**：这负责将数据从一个服务传输到另一个服务

+   **终端层**：这负责为给定服务构建终端

+   **服务层**：这是 API 处理程序的实际业务逻辑

使用以下命令安装 Go Kit：

```go
go get github.com/go-kit/kit
```

让我们为我们的第一个微服务制定计划。我们都知道消息的加密。可以使用密钥加密消息字符串，输出一个无意义的消息，可以通过网络传输。接收者解密消息并获得原始字符串。这个过程称为加密。我们将尝试将其作为微服务示例的一部分实现：

+   首先，开发加密逻辑

+   然后，将其与 Go Kit 集成

Go 自带了用于加密消息的包。我们需要从这些包中导入加密算法并使用它们。作为第一步，我们将编写一个使用**高级加密标准**（**AES**）的项目。

在`GOPATH/src/user`目录中创建一个名为`encryptString`的目录：

```go
mkdir $GOPATH/src/github.com/narenaryan/encryptString
cd $GOPATH/src/github.com/narenaryan/encryptString
```

现在让我们在新目录中再添加一个，名为 utils。在项目目录中添加两个文件，`main.go`和在名为`utils`的新目录中添加`utils.go`。目录结构如下：

```go
└── encryptString
    ├── main.go
    └── utils
        └── utils.go
```

现在让我们在我们的`utils.go`文件中添加加密逻辑。我们创建两个函数，一个用于加密，另一个用于解密消息，如下所示：

```go
package utils
import (
    "crypto/aes"
    "crypto/cipher"
    "encoding/base64"
)
```

AES 算法需要初始化向量。让我们首先定义它：

```go
// Implements AES encryption algorithm(Rijndael Algorithm)
/* Initialization vector for the AES algorithm
More details visit this link https://en.wikipedia.org/wiki/Advanced_Encryption_Standard */
var initVector = []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}
```

现在，让我们实现加密和解密的逻辑：

```go
// EncryptString encrypts the string with given key
func EncryptString(key, text string) string {
    block, err := aes.NewCipher([]byte(key))
    if err != nil {
        panic(err)
    }
    plaintext := []byte(text)
    cfb := cipher.NewCFBEncrypter(block, initVector)
    ciphertext := make([]byte, len(plaintext))
    cfb.XORKeyStream(ciphertext, plaintext)
    return base64.StdEncoding.EncodeToString(ciphertext)
}
```

在`EncryptString`函数中，我们正在使用密钥创建一个新的密码块。然后我们将该块传递给密码块加密器函数。该加密器接受块和初始化向量。然后我们通过在密码块上进行`XORKeyStream`来生成密文（加密消息）。它填充了密文。然后我们需要进行 Base64 编码以生成受保护的字符串：

```go
// DecryptString decrypts the encrypted string to original
func DecryptString(key, text string) string {
    block, err := aes.NewCipher([]byte(key))
    if err != nil {
        panic(err)
    }
    ciphertext, _ := base64.StdEncoding.DecodeString(text)
    cfb := cipher.NewCFBEncrypter(block, initVector)
    plaintext := make([]byte, len(ciphertext))
    cfb.XORKeyStream(plaintext, ciphertext)
    return string(plaintext)
}
```

在`DecryptString`函数中，解码 Base64 编码并使用密钥创建一个密码块。将这个密码块与初始化向量传递给`NewCFBEncrypter`。接下来，使用`XORKeyStream`将密文加载到明文中。基本上，这是一个在`XORKeyStream`中交换加密和解密消息的过程。这完成了`utils.go`文件。

现在让我们编辑`main.go`文件，以利用前面的`utils`包：

```go
package main
import (
    "log"
    "github.com/narenaryan/encryptString/utils"
)
// AES keys should be of length 16, 24, 32
func main() {
    key := "111023043350789514532147"
    message := "I am A Message"
    log.Println("Original message: ", message)
    encryptedString := utils.EncryptString(key, message)
    log.Println("Encrypted message: ", encryptedString)
    decryptedString := utils.DecryptString(key, encryptedString)
    log.Println("Decrypted message: ", decryptedString)
}
```

在这里，我们从`utils`包中导入加密/解密函数，并使用它们来展示一个例子。

如果我们运行这个程序，我们会看到以下输出：

```go
go run main.go

Original message: I am A Message
Encrypted message: 8/+JCfTb+ibIjzQtmCo=
Decrypted message: I am A Message
```

它展示了我们如何使用 AES 算法加密消息，并使用相同的秘钥将其解密。这个算法也被称为**Rijndael**（发音为 rain-dahl）算法。

# 使用 Go Kit 构建 REST 微服务

有了这些知识，我们准备构建我们的第一个提供加密/解密 API 的微服务。我们使用 Go Kit 和我们的加密`utils`来编写这个微服务。正如我们在前一节中讨论的，Go-Kit 微服务应该逐步构建。要创建一个服务，我们需要事先设计一些东西。它们是：

+   服务实现

+   端点

+   请求/响应模型

+   传输

坐稳。这个术语现在似乎很陌生。我们很快就会对它感到很舒适。让我们创建一个具有以下目录结构的目录。每个 Go Kit 项目都可以在这个项目结构中。让我们称我们的项目为`encryptService`。在`encryptService`目录中以相同的树结构创建这些文件：

```go
├── helpers
│   ├── endpoints.go
│   ├── implementations.go
│   ├── jsonutils.go
│   └── models.go
└── main.go
```

我们将逐个查看每个文件，看看应该如何构建。首先，在 Go Kit 中，创建一个接口，告诉我们的微服务执行所有功能。在这种情况下，这些功能是`Encrypt`和`Decrypt`。`Encrypt`接受密钥并将文本转换为密码消息。`Decrypt`使用密钥将密码消息转换回文本。看一下以下代码：

```go
import (
  "context"
)
// EncryptService is a blueprint for our service

type EncryptService interface {
  Encrypt(context.Context, string, string) (string, error)
  Decrypt(context.Context, string, string) (string, error)
}
```

服务需要实现这些函数以满足接口。接下来，为您的服务创建模型。模型指定服务可以接收和产生的数据。在项目的`helpers`目录中创建一个`models.go`文件：

`encryptService/helpers/models.go`

```go
package helpers

// EncryptRequest strctures request coming from client
type EncryptRequest struct {
  Text string `json:"text"`
  Key  string `json:"key"`
}

// EncryptResponse strctures response going to the client
type EncryptResponse struct {
  Message string `json:"message"`
  Err     string `json:"error"`
}

// DecryptRequest strctures request coming from client
type DecryptRequest struct {
  Message string `json:"message"`
  Key     string `json:"key"`
}

// DecryptResponse strctures response going to the client
type DecryptResponse struct {
  Text string `json:"text"`
  Err  string `json:"error"`
}
```

由于我们有两个服务函数，所以有四个函数映射到请求和响应。下一步是创建一个实现前面定义的接口`EncryptService`的结构体。因此，在以下路径中的实现文件中创建该逻辑：

`encryptService/helpers/implementations.go`

首先，让我们导入所有必要的包。同时，给出包的名称：

```go
package helpers
import (
    "context"
    "crypto/aes"
    "crypto/cipher"
    "encoding/base64"
    "errors"
)
// EncryptServiceInstance is the implementation of interface for micro service
type EncryptServiceInstance struct{}
// Implements AES encryption algorithm(Rijndael Algorithm)
/* Initialization vector for the AES algorithm
More details visit this link https://en.wikipedia.org/wiki/Advanced_Encryption_Standard */
var initVector = []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}
// Encrypt encrypts the string with given key
func (EncryptServiceInstance) Encrypt(_ context.Context, key string, text string) (string, error) {
    block, err := aes.NewCipher([]byte(key))
    if err != nil {
        panic(err)
    }
    plaintext := []byte(text)
    cfb := cipher.NewCFBEncrypter(block, initVector)
    ciphertext := make([]byte, len(plaintext))
    cfb.XORKeyStream(ciphertext, plaintext)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}
// Decrypt decrypts the encrypted string to original
func (EncryptServiceInstance) Decrypt(_ context.Context, key string, text string) (string, error) {
    if key == "" || text == "" {
        return "", errEmpty
    }
    block, err := aes.NewCipher([]byte(key))
    if err != nil {
        panic(err)
    }
    ciphertext, _ := base64.StdEncoding.DecodeString(text)
    cfb := cipher.NewCFBEncrypter(block, initVector)
    plaintext := make([]byte, len(ciphertext))
    cfb.XORKeyStream(plaintext, ciphertext)
    return string(plaintext), nil
}
var errEmpty = errors.New("Secret Key or Text should not be empty")
```

这利用了我们在前面示例中看到的相同的 AES 加密。在这个文件中，我们创建了一个名为`EncyptionServiceInstance`的结构体，它有两个方法，`Encrypt`和`Decrypt`。因此它满足了前面的接口。现在，我们如何将这些实际的服务实现与服务请求和响应联系起来呢？我们需要为此定义端点。因此，添加以下端点以将服务请求与服务业务逻辑链接起来。

我们使用`Capitalized`函数和变量名称，因为在 Go 中，任何以大写字母开头的函数或变量都是从该包名导出的。在`main.go`中，要使用所有这些函数，我们需要首先将它们导出。给予大写名称使它们对主程序可见。

在`helpers`目录中创建`endpoints.go`：

```go
package helpers
import (
    "context"
    "github.com/go-kit/kit/endpoint"
)
// EncryptService is a blueprint for our service
type EncryptService interface {
    Encrypt(context.Context, string, string) (string, error)
    Decrypt(context.Context, string, string) (string, error)
}
// MakeEncryptEndpoint forms endpoint for request/response of encrypt function
func MakeEncryptEndpoint(svc EncryptService) endpoint.Endpoint {
    return func(ctx context.Context, request interface{}) (interface{}, error) {
        req := request.(EncryptRequest)
        message, err := svc.Encrypt(ctx, req.Key, req.Text)
        if err != nil {
            return EncryptResponse{message, err.Error()}, nil
        }
        return EncryptResponse{message, ""}, nil
    }
}
// MakeDecryptEndpoint forms endpoint for request/response of decrypt function
func MakeDecryptEndpoint(svc EncryptService) endpoint.Endpoint {
    return func(ctx context.Context, request interface{}) (interface{}, error) {
        req := request.(DecryptRequest)
        text, err := svc.Decrypt(ctx, req.Key, req.Message)
        if err != nil {
            return DecryptResponse{text, err.Error()}, nil
        }
        return DecryptResponse{text, ""}, nil
    }
}
```

在这里，我们将之前的接口定义代码与端点定义代码结合在一起。端点以服务作为参数并返回一个函数。这个函数又以请求为参数并返回一个响应。这些东西与我们在`models.go`文件中定义的内容相同。我们检查错误，然后返回响应的结构体。

现在，一切都很好。在我们之前的 REST API 示例中，我们总是试图将 JSON 字符串解组为 Go 结构。对于响应，我们通过编组将结构转换回 JSON 字符串。在这里，我们分别解组和编组请求和响应。为此，我们编写一个用于编码/解码逻辑的文件。让我们称该文件为`jsonutils.go`并将其添加到`helpers`目录中：

```go
package helpers
import (
    "context"
    "encoding/json"
    "net/http"
)
// DecodeEncryptRequest fills struct from JSON details of request
func DecodeEncryptRequest(_ context.Context, r *http.Request) (interface{}, error) {
    var request EncryptRequest
    if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
        return nil, err
    }
    return request, nil
}
// DecodeDecryptRequest fills struct from JSON details of request
func DecodeDecryptRequest(_ context.Context, r *http.Request) (interface{}, error) {
    var request DecryptRequest
    if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
        return nil, err
    }
    return request, nil
}
// EncodeResponse is common for both the reponses from encrypt and decrypt services
func EncodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
    return json.NewEncoder(w).Encode(response)
}
```

`EncodeResponse`用于编组`EncyptService`和`DecryptService`的响应，但是在将 JSON 解码为结构时，我们需要两种不同的方法。我们将它们定义为`DecodeEncryptRequest`和`DecodeDecryptRequest`。这些函数使用 Go 的内部 JSON 包来编组和解组数据。

现在我们有了所有需要创建微服务的构造的辅助文件。让我们设计`main`函数，导入现有的内容并将微服务连接到服务器：

```go
package main
import (
    "log"
    "net/http"
    httptransport "github.com/go-kit/kit/transport/http"
    "github.com/narenaryan/encryptService/helpers"
)
func main() {
    svc := helpers.EncryptServiceInstance{}
    encryptHandler := httptransport.NewServer(helpers.MakeEncryptEndpoint(svc),
        helpers.DecodeEncryptRequest,\
        helpers.EncodeResponse)
    decryptHandler := httptransport.NewServer(helpers.MakeDecryptEndpoint(svc),
        helpers.DecodeDecryptRequest,
        helpers.EncodeResponse)
    http.Handle("/encrypt", encryptHandler)
    http.Handle("/decrypt", decryptHandler)
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

我们正在导入 Go Kit 的 transport/http 作为`httptransport`来创建处理程序。处理程序附加了端点、JSON 解码器和 JSON 编码器。然后，使用 Go 的 net/http，我们处理给定 URL 端点的 HTTP 请求。`httptransport.NewServer`接受一些参数：一个端点，JSON 解码器和 JSON 编码器。服务执行的逻辑在哪里？它在端点中。端点接受请求模型并输出响应模型。现在，让我们在`encryptService`目录中运行这个项目：

```go
go run main.go
```

我们可以使用 curl 进行`POST`请求来检查输出：

```go
curl -XPOST -d'{"key":"111023043350789514532147", "text": "I am A Message"}' localhost:8080/encrypt

{"message":"8/+JCfTb+ibIjzQtmCo=","error":""}
```

我们向微服务提供了密钥和消息。它返回了密文消息。这意味着服务加密了文本。通过传递相同的密钥以及密文消息，再发出一个请求来解密消息：

```go
curl -XPOST -d'{"key":"111023043350789514532147", "message": "8/+JCfTb+ibIjzQtmCo="}' localhost:8080/decrypt

{"text":"I am A Message","error":""}
```

它返回了我们最初传递的确切消息。万岁！我们编写了我们的第一个用于加密/解密消息的微服务。除了处理正常的 HTTP 请求外，Go Kit 还提供了许多其他有用的构造，例如用于中间件的：

+   传输日志

+   应用程序日志

+   应用程序仪表化

+   服务发现

在接下来的章节中，我们将讨论前面列表中的一些重要构造。

# 为您的微服务添加日志记录

在本节中，让我们学习如何向我们的 Go Kit 微服务添加传输级别日志和应用程序级别日志。我们使用上面的示例，但稍作修改。让我们称我们的新项目为`encryptServiceWithLogging`。在本书的 GitHub 项目中，您将找到这个目录。在本书中，我们多次讨论了中间件的概念。作为复习，中间件是在到达相应的请求处理程序之前/之后篡改请求/响应的函数。Go Kit 允许我们创建记录中间件，将其附加到我们的服务上。该中间件将具有记录逻辑。在这个示例中，我们尝试记录到 Stderr（控制台）。如下所示，将一个名为`middleware.go`的新文件添加到`helpers`目录中：

```go
package helpers
import (
    "context"
    "time"
    log "github.com/go-kit/kit/log"
)
// LoggingMiddleware wraps the logs for incoming requests
type LoggingMiddleware struct {
    Logger log.Logger
    Next EncryptService
}
// Encrypt logs the encyption requests
func (mw LoggingMiddleware) Encrypt(ctx context.Context, key string, text string) (output string, err error) {
    defer func(begin time.Time) {
        _ = mw.Logger.Log(
            "method", "encrypt",
            "key", key,
            "text", text,
            "output", output,
            "err", err,
            "took", time.Since(begin),
        )
    }(time.Now())
    output, err = mw.Next.Encrypt(ctx, key, text)
    return
}
// Decrypt logs the encyption requests
func (mw LoggingMiddleware) Decrypt(ctx context.Context, key string,
text string) (output string, err error) {
    defer func(begin time.Time) {
        _ = mw.Logger.Log(
            "method", "decrypt",
            "key", key,
            "message", text,
            "output", output,
            "err", err,
            "took", time.Since(begin),
        )
    }(time.Now())
    output, err = mw.Next.Decrypt(ctx, key, text)
    return
}
```

我们需要创建一个具有记录器和我们的服务实例的结构。然后，在该结构上定义一些方法，这些方法的名称与服务方法相似（在本例中，它们是`encrypt`和`decrypt`）。**Logger**是 Go Kit 的记录器，具有`Log`函数。这个`Log`函数接受一些参数。它接受一对参数。第一个和第二个是一组。第三个和第四个是另一组。请参考以下代码片段：

```go
mw.Logger.Log(
      "method", "decrypt",
      "key", key,
      "message", text,
      "output", output,
      "err", err,
      "took", time.Since(begin),
    )
```

我们需要维护日志应该打印的顺序。在记录我们的请求详细信息后，我们确保允许请求通过这个函数继续到下一个中间件/处理程序。`Next`是`EncryptService`类型，它是我们的实际实现：

```go
mw.Next.(Encrypt/Decrypt)
```

对于加密函数，中间件记录加密请求并将其传递给服务的实现。为了将创建的中间件挂接到我们的服务中，修改`main.go`如下：

```go
package main
import (
    "log"
    "net/http"
    "os"
    kitlog "github.com/go-kit/kit/log"
    httptransport "github.com/go-kit/kit/transport/http"
    "github.com/narenaryan/encryptService/helpers"
)
func main() {
    logger := kitlog.NewLogfmtLogger(os.Stderr)
    var svc helpers.EncryptService
    svc = helpers.EncryptServiceInstance{}
    svc = helpers.LoggingMiddleware{Logger: logger, Next: svc}
    encryptHandler := httptransport.NewServer(helpers.MakeEncryptEndpoint(svc),
        helpers.DecodeEncryptRequest,
        helpers.EncodeResponse)
    decryptHandler := httptransport.NewServer(helpers.MakeDecryptEndpoint(svc),
        helpers.DecodeDecryptRequest,
        helpers.EncodeResponse)
    http.Handle("/encrypt", encryptHandler)
    http.Handle("/decrypt", decryptHandler)
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

我们从 Go Kit 中导入日志作为`kitlog`。我们使用`NewLogfmtLogger(os.Stderr)`创建了一个新的记录器。这将日志附加到控制台。现在，将这个记录器和服务传递给`LoggingMiddleware`。它返回可以传递给 HTTP 服务器的服务。现在，让我们从`encryptServiceWithLogging`运行程序，看看控制台上的输出日志：

```go
go run main.go
```

它启动我们的微服务。现在，从`CURL`命令发出客户端请求：

```go
curl -XPOST -d'{"key":"111023043350789514532147", "text": "I am A Message"}' localhost:8080/encrypt

curl -XPOST -d'{"key":"111023043350789514532147", "message": "8/+JCfTb+ibIjzQtmCo="}' localhost:8080/decrypt
{"text":"I am A Message","error":""}
```

这在服务器控制台上记录以下消息：

```go
method=encrypt key=111023043350789514532147 text="I am A Message" output="8/+JCfTb+ibIjzQtmCo=" err=null took=11.32µs

method=decrypt key=111023043350789514532147 message="8/+JCfTb+ibIjzQtmCo=" output="I am A Message" err=null took=6.773µs
```

这是为了记录每个应用程序/服务的消息。系统级别的日志记录也是可用的，并且可以从 Go Kit 的文档中获取。

# 为您的微服务添加仪表

对于任何微服务，除了日志记录，仪表是至关重要的。Go Kit 的`metrics`包记录有关服务运行时行为的统计信息：计算已处理作业的数量，记录请求完成后的持续时间等。这也是一个篡改 HTTP 请求并收集指标的中间件。要定义一个中间件，只需添加一个与日志中间件类似的结构。除非我们监视，否则指标是无用的。**Prometheus**是一个可以收集延迟、给定服务的请求数等指标的指标监控工具。Prometheus 从 Go Kit 生成的指标中抓取数据。

您可以从这个网站下载最新稳定版本的 Prometheus。在使用 Prometheus 之前，请确保安装 Go Kit 需要的这些包：

```go
go get github.com/prometheus/client_golang/prometheus
go get github.com/prometheus/client_golang/prometheus/promhttp
```

安装了这些包之后，尝试将最后讨论的日志服务项目复制到一个名为`encryptServiceWithInstrumentation`的目录中。该目录与原来完全相同，只是我们在`helpers`目录中添加了一个名为`instrumentation.go`的文件，并修改了我们的`main.go`以导入仪表中间件。项目结构如下：

```go
├── helpers
│   ├── endpoints.go
│   ├── implementations.go
│   ├── instrumentation.go
│   ├── jsonutils.go
│   ├── middleware.go
│   └── models.go
└── main.go
```

仪表可以测量每个服务的请求数和延迟，以参数如`Counter`和`Histogram`为单位。我们尝试创建一个具有这两个测量（请求数、延迟）并实现给定服务的函数的中间件。在这些中间件函数中，我们尝试调用 Prometheus 客户端 API 来增加请求数、记录延迟等。核心的 Prometheus 客户端库尝试以这种方式增加请求计数：

```go
// Prometheus
c := prometheus.NewCounter(stdprometheus.CounterOpts{
    Name: "request_duration",
    ...
}, []string{"method", "status_code"})
c.With("method", "MyMethod", "status_code", strconv.Itoa(code)).Add(1)
```

`NewCounter`创建一个新的计数器结构，需要计数器选项。这些选项是操作的名称和其他细节。然后，我们需要在该结构上调用`With`函数，传入方法、方法名称和错误代码。这个特定的签名是 Prometheus 要求生成计数器指标的。最后，我们使用`Add(1)`函数调用增加计数器。

新添加的`instrumentation.go`文件的实现如下：

```go
package helpers
import (
    "context"
    "fmt"
    "time"
    "github.com/go-kit/kit/metrics"
)
// InstrumentingMiddleware is a struct representing middleware
type InstrumentingMiddleware struct {
    RequestCount metrics.Counter
    RequestLatency metrics.Histogram
    Next EncryptService
}
func (mw InstrumentingMiddleware) Encrypt(ctx context.Context, key string, text string) (output string, err error) {
    defer func(begin time.Time) {
        lvs := []string{"method", "encrypt", "error", fmt.Sprint(err != nil)}
        mw.RequestCount.With(lvs...).Add(1)
        mw.RequestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
    }(time.Now())
    output, err = mw.Next.Encrypt(ctx, key, text)
    return
}
func (mw InstrumentingMiddleware) Decrypt(ctx context.Context, key string, text string) (output string, err error) {
    defer func(begin time.Time) {
        lvs := []string{"method", "decrypt", "error", "false"}
        mw.RequestCount.With(lvs...).Add(1)
        mw.RequestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
    }(time.Now())
    output, err = mw.Next.Decrypt(ctx, key, text)
    return
}
```

这与日志中间件代码完全相同。我们创建了一个带有几个字段的结构体。我们附加了加密和解密服务的函数。在中间件函数内部，我们正在寻找两个指标；一个是计数，另一个是延迟。当一个请求通过这个中间件时：

```go
mw.RequestCount.With(lvs...).Add(1)
```

这一行增加了计数器。现在看看另一行：

```go
mw.RequestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
```

这一行通过计算请求到达时间和最终时间之间的差异来观察延迟（由于使用了 defer 关键字，这将在请求和响应周期完成后执行）。简而言之，前面的中间件将请求计数和延迟记录到 Prometheus 客户端提供的指标中。现在让我们修改我们的`main.go`文件，使其看起来像这样：

```go
package main
import (
    "log"
    "net/http"
    "os"
    stdprometheus "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    kitlog "github.com/go-kit/kit/log"
    httptransport "github.com/go-kit/kit/transport/http"
    "github.com/narenaryan/encryptService/helpers"
    kitprometheus "github.com/go-kit/kit/metrics/prometheus"
)
func main() {
    logger := kitlog.NewLogfmtLogger(os.Stderr)
    fieldKeys := []string{"method", "error"}
    requestCount := kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
        Namespace: "encryption",
        Subsystem: "my_service",
        Name: "request_count",
        Help: "Number of requests received.",
    }, fieldKeys)
    requestLatency := kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
        Namespace: "encryption",
        Subsystem: "my_service",
        Name: "request_latency_microseconds",
        Help: "Total duration of requests in microseconds.",
    }, fieldKeys)
    var svc helpers.EncryptService
    svc = helpers.EncryptServiceInstance{}
    svc = helpers.LoggingMiddleware{Logger: logger, Next: svc}
    svc = helpers.InstrumentingMiddleware{RequestCount: requestCount, RequestLatency: requestLatency, Next: svc}
    encryptHandler := httptransport.NewServer(helpers.MakeEncryptEndpoint(svc),
        helpers.DecodeEncryptRequest,
        helpers.EncodeResponse)
    decryptHandler := httptransport.NewServer(helpers.MakeDecryptEndpoint(svc),
        helpers.DecodeDecryptRequest,
        helpers.EncodeResponse)
    http.Handle("/encrypt", encryptHandler)
    http.Handle("/decrypt", decryptHandler)
    http.Handle("/metrics", promhttp.Handler())
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

我们导入了 kit Prometheus 包来初始化指标模板，以及客户端 Prometheus 包来提供选项结构。我们创建了`requestCount`和`requestLatency`类型的指标结构，并将它们传递给我们从`helpers`导入的`InstrumentingMiddleware`。如果你看到这一行：

```go
 requestCount := kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
    Namespace: "encryption",
    Subsystem: "my_service",
    Name:      "request_count",
    Help:      "Number of requests received.",
  }, fieldKeys)
```

这就是我们如何创建一个模板，与`helpers.go`中的`InstrumentingMiddleware`结构中的`RequestCount`匹配。我们传递的选项将附加到一个字符串中，同时生成指标：

```go
encryption_my_service_request_count
```

这是一个唯一可识别的服务仪器，告诉我们，“这是一个用于名为 Encryption 的我的微服务的请求计数操作”。我们还在`main.go`的服务器部分的代码中添加了一行有趣的内容：

```go
"github.com/prometheus/client_golang/prometheus/promhttp"
...
http.Handle("/metrics", promhttp.Handler())
```

这实际上创建了一个端点，可以生成一个包含收集到的指标的页面。Prometheus 可以解析此页面以存储、绘制和显示指标。如果我们运行程序并对加密服务进行 5 次 HTTP 请求，并对解密服务进行 10 次 HTTP 请求，指标页面将记录请求的计数和它们的延迟：

```go
go run main.go # This starts the server
```

从另一个 bash shell（在 Linux 中）循环对加密服务进行 5 次 CURL 请求：

```go
for i in 1 2 3 4 5; do curl -XPOST -d'{"key":"111023043350789514532147", "text": "I am A Message"}' localhost:8080/encrypt; done

{"message":"8/+JCfTb+ibIjzQtmCo=","error":""}
{"message":"8/+JCfTb+ibIjzQtmCo=","error":""}
{"message":"8/+JCfTb+ibIjzQtmCo=","error":""}
{"message":"8/+JCfTb+ibIjzQtmCo=","error":""}
{"message":"8/+JCfTb+ibIjzQtmCo=","error":""}
```

对解密服务进行 10 次 CURL 请求（输出已隐藏以保持简洁）：

```go
for i in 1 2 3 4 5 6 7 8 9 10; do curl -XPOST -d'{"key":"111023043350789514532147", "message": "8/+JCfTb+ibIjzQtmCo="}' localhost:8080/decrypt; done
```

现在，访问 URL`http://localhost:8080/metrics`，您将看到 Prometheus Go 客户端为我们生成的页面。页面的内容将包含以下信息：

```go
# HELP encryption_my_service_request_count Number of requests received.
# TYPE encryption_my_service_request_count counter
encryption_my_service_request_count{error="false",method="decrypt"} 10
encryption_my_service_request_count{error="false",method="encrypt"} 5
# HELP encryption_my_service_request_latency_microseconds Total duration of requests in microseconds.
# TYPE encryption_my_service_request_latency_microseconds summary
encryption_my_service_request_latency_microseconds{error="false",method="decrypt",quantile="0.5"} 5.4538e-05
encryption_my_service_request_latency_microseconds{error="false",method="decrypt",quantile="0.9"} 7.6279e-05
encryption_my_service_request_latency_microseconds{error="false",method="decrypt",quantile="0.99"} 8.097e-05
encryption_my_service_request_latency_microseconds_sum{error="false",method="decrypt"} 0.000603101
encryption_my_service_request_latency_microseconds_count{error="false",method="decrypt"} 10
encryption_my_service_request_latency_microseconds{error="false",method="encrypt",quantile="0.5"} 5.02e-05
encryption_my_service_request_latency_microseconds{error="false",method="encrypt",quantile="0.9"} 8.8164e-05
encryption_my_service_request_latency_microseconds{error="false",method="encrypt",quantile="0.99"} 8.8164e-05
encryption_my_service_request_latency_microseconds_sum{error="false",method="encrypt"} 0.000284823
encryption_my_service_request_latency_microseconds_count{error="false",method="encrypt"} 5
```

如您所见，有两种类型的指标：

+   `encryption_myservice_request_count`

+   `encryption_myservice_request_latency_microseconds`

如果您看到对`encrypt`方法和`decrypt`方法的请求数，它们与我们发出的 CURL 请求相匹配。

`encryption_myservice`指标类型对加密和解密微服务都有计数和延迟指标。方法参数告诉我们这些指标是从哪个微服务中提取的。

这些类型的指标为我们提供了关键的见解，例如哪个微服务被大量使用以及延迟趋势随时间的变化等。但是，要看到数据的实际情况，您需要安装 Prometheus 服务器，并为 Prometheus 编写一个配置文件，以从 Go Kit 服务中抓取指标。有关在 Prometheus 中创建目标（生成指标页面的主机）的更多信息，请访问[`prometheus.io/docs/operating/configuration/`](https://prometheus.io/docs/operating/configuration/)。

我们还可以将来自 Prometheus 的数据传递给 Grafana，这是一个用于漂亮实时图表的图形化和监控工具。Go Kit 还提供了许多其他功能，例如服务发现。只有在系统松散耦合、监控和优化的情况下，微服务才能进行扩展。

# 总结

在本章中，我们从微服务的定义开始。单体应用程序和微服务之间的主要区别在于紧密耦合的架构是如何被分解为松散耦合的架构。微服务之间使用基于 REST 的 JSON 或基于 RPC 的协议缓冲区进行通信。使用微服务，我们可以将业务逻辑分解为多个部分。每个服务都很好地完成了一项工作。这种方法也带来了一个缺点。监控和管理微服务是痛苦的。Go 提供了一个名为 Go Kit 的精彩工具包。这是一个微服务框架，使用它我们可以为微服务生成样板代码。

我们需要在 Go Kit 中定义一些东西。我们需要为 Go-Kit 服务创建实现、端点和模型。端点接收请求并返回响应。实现具有服务的实际业务逻辑。模型是解码和编码请求和响应对象的一种好方法。Go Kit 提供了各种中间件，用于执行重要任务，如日志记录、仪表（指标）和服务发现。

小型组织可以从单体应用开始，但在规模更大的组织中，拥有庞大团队的微服务更合适。在下一章中，我们将看到如何使用 Nginx 部署我们的 Go 服务。服务需要部署才能暴露给外部世界。
