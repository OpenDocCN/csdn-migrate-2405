# 精通 HTML5 表单（二）

> 原文：[`zh.annas-archive.org/md5/835835C6B2E78084A088423A2DB0B9BD`](https://zh.annas-archive.org/md5/835835C6B2E78084A088423A2DB0B9BD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：数据库连接

在前几章中，我们学习了表单，比如表单是什么，我们如何验证它们，以及我们如何改进它们的外观和感觉，但是表单有什么用，直到它们存储信息？在本章中，我们将学习如何使用 PHP 和 MySQL 将用户输入的数据存储到数据库中。

在本章中，我们将涵盖以下主题：

+   PHP 是什么

+   MySQL 是什么

+   欺骗和伪造表单

+   将表单链接到数据库

# PHP

PHP 也被用作通用编程语言，基本上是一种服务器端脚本语言，专门设计用于网页开发。通过 PHP 处理器模块，PHP 代码由 Web 服务器解释，生成网页。

与调用外部文件来处理数据不同，PHP 命令可以直接嵌入到 HTML 代码中。它可以用于独立的图形应用程序，并且可以部署在几乎所有操作系统和平台的大多数 Web 服务器上。

在 PHP 中，所有变量是区分大小写的，但用户定义的函数、类和关键字（如 if、else、while、echo 等）是不区分大小写的。

在服务器上，首先执行 PHP 脚本，然后将 HTML 结果发送回浏览器。

通过 HTML 表单，PHP 轻松操纵用户提交的信息的能力是其受欢迎的原因之一。

要使用 PHP，我们必须执行以下步骤：

1.  获取支持 PHP 和 MySQL 的 Web 服务器。

1.  在本章中，我们将使用 WAMP（用于 Windows 操作系统）软件，它会自动安装 Apache 服务器，配置 MySQL 数据库，并安装 PHP 支持应用程序，以便进行简单的维护和配置。

1.  然后，安装 PHP 和 MySQL。

## 语法

PHP 文件的默认扩展名是`.php`，PHP 脚本以`<?php`开头，以`?>`结尾。

```html
<?php
  // PHP script
?>
```

包含一些 PHP 脚本代码，PHP 文件通常包含 HTML 标记。分号用于终止 PHP 语句，我们不需要使用分号来终止 PHP 块的最后一行。

## 表单处理

`$_GET`和`$_POST` PHP 超全局变量（在所有范围中始终可用的内置变量）用于收集用户单击**提交**按钮时提交的表单数据。

### GET 方法

在`GET`方法中，表单中的信息对所有人都是可见的；例如，所有变量名和值都显示在 URL 中。此外，使用`GET`方法对可发送的信息量有限制，这个限制因浏览器而异。

当我们需要将网页加入书签时，这种方法就很有用，因为变量会显示在 URL 中。

我们不能使用`GET`方法发送敏感数据，比如密码或信用卡信息。

以下代码是一个简单的 HTML 页面：

```html
<html>
<body>
<form action="example.php" method="get">
  Name: <input type="text" name="name"><br>
  Age: <input type="text" name="age"><br>
  <input type="submit">
</form>
</body>
</html>
```

当用户填写上述表单并单击**提交**按钮时，表单数据将被发送到名为`example.php`的 PHP 文件进行处理。表单数据将使用`method="get"`发送。

`example.php`文件将类似于以下代码：

```html
<html>
<body>
  Hello! <?php echo $_GET["name"]; ?>!<br>
  You are <?php echo $_GET["age"]; ?> years old.
</body>
</html>
```

### POST 方法

在`POST`方法中，表单中的信息对所有人都是不可见的；例如，在 HTTP 请求的正文中，所有变量名和值都被嵌入。此外，使用`POST`方法对可发送的信息量没有限制。

当我们需要将网页加入书签时，这种方法就不太有用，因为变量不会显示在 URL 中。

此外，在将文件上传到服务器时，`POST`方法还支持高级功能，比如支持多部分二进制输入。

我们可以使用`POST`方法发送敏感数据，比如密码或信用卡信息。

以下代码是一个简单的 HTML 页面：

```html
<html>
<body>
<form action="example.php" method="post">
  Name: <input type="text" name="name"><br>
  Age: <input type="text" name="age"><br>
  <input type="submit">
</form>
</body>
</html>
```

当用户填写上述表单并单击提交按钮时，表单数据将被发送到名为`example.php`的 PHP 文件进行处理。表单数据将使用`method="post"`发送。

`example.php`文件如下所示：

```html
<html>
<body>
  Hello! <?php echo $_POST["name"]; ?>!<br>
  You are <?php echo $_POST["age"]; ?> years old.
</body>
</html>
```

`GET`和`POST`方法都分别填充`$_GET`和`$_POST`数组。由于这些是超全局变量，无论作用域如何，它们始终是可访问的，并且可以从任何类、函数或文件中访问，而无需进行任何特殊操作。这些数组描述如下：

+   `$_GET`: 这是一个变量数组，通过 URL 参数传递给当前脚本

+   `$_POST`: 这是一个变量数组，通过 HTTP POST 方法传递给当前脚本

### 注意

`POST`是发送表单数据的最常用方式，因为有安全方面的考虑。

## 过滤方法

`filter`方法通过验证或净化输入字段来过滤数据。当数据源包含未知数据时，如自定义输入或用户提供的输入时，它起着非常重要的作用并且非常有用。

例如，通过 HTML 表单输入的数据，如调查表单和新注册。

有两种主要类型的过滤：

+   验证

+   净化

输入数据的过滤是安全问题的主要关注点之一。外部数据包括来自用户、cookies、web 服务数据或数据库查询结果的输入数据。由于所有的 web 表单和应用程序都依赖于外部输入，因此通过过滤输入数据，我们可以确保我们的应用程序从用户那里得到有效的输入。

以下的`filter`函数可以用来过滤一个变量：

+   `filter_var_array()`: 获取多个变量，并使用相同或不同的过滤器对它们进行过滤

+   `filter_id()`: 返回指定过滤器的 ID 号

+   `filter_var()`: 使用指定的过滤器过滤单个变量

+   `filter_input()`: 通过名称获取一个输入变量，并可选择地对其进行过滤

+   `filter_has_var()`: 检查指定输入类型的变量是否存在

+   `filter_input_array()`: 获取多个输入变量，并使用相同或不同的过滤器对它们进行过滤

+   `filter_list()`: 返回所有支持的过滤器的列表

在下面的例子中，我们使用`filter_var()`函数验证一个整数：

```html
<?php
  $int = 'g819';
  if(!filter_var($int, FILTER_VALIDATE_INT))
  {
    echo("Entered integer is invalid");
  }
  else
  {
    echo("Entered integer is valid");
  }
?>
```

在上面的代码中，使用`FILTER_VALIDATE_INT`过滤器来过滤变量。由于整数无效，上面代码的输出将是**整数无效**，但如果我们尝试使用一个整数变量，比如 819，输出将是**整数有效**。

### 验证用户输入数据

`filter`方法用于验证用户输入数据。成功时返回值为**true**，失败时返回值为**false**。

严格的格式规则用于验证 IP 地址、URL、变量或电子邮件类型。

现在，在下面的例子中，我们将验证表单的一个输入字段。在开始之前，我们将首先检查所需输入数据的存在。然后，使用`filter_var()`函数，我们将验证输入数据。

```html
  <?php
  if(!filter_has_var($_GET"url"l))
  {
    echo("Input type is not present");
  }
  else
  {
  if (!filter_var($_GET["url"l, FILTER_VALIDATE_URL))
  {
    echo "Entered URL is invalid";
  }
  else
  {
    echo "Entered URL is valid";
  }
  }
?>
```

在上面的例子中，使用`GET`方法发送了一个输入`url`。它首先检查`GET`类型的输入`email`变量是否存在。当输入变量存在时，它验证 URL。

### 净化用户输入数据

净化的主要目的是允许或不允许字符串中的指定字符。它始终返回一个字符串值。它不遵循任何数据格式规则。

在下面的例子中，我们将验证表单的一个输入字段。在开始之前，我们将首先检查所需输入数据的存在。然后，使用`filter_var()`函数，我们将净化输入数据。

```html
<?php
  if(!filter_has_var(($_POST['string'l))
  {
    echo("Input type is not present");
  }
  else
  {
    $string = filter_var($_POST['string'l, FILTER_SANITIZE_STRING);
  }
?>
```

在上面的例子中，使用`POST`方法发送了一个输入`string`。它首先检查`POST`类型的输入`string`变量是否存在。当输入变量存在时，它验证字符串。

当用户输入一个坏的输入字符串，比如`MasteringååHTML5ååForms`，经过净化后，同样的字符串会变成`MasteringHTML5Form`。

### FILTER_CALLBACK 过滤器

使用`FILTER_CALLBACK`过滤器，可以调用用户定义的函数并将其用作过滤器。使用这个方法可以完全控制数据过滤。

与指定选项类似，指定要用于过滤的函数。

我们可以使用现有的 PHP 函数，也可以创建我们自己的用户定义函数。

在下面的例子中，我们将创建一个用户定义的函数，用于将所有的`*`符号替换为空格：

```html
<?php
  function towhitespace($string)
  {
    return str_replace("*", " ", $string);
  }
  $string = "Converting*To*Whitespace*Characters";
  echo filter_var($string, FILTER_CALLBACK,       
  array("options"=>"towhitespace"));
?>
```

上述代码的输出是：

![FILTER_CALLBACK 过滤器

在上面的例子中，字符串中的任何位置，无论多少次，所有的`*`符号都被替换为空格字符。

在上面的代码中，我们首先创建了一个函数，用于将所有的`*`符号替换为空格。然后，调用`filter_var()`函数，使用`FILTER_CALLBACK`过滤器和包含函数的数组。

### 过滤多个输入

如今，几乎每个网络表单都包含多个输入字段，比如注册页面。当一个表单包含多个输入字段时，为了验证或清理，对每个输入字段调用`filter_var()`或`filter_input()`函数不仅增加了代码的大小，还增加了复杂性。解决这个问题的方法是使用`filter_var_array()`或`filter_input_array()`函数。

在下面的例子中，我们将验证表单的两个输入字段。我们将使用`filter_var_array()`函数来过滤这些变量，并使用`POST`方法。输入是年龄和电子邮件地址。

```html
<?php
  $filters = array
  (
    "age" => array
    (
      "filter"=>FILTER_VALIDATE_INT,
      "options"=>array
        (
        "min_range"=>1,
        "max_range"=>99
      )
    ),
    "email"=> FILTER_VALIDATE_EMAIL
  );
  $output = filter_var_array($_POST, $filters);

  if (!$output["age"])
  {
    echo("Entered age must be between 1 and 99");
  }
  elseif(!$output["email"])
  {
    echo("Entered email is invalid");
  }
  else
  {
    echo("Entered inputs are valid");
  }
?>
```

在上面的例子中，输入字段是使用`POST`方法发送的。在这里，设置了一个包含输入变量名称（如`age`和`email`）的数组。我们还对这些输入变量使用了过滤器。

首先，我们使用`filter_var_array()`函数和我们设置的数组以`POST`方法输入变量。然后，我们在`$output`变量中验证了`age`和`email`变量的无效输入。

`filter_input_array()`或`filter_var_array()`函数的第二个参数可以是单个过滤器 ID 或数组。当参数是单个过滤器 ID 时，输入数组中的所有值都将被指定的过滤器过滤。

如果参数是一个数组，则必须遵循以下规则：

+   数组值必须是过滤器 ID 或指定标志、过滤器和选项的数组

+   必须有一个包含输入变量的关联数组，如`email`或`age`输入变量

# MySQL

数据库是一个结构化和组织良好的数据集合。每个前端应用程序都需要一个兼容的数据库，作为应用程序的后端。它是为了有效的存储和检索数据而组织的，而不是根据数据的性质或集合或检索方法。将数据库添加到网站提供了动态内容、灵活性和可管理性，以及各种用户交互，如果没有这个，将很难实现。

为了处理相应的数据，数据库管理系统应用程序与用户、其他应用程序和数据库本身进行交互。这个应用程序将作为管理所有数据的后端。有许多著名的数据库管理系统，包括 Microsoft SQL Server、Oracle、Sybase、MySQL、PostgreSQL、SQLite、Microsoft Access、dBASE、FoxPro、IBM 的 DB2、Libre Office Base 和 FileMaker Pro。

## PHP 的 MySQL

在使用 PHP 时，MySQL 是最兼容的数据库系统。这个数据库是几乎每个开源 PHP 应用程序的重要组成部分。

MySQL 是以*My*和*Michael Widenius*的女儿*My*的名字命名的，后者是 MySQL 的联合创始人。它由 Oracle Corporation 开发、分发和支持。这是一个免费的、易于下载的开源数据库管理系统。它非常快速、可靠，并支持标准的**结构化查询语言**（**SQL**）。

SQL 用于从称为数据库的存储区域访问和修改数据或信息。它以快速处理、可靠性和易用性和灵活性而闻名。由 IBM 开发，它是一种类似英语的语言，它以记录组的形式处理数据，而不是一次处理一条记录。以下是 SQL 的一些功能：

+   存储数据

+   修改数据

+   检索数据

+   删除数据

+   创建表和其他数据库对象

MySQL 中的数据存储在表中。表是相关数据的集合，所有数据都按列和行排列。在存储信息分类时，数据库非常有用。

## MySQL-PHP 连接

在使用任何数据库时，首先出现的问题是“我们如何从数据库中访问数据？”要访问任何数据库，我们首先必须连接到该数据库。

### 打开到 MySQL 服务器的连接

要建立连接，我们首先必须打开到 MySQL 服务器的连接。在 PHP 中，可以使用`mysqli_connect()`函数来实现。这个函数返回一个资源，这个资源是指向数据库连接的指针。它也被称为数据库句柄。

`mysqli_connect()`函数的语法是：

`mysqli_connect(server,username,password,dbname);`

它支持以下值：

+   `服务器`：它可以是 IP 地址或主机名。

+   `密码`：这是用于登录的密码，是可选的。

+   `用户名`：这是 MySQL 用户名，是可选的。此外，MySQL 可以有多个用户。

+   `dbname`：这是在执行查询时要使用的默认数据库，是可选的。

例如：

```html
<?php
  $username = "your_name";
  $password = "your_password";
  $hostname = "localhost";
  $dbname = "your_db"; 
  $dbconnect = mysqli_connect($hostname, $username, $password,$dbname)
  //Connects to the database
?>
```

### 关闭连接

PHP 将在脚本结束时自动关闭连接。但是如果我们想在结束之前关闭连接，我们可以使用`mysqli_close()`函数。

例如：

```html
<?php
  mysqli_close($dbhandle);
  //Closes the connection
?>
```

## 创建或选择一个数据库

一旦我们成功创建了与数据库的连接，下一步就是创建或选择将与我们的应用程序一起使用的任何数据库。

### 创建一个数据库

要创建数据库，我们使用`CREATE DATABASE`语句在 MySQL 中创建数据库表。

例如：

```html
<?php
  $createDB="CREATE DATABASE personal_info";
  //Creates a database with name as "personal_info"

  mysqli_query($createDB)
  //Executes the create database query
?>
```

### 选择一个数据库

要选择已经存在的数据库，我们使用`MYSQLI_SELECT_DB`语句在 MySQL 中选择数据库。

例如：

```html
<?php
  $dbconnect = mysqli_connect("host name", "username", "password", "dbname")
  //Connects to the database

  $dbselected = mysqli_select_db("personal_info",$dbconnect)
  //Selects the database to work with
?>
```

## 创建一个表

一旦我们创建或选择了一个数据库，下一步就是在数据库内创建一个表。

`CREATE TABLE`用于在 MySQL 中创建表。

例如：

```html
<?php
  $createTB="CREATE TABLE TbDummy(
    Firstname VARCHAR(255) NOT NULL,
    Lastname VARCHAR(255) NOT NULL);
  //Creating a table in MySQL with name as "TbDummy"

  mysqli_query($createTB)
  //Executing the create table query
?>
```

## 主键

为了增加表的灵活性和可靠性，必须存在主键字段。

一个表由许多记录组成，为了唯一标识每个记录，使用主键。每个记录必须有一个唯一的值，这个唯一的值将作为主键。此外，主键值不能为 null，因为为了定位记录，数据库引擎需要一个值。主键是列的组合，唯一标识记录。

例如：

让我们看一下包含组织中每个员工记录的`Employee`表：

| 员工 ID | 名字 | 职位 | 地点 |
| --- | --- | --- | --- |
| 101 | Gaurav Gupta | 程序分析师 | 浦那 |
| 102 | Gaurav Gupta | 程序分析师 | 浦那 |

该表包含两条记录，名称、职位和地点相同。员工的唯一员工 ID 号将是`Employee`表中主键的一个很好的选择。因此，我们将`Employee ID`列设置为此表的主键。

以下片段是一个示例代码，用于将列定义为主键来创建表：

```html
<?php
  $createDB="CREATE DATABASE DBEmployee";
  //Creates a database with name as "DBEmployee"

  mysqli_query($createDB)
  //Executes the create database query

  $createTB="CREATE TABLE Employee(
    Employee_ID INT NOT NULL,
    Name VARCHAR(255),
    Designation VARCHAR(255),
    Location VARCHAR(255),
    PRIMARY KEY(Employee_ID));
  //Creating a table with name as "Employee" and defining a column "Employee_ID" as a primary key

  mysqli_query($createTB)
  //Executing the create table query
?>
```

# 欺骗和伪造表单

如今，每个网站都有一个 HTML 表单供用户完成注册，以便用户可以访问该特定网站。由于互联网犯罪不断增加，我们如何验证完成表单的用户是通过您的网站完成的？因此，有必要知道没有人伪造我们的表单提交。

在我们看到如何保护我们的表单免受欺骗之前，让我们看看如何欺骗一个表单。通过以下两种方式，我们可以改变表单提交：

+   伪造 HTTP 请求

+   欺骗提交

## 伪造 HTTP 请求

我们可以使用 telnet 访问端口 80 来输入我们自己的请求。因此，通过这种方法，我们可以克服为每种类型的攻击生成或修改表单的麻烦，因为它可能只是使用原始 HTTP 来更改表单数据。由于这个原因，我们可以说这种方法比其他方法更复杂。

伪造 HTTP 请求是一种更高级的自动化攻击形式。

在以下示例中，我们要求登录到示例论坛：

```html
  POST /index.php?act=Login&CODE=01&CookieDate=1 HTTP/1.1
  Host: forums.example.com
  Connection: close
  Referrer: http://forums.example.com/
  Cookie: session_id=7819
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 44

  UserName=myname&PassWord=mypass&CookieDate=1
```

要使用前面提到的请求，您需要更改一些项目，包括：

+   将`myname`更改为我们的用户名

+   将`mypass`更改为我们的密码

+   将`session_id`更改为必要的值

+   将`Content-Length`更改为`POST`数据的新长度

## 欺骗提交

假设以下 HTML 表单位于`http://sampledomain.com/form.php`：

```html
<form action="/example.php" method="post">
  <select name="browser">
  <option value="chrome">Chrome</option>
  <option value="firefox">Firefox</option>
  </select>
  <input type="submit">
</form>
```

我们假设我们将能够引用`$_POST['browser']`，并且它将具有两个选项`chrome`或`firefox`中的一个值。现在，如果用户选择`chrome`，请求将类似于以下内容：

```html
  POST /example.php HTTP/1.1
  Host: sampledomain.com
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 8

  browser=chrome
```

用户可以将表单从浏览器保存到本地机器（台式机或笔记本电脑），然后打开保存的 HTML 文件并对其进行以下更改：

+   修改`action`标签，使其现在具有表单的完整 URL

+   在表单中删除`select`标签，并用`textarea`标签替换它

现在我们的表单将类似于以下代码：

```html
<form action=http://sampledomain.com/example.php method="post">
  <textarea name="myvar"></textarea>
  <input type="submit">
</form>
```

用户现在可以通过对表单进行这些简单更改来提交任何值`$_POST['myvar']`。此外，没有办法阻止操纵我们的表单的用户提交意外的表单变量或任何可以通过 HTML 表单实现的内容。

有解决方案可用于防止表单欺骗。从严格的协议角度来看，我们唯一知道的是 HTTP 请求和响应来回传递。没有明确而简洁的方法来确定表单提交是否被欺骗。

通过以下两种方式，我们可以防止表单欺骗，因为它们减少了通过遵循处理数据和表单的一般架构提交的不需要的值的可能性：

+   共享秘密

+   设定期望

## 共享秘密

共享秘密也被称为一次性令牌或哈希。我们创建一个只有服务器和用户知道的秘密。在这方面，实现方式各不相同，但它们共享的特征是对用户透明且难以利用。

其中一种实现方法是，在用户会话中，我们将把秘密存储如下代码所示：

```html
  $secret = md5(uniqid(rand(), true));
  $_SESSION['secret'] = $secret;
```

现在，它可以作为表单中的隐藏表单变量使用，如下所示：

```html
  <input type="hidden" name="secret" value="<? echo $secret; ?>" />
```

每次显示表单时，我们都会重新生成这个秘密，以便用户始终具有当前和正确的秘密值。这有助于防止**CSRF**（跨站点请求伪造）。

打开的页面可以通过比较表单发送的秘密和存储在相应会话变量中的秘密来检查这一点。

进一步进行，我们甚至可以通过限制超时窗口而不是依赖会话超时来增强此方法的安全性，后者可能对您的需求来说太大。

## 设定期望

具有最佳架构的应用程序总是假设：

+   **我们知道我们正在发送什么**：这意味着我们应该跟踪我们在网站上上传的表单，并制定接受表单提交的政策，例如超时、每个用户 ID 的多个表单、多次提交以及不接受我们不期望的表单。这可以使用令牌来实现。

+   **我们知道返回值将是什么**：这很重要，因为`<select>`字段包含某些值，我们可能会得到完全不同的东西，比如 PHP 代码、SQL 或其他内容：

+   要接受表单为有效，我们必须知道需要返回的字段

+   我们必须严格限制我们接受的输入值

+   我们必须始终最小化从表单或外部来源获取数据并直接在数据库查询或应用程序的其他内部部分中使用它

# 将表单链接到服务器

表单的基本目的是接受用户数据或存储用户数据，可以通过各种方式访问，例如调查、新注册、付款等。因此，在本节中，我们将学习如何将用户的输入数据存储到数据库中。

我们将重用我们在第三章中设计的表单，*美化表单*。

我们将使用`phpMyAdmin`（用于处理 MySQL 管理的开源工具）将表单数据存储到 MySQL 数据库中。

对于诸如 Linux 之类的操作系统，我们使用 XAMPP 服务器。

以下是在同一 HTML 页面中编写的服务器端脚本代码，但 HTML 文件扩展名`.html`已更改为`.php`：

```html
<?php
  mysqli_connect("localhost", "root", "");

  mysqli_select_db("DBpersonal_info");
  if(isset($_REQUEST['submit']))
  {
    $errorMessage = "";
    $Gender ="";
    $Firstname=$_POST['Firstname'];
    $Lastname=$_POST['Lastname'];
    $Dob=$_POST['Dob'];
    $Gender=$_POST['Gender'];
    $Saddress=$_POST['Saddress'];
    $City=$_POST['City'];
    $State=$_POST['State'];
    $Pincode=$_POST['Pincode'];
    $Country=$_POST['Country'];
    $Home=$_POST['Home'];
    $Work=$_POST['Work'];
    $Email=$_POST['Email'];
    $Aaddress = $_POST['Aaddress'];

    //Field validation
    if(empty($Firstname)) {
      $errorMessage .= "<li>You forgot to enter a first 
      name!</li>";
    }
    if(empty($Lastname)) {
      $errorMessage .= "<li>You forgot to enter a last 
      name!</li>";
    }
    if(empty($Dob)) {
      $errorMessage .= "<li>You forgot to select a date of 
      birth!</li>";
    }
    if(empty($Gender)) {
      $errorMessage .= "<li>You forgot to select your 
      Gender!</li>";
    }
    if(empty($Saddress)) {
      $errorMessage .= "<li>You forgot to enter street 
      address!</li>";
    }
    if(empty($City)) {
      $errorMessage .= "<li>You forgot to enter city!</li>";
    }
    if(empty($State)) {
      $errorMessage .= "<li>You forgot to enter state!</li>";
    }
    if(empty($Pincode)) {
      $errorMessage .= "<li>You forgot to enter pincode!</li>";
    }
    if(empty($Country)) {
       $errorMessage .= "<li>You forgot to select country!</li>";
    }
    if(empty($Home)) {
       $errorMessage .= "<li>You forgot to enter home phone 
       number!</li>";
    }
    if(empty($Work)) {
      $errorMessage .= "<li>You forgot to enter work phone 
      number!</li>";
    }
    if(empty($Email)) {
      $errorMessage .= "<li>You forgot to enter email id!</li>";
    }

    //Check if the number field is numeric
    if(is_numeric(trim($Pincode)) == false ) {
    $errorMessage .= "<li>Please enter numeric pincode value!</li>";
    }
    if(is_numeric(trim($Home)) == false ) {
      $errorMessage .= "<li>Please enter numeric home phone number!</li>";
    }
    if(is_numeric(trim($Work)) == false ) {
      $errorMessage .= "<li>Please enter numeric workphone number!</li>";
    }

    //Check if the length of field is upto required
    if(strlen($Pincode)!=6) {
      $errorMessage .= "<li>Pincode should be 6 digits only!</li>";
    }
    if(strlen($Work)!=10) {
      $errorMessage .= "<li>Work phone number should be 10 digits 
      only!</li>";
    }

    //Check for valid email format
    if(!filter_var($Email, FILTER_VALIDATE_EMAIL)) {
      $errorMessage .= "<li>You did not enter a invalid 
      email!</li>";
    }
        if ($errorMessage != "" ) {
      echo "<p class='message'>" .$errorMessage. "</p>" ;
    }
    else{  
      //Inserting record in table using INSERT query
      $insertTB="INSERT INTO `personal_info`.`personal`
      (`Firstname`, `Lastname`, `Dob`, `Gender`, `Saddress`, 
      `Aaddress`, `City`, `State`, `Pincode`, `Country`, `Home`,   
      `Work`, `Email`) VALUES ('$Firstname', '$Lastname', '$Dob',  
      '$Gender', '$Saddress', '$Aaddress', '$City', '$State', 
      '$Pincode', '$Country', '$Home', '$Work', '$Email')";

      mysqli_query($insertTB); 
    }
  }
?>
```

在执行代码之前，我们的先决条件是首先创建和选择一个数据库，然后创建一个表来存储信息。之后，我们对表单输入执行一些验证，最后，我们实现`Insert`查询以存储用户的输入数据。

以下是用户未输入任何数据并提交表单时显示的错误消息的屏幕截图：

![将表单链接到服务器](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_04_01.jpg)

以下是 HTML 代码。代码保持不变，但我们在`<form>`标签中添加了`method="POST"`属性和在`<input>`类型中添加了`name`属性：

```html
<form id="masteringhtml5_form" method="POST">
<label for="heading" class="heading">Health Survey Form</label>
  <fieldset class="fieldset_border">
  <legend class="legend">Personal Information</legend>
  <div>
  <label for="name">Name</label><br>
<input type="text" name="Firstname" class="name txtinput" placeholder="First" autofocus>
<input type="text" name="Lastname" class="name txtinput" placeholder="Last">
  </div><br>
  <div class="div_outer_dob">
  <div class="div_dob">
  <label for="dob">Date of Birth</label><br>
<input type="date" name="Dob" value="date of birth" class="txtinput dateinput">
  </div>
  <div class="gender">
  <label for="gender">Gender</label><br>
<input type="radio" name="Gender" value="male"> <span>Male</span>
<input type="radio" name="Gender" value="female"> <span>Female</span>
  </div>
  </div>    
<div class="div_outer_address">
  <label for="address">Address</label><br>
<input type="text" name="Saddress" class="txtinput tb address_img" placeholder="Street Address"><br>
<input type="text" name="Aaddress" class="txtinput tb address_img" placeholder="Address Line 2"><br>
<input type="text" name="City" class="txtinput tb1 address_img" placeholder="City">
<input type="text" name="State" class="txtinput tb1 address_img" placeholder="State/Province"><br>
<input type="text" name="Pincode" class="txtinput tb1 address_img" placeholder="Pincode">
  <select name="Country" class="txtinput select address_img" >
<option value="Country" class="select" >Select Country</option>
  <option value="India" class="select" >India</option>
  <option value="Australia" class="select" >Australia</option>
  </select>
  </div><br>
  <div>
  <label for="contact">Phone Number</label><br>
<input type="tel" name ="Home" class="txtinput tb1 home_tel" placeholder="Home">
<input type="tel" name="Work" class="txtinput tb1 work_tel" placeholder="Work">
  </div><br>
  <div>
  <label for="email">Email Address</label><br>
<input type="email" name="Email" class="txtinput tb1 email" placeholder="email@example.com">
  </div>
  </fieldset><br>
  <div class="submit">
<input type="submit" name="submit" class="submit_btn" value="Submit">
  </div>
</form>
```

通过点击**提交**按钮，我们可以将用户重定向到新页面，或在屏幕上显示消息，或简单地在屏幕上写一条消息，确认我们的表单已成功提交。

以下是用户在表单中输入数值后的屏幕截图：

![将表单链接到服务器](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_04_02.jpg)

以下是 MySQL 代码片段：

```html
//Creates database
CREATE DATABASE personal_info

//Creates table
CREATE TABLE personal(
Firstname VARCHAR(255) NOT NULL,
Lastname VARCHAR(255) NOT NULL,
Dob VARCHAR(255) NOT NULL,
Gender VARCHAR(255) NOT NULL,
Saddress VARCHAR(255) NOT NULL,
Aaddress VARCHAR(255) NOT NULL,
City VARCHAR(255) NOT NULL,
State VARCHAR(255) NOT NULL,
Pincode INT(11) NOT NULL,
Country VARCHAR(255) NOT NULL,
Home VARCHAR(255) NOT NULL,
Work VARCHAR(255) NOT NULL,
Email VARCHAR(255) NOT NULL)
```

在上述代码中，首先我们创建了一个数据库，然后创建了一个表来存储用户的输入数据。

以下是点击**提交**按钮后存储在数据库中的数值的屏幕截图：

![将表单链接到服务器](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_04_03.jpg)

# 总结

在本章中，我们学习了如何将数据存储到数据库中。我们还学习了用于存储用户输入数据的 PHP 和 MySQL 的基础知识。我们还了解了一些欺骗表单的方法以及如何防止表单的欺骗。

然后，借助一些代码，我们学习了通过重用我们在早期章节中构建的示例来存储表单数据的实际实现。


# 第五章：响应式网页表单

在之前的章节中，我们了解了表单：表单是什么，我们如何验证它们，我们如何改善表单的外观和感觉，以及如何将通过表单收集的信息存储到数据库中。但是，随着技术的提升，不同分辨率的不同设备需要不同的布局。因此，在本章中，我们将学习如何使我们的表单具有响应性。

在本章中，我们将涵盖以下主题：

+   什么是响应式设计

+   什么是媒体查询

+   什么是流体网格

+   如何使我们的表单具有响应性

+   使响应式表单更有效的指南

# 响应式设计

响应式设计这个术语是由作家和网页设计师 Ethan Marcotte 在 2010 年 5 月的一篇名为《响应式网页设计》的文章中引入的，该文章发表在《A List Apart》上。

基本上，响应式设计意味着内容如何显示在各种屏幕上，如手机、平板电脑或桌面上。响应式设计是一种方法，通过该方法，网站或特定页面会根据特定的屏幕分辨率动态调整自身，以提供最佳的用户体验。它确保了良好的用户体验，因为它可以独立地在各种设备和分辨率上运行。

使用流体、比例为基础的网格、灵活的图片和 CSS3 媒体查询，使用响应式网页设计设计的网站会自动调整布局以适应特定设备的分辨率。

网页设计曾经是简单的。网页设计师会为最流行的桌面屏幕尺寸设计，创建一个适用于大多数设备的单个布局，这使我们可以轻松地将设计分成各种网格，以便我们可以拥有一个布局良好、连贯和和谐的页面。

但随着技术的提升和各种设备的推出，如智能手机、平板电脑，甚至迷你笔记本电脑，网页布局和设计的整体体验发生了变化。

Web 的变化也改变了人们使用互联网的方式。在早期的网页设计方法中，很难在移动设备上使用互联网，因为专为桌面设计的特定网站需要滚动并且需要放大或缩小以阅读文本，浪费时间。例如，在桌面上查看的页面可能具有基于文本的紧凑链接，难以点击。但是通过响应式设计，我们可以利用 HTML5 和 CSS3 的可用功能和能力来解决这些问题。

如果该网站或页面是响应式的，文本将更大，所有内容将适合屏幕，并且导航将经过移动优化。

响应式网页设计中的断点是具有媒体查询声明的浏览器宽度，一旦达到声明的范围，就会改变网站或网页的布局。

## 谷歌对响应式设计的看法

谷歌建议构建智能手机优化的网站，并支持以下三种配置：

+   设计为响应式的网站为所有设备提供相同的 URL，每个 URL 向所有设备呈现相同的 HTML，并只利用 CSS 来更改页面在设备上的呈现方式

+   这些网站动态为所有设备提供相同的 URL，但每个 URL 根据用户代理是桌面还是移动设备提供不同的 HTML（和 CSS）。

+   有些网站有单独的移动和桌面 URL

## 使用响应式设计的好处

使用响应式设计网站的一些好处如下：

+   对于特定内容使用单个 URL 使用户更容易与内容交互，分享和链接。

+   与为桌面和移动设备开发和维护多个网站不同，我们只需要一个网站来开发和维护，适用于所有类型的设备。

+   由于不需要重定向即可获得设备优化的视图，加载时间减少。此外，基于用户代理的重定向可能会降低网站的用户体验，并且更容易出现错误。

+   它是未来友好的；这意味着它允许我们适应新技术，并随着时间的推移逐渐增强我们的网站。

除了改变布局，响应式设计还有很多其他方面。我们可以超越设备的视图大小，可以专注于设备的功能或能力。在某些情况下，我们的网站使用悬停功能，但我们需要为不支持悬停功能的触摸屏设备更改它，我们可以为不同的图像服务或在更改屏幕分辨率时裁剪图像。此外，我们还可以检查设备的位置是否可追踪，或者设备是否在互联网上工作，或者 WIFI，等等。

## 响应式设计如何工作

网页布局取决于或者我们可以说是由以下网络语言抽象地控制：

+   HTML

+   CSS

+   JavaScript

HTML 描述内容是什么，CSS 负责内容的外观，而使用 JavaScript 我们可以做一些非常酷的事情，比如回退机制。网站被设计为适用于各种屏幕尺寸和设备，根据条件自适应和改变自身，采用内容优先的方法。这是通过使用媒体查询实现的，它允许我们拥有特定的 CSS，用于根据我们的需要定制布局。我们将在本章后面讨论媒体查询。

## 屏幕分辨率

不同的设备在横向和纵向模式下具有不同的屏幕分辨率。以下是一些设备和设备支持的横向和纵向视图的屏幕分辨率：

| 设备 | 纵向视图 | 横向视图 |
| --- | --- | --- |
| iPhone 3G/3GS | 320 x 480 | 480 x 320 |
| 三星 Galaxy S Duos | 480 x 800 | 800 x 480 |
| iPhone 4 | 640 x 960 | 960 x 640 |
| iPad | 768 x 1024 | 1024 x 768 |
| 设备 | 分辨率 |
| --- | --- |
| 大多数上网本 | 1024 x 600 |
| MacBook Air 08 | 1280 x 800 |
| 一些笔记本电脑 | 1366 x 768 |
| MacBook Pro 15" | 1440 x 900 |

除了这些分辨率，今天的最新设备，如三星 Galaxy S4 或 iPhone 5，在移动设备领域具有非常高的分辨率。

## 视口

元数据是关于数据的数据（信息）。`<meta>` 标签提供了关于 HTML 文档的元数据。元数据不会显示在页面上，但可以被机器解析。

元素通常用于指定页面描述、关键词、文档最后修改的作者以及其他元数据。

元数据可以被浏览器（如何显示内容或重新加载页面）、搜索引擎（关键词）或其他网络服务使用。

对于响应式设计，在移动设备上设置视口宽度和初始缩放，通常使用以下 `<meta>` 标签。尽管是响应式设计，但在我们最终确定适合或重新启动的方法之前，我们也可以在非响应式设计中使用此标签。事实上，如果我们正在构建一个响应式网站或任何移动网站，我们仍然需要以下标签：

```html
<meta name="viewport" content="width=device-width, initial-scale=1.0">
```

# 媒体查询

媒体查询是 CSS3 模块，允许内容适应各种屏幕分辨率，如智能手机、平板电脑和高清屏幕。

为了为不同的设备提供不同的样式，媒体查询是实现这一目标的绝佳方式，为每种类型的用户提供最佳体验。作为 CSS3 规范的一部分，媒体查询扩展了控制样式应用方式的 `media` 属性的作用。

媒体查询由一个或多个表达式和涉及导致真或假的特征的媒体类型组成。此外，当媒体查询为真时，将应用相关的样式表或样式规则，遵循常规的级联规则。

以下片段是一个非常简单的例子，当设备宽度大于 500 像素时适用：

```html
@media screen and (min-width: 500px)
{
  /* some css here */
}
```

## 媒体类型

`media`属性的值指定了链接文档（外部 CSS）将应用的设备。在 HTML 文档的头部使用`<link>`元素内的`media`属性，可以声明媒体类型。在 XML 处理指令中，可以声明媒体类型，并且可以使用`@import` at-rule 和`@media` at-rule。

CSS2 定义的其他媒体类型包括：

+   `projection`：用于投影演示，如幻灯片

+   `embossed`：用于盲文打印机

+   `all`：用于所有媒体类型设备

+   `aural`：用于声音和语音合成器

+   `tv`：用于电视类型设备

+   `screen`：用于计算机屏幕

+   `braille`：用于盲文触觉反馈设备

+   `handheld`：用于手持设备或小型设备

+   `print`：用于打印机

+   `tty`：用于使用固定间距字符网格的媒体，如电传打印机和终端

样式表的一个重要特性是它们指定了文档在不同媒体上的呈现方式，比如在纸上、屏幕上使用语音合成器，或者在盲文设备上。

我们可以根据页面视图所使用的媒介应用不同的样式。借助`media`属性，可以将内部和外部样式表与媒体类型关联起来。

### 内部媒体查询

这些查询是在 HTML 页面内的`<style>`标签中编写的。

内部媒体查询的优点如下：

+   不需要额外的 HTTP 请求

+   在更新旧文件时保持可见且不被遗忘

内部媒体查询的缺点如下：

+   如果用户需要下载，文件大小会增加

+   为了使其在较旧版本的 Internet Explorer 浏览器中工作，我们必须使用 JavaScript

#### 语法

内部媒体查询的语法如下：

```html
body{
  background: blue;
}

@media screen and (max-width: 480px){
  body{
    background: black;
  }
}
```

最初，它将背景颜色设置为蓝色。但在最大宽度为 480 像素时，它将背景颜色设置为黑色，覆盖了 CSS 样式。

### 外部媒体查询

这些查询是在单独的文件或外部 CSS 文件中编写和维护的。

外部媒体查询的优点如下：

+   这在广泛使用时很容易保持和维护 CSS

+   使用条件注释，可以在旧版本的 Internet Explorer 中使用外部媒体查询

+   对于不支持的浏览器，文件大小较小

外部媒体查询的缺点如下：

+   需要额外的 HTTP 请求来应用它

+   在更新旧文件时很容易被忘记

扩展链接元素或`@import`规则的现有媒体部分：

```html
<link href="example.css" rel="stylesheet" media="only screen and (max-width:480px)">
@import url(example.css) only screen and (max-width:480px);
```

## 媒体特性

媒体特性在语法上类似于 CSS 属性，因为它们有名称并接受某些值，或者我们可以说它们是我们可以自定义响应式设计的条件。

以下表格列出了一些媒体特性：

| 特征 | 接受最小/最大前缀 | 值 | 描述 |
| --- | --- | --- | --- |
| `device-width` | 是 | 长度 | 无论浏览器窗口的宽度如何，这确定了设备整个屏幕的宽度。 |
| `device-height` | 是 | 长度 | 这确定了设备屏幕的高度。 |
| `orientation` | 否 | 纵向或横向 | 这确定了设备的方向。两种方向模式是横向和纵向。 |
| `width` | 是 | 长度 | 这确定了可显示区域的宽度。在大多数移动浏览器中保持不变，因为无法调整浏览器大小，但在台式电脑上，当用户调整浏览器大小时，宽度会改变。 |
| `height` | 是 | 长度 | 这确定了显示区域的高度。 |
| `grid` | 否 | 1 或 0 | 这检测输出设备是位图还是网格。基于网格的设备返回值为 1，所有其他设备返回值为 0。 |
| `device-aspect-ratio` | 是 | 比率 | 这确定了`device-width`媒体与`device-height`媒体的值的比率。 |
| `resolution` | 是 | 分辨率 | 这确定了像素密度或输出设备的分辨率。 |
| `color` | 是 | 整数 | 这确定了设备每个颜色分量的位数。当设备不是彩色设备时，该值为零。 |
| `color-index` | 是 | 整数 | 在输出设备的颜色查找表中，这确定了条目的数量。 |
| `monochrome` | 是 | 整数 | 这确定了单色帧缓冲区中每像素的位数。对于非单色设备，该值为`0`。 |
| `aspect-ratio` | 是 | 比率 | 这确定了`width`媒体与`height`媒体的值的比率。 |
| `scan` | 否 | 逐行或隔行 | 逐行或隔行，这确定了电视的扫描过程。 |

## 不同的屏幕分辨率

在这个特定的部分，我们将专注于设置一般和特定设备屏幕分辨率的最小或最大宽度的语法。我们还将讨论设备的方向。

我们无法使用 CSS 设置浏览器的屏幕分辨率。

### 小屏幕设备

我们可以使用以下代码来处理最大设备宽度为 480 像素的小屏幕设备：

```html
@media screen and (max-device-width: 480px)
{
  /* some CSS here */
}
```

媒体查询中的任何 CSS 都将应用于宽度为 480 像素或更小的设备。使用`max-device-width`而不是`device-width`的目的是，`device-width`指的是设备的宽度，但不指的是显示区域的宽度。在我们可以改变分辨率的浏览器中，如果用户调整大小，分辨率可以改变，因此我们使用了`max-device-width`。

除非屏幕分辨率或浏览器大小（在可以更改浏览器大小的情况下）为 480 像素或更小，否则媒体查询不会生效，这基本上为我们留下了移动设备。

### 苹果移动设备的高分辨率显示

苹果推出了 iPhone 5 和 iPad 3 等设备。在早期的设备中，如 iPhone 4 和 4S，他们引入了视网膜显示的概念。在视网膜显示中，设备的屏幕分辨率加倍。苹果支持一个名为`-webkit-device-pixel-ratio`的专有属性，返回设备的像素密度。因此，该设备返回值为`2`。

#### 针对高分辨率设备

我们可以使用以下代码来处理通用的苹果设备高分辨率：

```html
@media screen and (-webkit-min-device-pixel-ratio: 1.5)
{
  /* some css here */
}
```

#### 针对小屏幕高分辨率设备

我们可以使用以下代码来处理小屏幕高分辨率设备，如 iPhone 4：

```html
@media screen and (-webkit-min-device-pixel-ratio: 2) and (max-device-width: 480px)
{
  /* some css here */
}
```

#### 针对大屏幕高分辨率设备

我们可以使用以下代码来处理大屏幕高分辨率设备，如 iPad 3：

```html
@media screen and (-webkit-min-device-pixel-ratio: 2) and (min-device-width: 768px)
{
  /* some css here */
}
```

由于高分辨率，图像是最受欢迎的选择，可以针对视网膜显示进行优化，根据设备的不同，我们可以提供图像的两个不同版本。对于视网膜显示，我们将原始图像的尺寸和分辨率加倍，但在使用此图像时，我们对其尺寸施加约束，使其与原始图像的尺寸相同，并允许视网膜设备显示每个像素的两个像素，结果得到了一个超清晰的图像。

以下代码是背景图片的示例：

```html
normal background for the browsers:

div#featuredbox{
  width: 80%;
  height: 350px;
  background: url(normal_background.jpg) center no-repeat;
}

retina devices with larger screens:

@media screen and (-webkit-min-device-pixel-ratio: 2) and (min-device-width: 768px){
div#featuredbox{
  -webkit-background-size: 50% auto;
  background: url(highresolution_background.jpg) center no-repeat; 
  }
}
```

在上面的示例中，`-webkit-background-size: 50% auto;`将图像缩小了实际尺寸的 50%，与原始图像的尺寸相匹配。`background: url(highresolution_background.jpg) center no-repeat;`是高分辨率图像，它将原始图像的尺寸或分辨率加倍。

### 横向和纵向模式的设备

除了处理屏幕尺寸，处理媒体查询之前设备的方向是棘手的，但是媒体查询的引入简化了开发人员的生活：

```html
@media screen and (orientation: portrait)
{
  /* some CSS here */
}
```

前面的代码将针对所有屏幕高度大于宽度的设备。在用户可能使用方向很重要的小屏设备的情况下更进一步。

#### 仅限纵向模式的小屏设备

我们可以使用以下代码来适应最大宽度为 480 像素分辨率的纵向模式屏幕：

```html
@media screen and (max-device-width: 480px)and (orientation: portrait)
{
  /* some CSS here */
}
```

#### 仅限横向模式的小屏设备

我们可以使用以下代码来适应最大宽度为 640 像素分辨率的横向模式屏幕：

```html
@media screen and (max-device-width: 640px) and (orientation: landscape)
{
  /* some CSS here */
}
```

在响应式网页设计的技术支柱中，媒体查询是最成熟和支持最好的。此外，它们从设计的角度提供了可靠的回报，并且可以应用于现有应用程序以产生良好的效果。

# 流体网格

流体是一种在受到剪切应力时不断改变其形状和形式的物质。

在网页设计方面，流体指的是我们根据屏幕分辨率进行调整的设计，而剪切应力则指流体组件根据屏幕分辨率进行调整。流体设计中的组件会根据环境或屏幕分辨率进行调整和流动。

对于响应式设计，我们可以说这是一种元素的组合，其中一个是流体网格，另一个是使用媒体查询根据屏幕尺寸和类型加载 CSS；所以我们可以说流体网格本身并不完全是响应式设计。

为了保持布局清晰，并且可以轻松地将网格划分为特定数量的列，流体网格中定义了最大布局尺寸。每个网格内的元素都是按比例宽度和高度设计的，以便根据父容器进行调整。当屏幕尺寸改变时，元素将根据其所在的容器调整宽度和高度。

由于流体网格随着尺寸变化自然流动，我们必须对不同的屏幕尺寸和设备类型进行有限的调整。而在自适应网格的情况下，我们必须定义明确的基于像素的尺寸，并且必须在设备视口中手动调整元素的高度和宽度。在流体网格中，我们可以调整`max-width`，这非常重要，因为现在的移动设备更加强大，所以一个人可能会花费大部分时间使用移动设备执行各种任务。

## 流体网格生成器

流体网格并不容易，从头开始创建它们需要付出努力和时间，是一项繁琐的任务。由于大多数网格框架都具有先进的内置功能，并且已经在各种主要浏览器中进行了测试，因此明智的选择是选择现有的 CSS 网格框架或网格生成器作为我们布局创建和设计的基础。我们可以使用的一些 CSS 网格系统和生成器包括：

+   流体网格系统

+   微型流体网格

+   通过计算器的流体网格

+   通过 bootstrap 的流体网格

当我们有一个 CSS 框架时，创建具有流体列的网格很容易，但并非所有设计都会直截了当。我们可能需要在其他列和行内创建列和行。嵌套列是包含在父列中的列。

## 960 网格系统

从桌面作为主要焦点开始，960 网格系统是由*Nathan Smith*设计的，如果你正在寻找桌面解决方案，它是相当不错的。Smith 最近也努力将框架移植到移动设备上。

该系统提供了一个工具，包括用于处理快速原型设计和发布的 CSS 和 JavaScript 文件，以及许多流行设计环境的模板，如 Omnigraffle、Fireworks、Balsamiq 和 Photoshop，以便为桌面和移动设备提供一个单一的解决方案。

960 网格系统对细节的关注已经激发了弹性和流体变体，主题以及适应我们自己的 CSS 偏好的系统。因此，我们可以说，通过这个系统，我们可以设置我们喜欢的列数，列宽和间距宽度，同时享受 960 网格系统社区的好处。

960 网格系统的优点如下：

+   创建者还发布了其他基于 960 的解决方案，这简化了其集成

+   它具有用于自定义 CSS 的自定义 CSS 生成器

+   960 网格系统有很多列配置，因为它有很多除数——28 及以上

960 网格系统的缺点如下：

+   它包含比其他解决方案更多的标记

+   与其他解决方案相比，它的 CSS 文件大小更大

+   它包含非语义类名

## Bootstrap

Bootstrap 是一个 HTML，CSS 和 JavaScript 框架，可用作创建网站或 Web 应用程序的基础。如果您今天从事 Web 开发，您一定听说过 Twitter 和 GitHub，所以当您听说一个在 Twitter 开始生活并且是 GitHub 上最受欢迎的存储库的框架时——甚至超过了 jQuery 和 Node.js——您会对 Bootstrap 所带来的病毒式传播有所了解。换句话说，它是一个流畅，直观和强大的前端框架，可加快和简化 Web 开发。

简而言之，它代表了响应式网页设计背后的驱动力，使开发人员能够快速发布将用户需求置于首位的应用程序。

由于其响应特性足够强大，可以独立存在，Bootstrap 及其组件库是最佳解决方案之一。我们可以利用流体嵌套和偏移，这有助于使该框架脱颖而出。虽然我们会避免利用许多开发人员采用 Bootstrap 的组件样式，但网格的轻松实现会让您渴望探索框架的其他特性。

Bootstrap 的优点如下：

+   它可以完全定制，包括我们需要使用的功能

+   它已经经过开发人员的严格测试

+   Bootstrap 很受欢迎，这意味着开发人员熟悉它

+   它可以帮助在短时间内在网络上做出令人惊叹的事情

Bootstrap 的缺点如下：

+   它包含比其他解决方案更多的标记

+   与其他解决方案相比，它的 CSS 文件大小更大

+   它包含非语义类名

但使用响应式 CSS 框架并不会使我们的设计响应式，而且响应式设计并不那么简单。除非我们仔细规划设计，用户在使用流体网格时在较小的设备上浏览内容时总会遇到问题。

为了实现完美的响应式设计，我们不能依赖流体网格，但我们可以根据设计需要调整流体网格，以为用户提供最佳的浏览体验。

# 自适应图片

自适应图片根据客户端自适应加载不同类型的图片。它们检测用户的设备屏幕大小，并自动创建缓存并传递适当类型的 HTML 网页图像。它们的基本目的是用于响应式设计，并与流体图像技术结合使用。这是因为我们的网站不仅在较小的设备上查看，而且在速度较慢且带宽较低的设备上查看。因此，特别是在这些设备上，我们的基于桌面的图像加载速度较慢，这会导致更多的用户带宽，增加成本，并且用户界面的渲染需要时间。所有这些问题都可以通过自适应图片来解决。

自适应图片遵循相同的语义和结构模型，用于`<img>`，`<audio>`或`<video>`元素。此外，`<source>`元素应该有支持 CSS3 媒体查询的`media`属性，这些查询会在给定设备上呈现相应的元素。

例如：

```html
<imgsrc="img/header.png" width="480" height="240" alt="head" media= "handheld and (max-device-width: 480px)">
<source src= "header.png" type="image/png" media= "screen and (max-device-width: 800px)">
<source src= "header.png" type="image/png" media="screen and (max-device-width: 1600px)">
</img>
```

## 特点

自适应图片的一些特点如下：

+   它不需要标记更改

+   它可以轻松配置或定制

+   它可以很好地与任何 CMS 一起使用，也可以在没有 CMS 的情况下使用

+   它可以轻松地在我们现有的网站上使用

+   它遵循先移动设备的哲学，这意味着首先覆盖移动设备的设计，然后是更大的屏幕。

+   它可以在几分钟内启动和运行

## 它是如何工作的

使用自适应图像的步骤如下：

1.  将`.htaccess`和`adaptive-images.php`文件添加到`document-root`文件夹中。

1.  我们可以从[`github.com/mattwilcox/Adaptive-Images`](https://github.com/mattwilcox/Adaptive-Images)下载这些文件。

1.  将 JavaScript 添加到网页的`<head>`中。以下是需要复制的 JavaScript：

```html
<script>
document.cookie='resolution='+Math.max(screen.width,screen.height)+'; path=/';
</script>
```

1.  对于苹果设备的视网膜显示屏，我们可以使用以下行：

```html
<script>
document.cookie='resolution='+Math.max(screen.width,screen.height)+("devicePixelRatio" in window ? ","+devicePixelRatio : ",1")+'; path=/';
</script>
```

1.  在 PHP 文件中向`$resolutions`添加 CSS 媒体查询值。

## 定制

我们还可以通过查看 PHP 文件（`adaptive-images.php`）顶部的配置部分来更改默认值。以下要点可以相应地进行自定义：

+   我们可以设置断点以匹配 CSS 媒体查询

+   我们可以更改`ai-cache`文件夹的名称和位置

+   我们可以更改保存的任何生成的 JPG 图像的质量

+   我们可以设置浏览器缓存图像的时间

+   为了保持细节，我们可以锐化重新缩放的图像

# 使我们的表单响应

在前几章中，从表单的基础知识中，我们学习了如何样式化，验证和将我们的表单与数据库链接。在本节中，我们将学习如何使我们的表单响应。

我们将重复使用之前样式化的表单，并将看到新的技术，以使我们的表单响应。

HTML 代码保持不变，只是将以下链接添加到 HTML 页面的`<head>`标签中。

以下第一行提到的是视口`<meta>`标签：

```html
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
```

第二行是外部媒体查询（例如解释）。该代码保存在一个单独的文件中，但媒体查询是写在`<head>`标签中的。

下面提到的 CSS 文件将被包含，并在设备屏幕分辨率宽度低于或等于 520 像素时生效，但一旦设备分辨率超过 520 像素宽度，媒体查询就不再生效。

在样式中，我们将输入文本元素的宽度设置为 85％。我们还清除了标有性别类的表单元素单选按钮的值为 none。对**提交**按钮的样式进行了调整，字体大小设置为 15 像素，并将宽度增加到 23％。出生日期的类`div_dob`也被清除为 none，以便按顺序排列在同一行上。

```html
<link rel='stylesheet' media='screen and (max-width: 520px)' href='Css/Internal_MediaQuery.css' />
```

以下是 CSS 中的代码：

```html
#masteringhtml5_form .txtinput.textbox{
  width: 85%;
}
#masteringhtml5_form .txtinput{
  width: 85%;
}
#masteringhtml5_form .gender{
  float:none;
}
#masteringhtml5_form .gender span{
  font-size: 14px;
}
#masteringhtml5_form .txtinput.select{
  width: 97%;
}
#masteringhtml5_form .submit_btn{
  font-size:15px;
  width:23%;
  padding-top: 3px;
  padding-bottom: 3px;
}
#masteringhtml5_form .div_dob{
  width: 100%;
  float:none;
}
```

前面的 CSS 代码已经在第三章中解释过了，但这里重要的一点是内部媒体查询，使我们的表单对小屏幕设备响应。

第三行是链接到主 HTML 页面的外部媒体查询文件：

```html
<link href="Css/External_MediaQuery.css" rel="stylesheet" />
```

以下片段是保存在单独文件中的 CSS 代码：

```html
@media screen and (min-width: 1169px) and (max-width: 1255px){
  #masteringhtml5_form .txtinput{
    width:45.7%;
  }
  #masteringhtml5_form .dateinput{
    width: 90%;
  }
}

@media screen and (min-width: 957px) and (max-width: 1170px){
  #masteringhtml5_form .txtinput{
    width:44.7%;
  }
  #masteringhtml5_form .dateinput{
    width: 90%;
  }
#masteringhtml5_form .txtinput.textbox{
    width: 94%;
  }
}

@media screen and (min-width: 811px) and (max-width: 958px){
  #masteringhtml5_form .txtinput{
    width:43.7%;
  }
  #masteringhtml5_form .txtinput.textbox{
    width: 93.7%;
  }
  #masteringhtml5_form .dateinput{
    width: 88%;
  }
}

@media screen and (min-width: 707px) and (max-width: 812px){
  #masteringhtml5_form .txtinput{
    width:42.7%;
  }
  #masteringhtml5_form .txtinput.textbox{
    width: 92.7%;
  }
  #masteringhtml5_form .dateinput{
    width: 88%;
  }
}

@media screen and (min-width: 624px) and (max-width: 708px){
  #masteringhtml5_form .txtinput{
    width:41.7%;
  }
  #masteringhtml5_form .txtinput.textbox{
    width: 92%;
  }
  #masteringhtml5_form .dateinput{
    width: 86%;
  }
}

@media screen and (min-width: 567px) and (max-width: 625px){
  #masteringhtml5_form .txtinput{
    width:40.7%;
  }
  #masteringhtml5_form .txtinput.textbox{
    width: 90%;
  }
  #masteringhtml5_form .dateinput{
    width: 84%;
  }
}

@media screen and (min-width: 521px) and (max-width: 568px){
  #masteringhtml5_form .txtinput{
    width:39.7%;
  }
  #masteringhtml5_form .txtinput.select{
    width: 48.7%;
  }
  #masteringhtml5_form .txtinput.textbox{
    width: 90%;
  }
  #masteringhtml5_form .dateinput{
    width: 84%;
  }
}
```

在前面的代码中，媒体查询应用于具有特定最小屏幕宽度和特定最大屏幕宽度的屏幕类型。我们已经覆盖了`txtinput`，`select`和`dateinput`类的宽度，这些类根据屏幕分辨率进行调整。元素会根据特定的屏幕分辨率重新流动和调整。

以下截图是我们制作的响应式表单。这个响应式表单对 Web 浏览器（更改浏览器大小）和各种设备屏幕分辨率都有响应。

对于分辨率 480 x 800，我们的表单如下截图所示：

![使我们的表单响应](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_05_01.jpg)

对于分辨率 768 x 1024，我们的表单如下截图所示：

![使我们的表单响应](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_05_02.jpg)

对于分辨率 1280 x 800，我们的表单如下截图所示：

![使我们的表单响应](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_05_03.jpg)

对于每个特定的分辨率，我们可以注意到我们能够在不滚动任何一侧的情况下查看完整的表单。

在先前的场景中，对于不同的分辨率，一些元素被调整大小，并且动态地从原始位置移动，以获得更好的用户体验。

这样，我们的表单可以动态响应不同的分辨率。

# 限制

移动网页设计的新方法是响应式设计，但对于网页设计师和他们的客户来说，最大的挑战之一是最终确定网站的布局或线框图。

我们需要克服的其他一些挑战包括：

+   响应式设计比构建其他网站需要更多的开发时间。

+   缩放图像会降低图像质量，因为缩放是基于屏幕大小而不是上下文的。

+   在较小的设备上，使用导航菜单变得具有挑战性。

+   浏览器兼容性成为一个问题；由于旧版浏览器的支持，媒体查询的支持变得有限。

+   使用这项技术构建复杂的网站变得乏味。

+   开发成本更高

+   网站的响应时间变慢，因为网页的大小大大增加。

+   在移动设备上，下载甚至没有显示的桌面内容会增加加载时间。

# 指南

在本节中，我们将看一下响应式设计的指南，以使我们的表单更有效。

一些响应式设计的最佳实践包括：

+   尽量将网页上的内容保持最少，以获得更好的响应式设计。

+   在较小的屏幕上，始终优先考虑内容。

+   尽量少使用导航。

+   网页必须得到有效的编程和结构。

+   响应式设计不仅适用于手机。响应式设计的范围不仅限于手机或平板电脑；事实上，我们应该记住人们也使用大尺寸的 27 英寸台式电脑屏幕。

+   始终专注于浏览器兼容性。

+   保持表单简短；如果使用长表单，添加一个“保存”按钮，并将用户导航到下一页。

+   始终保持响应式设计的单独文件，以便轻松维护代码。

# 摘要

在本章中，我们学习了响应式设计。除此之外，我们还看到了响应式设计的优势和建议。

我们学习了各种技术，可以使我们的表单具有响应性。

然后，借助代码，我们学习了响应式网页表单的实际实现，通过重复使用我们在之前章节中构建的示例。

最后，我们看到了使响应式表单更有效的最佳实践。
