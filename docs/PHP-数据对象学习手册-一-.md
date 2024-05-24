# PHP 数据对象学习手册（一）

> 原文：[`zh.annas-archive.org/md5/33ff31751d56930c46ef1daf9ca0ebcb`](https://zh.annas-archive.org/md5/33ff31751d56930c46ef1daf9ca0ebcb)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书将向您介绍 PHP 5.0 版本开始提供的最重要的扩展之一——PHP 数据对象，通常称为 PDO。

PHP 由于其简单性和易用性而成为非常流行的 Web 编程语言。这种不断增长的成功的关键因素之一是内置的访问许多流行的关系数据库管理系统（RDBMS）的可能性，比如 MySQL、PostgreSQL 和 SQLite 等。今天，大多数现有的和新创建的 Web 应用程序都与这些数据库相互连接，以生成动态的、数据驱动的网站。

虽然大多数支持 PHP 的 Web 服务器仍在运行 PHP 5.0 之前的版本，但这个新版本引入的增强功能和性能改进将在未来几年内导致 PHP 5 在各个层面得到广泛接受。这就需要我们开始熟悉今天在这个版本中可用的所有高级功能。

# 本书涵盖内容

第一章概述了 PDO 以及一些功能，比如创建连接的单一接口、连接字符串、统一的语句方法以及异常的使用和单一的错误代码系统。

第二章帮助您开始使用 PDO，通过创建一个示例数据库，然后创建一个连接对象。它还介绍了 PDOStatement 类。

第三章涉及各种错误处理过程及其用途。

第四章介绍了准备好的语句。它涉及在不绑定值的情况下使用准备好的语句，绑定变量以及将参数绑定到准备好的语句。我们还看一下如何使用流处理 BLOB，以便我们不会出现查询失败的风险。

第五章帮助我们确定返回结果集中的行数。此外，我们还遇到了一个新概念——可滚动的游标，它允许我们从结果集中获取子集行。

第六章讨论了 PDO 的高级用法，包括设置连接参数、事务以及`PDO`和`PDOStatement`类的方法。

第七章给出了一个例子，讨论了 MVC 应用程序的方法部分的创建。

附录 A 解释了面向对象的特性，比如继承、封装、多态和异常处理。

# 本书的目标读者

本书面向考虑迁移到 PHP 5 并使用新的数据库连接抽象库 PHP 数据对象的 PHP 程序员。虽然 PDO 是完全面向对象的，但需要熟悉这种编程范式。不熟悉 PHP 5 面向对象特性的初学者可能会考虑先阅读附录 A，以便能够跟随本书中的代码示例。

我们假设读者熟悉 SQL，能够创建表并进行简单的 SELECT 查询和更新。我们的示例基于 MySQL 和 SQLite 数据库，因为它们是最常用的选项，也是大多数廉价托管提供商提供的唯一选项。

本书末尾将呈现一个更高级的例子，可能会引起对 SQL 和编程概念有更深入了解的专业程序员的兴趣。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些样式的示例，以及它们的含义解释。

代码有三种样式。文本中的代码单词显示如下："PostgreSQL 用户可能已经使用了`pg_prepare()`和`pg_execute()`对。"

代码块将设置如下：

```php
// Assume we also want to filter by make
$sql = 'SELECT * FROM cars WHERE make=?';
$stmt = $conn->prepare($sql);
$stmt->execute(array($_REQUEST['make']));

```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将被加粗：

```php
// Assume we also want to filter by make
$sql = 'SELECT * FROM cars WHERE make=?';
**$stmt = $conn->prepare($sql);**
$stmt->execute(array($_REQUEST['make']));

```

**新术语**和**重要单词**以粗体字体介绍。您在屏幕上看到的单词，比如菜单或对话框中的单词，在我们的文本中会出现如下："您可以在浏览器中的图书列表页面上简单点击**作者**链接"。

### 注意

重要提示会以这样的框出现。

### 注意

提示和技巧会出现在这样的形式中。


# 第一章：介绍

**PHP 数据对象**（**PDO**）是一个 PHP5 扩展，定义了一个轻量级的数据库连接抽象库（有时称为数据访问抽象库）。对于像 PDO 这样的工具的需求是由 PHP 支持的大量数据库系统所决定的。这些数据库系统中的每一个都需要一个单独的扩展，为执行相同的任务定义自己的 API，从建立连接到准备语句和错误处理等高级功能。

这些 API 不统一的事实使得在底层数据库之间的转换痛苦，通常导致许多代码行的重写，进而导致需要时间来跟踪、调试和纠正新的编程错误。另一方面，缺乏像 Java 的 JDBC 那样的统一库，使得 PHP 在编程语言世界中落后于大型玩家。现在有了这样的库，PHP 正在重新夺回其地位，并成为数百万程序员的首选平台。

然而，值得注意的是，存在一些用 PHP 编写的库，用于与 PDO 具有相同的目的。最流行的是 ADOdb 库和 PEAR DB 包。它们与 PDO 之间的关键区别在于速度。PDO 是用编译语言（C/C++）编写的 PHP 扩展，而 PHP 库是用解释语言编写的。此外，一旦启用 PDO，它就不需要您在脚本中包含源文件并将其与应用程序一起重新分发。这使得安装您的应用程序更容易，因为最终用户不需要关心第三方软件。

### 注意

在这里，我们既不比较这些库与 PDO，也不主张使用 PDO 取代这些库。我们只是展示这个扩展的优缺点。例如，PEAR 包 MDB2 具有更丰富的功能，是一个高级的数据库抽象库，而 PDO 没有。

PDO 作为一个 PECL 扩展，本身依赖于特定于数据库的驱动程序和其他 PECL 扩展。这些驱动程序也必须安装才能使用 PDO（您只需要用于您正在使用的数据库的驱动程序）。由于安装 PDO 和特定于数据库的驱动程序的描述超出了本书的范围，您可以参考 PHP 手册[www.php.net/pdo](http://www.php.net/pdo)获取有关安装和升级问题的技术信息。

### 注意

PECL 是 PHP 扩展社区库，一个用 C 语言编写的 PHP 扩展库。这些扩展提供了在 PHP 中无法实现的功能，以及一些出于性能原因存在的扩展，因为 C 代码比 PHP 快得多。PECL 的主页位于[`pecl.php.net`](http://pecl.php.net)

# 使用 PDO

正如前一节中所指出的，PDO 是一个连接或数据访问抽象库。这意味着 PDO 定义了一个统一的接口，用于创建和维护数据库连接，发出查询，引用参数，遍历结果集，处理准备好的语句和错误处理。

我们将在这里简要概述这些主题，并在接下来的章节中更详细地讨论它们。

## 连接到数据库

让我们考虑一下著名的 MySQL 连接场景：

```php
mysql_connect($host, $user, $password);
mysql_select_db($db);

```

在这里，我们建立一个连接，然后选择连接的默认数据库。（我们忽略可能出现的错误。）

例如，在 SQLite 中，我们会写出以下内容：

```php
$dbh = sqlite_open($db, 0666);

```

在这里我们再次忽略错误（稍后我们将更多地涵盖这一点）。为了完整起见，让我们看看如何连接到 PostgreSQL：

pg_connect("host=$host dbname=$db user=$user password=$password");

正如您所看到的，所有三个数据库都需要完全不同的方式来打开连接。虽然现在这不是问题，但如果您总是使用相同的数据库管理系统，以防需要迁移，您将不得不重写您的脚本。

现在，让我们看看 PDO 提供了什么。由于 PDO 是完全面向对象的，我们将处理**连接对象**，与数据库的进一步交互将涉及调用这些对象的各种方法。上面的示例暗示了需要类似于这些连接对象的东西——调用`mysql_connect`或`pg_connect`返回链接标识符和特殊类型的 PHP 变量：**resource**。然而，我们当时没有使用连接对象，因为这两个数据库 API 不要求我们在脚本中只有一个连接时显式使用它们。然而，SQLite 始终需要一个链接标识符。

使用 PDO，我们将始终必须显式使用连接对象，因为没有其他调用其方法的方式。（不熟悉面向对象编程的人应参考附录 A）。

上述三个连接可以以以下方式建立：

```php
// For MySQL:
$conn = new PDO("mysql:host=$host;dbname=$db", $user, $pass);
// For SQLite:
$conn = new PDO("sqlite:$db");
// And for PostgreSQL:
$conn = new PDO("pgsql:host=$host dbname=$db", $user, $pass);

```

正如你所看到的，这里唯一变化的部分是传递给 PDO 构造函数的第一个参数。对于 SQLite，不使用用户名和密码，第二和第三个参数可以省略。

### 注意

SQLite 不是一个数据库服务器，而是一个嵌入式 SQL 数据库库，它在本地文件上运行。有关 SQLite 的更多信息可以在[www.sqlite.org](http://www.sqlite.org)找到，有关使用 SQLite 与 PHP 的更多信息可以在[www.php.net/sqlite](http://www.php.net/sqlite)找到。有关使用 PDO 与 SQLite 的信息可以从[www.php.net/manual/en/ref.pdo-sqlite.php](http://www.php.net/manual/en/ref.pdo-sqlite.php)获取。

## 连接字符串

正如你在前面的示例中看到的，PDO 使用所谓的**连接字符串**（或数据源名称，缩写为 DSN），允许 PDO 构造函数选择适当的驱动程序并将后续方法调用传递给它。这些连接字符串或 DSN 对于每个数据库管理系统都是不同的，是你唯一需要更改的东西。

如果你正在设计一个能够与不同数据库一起工作的大型应用程序，那么这个连接字符串（连同连接用户名和密码）可以在配置文件中定义，并以后以以下方式使用（假设你的配置文件类似于`php.ini`）。

```php
$config = parse_ini_file($pathToConfigFile);
$conn = new PDO($config['db.conn'], $config['db.user'],
$config['db.pass']);

```

然后你的配置文件可能如下所示：

```php
db.conn="mysql:host=localhost;dbname=test"
db.user="johns"
db.pass="mypassphrase"

```

我们将在第二章中更详细地介绍连接字符串；在这里，我们给出了一个快速示例，以便你可以看到使用 PDO 连接到不同数据库系统有多么容易。

## 发出 SQL 查询、引用参数和处理结果集

如果 PDO 没有超越创建数据库连接的单一接口，那么它就不值得写一本书。在前面的示例中介绍的 PDO 对象具有统一执行查询所需的所有方法，而不管使用的是哪种数据库。

让我们考虑一个简单的查询，它将从一个虚构的二手车停车场所使用的数据库中选择所有汽车的`make`属性。查询就像下面的 SQL 命令一样简单：

```php
SELECT DISTINCT make FROM cars ORDER BY make;

```

以前，我们必须调用不同的函数，这取决于数据库：

```php
// Let's keep our SQL in a single variable
$sql = 'SELECT DISTINCT make FROM cars ORDER BY make';
// Now, assuming MySQL:
mysql_connect('localhost', 'boss', 'password');
mysql_select_db('cars');
$q = mysql_query($sql);
// For SQLite we would do:
$dbh = sqlite_open('/path/to/cars.ldb', 0666);
$q = sqlite_query($sql, $dbh);
// And for PostgreSQL:
pg_connect("host=localhost dbname=cars user=boss
password=password");
$q = pg_query($sql);

```

现在我们使用 PDO，可以这样做：

```php
// assume the $connStr variable holds a valid connection string
// as discussed in previous point
$sql = 'SELECT DISTINCT make FROM cars ORDER BY make';
$conn = new PDO($connStr, 'boss', 'password');
$q = $conn->query($sql);

```

如你所见，用 PDO 的方式并不太不同于发出查询的传统方法。此外，这里应该强调的是，对`$conn->query()`的调用返回`PDOStatement`类的另一个对象，而不像对`mysql_query()`、`sqlite_query()`和`pg_query()`的调用，它们返回 PHP 变量的**resource**类型。

现在，让我们将我们简单的 SQL 查询变得更加复杂，以便它选择我们想象中汽车停车场上所有福特车的总价值。查询看起来会像这样：

```php
SELECT sum(price) FROM cars WHERE make='Ford'

```

为了使我们的示例更加有趣，让我们假设汽车制造商的名称保存在一个变量（$make）中，这样我们必须在传递给数据库之前对其进行引用。我们的非 PDO 查询现在看起来像这样：

```php
$make = 'Ford';
// MySQL:
$m = mysql_real_escape_string($make);
$q = mysql_query("SELECT sum(price) FROM cars WHERE make='$m'");
// SQLite:
$m = sqlite_escape_string($make);
$q = sqlite_query("SELECT sum(price) FROM cars WHERE make='$m'",
$dbh);
// and PostgreSQL:
$m = pg_escape_string($make);
$q = pg_query("SELECT sum(price) FROM cars WHERE make='$m'");

```

PDO 类定义了一个用于引用字符串的方法，以便它们可以安全地用于查询。我们将在第三章中讨论诸如 SQL 注入之类的安全问题。这个方法做了一个很好的事情；如果有必要，它会自动在值周围添加引号：

```php
$m = $conn->quote($make);
$q = $conn->query("SELECT sum(price) FROM cars WHERE make=$m");

```

再次，您可以看到 PDO 允许您使用与以前相同的模式，但所有方法的名称都是统一的。

现在我们已经发出了查询，我们将想要查看其结果。由于上一个示例中的查询总是只返回一行，我们将想要更多行。同样，这三个数据库将要求我们在从`mysql_query(), sqlite_query()`或`pg_query()`中返回的`$q`变量上调用不同的函数。因此，我们获取所有汽车的代码将类似于这样：

```php
// assume the query is in the $sql variable
$sql = "SELECT DISTINCT make FROM cars ORDER BY make";
// For MySQL:
$q = mysql_query($sql);
while($r = mysql_fetch_assoc($q))
{
echo $r['make'], "\n";
}
// For SQLite:
$q = sqlite_query($dbh, $sql);
while($r = sqlite_fetch_array($q, SQLITE_ASSOC))
{
echo $r['make'], "\n";
}
// and, finally, PostgreSQL:
$q = pg_query($sql);
while($r = pg_fetch_assoc($q))
{
echo $r['make'], "\n";
}

```

正如你所看到的，想法是一样的，但我们必须使用不同的函数名。另外，需要注意的是，如果我们想以与 MySQL 和 PostgreSQL 相同的方式获取行，SQLite 需要一个额外的参数（当然，这可以省略，但返回的行将包含列名索引和数字索引的元素。）

正如您可能已经猜到的那样，当涉及到 PDO 时，事情变得非常简单：我们不关心底层数据库是什么，获取行的方法在所有数据库中都是相同的。因此，上面的代码可以以以下方式重写为 PDO：

```php
$q = $conn->query("SELECT DISTINCT make FROM cars ORDER BY make");
while($r = $q->fetch(PDO::FETCH_ASSOC))
{
echo $r['make'], "\n";
}

```

之前发生的事情与以往无异。这里需要注意的一点是，我们在这里明确指定了`PDO::FETCH_ASSOC`的获取样式常量，因为 PDO 的默认行为是将结果行作为数组索引，既按列名又按数字索引。（这种行为类似于`mysql_fetch_array(), sqlite_fetch_array()`没有第二个参数，或者`pg_fetch_array()`。）我们将在第二章中讨论 PDO 提供的获取样式。

### 注意

最后一个示例并不是用于呈现 HTML 页面，因为它使用换行符来分隔输出行。要在真实的网页中使用它，您需要将`echo $r['make'], "\n"`;更改为`echo $r['make'], "<br>\n"`;

## 错误处理

当然，上面的示例没有提供任何错误检查，因此对于实际应用程序来说并不是非常有用。

在与数据库一起工作时，我们应该在打开数据库连接时，选择数据库时以及发出每个查询后检查错误。然而，大多数 Web 应用程序只需要在出现问题时显示错误消息（而不需要详细的错误信息，这可能会泄露一些敏感信息）。但是，在调试错误时，您（作为开发人员）需要尽可能详细的错误信息，以便您可以在最短的时间内调试错误。

一个简单的情景是中止脚本并呈现错误消息（尽管这可能不是你想要做的）。根据数据库的不同，我们的代码可能如下所示：

```php
// For SQLite:
$dbh = sqlite_open('/path/to/cars.ldb', 0666) or die
('Error opening SQLite database: ' .
sqlite_error_string(sqlite_last_error($dbh)));
$q = sqlite_query("SELECT DISTINCT make FROM cars ORDER BY make",
$dbh) or die('Could not execute query because: ' .
sqlite_error_string(sqlite_last_error($dbh)));
// and, finally, for PostgreSQL:
pg_connect("host=localhost dbname=cars user=boss
password=password") or die('Could not connect to
PostgreSQL: . pg_last_error());
$q = pg_query("SELECT DISTINCT make FROM cars ORDER BY make")
or die('Could not execute query because: ' . pg_last_error());

```

如您所见，与 MySQL 和 PostgreSQL 相比，对于 SQLite 来说，错误处理开始有点不同。（请注意调用`sqlite_error_string (sqlite_last_error($dbh)).)`)

在我们看如何使用 PDO 实现相同的错误处理策略之前，我们应该注意，这将是 PDO 中三种可能的错误处理策略之一。我们将在本书的后面详细介绍它们。在这里，我们将只使用最简单的一个：

```php
// PDO error handling
// Assume the connection string is one of the following:
// $connStr = 'mysql:host=localhost;dbname=cars'
// $connStr = 'sqlite:/path/to/cars.ldb';
// $connStr = 'pgsql:host=localhost dbname=cars';
try
{
$conn = new PDO($connStr, 'boss', 'password');
}
catch(PDOException $pe)
{
die('Could not connect to the database because: ' .
$pe->getMessage();
}
$q = $conn->query("SELECT DISTINCT make FROM cars ORDER BY make");
if(!$q)
{
$ei = $conn->errorInfo();
die('Could not execute query because: ' . $ei[2]);
}

```

这个例子表明，PDO 会强制我们使用与传统错误处理方案略有不同的方案。我们将对 PDO 构造函数的调用包装在*try* … *catch*块中。（那些对 PHP5 的面向对象特性不熟悉的人应该参考附录 A。）这是因为虽然 PDO 可以被指示不使用异常（事实上，PDO 的默认行为是不使用异常），但是在这里你无法避免异常。如果构造函数调用失败，异常将总是被抛出。

捕获这个异常是一个非常好的主意，因为默认情况下，PHP 会中止脚本执行，并显示这样的错误消息：

**致命错误：未捕获的异常'PDOException'，消息为'SQLSTATE[28000] [1045] 用户'bosss'@'localhost'被拒绝访问（使用密码：YES）'，位于/var/www/html/pdo.php5:3 堆栈跟踪：#0 c:\www\hosts\localhost\pdo.php5(3)：PDO->__construct('mysql:host=loca...', 'bosss', 'password', Array) #1 {main} 在/var/www/html/pdo.php5 的第 3 行抛出**

我们通过在对 PDO 构造函数的调用中提供错误的用户名*bosss*来制造了这个异常。正如你从这个输出中看到的，它包含了一些我们不希望其他人看到的细节：像文件名和脚本路径，正在使用的数据库类型，最重要的是用户名和密码。假设这个异常发生在我们提供了正确的用户名并且数据库服务器出了问题的情况下。那么屏幕输出将包含真实的用户名和密码。

如果我们正确捕获异常，错误输出可能会像这样：

**SQLSTATE[28000] [1045] 用户'bosss'@'localhost'被拒绝访问（使用密码：YES）**

这个错误消息包含了更少的敏感信息。（事实上，这个输出与我们的非 PDO 示例中产生的错误输出非常相似。）但我们再次警告您，最好的策略是只显示一些中立的错误消息，比如：“抱歉，服务暂时不可用。请稍后再试。”当然，您还应该记录所有错误，以便以后找出是否发生了任何不好的事情。

## **预处理语句**

这是一个相当高级的话题，但你应该熟悉它。如果你是一个使用 PHP 与 MySQL 或 SQLite 的用户，那么你可能甚至没有听说过预处理语句，因为 PHP 的 MySQL 和 SQLite 扩展不提供这个功能。PostgreSQL 用户可能已经使用了`pg_prepare()`和`pg_execute()`。MySQLi（改进的 MySQL 扩展）也提供了预处理语句功能，但方式有些别扭（尽管可能是面向对象的风格）。

对于那些不熟悉**预处理语句**的人，我们现在将给出一个简短的解释。

当开发基于数据库的交互式动态应用程序时，您迟早会需要接受用户输入（可能来自表单），并将其作为查询的一部分传递给数据库。例如，给定我们的汽车数据库，您可能设计一个功能，将输出在任意两年之间制造的汽车列表。如果允许用户在表单中输入这些年份，代码将看起来像这样：

```php
// Suppose the years come in the startYear and endYear
// request variables:
$sy = (int)$_REQUEST['startYear'];
$ey = (int)$_REQUEST['endYear'];
if($ey < $sy)
{
// ensure $sy is less than $ey
$tmp = $ey;
$ey = $sy;
$sy = $tmp;
}
$sql = "SELECT * FROM cars WHERE year >= $sy AND year <= $ey";
// send the query in $sql…

```

在这个简单的例子中，查询依赖于两个变量，这些变量是结果 SQL 的一部分。在 PDO 中，相应的预处理语句看起来像这样：

```php
$sql = 'SELECT * FROM cars WHERE year >= ? AND year <= ?';

```

正如你所看到的，我们在查询体中用占位符替换了`$sy`和`$ey`变量。现在我们可以操作这个查询来创建预处理语句并执行它：

```php
// Assuming we have already connected and prepared
// the $sy and $ey variables
$sql = 'SELECT * FROM cars WHERE year >= ? AND year <= ?';
$stmt = $conn->prepare($sql);
$stmt->execute(array($sy, $ey));

```

这三行代码告诉我们，预处理语句是对象（具有类`PDOStatement`）。它们是使用调用`PDO::prepare()`方法创建的，该方法接受带有占位符的 SQL 语句作为其参数。

然后必须*执行*准备好的语句，以通过调用`PDOStatement::execute()`方法获取查询结果。正如示例所示，我们使用一个包含占位符值的数组来调用这个方法。请注意，该数组中变量的顺序与`$sql`变量中占位符的顺序相匹配。显然，数组中的元素数量必须与查询中占位符的数量相同。

您可能已经注意到，我们没有将对`PDOStatement::execute()`方法的调用结果保存在任何变量中。这是因为语句对象本身用于访问查询结果，这样我们就可以将我们的示例完善成这样：

```php
// Suppose the years come in the startYear and endYear
// request variables:
$sy = (int)$_REQUEST['startYear'];
$ey = (int)$_REQUEST['endYear'];
if($ey < $sy)
{
// ensure $sy is less than $ey
$tmp = $ey;
$ey = $sy;
$sy = $tmp;
}
$sql = 'SELECT * FROM cars WHERE year >= ? AND year <= ?';
$stmt = $conn->prepare($sql);
$stmt->execute(array($sy, $ey));
// now iterate over the result as if we obtained
// the $stmt in a call to PDO::query()
while($r = $stmt->fetch(PDO::FETCH_ASSOC))
{
echo "$r[make] $r[model] $r[year]\n";
}

```

正如这个完整的示例所示，我们调用`PDOStatement::fetch()`方法，直到它返回 false 值为止，此时循环退出——就像我们在讨论结果集遍历时的先前示例中所做的那样。

当然，用实际值替换问号占位符并不是准备好的语句唯一能做的事情。它们的强大之处在于可以根据需要执行多次。这意味着我们可以调用`PDOStatement::execute()`方法多次，每次都可以为占位符提供不同的值。例如，我们可以这样做：

```php
$sql = 'SELECT * FROM cars WHERE year >= ? AND year <= ?';
$stmt = $conn->prepare($sql);
// Fetch the 'new' cars:
$stmt->execute(array(2005, 2007));
$newCars = $stmt->fetchAll(PDO::FETCH_ASSOC);
// now, 'older' cars:
$stmt->execute(array(2000, 2004));
$olderCars = $stmt->fetchAll(PDO::FETCH_ASSOC);
// Show them
echo 'We have ', count($newCars), ' cars dated 2005-2007';
print_r($newCars);
echo 'Also we have ', count($olderCars), ' cars dated 2000-2004';
print_r($olderCars);

```

准备好的语句执行起来比调用`PDO::query()`方法要快，因为数据库驱动程序只会在调用`PDO::prepare()`方法时对它们进行优化一次。使用准备好的语句的另一个优点是，您不必引用在调用`PDOStatement::execute()`时传递的参数。

在我们的示例中，我们将请求参数显式转换为整数变量，但我们也可以这样做：

```php
// Assume we also want to filter by make
$sql = 'SELECT * FROM cars WHERE make=?';
$stmt = $conn->prepare($sql);
$stmt->execute(array($_REQUEST['make']));

```

这里的准备好的语句将负责在执行查询之前进行适当的引用。

最重要的一点是，PDO 为每个支持的数据库模拟了准备好的语句。这意味着您可以在任何数据库中使用准备好的语句；即使它们不知道这是什么。

## 对 PDO 的适当理解

如果我们不提到这一点，我们的介绍就不完整了。PDO 是一个数据库连接抽象库，因此不能保证您的代码对其支持的每个数据库都有效。只有当您的 SQL 代码是可移植的时，才会发生这种情况。例如，MySQL 使用以下形式的插入扩展了 SQL 语法：

```php
INSERT INTO mytable SET x=1, y='two';

```

这种 SQL 代码是不可移植的，因为其他数据库不理解这种插入方式。为了确保您的插入在各个数据库中都能正常工作，您应该用以下代码替换上面的代码：

```php
INSERT INTO mytable(x, y) VALUES(1, 'two');

```

这只是使用 PDO 时可能出现的不兼容性的一个例子。只有通过使数据库架构和 SQL 可移植，才能确保您的代码与其他数据库兼容。然而，确保这种可移植性超出了本文的范围。

# 总结

这个介绍性的章节向您展示了在使用 PHP5 语言开发动态、数据库驱动应用程序时使用 PDO 的基础知识。我们还看到了 PDO 如何有效地消除了不同传统数据库访问 API 之间的差异，并产生了更清晰、更可移植的代码。

在接下来的章节中，我们将更详细地讨论本章讨论的每个功能，以便您完全掌握 PHP 数据对象扩展。


# 第二章：使用 PHP 数据对象：第一步

在上一章中，我们简要概述了 PDO 是什么，如何使用 PDO 连接到您喜欢的数据库，如何发出简单的查询以及如何处理错误。现在您已经确信 PDO 是一个好东西，并且正在考虑积极使用它，我们将深入了解它所提供的所有功能。

在本章中，我们将更仔细地研究使用 PDO 和连接字符串（数据源名称）创建数据库连接，`PDOStatement`类以及如何遍历结果集。我们还将创建一个小型的图书管理应用程序，它将允许我们管理您家中图书的收藏。该应用程序将能够列出书籍和作者，并添加和编辑它们。

我们将首先看一下连接字符串，因为没有它们，我们将无法连接到任何数据库。然后我们将创建一个示例数据库，本书中的所有示例都将基于此数据库。

我们将离开简单的、想象中的汽车数据库，并创建一个真正的工作数据库，其中包含几个表。但是，现在我们将处理书籍和作者的经典示例。我们选择这个例子是因为这样的实体更常见。关系模型将相对简单，这样您就可以轻松地跟随示例，如果您已经在其他地方遇到过这样的数据库。

# 连接字符串

连接字符串或数据源名称（在 PDO 文档中称为 DSN）是 PHP 字符串，其中包含数据库管理系统的名称和数据库本身的名称，以及其他连接参数。

它们相对于使用传统的方法创建数据库连接的优势在于，如果更改数据库管理系统，您无需修改代码。连接字符串可以在配置文件中定义，并且该文件由您的应用程序处理。如果您的数据库（数据源）更改，您只需编辑该配置文件，其余代码将保持完整。

由于不同的数据库管理系统的存在，PDO 中使用的连接字符串不同。但是，它们始终具有一个共同的前缀，表示底层数据库驱动程序。请记住第一章中的 MySQL、SQLite 和 PostgreSQL 示例。三个连接字符串看起来像下面这样：

```php
mysql:host=localhost;dbname=cars
sqlite:/path/to/cars.db
pgsql:host=localhost dbname=cars

```

如我们所见，前缀（第一个分号之前的子字符串）始终保留 PDO 驱动程序的名称。由于我们不必使用不同的函数来创建与 PDO 的连接，这个前缀告诉我们应该使用哪个内部驱动程序。字符串的其余部分由该驱动程序解析以进一步初始化连接。在这些情况下，我们提供了数据库名称；对于 MySQL 和 PostgreSQL；我们还提供了服务器运行的主机名。（由于 SQLite 是一个本地数据库引擎，这样的参数是没有意义的。）

如果您想指定其他参数，您应该查阅您的数据库手册（[www.php.net/pdo](http://www.php.net/pdo)始终是一个很好的起点）。例如，MySQL PDO 驱动程序理解以下参数：

+   **host** - 服务器运行的主机名（在我们的示例中为*localhost*）

+   **port** - 数据库服务器正在侦听的端口号（默认为*3306*）

+   **dbname** - 数据库的名称（在我们的示例中为*cars*）

+   **unix_socket** - MySQL 的 UNIX 套接字（而不是主机和/或端口）。

### 注意

`SQLite:`前缀表示连接到 SQLite 3 数据库。要连接到 SQLite 2 数据库，您必须使用`SQLite2:`前缀。有关详细信息，请参阅[`www.php.net/manual/en/ref.pdo-sqlite.connection.php`](http://www.php.net/manual/en/ref.pdo-sqlite.connection.php)。

正如您可能已经注意到的，不同的驱动程序使用不同的字符来分隔参数——例如 MySQL 中的分号和 PostgreSQL 中的空格。

## 创建示例数据库

假设您在家里有一个很好的图书馆，您希望计算机帮助您管理它。您决定使用 PHP 和当然 PDO 创建一个基于 Web 的数据库。从现在开始，示例将是针对 MySQL 和 SQLite 数据库的。

### 数据模型

由于我们的数据库非常简单，因此我们只会在其中有两个实体：作者和书籍。因此，我们将创建两个同名的表。现在，让我们考虑每个实体将具有哪些属性。

作者将有他们的名字、姓氏和简短的传记。表格将需要一个我们称之为*id*的主键。我们将使用它来从`books`表中引用作者。

书是由作者写的。（有时它们是由多位作者写的，但我们将在这里只考虑由一位作者写的书。）因此，我们将需要一个字段来存储作者的 ID，以及书的标题、ISBN 号、出版商名称和出版年份。此外，我们将包括书的简短摘要。

我们需要一个单独的作者表，因为一个作者可能写了多本书。否则，我们的示例将非常简单！因此，我们选择了一个两表数据库结构。如果我们考虑由多位作者编写的书籍，我们将需要三个表，这将使示例变得非常复杂。

### 创建 MySQL 数据库

当您启动了 MySQL 命令行客户端后，您将看到`mysql>`提示符，您可以在其中发出命令来创建数据库和其中的表：

```php
mysql> create database pdo;
Query OK, 1 row affected (0.05 sec)
mysql> use pdo;
Database changed
mysql> create table books(
-> id int primary key not null auto_increment,
-> author int not null,
-> title varchar(70) not null,
-> isbn varchar(20),
-> publisher varchar(30) not null,
-> year int(4) not null,
-> summary text(2048));
Query OK, 0 rows affected (0.17 sec)
mysql> create table authors(
-> id int primary key not null auto_increment,
-> firstName varchar(30) not null,
-> lastName varchar(40) not null,
-> bio text(2048));
Query OK, 0 rows affected (0.00 sec)

```

如您所见，我们已经创建了一个名为`pdo`的数据库。我们还创建了两个表：books 和 authors，就像我们计划的那样。现在让我们看看如何在 SQLite 中做到这一点。由于我们无法在 SQLite 命令行客户端内创建数据库，我们会这样启动它：

```php
> sqlite3 pdo.db
sqlite> create table books(
...> id integer primary key,
...> author integer(11) not null,
...> title varchar(70) not null,
...> isbn varchar(20),
...> publisher varchar(30) not null,
...> year integer(4) not null,
...> summary text(2048));
sqlite> create table authors(
...> id integer(11) primary key,
...> firstName varchar(30) not null,
...> lastName varchar(40) not null,
...> bio text(2048));

```

如您所见，SQLite 的 SQL 略有不同——主键声明时没有`NOT NULL`和`auto_increment`选项。在 SQLite 中，声明为`INTEGER PRIMARY KEY`的列会自动递增。现在让我们向数据库插入一些值。MySQL 和 SQLite 的语法将是相同的，所以这里我们只呈现 MySQL 命令行客户端的示例。我们将从作者开始，因为我们需要他们的主键值来插入到书籍表中：

```php
mysql> insert into authors(firstName, lastName, bio) values(
-> 'Marc', 'Delisle', 'Marc Delisle is a member of the MySQL
Developers Guide');
Query OK, 1 row affected (0.14 sec)
mysql> insert into authors(firstName, lastName, bio) values(
-> 'Sohail', 'Salehi', 'In recent years, Sohail has contributed
to over 20 books, mainly in programming and computer graphics');
Query OK, 1 row affected (0.00 sec)
mysql> insert into authors(firstName, lastName, bio) values(
-> 'Cameron', 'Cooper', 'J. Cameron Cooper has been playing
around on the web since there was not much of a web with which to
play around');
Query OK, 1 row affected (0.00 sec)

```

现在我们已经插入了三位作者，让我们添加一些书籍。但在这样做之前，我们应该知道哪个*作者*有哪个*id*。一个简单的`SELECT`查询将帮助我们：

```php
mysql> select id, firstName, lastName from authors;
+----+-----------+----------+
| id | firstName | lastName |
+----+-----------+----------+
| 1 | Marc | Delisle |
| 2 | Sohail | Salehi |
| 3 | Cameron | Cooper |
+----+-----------+----------+
3 rows in set (0.03 sec)

```

现在我们终于可以使用这些信息添加三本书，每本书都是由这些作者中的一位写的：

```php
mysql> insert into books(author, title, isbn, publisher, year, summary) values(
-> 1, 'Creating your MySQL Database: Practical Design Tips and
Techniques', '1904811302', 'Packt Publishing Ltd', '2006',
-> 'A short guide for everyone on how to structure your data and
set-up your MySQL database tables efficiently and easily.');
Query OK, 1 row affected (0.00 sec)
mysql> insert into books(author, title, isbn, publisher, year, summary) values(
-> 2, 'ImageMagick Tricks', '1904811868', 'Packt Publishing
Ltd', '2006',
-> 'Unleash the power of ImageMagick with this fast, friendly
tutorial, and tips guide');
Query OK, 1 row affected (0.02 sec)
mysql> insert into books(author, title, isbn, publisher, year,
summary) values(
-> 3, 'Building Websites with Plone', '1904811027', 'Packt
Publishing Ltd', '2004',
-> 'An in-depth and comprehensive guide to the Plone content
management system');
Query OK, 1 row affected (0.00 sec)

```

现在我们已经填充了`authors`和`books`表，我们可以开始创建我们小型图书馆管理网络应用的第一个页面。

### 注意

所使用的数据基于由 Packt Publishing Ltd 出版的真实书籍（这是为您带来正在阅读的这本书的出版商）。要了解更多信息，请访问他们的网站[`www.packtpub.com`](http://www.packtpub.com)

# 设计我们的代码

良好的应用架构是应用的另一个关键因素，除了正确的数据模型。由于我们将在本章开发的应用程序相对较小，因此这项任务并不是很复杂。首先，我们将创建两个页面，分别列出书籍和作者。首先，我们应该考虑这些页面的外观。为了使我们的简单示例小巧紧凑，我们将在所有页面上呈现一个标题，其中包含指向书籍列表和作者列表的链接。稍后，我们将添加另外两个页面，允许我们添加作者和书籍。

当然，我们应该创建一个通用的包含文件，用于定义共同的函数，如标题和页脚显示以及与数据库的连接。我们的示例非常小，因此我们将不使用任何模板系统甚至面向对象的语法。（事实上，这些主题超出了本书的范围。）因此，总结一下：

+   所有通用函数（包括创建 PDO 连接对象的代码）将保存在一个包含文件中（称为`common.inc.php`）。

+   每个页面将保存在一个单独的文件中，其中包括`common.inc.php`文件。

+   每个页面将处理数据并显示数据（因此我们没有数据处理和数据呈现的分离，这是人们从设计为模型-视图-控制器模式的应用程序所期望的）。

现在我们有了这个小计划，我们可以开始编写我们的`common.inc.php`文件。正如我们刚刚讨论的，目前，它将包含显示页眉和页脚的函数，以及创建连接对象的代码。让我们将 PDO 对象保存在一个名为`$conn`的全局变量中，并调用我们的页眉函数`showHeader()`，页脚函数`showFooter()`。此外，我们将在这个包含文件中保留数据库连接字符串、用户名和密码：

```php
<?php
/**
* This is a common include file
* PDO Library Management example application
* @author Dennis Popel
*/
// DB connection string and username/password
$connStr = 'mysql:host=localhost;dbname=pdo';
$user = 'root';
$pass = 'root';
/**
* This function will render the header on every page,
* including the opening html tag,
* the head section and the opening body tag.
* It should be called before any output of the
* page itself.
* @param string $title the page title
*/
function showHeader($title)
{
?>
<html>
<head><title><?=htmlspecialchars($title)?></title></head>
<body>
<h1><?=htmlspecialchars($title)?></h1>
<a href="books.php">Books</a>
<a href="authors.php">Authors</a>
<hr>
<?php
}
/**
* This function will 'close' the body and html
* tags opened by the showHeader() function
*/
function showFooter()
{
?>
</body>
</html>
<?php
}
// Create the connection object
$conn = new PDO($connStr, $user, $pass);

```

正如你所看到的，这个文件非常简单，你只需要更改`$user`和`$pass`变量的值（第 9 行和第 10 行）以匹配你的设置。对于 SQLite 数据库，你还需要更改第 8 行，使其包含一个适当的连接字符串，例如：

```php
$connStr = 'sqlite:/www/hosts/localhost/pdo.db';

```

当然，你应该根据你创建 SQLite 数据库的路径进行更改。此外，`showHeader()`函数只是呈现 HTML 代码，并通过`htmlspecialchars()`函数传递`$title`变量的值，以便任何非法字符（如小于号）都能得到适当的转义。

将文件保存到您的 Web 根目录。这取决于您的 Web 服务器设置。例如，它可以是`C:\Apache\htdocs`或`/var/www/html`。

现在，让我们创建一个列出书籍的页面。我们将发出查询，然后遍历结果，以呈现每本书的单独行。稍后，我们将创建一个页面，列出我们之前创建的数据库中的所有作者。完成这项任务后，我们将查看结果集遍历。

让我们称我们的文件为`books.php`并创建代码：

```php
<?php
/**
* This page lists all the books we have
* PDO Library Management example application
* @author Dennis Popel
*/
// Don't forget the include
include('common.inc.php');
// Issue the query
$q = $conn->query("SELECT * FROM books ORDER BY title");
// Display the header
showHeader('Books');
// now create the table
?>
<table width="100%" border="1" cellpadding="3">
<tr style="font-weight: bold">
<td>Title</td>
<td>ISBN</td>
<td>Publisher</td>
<td>Year</td>
<td>Summary</td>
</tr>
<?php
// Now iterate over every row and display it
while($r = $q->fetch(PDO::FETCH_ASSOC))
{
?>
<tr>
<td><?=htmlspecialchars($r['title'])?></td>
<td><?=htmlspecialchars($r['isbn'])?></td>
<td><?=htmlspecialchars($r['publisher'])?></td>
<td><?=htmlspecialchars($r['year'])?></td>
<td><?=htmlspecialchars($r['summary'])?></td>
</tr>
<?php
}
?>
</table>
<?php
// Display footer
showFooter();

```

这个文件应该保存在`common.inc.php`文件所在的目录中。正如你所看到的，代码中有更多的注释和 HTML，但这里没有什么非常复杂的东西。正如我们之前决定的，代码包括`common.inc.php`文件，然后呈现页面页眉，在第 10 行发出查询，呈现表头，最后遍历结果集中的每一行，输出每本书的详细信息。

就像在第一章中一样，我们使用`PDOStatement`对象的`fetch()`方法（保存在`$q`变量中）在`while`行中遍历结果集。我们指示该方法返回由表列名称索引的数组行（通过指定`PDO::FETCH_ASSOC`参数）。

在循环内，我们呈现每一行的 HTML，插入表中的列。循环结束后，我们关闭表并显示页脚。

现在是测试我们第一个 PDO 驱动的应用程序的时候了。打开你的浏览器，转到`http://localhost/books.php`。如果你做得正确（这样你的 Web 服务器和数据库都正确设置），你应该看到一个类似下面截图的表格（尽管你的页面可能看起来更宽，我们在截图之前调整了窗口大小，以便它适合打印页面）：

![设计我们的代码](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php-data-obj/img/2660-02-01.jpg)

一旦我们确保我们的应用程序可以与 MySQL 一起工作，让我们看看它如何与 SQLite 一起工作。为此，我们必须编辑`common.inc.php`文件中的第 8 行，使其包含 SQLite DSN：

```php
$connStr = 'sqlite:/www/hosts/localhost/pdo.db';

```

如果你做得正确，那么刷新你的浏览器后，你应该看到相同的屏幕。正如我们之前讨论过的——当你开始使用另一个数据库系统时，只需要更改一个配置选项。

现在，让我们为列出作者的页面创建代码。创建一个名为`authors.php`的文件，并将其放在您保存前两个文件的目录中。代码几乎与书籍列表页面相同：

```php
<?php
/**
* This page lists all the authors we have
* PDO Library Management example application
* @author Dennis Popel
*/
// Don't forget the include
include('common.inc.php');
// Issue the query
$q = $conn->query("SELECT * FROM authors ORDER BY lastName,
firstName");
// Display the header
showHeader('Authors');
// now create the table
?>
<table width="100%" border="1" cellpadding="3">
<tr style="font-weight: bold">
<td>First Name</td>
<td>Last Name</td>
<td>Bio</td>
</tr>
<?php
// Now iterate over every row and display it
while($r = $q->fetch(PDO::FETCH_ASSOC))
{
?>
<tr>
<td><?=htmlspecialchars($r['firstName'])?></td>
<td><?=htmlspecialchars($r['lastName'])?></td>
<td><?=htmlspecialchars($r['bio'])?></td>
</tr>
<?php
}
?>
</table>
<?php
// Display footer
showFooter();

```

这个文件遵循相同的逻辑：包含`common.inc.php`文件，然后发出查询并遍历结果集。如果你做的一切都正确，那么你只需在浏览器中点击位于书籍列表页面上的**作者**链接，就可以得到以下页面：

![设计我们的代码](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php-data-obj/img/2660-02-02.jpg)

正如您所看到的，页面正确地呈现了我们在本章开头添加的三位作者。如果您想要使用 SQLite 进行测试，请将第 10 行更改为包含 SQLite 连接字符串。刷新浏览器后，您应该看到相同的页面，但现在基于 SQLite 数据库内容。

现在我们已经创建了这两个页面，并且看到使用 PDO 并不复杂，让我们在扩展应用程序之前先看一些理论。

# PDO 语句和结果集

我们的示例使用了 PHP 数据对象中的两个主要类：`PDO`类，用于创建连接和发出查询，以及`PDOStatement`类，我们用它来循环遍历结果集。我们将在后面的章节中查看这两个类中的第一个。在这里，我们将检查`PDOStatement`类，看看它提供了哪些其他遍历结果集的方式。

正如我们已经知道的那样，从对`PDO::query()`方法的调用中返回`PDOStatement`类的实例。这个类的主要目的是提供一个接口来访问结果集。事实上，我们已经使用了它最重要的方法来遍历结果集。我们只看了一个获取样式（或返回行的模式），但 PDO 提供了几种样式。这个类还可以提供有关结果集的其他信息，比如行数和列数，并将整个结果集获取到一个二维数组中。

让我们首先看一些不同的获取样式。我们已经知道`PDO::FETCH_ASSOC`模式，它返回一个由列名索引的数组。`PDOStatement`对象的默认操作是返回一个由整数索引和列名索引的数组，即`PDO::FETCH_BOTH`获取模式。我们还可以使用`PDO::FETCH_NUM`获取样式来请求只有整数索引的数组。PDO 还支持使用`PDO::FETCH_OBJ`模式将行作为对象获取。在这种情况下，对`PDO::fetch()method`的调用将返回一个`stdClass`内部类的实例，其属性填充了行的值。这在以下代码中发生：

```php
$q = $conn->query('SELECT * FROM authors ORDER BY lastName,
firstName');
$r = $q->fetch(PDO::FETCH_OBJ);
var_dump($r);
//would print:
object(stdClass)#4 (4)
{
["id"]=>
string(1) "3"
["firstName"]=>
string(7) "Cameron"
["lastName"]=>
string(6) "Cooper"
["bio"]=>
string(112) "J. Cameron Cooper has been playing around on the web
since there was not much of a web with which to play around"
}

```

`PDOStatement`类还允许您为所有后续对其`fetch()`方法的调用设置获取模式。这是通过`PDOStatement::setFetchMode()`方法完成的，该方法接受`PDO::FETCH_ASSOC, PDO::FETCH_BOTH, PDO::FETCH_NUM`和`PDO::FETCH_OBJ`常量中的任何一个。有了这个想法，我们可以将`authors.php`文件的第 23 和 24 行重写为以下形式：

```php
// Now iterate over every row and display it
$q->setFetchMode(PDO::FETCH_ASSOC);
while($r = $q->fetch())
{

```

您可以在`authors.php`文件的副本上尝试并刷新浏览器，看看它是否有效。

您可能已经注意到，SQLite、MySQL 和 pgSQL PHP 扩展都提供了类似的功能。事实上，我们可以使用`mysql_fetch_row()、mysql_fetch_assoc()、mysql_fetch_array()`或`mysql_fetch_object()`函数来实现相同的效果。这就是为什么 PDO 更进一步，使我们能够使用三种额外的获取模式。这三种模式只能通过`PDOStatement::setFetchMode()`调用来设置，它们分别是：

+   `PDO::FETCH_COLUMN`允许您指示`PDOStatement`对象返回每行的指定列。在这种情况下，`PDO::fetch()`将返回一个标量值。列从 0 开始编号。这在以下代码片段中发生：

```php
$q = $conn->query('SELECT * FROM authors ORDER BY lastName,
firstName');
$q->setFetchMode(PDO::FETCH_COLUMN, 1);
while($r = $q->fetch())
{
var_dump($r);
}
//would print:
string(7) "Cameron"
string(4) "Marc"
string(6) "Sohail"

```

这揭示了对`$q->fetch()`的调用确实返回标量值（而不是数组）。请注意，索引为 1 的列应该是作者的姓，而不是他们的名，如果您只是查看作者列表页面。然而，我们的查询看起来像是`SELECT * FROM authors`，所以它也检索了作者的 ID，这些 ID 存储在第 0 列中。您应该意识到这一点，因为您可能会花费数小时来寻找这样一个逻辑错误的源头。

+   `PDO::FETCH_INTO`可以用来修改对象的实例。让我们将上面的示例重写如下：

```php
$q = $conn->query('SELECT * FROM authors ORDER BY lastName,
firstName');
$r = new stdClass();
$q->setFetchMode(PDO::FETCH_INTO, $r);
while($q->fetch())
{
var_dump($r);
}
//would print something like:
object(stdClass)#3 (4)
{
["id"]=>
string(1) "3"
["firstName"]=>
string(7) "Cameron"
["lastName"]=>
string(6) "Cooper"
["bio"]=>
string(112) "J. Cameron Cooper has been playing around on the
web since there was not much of a web with which to play around"
}
object(stdClass)#3 (4)
{
["id"]=>
string(1) "1"
["firstName"]=>
string(4) "Marc"
["lastName"]=>
string(7) "Delisle"
["bio"]=>
string(54) "Marc Delisle is a member of the MySQL Developer Guide"
}
object(stdClass)#3 (4)
{
["id"]=>
string(1) "2"
["firstName"]=>
string(6) "Sohail"
["lastName"]=>
string(6) "Salehi"
["bio"]=>
string(101) "In recent years, Sohail has contributed to over 20
books, mainly in programming and computer graphics"
}

```

### 注意

在`while`循环中，我们没有分配`$r`变量，这是`$q->fetch()`的返回值。在循环之前，通过调用`$q->setFetchMode()`将`$r`绑定到这个方法。

+   `PDO::FETCH_CLASS`可以用来返回指定类的对象。对于每一行，将创建这个类的一个实例，并将结果集列的值命名和赋值给这些属性。请注意，该类不一定要声明这些属性，因为 PHP 允许在运行时创建对象属性。例如：

```php
$q = $conn->query('SELECT * FROM authors ORDER BY lastName,
firstName');
$q->setFetchMode(PDO::FETCH_CLASS, stdClass);
while($r = $q->fetch())
{
var_dump($r);
}

```

这将打印类似于上一个示例的输出。此外，这种获取模式允许您通过将参数数组传递给它们的构造函数来创建实例：

```php
$q->setFetchMode(PDO::FETCH_CLASS, SomeClass, array(1, 2, 3));

```

（这只有在`SomeClass`类已经被定义的情况下才会起作用。）

我们建议使用`PDOStatement::setFetchMode()`，因为它更方便，更容易维护（当然，功能也更多）。

描述所有这些获取模式可能看起来有些多余，但在某些情况下，它们每一个都是有用的。实际上，您可能已经注意到书籍列表有些不完整。它不包含作者的名字。我们将添加这个缺失的列，并且为了使我们的示例更加棘手，我们将使作者的名字可点击，并将其链接到作者的个人资料页面（我们将创建）。这个个人资料页面需要作者的 ID，以便我们可以在 URL 中传递它。它将显示我们关于作者的所有信息，以及他们所有书籍的列表。让我们从这个作者的个人资料页面开始：

```php
<?php
/**
* This page shows an author's profile
* PDO Library Management example application
* @author Dennis Popel
*/
// Don't forget the include
include('common.inc.php');
// Get the author
$id = (int)$_REQUEST['id'];
$q = $conn->query("SELECT * FROM authors WHERE id=$id");
$author = $q->fetch(PDO::FETCH_ASSOC);
$q->closeCursor();
// Now see if the author is valid - if it's not,
// we have an invalid ID
if(!$author) {
showHeader('Error');
echo "Invalid Author ID supplied";
showFooter();
exit;
}
// Display the header - we have no error
showHeader("Author: $author[firstName] $author[lastName]");
// Now fetch all his books
$q = $conn->query("SELECT * FROM books WHERE author=$id ORDER BY title");
$q->setFetchMode(PDO::FETCH_ASSOC);
// now display everything
?>
<h2>Author</h2>
<table width="60%" border="1" cellpadding="3">
<tr>
<td><b>First Name</b></td>
<td><?=htmlspecialchars($author['firstName'])?></td>
</tr>
<tr>
<td><b>Last Name</b></td>
<td><?=htmlspecialchars($author['lastName'])?></td>
</tr>
<tr>
<td><b>Bio</b></td>
<td><?=htmlspecialchars($author['bio'])?></td>
</tr>
</table>
<h2>Books</h2>
<table width="100%" border="1" cellpadding="3">
<tr style="font-weight: bold">
<td>Title</td>
<td>ISBN</td>
<td>Publisher</td>
<td>Year</td>
<td>Summary</td>
</tr>
<?php
// Now iterate over every book and display it
while($r = $q->fetch())
{
?>
<tr>
<td><?=htmlspecialchars($r['title'])?></td>
<td><?=htmlspecialchars($r['isbn'])?></td>
<td><?=htmlspecialchars($r['publisher'])?></td>
<td><?=htmlspecialchars($r['year'])?></td>
<td><?=htmlspecialchars($r['summary'])?></td>
</tr>
<?php
}
?>
</table>
<?php
// Display footer
showFooter();

```

将此文件命名为`author.php`并将其保存到其他文件所在的目录中。

以下是有关代码的一些评论：

+   我们通过将作者的 ID（第 13 行）显式转换为整数来处理它，以防止可能的安全漏洞。我们稍后将`$id`变量传递给查询文本，而不用引号引用，因为对于数字值来说这样做是可以的。

+   我们将在接下来的章节中讨论第 13 行中对`$q->closeCursor(); $q = null`的调用。在这里我们只想指出，调用这个方法是一个好主意，可以在同一个连接对象上执行查询之间调用它，然后将其设置为 null。我们的示例如果没有它将无法工作。还要注意的是，在最后一个查询之后我们不需要这样做。

+   我们在这里也进行了简单的错误处理：我们检查作者 ID 是否无效。如果无效，我们会显示错误消息，然后退出。（见第 22 至 27 行。）

+   在第 25 和 27 行，我们使用作者的 ID 创建查询，并将获取模式设置为`PDO::FETCH_ASSOC`。然后我们继续显示数据：首先我们呈现作者的详细信息，然后是他的所有书籍。

现在您可以返回浏览器，将其指向 URL：`http://localhost/author.php?id=1`。

以下屏幕应该出现：

![PDO 语句和结果集](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php-data-obj/img/2660-02-03.jpg)

正如您所看到的，页面上的一切都是正确的：我们首先填写的作者详细信息（`id=1`），以及这位作者的唯一一本书。现在让我们看看我们的应用程序如何对提交的无效 ID 做出反应。我们知道我们只有三位作者，所以除了 1、2 或 3 之外的任何数字都是无效的。此外，非数字参数将计算为 0，这是无效的。如果我们将地址栏中的 URL 更改为`http://localhost/author.php?id=zzz`。我们将得到以下结果：

![PDO 语句和结果集](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php-data-obj/img/2660-02-04.jpg)

您还应该在`common.inc.php`中切换到 SQLite，并查看此页面是否也适用于此数据库。

现在，让我们修改现有的`books.php`文件，以添加一个带有指向作者个人资料页面的链接的作者列。我们将不得不连接两个表，其中书的`作者`字段等于作者的 ID 字段，并选择作者的 ID、名和姓。因此，我们的查询将如下所示：

```php
SELECT authors.id, authors.firstName, authors.lastName, books.* FROM authors, books WHERE author=authors.id ORDER BY title;

```

在继续更改之前，让我们在命令行客户端中运行此查询。我们还将修改此查询以适应客户端，因为其窗口无法容纳整行：

```php
mysql> SELECT authors.id, firstName, lastName, books.id, title FROM
authors, books WHERE books.author=authors.id;
+----+-----------+----------+----+------------------------------+
| id | firstName | lastName | id | title |
+----+-----------+----------+----+------------------------------+
| 1 | Marc | Delisle | 1 | Creating your MySQL... |
| 2 | Sohail | Salehi | 2 | ImageMagick Tricks | | 3 | Cameron | Cooper | 3 | Building Websites with Plone |
+----+-----------+----------+----+------------------------------+
3 rows in set (0.00 sec)

```

正如您所看到的，查询返回了两列名为`id`。这意味着我们将无法使用`PDO::FETCH_ASSOC`模式，因为只能有一个`id`数组索引。我们有两个选择：要么使用`PDO::FETCH_NUM`模式，要么使用别名检索 ID 字段。

让我们看看如何使用`PDO::FETCH_NUM`编写页面：

```php
<?php
/**
* This page lists all the books we have
* PDO Library Management example application
* @author Dennis Popel
*/
// Don't forget the include
include('common.inc.php');
// Issue the query
**$q = $conn->query("SELECT authors.id, firstName, lastName, books.*
FROM authors, books WHERE author=authors.id ORDER
BY title");
$q->setFetchMode(PDO::FETCH_NUM);**
// Display the header
showHeader('Books');
// now create the table
?>
<table width="100%" border="1" cellpadding="3">
<tr style="font-weight: bold">
**<td>Author</td>**
<td>Title</td>
<td>ISBN</td>
<td>Publisher</td>
<td>Year</td>
<td>Summary</td>
</tr>
<?php
// Now iterate over every row and display it
**while($r = $q->fetch())**
{
?>
<tr>
**<td><a href="author.php?id=<?=$r[0]?>">
<?=htmlspecialchars("$r[1] $r[2]")?></a></td>
<td><?=htmlspecialchars($r[5])?></td>
<td><?=htmlspecialchars($r[6])?></td>
<td><?=htmlspecialchars($r[7])?></td>
<td><?=htmlspecialchars($r[8])?></td>
<td><?=htmlspecialchars($r[9])?></td>**
</tr>
<?php
}
?>
</table>
<?php
// Display footer
showFooter();

```

请注意高亮显示的行-它们包含更改；文件的其余部分相同。正如您所看到的，我们添加了对`$q->setFetchMode()`的调用，并更改了循环以使用数字列索引。

如果我们导航回`http://localhost/books.php`，我们将看到与此截图中类似的列表：

![PDO 语句和结果集](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php-data-obj/img/2660-02-05.jpg)

我们可以点击每个作者以进入其个人资料页面。当然，在`common.inc.php`中切换回 SQLite 也应该起作用。

另一个（更好的）选择是在 SQL 代码中为列名使用别名。如果我们这样做，我们就不必关心数字索引，并且每次从我们的表中添加或删除列时都要更改代码。我们只需将 SQL 更改为以下内容：

```php
SELECT authors.id AS authorId, firstName, lastName, books.* FROM
authors, books WHERE author=authors.id ORDER BY title;

```

`books.php`的最终版本将如下所示：

```php
<?php
/**
* This page lists all the books we have
* PDO Library Management example application
* @author Dennis Popel
*/
// Don't forget the include
include('common.inc.php');
// Issue the query
**$q = $conn->query("SELECT authors.id AS authorId, firstName,
lastName, books.* FROM authors, books WHERE
author=authors.id
ORDER BY title");
$q->setFetchMode(PDO::FETCH_ASSOC);**
// Display the header
showHeader('Books');
// now create the table
?>
<table width="100%" border="1" cellpadding="3">
<tr style="font-weight: bold">
<td>Author</td>
<td>Title</td>
<td>ISBN</td>
<td>Publisher</td>
<td>Year</td>
<td>Summary</td>
</tr>
<?php
// Now iterate over every row and display it
while($r = $q->fetch())
{
?>
<tr>
**<td><a href="author.php?id=<?=$r['authorId']?>">
<?=htmlspecialchars("$r[firstName] $r[lastName]")?></a></td>
<td><?=htmlspecialchars($r['title'])?></td>
<td><?=htmlspecialchars($r['isbn'])?></td>
<td><?=htmlspecialchars($r['publisher'])?></td>
<td><?=htmlspecialchars($r['year'])?></td>
<td><?=htmlspecialchars($r['summary'])?></td>**
</tr>
<?php
}
?>
</table>
<?php
// Display footer
showFooter();

```

请注意，我们将提取模式更改回`PDO::FETCH_ASSOC`。此外，我们在第 34 行使用`$r['authorId']`访问作者的 ID，因为我们在查询中使用`authorId`对该列进行了别名。

PDO 还允许我们将所有结果提取到数组中。我们可能需要这个用于进一步处理或传递给某个函数。但是，这应该仅用于小型结果集。这在我们这样的应用程序中是非常不鼓励的，因为我们只是显示书籍或作者的列表。将大型结果集提取到数组中将需要为整个结果分配内存，而在我们的情况下，我们逐行显示结果，因此只需要一行的内存。

这个方法被称为`PDOStatement::fetchAll()`。结果数组可以是一个二维数组，也可以是对象列表-这取决于提取模式。这个方法接受所有`PDO::FETCH_xxxx`常量，就像`PDOStatement::fetch()`一样。例如，我们可以以以下方式重写我们的`books.php`文件以达到相同的结果。以下是`books.php`第 9 到 46 行的相关部分：

```php
// Issue the query
$q = $conn->query("SELECT authors.id AS authorId, firstName,
lastName, books.* FROM authors, books WHERE
author=authors.id ORDER BY title");
**$books = $q->fetchAll(PDO::FETCH_ASSOC);**
// Display the header
showHeader('Books');
// now create the table
?>
<table width="100%" border="1" cellpadding="3">
<tr style="font-weight: bold">
<td>Author</td>
<td>Title</td>
<td>ISBN</td>
<td>Publisher</td>
<td>Year</td>
<td>Summary</td>
</tr>
<?php
// Now iterate over every row and display it
**foreach($books as $r)
{**
?>
<tr>
<td><a href="author.php?id=<?=$r['authorId']?>">
<?=htmlspecialchars("$r[firstName] $r[lastName]")?></a></td>
<td><?=htmlspecialchars($r['title'])?></td>
<td><?=htmlspecialchars($r['isbn'])?></td>
<td><?=htmlspecialchars($r['publisher'])?></td>
<td><?=htmlspecialchars($r['year'])?></td>
<td><?=htmlspecialchars($r['summary'])?></td>
</tr>
<?php
}
?>
</table>

```

请注意这里的高亮显示的行-我们在第 5 行将整个结果提取到`$books`数组中，然后在第 21 行使用`foreach`循环对其进行迭代。如果运行修改后的页面，您将看到我们收到相同的结果。如果在`common.inc.php`文件中切换到 SQLite 数据库，这也将起作用。

`PDOStatement::fetchAll()`方法还允许我们使用`PDO::FETCH_COLUMN`模式选择单个列的值。如果我们想使用上一个示例中的查询提取整个书名，我们可以这样做（注意列的数量和顺序）：

```php
$q = $conn->query("SELECT authors.id AS authorId, firstName,
lastName, books.* FROM authors, books WHERE
author=authors.id ORDER BY title");
$books = $q->fetchAll(PDO::FETCH_COLUMN, 5);
var_dump($books);

```

这将产生以下输出：

```php
array(3)
{
[0]=>
string(28) "Building Websites with Plone"
[1]=>
string(66) "Creating your MySQL Database: Practical Design Tips and
Techniques"
[2]=>
string(18) "ImageMagick Tricks"
}

```

正如您所看到的，当请求单个列时，此方法返回一维数组。

# 检索结果集元数据

正如我们在前一节中所看到的，`PDOStatement`类允许我们检索有关结果集中包含的数据的一些信息。这些信息称为**元数据**，您可能已经以某种方式使用过其中的一些。

结果集最重要的元数据当然是它包含的行数。我们可以使用行数来增强用户体验，例如对长结果集进行分页。我们的示例库应用目前还很小，只有三本书，但随着数据库的增长，我们肯定需要一些工具来获取每个表的总行数，并对其进行分页以便浏览。

传统上，您会使用`mysql_num_rows(), sqlite_num_rows()`函数或`pg_num_rows()`函数（取决于您的数据库）来获取查询返回的总行数。在 PDO 中，负责检索行数的方法称为`PDOStatement::rowCount()`。但是，如果你想用以下代码测试它：

```php
$q = $conn->query("SELECT * FROM books ORDER BY title");
$q->setFetchMode(PDO::FETCH_ASSOC);
var_dump($q->rowCount());

```

你会发现 PDO 对 MySQL 和 SQLite 都返回 0。这是因为 PDO 的操作方式与传统的数据库扩展不同。文档中说：“如果与关联的`PDOStatement`类执行的最后一个 SQL 语句是`SELECT`语句，则某些数据库可能返回该语句返回的行数。但是，并不是所有数据库都保证这种行为。”

可移植应用程序不应依赖于这种方法。" MySQL 和 SQLite 驱动程序都不支持此功能，这就是为什么该方法的返回值为 0。我们将在第五章中看到如何使用 PDO 计算返回的行数（因此这是一个真正可移植的方法）。

### 注意

*RDBMS*不知道查询将返回多少行，直到检索到最后一行。这是出于性能考虑。在大多数情况下，带有`WHERE`子句的查询只返回表中存储的部分行，数据库服务器会尽力确保这样的查询尽快执行。这意味着他们在发现与`WHERE`子句匹配的行时就开始返回行——这比到达最后一行要早得多。这就是为什么他们真的不知道事先将返回多少行。`mysql_num_rows(), sqlite_num_rows()`函数或`pg_num_rows()`函数操作的是已经预取到内存中的结果集（缓冲查询）。PDO 的默认行为是使用非缓冲查询。我们将在第六章中讨论 MySQL 缓冲查询。

另一个可能感兴趣的方法是`PDOStatement::columnCount()`方法，它返回结果集中的列数。当我们执行任意查询时，这很方便。（例如，像`phpMyAdmin`这样的数据库管理应用程序可以充分利用这种方法，因为它允许用户输入任意 SQL 查询。）我们可以这样使用它：

```php
$q = $conn->query("SELECT authors.id AS authorId, firstName,
lastName, books.* FROM authors, books WHERE
author=authors.id ORDER BY title");
var_dump($q->columnCount());

```

这将揭示我们的查询返回了一个包含 10 列的结果集（**books**表的七列和**authors**表的三列）。

不幸的是，PDO 目前不允许您从结果集中检索表的名称或特定列的名称。如果您的应用程序使用了连接两个或多个表的查询，这个功能就很有用。在这种情况下，可以根据其数字索引（从 0 开始）获取每列的表名。但是，正确使用列别名可以消除使用这种功能的需要。例如，当我们修改书籍列表页面以显示作者的姓名时，我们为作者的 ID 列设置了别名以避免名称冲突。该别名清楚地标识了该列属于`authors`表。

# 总结

在本章中，我们初步使用了 PDO，甚至创建了一个可以在两个不同数据库上运行的小型数据库驱动动态应用程序。现在你应该能够连接到任何支持的数据库，使用构建连接字符串的规则。然后你应该能够对其运行查询，并遍历和显示结果集。

在下一章中，我们将处理任何数据库驱动应用程序的一个非常重要的方面——错误处理。我们还将通过为其添加和编辑书籍和作者的功能来扩展我们的示例应用程序，从而使其更加真实和有用。


# 第三章：错误处理

现在我们已经构建了使用 PDO 的第一个应用程序，我们将更仔细地研究用户友好的 Web 应用程序的一个重要方面——错误处理。它不仅通知用户有错误发生，而且在错误发生时没有被检测到时，它还限制了损害。

大多数 Web 应用程序都有相当简单的错误处理策略。当发生错误时，脚本终止并显示错误页面。错误应该记录在错误日志中，开发人员或维护人员应该定期检查日志。数据库驱动的 Web 应用程序中最常见的错误来源如下：

+   服务器软件故障或过载，比如著名的“连接过多”错误

+   应用程序配置不当，当我们使用不正确的连接字符串时可能会发生，这在将应用程序从一个主机移动到另一个主机时是一个相当常见的错误

+   用户输入验证不当，可能导致 SQL 格式不正确，从而导致查询失败

+   插入具有重复主键或唯一索引值的记录，这可能是应用程序业务逻辑错误导致的，也可能发生在受控情况下

+   SQL 语句中的语法错误

在本章中，我们将扩展我们的应用程序，以便我们可以编辑现有记录以及添加新记录。由于我们将处理通过 Web 表单提供的用户输入，我们必须对其进行验证。此外，我们可能会添加错误处理，以便我们可以对非标准情况做出反应，并向用户呈现友好的消息。

在我们继续之前，让我们简要地检查上面提到的错误来源，并看看在每种情况下应该应用什么错误处理策略。我们的错误处理策略将使用异常，所以你应该熟悉它们。如果你不熟悉，你可以参考附录 A，它将向你介绍 PHP5 的新面向对象特性。

我们有意选择使用异常，即使 PDO 可以被指示不使用它们，因为有一种情况是它们无法避免的。当数据库对象无法创建时，PDO 构造函数总是抛出异常，所以我们可能会将异常作为我们在整个代码中的主要错误捕获方法。

# 错误来源

要创建一个错误处理策略，我们首先应该分析错误可能发生的地方。错误可能发生在对数据库的每次调用上，尽管这可能不太可能，我们将研究这种情况。但在这样做之前，让我们检查每个可能的错误来源，并为处理它们定义一个策略。

## 服务器软件故障或过载

这可能发生在一个非常繁忙的服务器上，无法处理更多的传入连接。例如，后台可能正在运行一个漫长的更新。结果是我们无法从数据库中获取任何数据，所以我们应该做以下事情。

如果 PDO 构造函数失败，我们会显示一个页面，上面显示一条消息，说明用户的请求目前无法满足，他们应该稍后再试。当然，我们也应该记录这个错误，因为它可能需要立即处理。（一个好主意是通过电子邮件通知数据库管理员有关这个错误。）

这个错误的问题在于，虽然它通常在与数据库建立连接之前就显现出来（在调用 PDO 构造函数时），但有一点风险，它可能在连接建立之后发生（在调用`PDO`或`PDOStatement`对象的方法时，数据库服务器正在关闭）。在这种情况下，我们的反应将是一样的——向用户呈现一个错误消息，要求他们稍后再试。

## 应用程序配置不当

这个错误只会在我们将应用程序从数据库访问细节不同的服务器上移动时发生；这可能是当我们从开发服务器上传到生产服务器时，数据库设置不同。这不是在应用程序正常执行期间可能发生的错误，但在上传时应该注意，因为这可能会中断网站的运行。

如果发生此错误，我们可以显示另一个错误消息，如：“该网站正在维护中”。在这种情况下，网站维护者应立即做出反应，因为如果不纠正连接字符串，应用程序就无法正常运行。

## 用户输入验证不正确

这是一个与 SQL 注入漏洞密切相关的错误。每个数据库驱动应用程序的开发人员都必须采取适当的措施来验证和过滤所有用户输入。这个错误可能导致两个主要后果：要么查询由于 SQL 格式不正确而失败（因此不会发生特别糟糕的事情），要么可能发生 SQL 注入并且应用程序安全可能会受到损害。虽然后果不同，但这两个问题可以以相同的方式防止。

让我们考虑以下情景。我们从表单中接受一些数值，并将其插入数据库。为了使我们的例子简单，假设我们想要更新一本书的出版年份。为了实现这一点，我们可以创建一个包含书的 ID 的隐藏字段和一个输入年份的文本字段的表单。我们将在这里跳过实现细节，并看看使用一个设计不良的脚本来处理这个表单可能会导致错误并将整个系统置于风险之中。

表单处理脚本将检查两个请求变量：`$_REQUEST['book']`，其中包含书的 ID 和`$_REQUEST['year']`，其中包含出版年份。如果没有对这些值进行验证，最终的代码将类似于这样：

```php
$book = $_REQUEST['book'];
$year = $_REQUEST['year'];
$sql = "UPDATE books SET year=$year WHERE id=$book";
$conn->query($sql);

```

让我们看看如果用户将`book`字段留空会发生什么。最终的 SQL 将如下所示：

```php
UPDATE books SET year= WHERE id=1;

```

这个 SQL 是格式不正确的，会导致语法错误。因此，我们应该确保这两个变量都包含数值。如果它们不包含数值，我们应该重新显示表单并显示错误消息。

现在，让我们看看攻击者如何利用这一点来删除整个表的内容。为了实现这一点，他们可以在`year`字段中输入以下内容：

```php
2007; DELETE FROM books;

```

这将一个查询变成了三个查询：

```php
UPDATE books SET year=2007; DELETE FROM books; WHERE book=1;

```

当然，第三个查询是格式不正确的，但第一个和第二个将执行，并且数据库服务器将报告一个错误。为了解决这个问题，我们可以使用简单的验证来确保`year`字段包含四位数字。然而，如果我们有可能包含任意字符的文本字段，字段的值在创建 SQL 之前必须进行转义。

## 插入具有重复主键或唯一索引值的记录

当应用程序插入具有主键或唯一索引的重复值的记录时，可能会出现这个问题。例如，在我们的作者和书籍数据库中，我们可能希望防止用户因错误而两次输入相同的书。为此，我们可以在`books`表的 ISBN 列上创建一个唯一索引。由于每本书都有一个唯一的 ISBN，任何尝试插入相同的 ISBN 都会生成一个错误。我们可以捕获这个错误，并通过显示一个错误消息要求用户纠正 ISBN 或取消其添加来做出相应反应。

## SQL 语句中的语法错误

如果我们没有正确测试应用程序，可能会发生此错误。一个好的应用程序不应包含这些错误，开发团队有责任测试每种可能的情况，并检查每个 SQL 语句是否执行时没有语法错误。

如果发生这种错误，我们会使用异常来捕获它，并显示一个致命错误消息。开发人员必须立即纠正这种情况。

现在我们已经了解了可能的错误来源，让我们来看看 PDO 如何处理错误。

# PDO 中的错误处理类型

默认情况下，PDO 使用**静默错误处理模式**。这意味着调用`PDO`或`PDOStatement`类的方法时发生的任何错误都不会被报告。在这种模式下，每次发生错误时，都必须调用`PDO::errorInfo()`、`PDO::errorCode()`、`PDOStatement::errorInfo()`或`PDOStatement::errorCode()`来查看是否真的发生了错误。请注意，这种模式类似于传统的数据库访问——通常，在调用可能引起错误的函数之后，代码会调用`mysql_errno()`和`mysql_error()`（或其他数据库系统的等效函数），在连接到数据库之后和发出查询之后。

另一种模式是**警告模式**。在这里，`PDO`将与传统的数据库访问行为相同。与数据库通信期间发生的任何错误都会引发一个`E_WARNING`错误。根据配置，可能会显示错误消息或将其记录到文件中。

最后，PDO 引入了一种处理数据库连接错误的现代方式——使用**异常**。对`PDO`或`PDOStatement`方法的任何失败调用都会引发异常。

正如我们之前注意到的，PDO 默认使用静默模式。要切换到所需的错误处理模式，我们必须通过调用`PDO::setAttribute()`方法来指定它。每个错误处理模式由 PDO 类中定义的以下常量指定：

+   `PDO::ERRMODE_SILENT` - *静默*策略。

+   `PDO::ERRMODE_WARNING` - *警告*策略。

+   `PDO::ERRMODE_EXCEPTION` - 使用*异常*。

要设置所需的错误处理模式，我们必须以以下方式设置`PDO::ATTR_ERRMODE`属性：

```php
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

```

要查看 PDO 如何抛出异常，请在`common.inc.php`文件中编辑，在第 46 行后添加上述语句。如果您想测试当 PDO 抛出异常时会发生什么，请更改连接字符串以指定不存在的数据库。现在将浏览器指向图书列表页面。

您应该看到类似于以下的输出：

![PDO 中的错误处理类型](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php-data-obj/img/2660_03_01.jpg)

这是 PHP 对未捕获异常的默认反应——它们被视为致命错误，程序执行停止。错误消息显示了异常的类`PDOException`、错误描述和一些调试信息，包括抛出异常的语句的名称和行号。请注意，如果要测试 SQLite，指定不存在的数据库可能不起作用，因为如果数据库不存在，它将被创建。要查看它是否适用于 SQLite，请更改第 10 行的`$connStr`变量，以便数据库名称中有一个非法字符：

```php
$connStr = 'sqlite:/path/to/pdo*.db';

```

刷新您的浏览器，您应该看到类似于这样的内容：

![PDO 中的错误处理类型](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php-data-obj/img/2660_03_02.jpg)

如您所见，显示了类似于上一个示例的消息，指定了错误的原因和源代码中的位置。

# 定义错误处理函数

如果我们知道某个语句或代码块可能会抛出异常，我们应该将该代码包装在*try...catch*块中，以防止显示默认错误消息并呈现用户友好的错误页面。但在我们继续之前，让我们创建一个函数，用于呈现错误消息并退出应用程序。由于我们将从不同的脚本文件中调用它，所以最好的地方就是`common.inc.php`文件。

我们的函数，名为`showError()`，将执行以下操作：

+   呈现一个标题，写着“错误”。

+   呈现错误消息。我们将使用`htmlspecialchars()`函数转义文本，并使用`nl2br()`函数处理它，以便我们可以显示多行消息。（此函数将所有换行字符转换为`<br>`标签。）

+   调用`showFooter()`函数来关闭打开的`<html>`和`<body>`标签。该函数将假定应用程序已经调用了`showHeader()`函数。（否则，我们将得到破损的 HTML。）

我们还必须修改在`common.inc.php`中创建连接对象的块，以捕获可能的异常。通过所有这些更改，`common.inc.php`的新版本将如下所示：

```php
<?php
/**
* This is a common include file
* PDO Library Management example application
* @author Dennis Popel
*/
// DB connection string and username/password
$connStr = 'mysql:host=localhost;dbname=pdo';
$user = 'root';
$pass = 'root';
/**
* This function will render the header on every page,
* including the opening html tag,
* the head section and the opening body tag.
* It should be called before any output of the
* page itself.
* @param string $title the page title
*/
function showHeader($title)
{
?>
<html>
<head><title><?=htmlspecialchars($title)?></title></head>
<body>
<h1><?=htmlspecialchars($title)?></h1>
<a href="books.php">Books</a>
<a href="authors.php">Authors</a>
<hr>
<?php
}
/**
* This function will 'close' the body and html
* tags opened by the showHeader() function
*/
function showFooter()
{
?>
</body>
</html>
<?php
}
**/**
* This function will display an error message, call the
* showFooter() function and terminate the application
* @param string $message the error message
*/
function showError($message)
{
echo "<h2>Error</h2>";
echo nl2br(htmlspecialchars($message));
showFooter();
exit();
}
// Create the connection object
try
{
$conn = new PDO($connStr, $user, $pass);
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
}
catch(PDOException $e)
{
showHeader('Error');
showError("Sorry, an error has occurred. Please try your request
later\n" . $e->getMessage());
}**

```

正如您所看到的，新创建的函数非常简单。更有趣的部分是我们用来捕获异常的*try…catch*块。现在通过这些修改，我们可以测试真正的异常将如何被处理。为此，请确保您的连接字符串是错误的（这样它就为 MySQL 指定了错误的数据库名称，或者包含了 SQLite 的无效文件名）。将浏览器指向`books.php`，您应该会看到以下窗口：

![定义错误处理函数](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php-data-obj/img/2660_03_03.jpg)

# 创建编辑书籍页面

正如我们之前讨论的，我们希望扩展我们的应用程序，以便我们可以添加和编辑书籍和作者。此外，我们的系统应该能够通过在书籍表的`ISBN`列上强制执行唯一索引来防止我们输入相同的书籍两次。

在继续进行代码之前，我们将创建索引。启动您的命令行客户端，并输入以下命令（对于 MySQL 和 SQLite 是相同的）：

```php
CREATE UNIQUE INDEX idx_isbn ON books(isbn);

```

我们还将使我们的编辑书籍页面同时具有两个目的——添加新书和编辑现有书籍。脚本将通过书籍 ID 的存在来区分要采取的操作，无论是在 URL 中还是在隐藏的表单字段中。我们将从`books.php`中链接到这个新页面，这样我们就可以通过在书籍列表页面上点击链接来编辑每一本书。

这个页面比上一章描述的页面更复杂，所以我会先给你代码，然后再讨论它。让我们称这个页面为 edit `Book.php:`

```php
<?php
/**
* This page allows to add or edit a book
* PDO Library Management example application
* @author Dennis Popel
*/
// Don't forget the include
include('common.inc.php');
// See if we have the book ID passed in the request
$id = (int)$_REQUEST['book'];
if($id) {
// We have the ID, get the book details from the table
$q = $conn->query("SELECT * FROM books WHERE id=$id");
$book = $q->fetch(PDO::FETCH_ASSOC);
$q->closeCursor();
$q = null;
}
else {
// We are creating a new book
$book = array();
}
// Now get the list of all authors' first and last names
// We will need it to create the dropdown box for author
$authors = array();
$q = $conn->query("SELECT id, lastName, firstName FROM authors ORDER
BY lastName, firstName");
$q->setFetchMode(PDO::FETCH_ASSOC);
while($a = $q->fetch())
{
$authors[$a['id']] = "$a[lastName], $a[firstName]";
}
// Now see if the form was submitted
if($_POST['submit']) {
// Validate every field
$warnings = array();
// Title should be non-empty
if(!$_POST['title'])
{
$warnings[] = 'Please enter book title';
}
// Author should be a key in the $authors array
if(!array_key_exists($_POST['author'], $authors))
{
$warnings[] = 'Please select author for the book';
}
// ISBN should be a 10-digit number
if(!preg_match('~^\d{10}$~', $_POST['isbn'])) {
$warnings[] = 'ISBN should be 10 digits';
}
// Published should be non-empty
if(!$_POST['publisher']) {
$warnings[] = 'Please enter publisher';
}
// Year should be 4 digits
if(!preg_match('~^\d{4}$~', $_POST['year'])) {
$warnings[] = 'Year should be 4 digits';
}
// Sumary should be non-empty
if(!$_POST['summary']) {
$warnings[] = 'Please enter summary';
}
// If there are no errors, we can update the database
// If there was book ID passed, update that book
if(count($warnings) == 0) {
if(@$book['id']) {
$sql = "UPDATE books SET title=" . $conn>quote($_POST['title']) .
', author=' . $conn->quote($_POST['author']) .
', isbn=' . $conn->quote($_POST['isbn']) .
', publisher=' . $conn->quote($_POST['publisher']) .
', year=' . $conn->quote($_POST['year']) .
', summary=' . $conn->quote($_POST['summary']) .
" WHERE id=$book[id]";
}
else {
$sql = "INSERT INTO books(title, author, isbn, publisher,
year,summary) VALUES(" .
$conn->quote($_POST['title']) .
', ' . $conn->quote($_POST['author']) .
', ' . $conn->quote($_POST['isbn']) .
', ' . $conn->quote($_POST['publisher']) .
', ' . $conn->quote($_POST['year']) .
', ' . $conn->quote($_POST['summary']) .
')';
}
// Now we are updating the DB.
// We wrap this into a try/catch block
// as an exception can get thrown if
// the ISBN is already in the table
try
{
$conn->query($sql);
// If we are here that means that no error
// We can return back to books listing
header("Location: books.php");
exit;
}
catch(PDOException $e)
{
$warnings[] = 'Duplicate ISBN entered. Please correct';
}
}
}
else {
// Form was not submitted.
// Populate the $_POST array with the book's details
$_POST = $book;
}
// Display the header
showHeader('Edit Book');
// If we have any warnings, display them now
if(count($warnings)) {
echo "<b>Please correct these errors:</b><br>";
foreach($warnings as $w)
{
echo "- ", htmlspecialchars($w), "<br>";
}
}
// Now display the form
?>
<form action="editBook.php" method="post">
<table border="1" cellpadding="3">
<tr>
<td>Title</td>
<td>
<input type="text" name="title"
value="<?=htmlspecialchars($_POST['title'])?>">
</td>
</tr>
<tr>
<td>Author</td>
<td>
<select name="author">
<option value="">Please select...</option>
<?php foreach($authors as $id=>$author) { ?>
<option value="<?=$id?>"
<?= $id == $_POST['author'] ? 'selected' : ''?>>
<?=htmlspecialchars($author)?>
</option>
<?php } ?>
</select>
</td>
</tr>
<tr>
<td>ISBN</td>
<td>
<input type="text" name="isbn"
value="<?=htmlspecialchars($_POST['isbn'])?>">
</td>
</tr>
<tr>
<td>Publisher</td>
<td>
<input type="text" name="publisher"
value="<?=htmlspecialchars($_POST['publisher'])?>">
</td>
</tr>
<tr>
<td>Year</td>
<td>
<input type="text" name="year"
value="<?=htmlspecialchars($_POST['year'])?>">
</td>
</tr>
<tr>
<td>Summary</td>
<td>
<textarea name="summary"><?=htmlspecialchars( $_POST['summary'])?></textarea>
</td>
</tr>
<tr>
<td colspan="2" align="center">
<input type="submit" name="submit" value="Save">
</td>
</tr>
</table>
<?php if(@$book['id']) { ?>
<input type="hidden" name="book" value="<?=$book['id']?>">
<?php } ?>
</form>
<?php
// Display footer
showFooter();

```

代码相当自我解释，但让我们简要地浏览一下它的主要部分。12 到 23 行处理如果页面使用书籍 ID 请求，则会获取要编辑的书籍详情。这些细节存储在`$book`变量中。请注意，我们明确将请求参数`book`转换为`整数`，以便不会发生 SQL 注入（第 13 行）。如果没有提供书籍 ID，则将其设置为空数组。请注意我们如何调用`closeCursor()`函数，然后将`$q`变量赋值为 null。这是必要的，因为我们将重用连接对象。

26 到 33 行准备作者列表。由于我们的系统每本书只允许一个作者，我们将创建一个选择框字段列出所有作者。

35 行检查是否提交了表单。如果测试成功，脚本将验证每个字段（37 到 68 行）。每个失败的验证都会附加到警告列表中。（`$warnings`变量初始化为空数组。）我们将使用此列表来查看验证是否成功，并在验证失败时存储错误消息。

69 到 94 行构建实际的更新 SQL。最终的 SQL 取决于我们是在更新书籍（当`$book`数组包含**id**键时），还是添加新书。请注意，在查询执行之前如何引用每个列值。

95 到 112 行尝试执行查询。如果用户输入了重复的 ISBN，查询可能会失败，因此我们将代码包装在`try…catch`块中。如果确实抛出了异常，`catch`块将向`$warnings`数组附加相应的警告。如果一切正常且没有错误，脚本将重定向到书籍列表页面，您应该能看到更改。

113 到 118 行在表单没有提交时执行。在这里，`$_POST`数组被`$books`变量的内容填充。我们这样做是因为我们将使用`$_POST`数组在代码后面显示表单字段的值。

请注意我们如何在 122 到 129 行显示错误消息（如果有的话），以及在 141 到 154 行显示选择框。 （我们正在浏览所有作者，如果作者的 ID 与此书作者的 ID 匹配，则将该作者标记为选定的选项。）此外，其他表单字段是使用`htmlspecialchars（）`函数应用于`$_POST`数组的项目来呈现的。 189 到 191 行将向表单添加一个包含当前编辑的书籍的 ID 的隐藏字段（如果有的话）。

现代 Web 应用程序除了对用户提供的数据进行服务器端验证外，还采用了客户端验证。虽然这不在本书的范围内，但您可能会考虑在项目中使用基于浏览器的验证，以增加响应性并可能减少 Web 服务器的负载。

现在，我们应该从`books.php`页面链接到新创建的页面。我们将为每个列出的书籍提供一个*编辑此书*链接，以及在表格下方提供一个*添加书籍*链接。我不会在这里重复整个`books.php`源代码，只是应该更改的行。因此，应该将 32 到 48 行替换为以下内容：

```php
<?php
// Now iterate over every row and display it
while($r = $q->fetch())
{
?>
<tr>
<td><ahref="author.php?id=<?=$r['authorId']?>">
<?=htmlspecialchars("$r[firstName] $r[lastName]")?></a></td>
<td><?=htmlspecialchars($r['title'])?></td>
<td><?=htmlspecialchars($r['isbn'])?></td>
<td><?=htmlspecialchars($r['publisher'])?></td>
<td><?=htmlspecialchars($r['year'])?></td>
<td><?=htmlspecialchars($r['summary'])?></td>
**<td>
<a href="editBook.php?book=<?=$r['id']?>">Edit</a>
</td>**
</tr>
<?php
}
?>

```

应该在调用`showFooter（）`函数之前添加以下内容，以便这四行看起来像这样：

```php
<a href="editBook.php">Add book...</a>
<?php
// Display footer
showFooter();

```

现在，如果您再次导航到`books.php`页面，您应该看到以下窗口：

![创建编辑书籍页面](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php-data-obj/img/2660_03_04.jpg)

要查看我们的编辑书籍页面的外观，请单击表格最后一列中的任何**编辑**链接。您应该看到以下表单：

![创建编辑书籍页面](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php-data-obj/img/2660_03_05.jpg)

让我们看看我们的表单是如何工作的。它正在验证发送到数据库的每个表单字段。如果有任何验证错误，表单将不会更新数据库，并提示用户更正提交。例如，尝试将作者选择框更改为默认选项（标有*请选择...*），并将 ISBN 编辑为 5 位数。

如果单击**保存**按钮，您应该看到表单显示以下错误消息：

![创建编辑书籍页面](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php-data-obj/img/2660_03_06.jpg)

现在纠正错误，并尝试将 ISBN 更改为 1904811027。这个 ISBN 已经在我们的数据库中被另一本书使用，所以表单将再次显示错误。您还可以通过添加一本书来进一步测试表单。您可能还想测试它在 SQLite 中的工作方式。

# 创建编辑作者页面

我们的应用程序仍然缺少添加/编辑作者功能。这个页面将比编辑书籍页面简单一些，因为它不会有作者的选择框和唯一索引。（您可能希望在作者的名字和姓氏列上创建唯一索引，以防止那里也出现重复，但我们将把这个问题留给您。）

让我们称这个页面为`editAuthor.php`。以下是它的源代码：

```php
<?php
/**
* This page allows to add or edit an author
* PDO Library Management example application
* @author Dennis Popel
*/
// Don't forget the include
include('common.inc.php');
// See if we have the author ID passed in the request
$id = (int)$_REQUEST['author'];
if($id) {
// We have the ID, get the author details from the table
$q = $conn->query("SELECT * FROM authors WHERE id=$id");
$author = $q->fetch(PDO::FETCH_ASSOC);
$q->closeCursor();
$q = null;
}
else {
// We are creating a new book
$author = array();
}
// Now see if the form was submitted
if($_POST['submit']) {
// Validate every field
$warnings = array();
// First name should be non-empty
if(!$_POST['firstName']) {
$warnings[] = 'Please enter first name';
}
// Last name should be non-empty
if(!$_POST['lastName']) {
$warnings[] = 'Please enter last name';
}
// Bio should be non-empty
if(!$_POST['bio']) {
$warnings[] = 'Please enter bio';
}
// If there are no errors, we can update the database
// If there was book ID passed, update that book
if(count($warnings) == 0) {
if(@$author['id']) {
$sql = "UPDATE authors SET firstName=" .
$co>quote($_POST['firstName']) .
', lastName=' . $conn->quote($_POST['lastName']) .
', bio=' . $conn->quote($_POST['bio']) .
" WHERE id=$author[id]";
}
else {
$sql = "INSERT INTO authors(firstName, lastName, bio) VALUES(" .
$conn->quote($_POST['firstName']) .
', ' . $conn->quote($_POST['lastName']) .
', ' . $conn->quote($_POST['bio']) .
')';
}
$conn->query($sql);
header("Location: authors.php");
exit;
}
}
else {
// Form was not submitted.
// Populate the $_POST array with the author's details
$_POST = $author;
}
// Display the header
showHeader('Edit Author');
// If we have any warnings, display them now
if(count($warnings)) {
echo "<b>Please correct these errors:</b><br>";
foreach($warnings as $w)
{
echo "- ", htmlspecialchars($w), "<br>";
}
}
// Now display the form
?>
<form action="editAuthor.php" method="post">
<table border="1" cellpadding="3">
<tr>
<td>First name</td>
<td>
<input type="text" name="firstName"
value="<?=htmlspecialchars($_POST['firstName'])?>">
</td>
</tr>
<tr>
<td>Last name</td>
<td>
<input type="text" name="lastName"
value="<?=htmlspecialchars($_POST['lastName'])?>">
</td>
</tr>
<tr>
<td>Bio</td>
<td>
<textarea name="bio"><?=htmlspecialchars($_POST['bio'])?>
</textarea>
</td>
</tr>
<tr>
<td colspan="2" align="center">
<input type="submit" name="submit" value="Save">
</td>
</tr>
</table>
<?php if(@$author['id']) { ?>
<input type="hidden" name="author" value="<?=$author['id']?>">
<?php } ?>
</form>
<?php
// Display footer
showFooter();

```

此源代码与`editBook.php`页面以相同的方式构建，因此您应该能够轻松地跟随它。

我们将以与我们从`books.php`页面链接到`editBook.php`页面相同的方式链接到`editAuthors.php`页面。编辑`authors.php`文件，并将 30-41 行更改为以下内容：

```php
while($r = $q->fetch(PDO::FETCH_ASSOC))
{
?>
<tr>
<td><?=htmlspecialchars($r['firstName'])?></td>
<td><?=htmlspecialchars($r['lastName'])?></td>
<td><?=htmlspecialchars($r['bio'])?></td>
**<td>
<a href="editAuthor.php?author=<?=$r['id']?>">Edit</a>
</td>**
</tr>
<?php
}

```

在最后一个 PHP 块之前添加以下行：

```php
<a href="editAuthor.php">Add Author...</a>

```

现在，如果您刷新`authors.php`页面，您将看到以下内容：

![创建编辑作者页面](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php-data-obj/img/2660_03_07.jpg)

您可以单击右侧列中的**编辑**链接来编辑每位作者的详细信息。您可以尝试使用空值提交表单，以查看无效提交将被拒绝。此外，您可以尝试向系统添加新作者。成功完成后，您可能希望返回到书籍列表并编辑一些书籍。您将看到新创建的作者可用于**作者**选择框。

# 防止未捕获异常

正如我们之前所看到的，我们在可能引发异常的代码周围放置了*try...catch*块。然而，在非常罕见的情况下，可能会出现一些意外的异常。我们可以通过修改其中一个查询来模拟这样的异常，使其包含一些格式不正确的 SQL。例如，让我们编辑`authors.php`，将第 16 行修改为以下内容：

```php
$q = $conn->query("SELECT * FROM authors ORDER BY lastName, firstName");

```

现在尝试使用浏览器导航到`authors.php`，看看是否发生了未捕获的异常。为了正确处理这种情况，我们要么创建一个异常处理程序，要么将调用`PDO`或`PDOStatement`类方法的每个代码块包装在*try...catch*块中。

让我们看看如何创建异常处理程序。这是一种更简单的方法，因为它不需要改变大量的代码。然而，对于大型应用程序来说，这可能是一个不好的做法，因为在发生异常的地方处理异常可能更安全，并且可以应用更好的恢复逻辑。

然而，对于我们简单的应用程序，我们可以使用全局异常处理程序。它将只是使用`showError()`函数来表示网站正在维护中。

```php
/**
* This is the default exception handler
* @param Exception $e the uncaught exception
*/
function exceptionHandler($e)
{
showError("Sorry, the site is under maintenance\n" .
$e->getMessage());
}
// Set the global excpetion handler
set_exception_handler('exceptionHandler');

```

将这段代码放入`common.inc.php`中，就在连接创建代码块之前。如果现在刷新`authors.php`页面，你会看到处理程序被调用了。

拥有默认的异常处理程序总是一个好主意。正如你已经注意到的，未处理的异常会暴露太多敏感信息，包括数据库连接详细信息。此外，在真实世界的应用程序中，错误页面不应显示有关错误类型的任何信息。（请注意，我们的示例应用程序是这样的。）默认处理程序应该写入错误日志，并通知网站维护人员有关错误的信息。

# 总结

在本章中，我们研究了`PDO`如何处理错误，并介绍了异常。此外，我们调查了错误的来源，并看到了如何对抗它们。

我们的示例应用程序已经扩展了一些真实世界的管理功能，使用了数据验证，并且受到了 SQL 注入攻击的保护。当然，他们还应该只允许基于登录名和密码的特定用户对数据库进行修改。然而，这超出了本书的范围。

在下一章中，我们将看到 PDO 和数据库编程中另一个非常重要的方面——使用预处理语句。我们将看到如何借助它们来简化我们的管理页面，从而减少代码量并提高维护性。
