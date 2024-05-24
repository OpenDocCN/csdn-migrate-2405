# Python GUI 编程（四）

> 原文：[`zh.annas-archive.org/md5/9d5f7126bd532a80dd6a9dce44175aaa`](https://zh.annas-archive.org/md5/9d5f7126bd532a80dd6a9dce44175aaa)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：使用 SQL 改进数据存储

随着时间的推移，实验室出现了一个越来越严重的问题：CSV 文件到处都是！冲突的副本，丢失的文件，非数据输入人员更改的记录，以及其他与 CSV 相关的挫折正在困扰着项目。很明显，单独的 CSV 文件不适合作为存储实验数据的方式。需要更好的东西。

该设施有一个安装了 PostgreSQL 数据库的较旧的 Linux 服务器。您被要求更新您的程序，以便将数据存储在 PostgreSQL 数据库中，而不是在 CSV 文件中。这将是对您的应用程序的重大更新！

在本章中，您将学习以下主题：

+   安装和配置 PostgreSQL 数据库系统

+   在数据库中构建数据以获得良好的性能和可靠性

+   SQL 查询的基础知识

+   使用`psycopg2`库将您的程序连接到 PostgreSQL

# PostgreSQL

PostgreSQL（通常发音为 post-gress）是一个免费的、开源的、跨平台的关系数据库系统。它作为一个网络服务运行，您可以使用客户端程序或软件库进行通信。在撰写本文时，该项目刚刚发布了 10.0 版本。

尽管 ABQ 提供了一个已安装和配置的 PostgreSQL 服务器，但您需要为开发目的在您的工作站上下载并安装该软件。

共享的生产资源，如数据库和网络服务，永远不应该用于测试或开发。始终在您自己的工作站或单独的服务器上设置这些资源的独立开发副本。

# 安装和配置 PostgreSQL

要下载 PostgreSQL，请访问[`www.postgresql.org/download/`](https://www.postgresql.org/download)。EnterpriseDB 公司为 Windows、macOS 和 Linux 提供了安装程序，这是一个为 PostgreSQL 提供付费支持的商业实体。这些软件包包括服务器、命令行客户端和 pgAdmin 图形客户端。

要安装软件，请使用具有管理权限的帐户启动安装程序，并按照安装向导中的屏幕进行操作。

安装后，启动 pgAdmin，并通过选择 Object | Create | Login/Group Role 来为自己创建一个新的管理员用户。确保访问特权选项卡以检查超级用户，并访问定义选项卡以设置密码。然后，通过选择 Object | Create | Database 来创建一个数据库。确保将您的用户设置为所有者。要在数据库上运行 SQL 命令，请选择您的数据库并单击 Tools | Query Tool。

喜欢使用命令行的 MacOS 或 Linux 用户也可以使用以下命令：

```py
sudo -u postgres createuser -sP myusername
sudo -u postgres createdb -O myusername mydatabasename
psql -d mydatabasename -U myusername
```

尽管 Enterprise DB 为 Linux 提供了二进制安装程序，但大多数 Linux 用户更喜欢使用其发行版提供的软件包。您可能会得到一个稍旧的 PostgreSQL 版本，但对于大多数基本用例来说这并不重要。请注意，pgAdmin 通常是单独的软件包的一部分，最新版本（pgAdmin 4）可能不可用。不过，您应该没有问题遵循本章使用旧版本。

# 使用 psycopg2 连接

要从我们的应用程序进行 SQL 查询，我们需要安装一个可以直接与我们的数据库通信的 Python 库。最受欢迎的选择是`psycopg2`。`psycopg2`库不是 Python 标准库的一部分。您可以在[`initd.org/psycopg/docs/install.html`](http://initd.org/psycopg/docs/install.html)找到最新的安装说明；但是，首选方法是使用`pip`。

对于 Windows、macOS 和 Linux，以下命令应该有效：

```py
pip install --user psycopg2-binary
```

如果这不起作用，或者您更愿意从源代码安装它，请在网站上检查要求。`psycopg2`库是用 C 编写的，而不是 Python，因此它需要 C 编译器和其他几个开发包。Linux 用户通常可以从其发行版的软件包管理系统中安装`psycopg2`。我们将在本章后面深入研究`psycopg2`的使用。

# SQL 和关系数据库基础知识

在我们开始使用 Python 与 PostgreSQL 之前，您至少需要对 SQL 有基本的了解。如果您已经有了，可以跳到下一节；否则，准备好接受关系数据库和 SQL 的超短速成课程。

三十多年来，关系数据库系统一直是存储业务数据的事实标准。它们更常被称为**SQL 数据库**，因为与它们交互的**结构化查询语言**（**SQL**）。

SQL 数据库由表组成。表类似于我们的 CSV 文件，因为它具有表示单个项目的行和表示与每个项目关联的数据值的列。SQL 表与我们的 CSV 文件有一些重要的区别。首先，表中的每一列都被分配了一个严格执行的数据类型；就像当您尝试将`abcd`作为`int`使用时，Python 会产生错误一样，当您尝试将字母插入到数字或其他非字符串列中时，SQL 数据库会抱怨。SQL 数据库通常支持文本、数字、日期和时间、布尔值、二进制数据等数据类型。

SQL 表还可以具有约束，进一步强制执行插入到表中的数据的有效性。例如，可以给列添加唯一约束，这可以防止两行具有相同的值，或者添加非空约束，这意味着每一行都必须有一个值。

SQL 数据库通常包含许多表；这些表可以连接在一起，以表示更复杂的数据结构。通过将数据分解为多个链接的表，可以以比我们的二维纯文本 CSV 文件更有效和更具弹性的方式存储数据。

# 基本的 SQL 操作

SQL 是一个用于对表格数据进行大规模操作的强大而表达性的语言，但基础知识可以很快掌握。SQL 作为单独的查询来执行，这些查询要么定义数据，要么在数据库中操作数据。SQL 方言在不同的关系数据库产品之间略有不同，但它们大多数支持 ANSI/ISO 标准 SQL 进行核心操作。虽然我们将在本章中使用 PostgreSQL，但我们编写的大多数 SQL 语句都可以在不同的数据库中使用。

要遵循本节，连接到您的 PostgreSQL 数据库服务器上的空数据库，可以使用`psql`命令行工具、pgAdmin 4 图形工具或您选择的其他数据库客户端软件。

# 与 Python 的语法差异

如果您只在 Python 中编程过，那么最初可能会觉得 SQL 很奇怪，因为规则和语法非常不同。

我们将介绍各个命令和关键字，但以下是与 Python 不同的一些一般区别：

+   **SQL（大部分）不区分大小写**：尽管为了可读性的目的，按照惯例，将 SQL 关键字输入为全大写，但大多数 SQL 实现不区分大小写。这里有一些小的例外，但大部分情况下，您可以以最容易的方式输入 SQL 的大小写。

+   **空格不重要**：在 Python 中，换行和缩进可以改变代码的含义。在 SQL 中，空格不重要，语句以分号结尾。查询中的缩进和换行只是为了可读性。

+   **SQL 是声明性的**：Python 可以被描述为一种命令式编程语言：我们通过告诉 Python 如何做来告诉 Python 我们想要它做什么。SQL 更像是一种声明性语言：我们描述我们想要的，SQL 引擎会找出如何做。

当我们查看特定的 SQL 代码示例时，我们会遇到其他语法差异。

# 定义表和插入数据

SQL 表是使用`CREATE TABLE`命令创建的，如下面的 SQL 查询所示：

```py
CREATE TABLE musicians (id SERIAL PRIMARY KEY, name TEXT NOT NULL, born DATE, died DATE CHECK(died > born));
```

在这个例子中，我们正在创建一个名为`musicians`的表。在名称之后，我们指定了一系列列定义。每个列定义都遵循`column_name data_type constraints`的格式。

在这种情况下，我们有以下四列：

+   `id`列将是任意的行 ID。它的类型是`SERIAL`，这意味着它将是一个自动递增的整数字段，其约束是`PRIMARY KEY`，这意味着它将用作行的唯一标识符。

+   `name`字段的类型是`TEXT`，因此它可以容纳任意长度的字符串。它的`NOT NULL`约束意味着在该字段中不允许`NULL`值。

+   `born`和`died`字段是`DATE`字段，因此它们只能容纳日期值。`born`字段没有约束，但`died`有一个`CHECK`约束，强制其值必须大于任何给定行的`born`的值。

虽然不是必需的，但为每个表指定一个主键是一个好习惯。主键可以是一个字段，也可以是多个字段的组合，但对于任何给定的行，值必须是唯一的。例如，如果我们将`name`作为主键字段，那么我们的表中不能有两个同名的音乐家。

要向该表添加数据行，我们使用`INSERT INTO`命令如下：

```py
INSERT INTO musicians (name, born, died) VALUES ('Robert Fripp', '1946-05-16', NULL),   ('Keith Emerson', '1944-11-02', '2016-03-11'), ('Greg Lake', '1947-11-10', '2016-12-7'),   ('Bill Bruford', '1949-05-17', NULL), ('David Gilmour', '1946-03-06', NULL);
```

`INSERT INTO`命令接受表名和一个可选的列表，指定接收数据的字段；其他字段将接收它们的默认值（如果在`CREATE`语句中没有另外指定，则为`NULL`）。`VALUES`关键字表示要跟随的数据值列表，格式为逗号分隔的元组列表。每个元组对应一个表行，必须与在表名之后指定的字段列表匹配。

请注意，字符串由单引号字符括起来。与 Python 不同，单引号和双引号在 SQL 中具有不同的含义：单引号表示字符串文字，而双引号用于包含空格或需要保留大小写的对象名称。如果我们在这里使用双引号，将导致错误。

让我们创建并填充一个`instruments`表：

```py
CREATE TABLE instruments (id SERIAL PRIMARY KEY, name TEXT NOT NULL);
INSERT INTO instruments (name) VALUES ('bass'), ('drums'), ('guitar'), ('keyboards');
```

请注意，`VALUES`列表必须始终在每一行周围使用括号，即使每行只有一个值。

表在创建后可以使用`ALTER TABLE`命令进行更改，如下所示：

```py
ALTER TABLE musicians ADD COLUMN main_instrument INT REFERENCES instruments(id);
```

`ALTER TABLE`命令接受表名，然后是改变表的某个方面的命令。在这种情况下，我们正在添加一个名为`main_instrument`的新列，它将是一个整数。我们指定的`REFERENCES`约束称为**外键**约束；它将`main_instrument`的可能值限制为`instruments`表中现有的 ID 号码。

# 从表中检索数据

要从表中检索数据，我们使用`SELECT`语句如下：

```py
SELECT name FROM musicians;
```

`SELECT`命令接受一个列或以逗号分隔的列列表，后面跟着一个`FROM`子句，指定包含指定列的表或表。此查询要求从`musicians`表中获取`name`列。

它的输出如下：

| `name` |
| --- |
| `Bill Bruford` |
| `Keith Emerson` |
| `Greg Lake` |
| `Robert Fripp` |
| `David Gilmour` |

我们还可以指定一个星号，表示所有列，如下面的查询所示：

```py
SELECT * FROM musicians;
```

前面的 SQL 查询返回以下数据表：

| `ID` | `name` | `born` | `died` | `main_instrument` |
| --- | --- | --- | --- | --- |
| `4` | `Bill Bruford` | `1949-05-17` |  |  |
| `2` | `Keith Emerson` | `1944-11-02` | `2016-03-11` |  |
| `3` | `Greg Lake` | `1947-11-10` | `2016-12-07` |  |
| `1` | `Robert Fripp` | `1946-05-16` |  |  |
| `5` | `David Gilmour` | `1946-03-06` |  |  |

为了过滤掉我们不想要的行，我们可以指定一个`WHERE`子句，如下所示：

```py
SELECT name FROM musicians WHERE died IS NULL;
```

`WHERE`命令必须跟随一个条件语句；满足条件的行将被显示，而不满足条件的行将被排除。在这种情况下，我们要求没有死亡日期的音乐家的名字。

我们可以使用`AND`和`OR`运算符指定复杂条件如下：

```py
SELECT name FROM musicians WHERE born < '1945-01-01' AND died IS NULL;
```

在这种情况下，我们只会得到 1945 年之前出生且尚未去世的音乐家。

`SELECT`命令也可以对字段进行操作，或者按照某些列重新排序结果：

```py
SELECT name, age(born), (died - born)/365 AS "age at death" FROM musicians ORDER BY born DESC;
```

在这个例子中，我们使用`age()`函数来确定音乐家的年龄。我们还对`died`和`born`日期进行数学运算，以确定那些已故者的死亡年龄。请注意，我们使用`AS`关键字来重命名或别名生成的列。

当运行此查询时，请注意，对于没有死亡日期的人，`age at death`为`NULL`。对`NULL`值进行数学或逻辑运算总是返回`NULL`。

`ORDER BY`子句指定结果应该按照哪些列进行排序。它还接受`DESC`或`ASC`的参数来指定降序或升序。我们在这里按出生日期降序排序输出。请注意，每种数据类型都有其自己的排序规则，就像在 Python 中一样。日期按照它们的日历位置排序，字符串按照字母顺序排序，数字按照它们的数值排序。

# 更新行，删除行，以及更多的 WHERE 子句

要更新或删除现有行，我们使用`UPDATE`和`DELETE FROM`关键字与`WHERE`子句一起选择受影响的行。

删除很简单，看起来像这样：

```py
DELETE FROM instruments WHERE id=4;
```

`DELETE FROM`命令将删除与`WHERE`条件匹配的任何行。在这种情况下，我们匹配主键以确保只删除一行。如果没有行与`WHERE`条件匹配，将不会删除任何行。然而，请注意，`WHERE`子句在技术上是可选的：`DELETE FROM instruments`将简单地删除表中的所有行。

更新类似，只是包括一个`SET`子句来指定新的列值如下：

```py
UPDATE musicians SET main_instrument=3 WHERE id=1;
UPDATE musicians SET main_instrument=2 WHERE name='Bill Bruford';
```

在这里，我们将`main_instrument`设置为两位音乐家对应的`instruments`主键值。我们可以通过主键、名称或任何有效的条件集来选择要更新的音乐家记录。与`DELETE`一样，省略`WHERE`子句会影响所有行。

`SET`子句中可以更新任意数量的列：

```py
UPDATE musicians SET main_instrument=4, name='Keith Noel Emerson' WHERE name LIKE 'Keith%';
```

额外的列更新只需用逗号分隔。请注意，我们还使用`LIKE`运算符与`%`通配符一起匹配记录。`LIKE`可用于文本和字符串数据类型，以匹配部分数值。标准 SQL 支持两个通配符字符：`%`，匹配任意数量的字符，`_`，匹配单个字符。

我们也可以匹配转换后的列值：

```py
UPDATE musicians SET main_instrument=1 WHERE LOWER(name) LIKE '%lake';
```

在这里，我们使用`LOWER`函数将我们的字符串与列值的小写版本进行匹配。这不会永久改变表中的数据；它只是临时更改值以进行检查。

标准 SQL 规定`LIKE`是区分大小写的匹配。PostgreSQL 提供了一个`ILIKE`运算符，它可以进行不区分大小写的匹配，还有一个`SIMILAR TO`运算符，它使用更高级的正则表达式语法进行匹配。

# 子查询

与其每次使用`instruments`表的原始主键值，我们可以像以下 SQL 查询中所示使用子查询：

```py
UPDATE musicians SET main_instrument=(SELECT id FROM instruments WHERE name='guitar') WHERE name IN ('Robert Fripp', 'David Gilmour');
```

子查询是 SQL 查询中的 SQL 查询。如果可以保证子查询返回单个值，它可以用在任何需要使用文字值的地方。在这种情况下，我们让我们的数据库来确定`guitar`的主键是什么，并将其插入我们的`main_instrument`值。

在`WHERE`子句中，我们还使用`IN`运算符来匹配一个值列表。这允许我们匹配一个值列表。

`IN`可以与子查询一起使用，如下所示：

```py
SELECT name FROM musicians WHERE main_instrument IN (SELECT id FROM instruments WHERE name like '%r%')
```

由于`IN`是用于与值列表一起使用的，任何返回单列的查询都是有效的。

返回多行和多列的子查询可以在任何可以使用表的地方使用：

```py
SELECT name FROM (SELECT * FROM musicians WHERE died IS NULL) AS living_musicians;
```

请注意，`FROM`子句中的子查询需要一个别名；我们将子查询命名为`living_musicians`。

# 连接表

子查询是使用多个表的一种方法，但更灵活和强大的方法是使用`JOIN`。

`JOIN`在 SQL 语句的`FROM`子句中使用如下：

```py
SELECT musicians.name, instruments.name as main_instrument FROM musicians JOIN instruments ON musicians.main_instrument = instruments.id;
```

`JOIN`语句需要一个`ON`子句，指定用于匹配每个表中的行的条件。`ON`子句就像一个过滤器，就像`WHERE`子句一样；你可以想象`JOIN`创建一个包含来自两个表的每个可能组合的新表，然后过滤掉不匹配`ON`条件的行。表通常通过匹配共同字段中的值进行连接，比如在外键约束中指定的那些字段。在这种情况下，我们的`musicians.main_instrument`列包含`instrument`表的`id`值，所以我们可以基于此连接这两个表。

连接用于实现以下四种类型的表关系：

+   一对一连接将第一个表中的一行精确匹配到第二个表中的一行。

+   多对一连接将第一个表中的多行精确匹配到第二个表中的一行。

+   一对多连接将第一个表中的一行匹配到第二个表中的多行。

+   多对多连接匹配两个表中的多行。这种连接需要使用一个中间表。

早期的查询显示了一个多对一的连接，因为许多音乐家可以有相同的主要乐器。当一个列的值应该限制在一组选项时，通常会使用多对一连接，比如我们的 GUI 可能会用`ComboBox`小部件表示的字段。连接的表称为**查找表**。

如果我们要反转它，它将是一对多：

```py
SELECT instruments.name AS instrument, musicians.name AS musician FROM instruments JOIN musicians ON musicians.main_instrument = instruments.id;
```

一对多连接通常在记录有与之关联的子记录列表时使用；在这种情况下，每个乐器都有一个将其视为主要乐器的音乐家列表。连接的表通常称为**详细表**。

前面的 SQL 查询将给出以下输出：

| `instrument` | `musician` |
| --- | --- |
| `drums` | `Bill Bruford` |
| `keyboards` | `Keith Emerson` |
| `bass` | `Greg Lake` |
| `guitar` | `Robert Fripp` |
| `guitar` | `David Gilmour` |

请注意，`guitar`在乐器列表中重复了。当两个表连接时，结果的行不再指代相同类型的对象。乐器表中的一行代表一个乐器。`musician`表中的一行代表一个音乐家。这个表中的一行代表一个`instrument`-`musician`关系。

但假设我们想要保持输出，使得一行代表一个乐器，但仍然可以在每行中包含有关关联音乐家的信息。为了做到这一点，我们需要使用聚合函数和`GROUP BY`子句来聚合匹配的音乐家行，如下面的 SQL 查询所示：

```py
SELECT instruments.name AS instrument, count(musicians.id) as musicians FROM instruments JOIN musicians ON musicians.main_instrument = instruments.id GROUP BY instruments.name;
```

`GROUP BY`子句指定输出表中的每一行代表什么列。不在`GROUP BY`子句中的输出列必须使用聚合函数减少为单个值。在这种情况下，我们使用`count()`函数来计算与每个乐器关联的音乐家记录的总数。标准 SQL 包含几个更多的聚合函数，如`min()`、`max()`和`sum()`，大多数 SQL 实现也扩展了这些函数。

多对一和一对多连接并不能完全涵盖数据库需要建模的每种可能情况；很多时候，需要一个多对多的关系。

为了演示多对多连接，让我们创建一个名为`bands`的新表，如下所示：

```py
CREATE TABLE bands (id SERIAL PRIMARY KEY, name TEXT NOT NULL);
INSERT INTO bands(name) VALUES ('ABWH'), ('ELP'), ('King Crimson'), ('Pink Floyd'), ('Yes');
```

一个乐队有多位音乐家，音乐家也可以是多个乐队的一部分。我们如何在音乐家和乐队之间创建关系？如果我们在`musicians`表中添加一个`band`字段，这将限制每个音乐家只能属于一个乐队。如果我们在`band`表中添加一个`musician`字段，这将限制每个乐队只能有一个音乐家。为了建立连接，我们需要创建一个**连接表**，其中每一行代表一个音乐家在一个乐队中的成员资格。

按照惯例，我们称之为`musicians_bands`：

```py
CREATE TABLE musicians_bands (musician_id INT REFERENCES musicians(id), band_id INT REFERENCES bands(id), PRIMARY KEY (musician_id, band_id));
INSERT INTO musicians_bands(musician_id, band_id) VALUES (1, 3), (2, 2), (3, 2), (3, 3), (4, 1), (4, 2), (4, 5), (5,4);
```

`musicians_bands`表只包含两个外键字段，一个指向音乐家的 ID，一个指向乐队的 ID。请注意，我们使用两个字段的组合作为主键，而不是创建或指定一个字段作为主键。有多行具有相同的两个值是没有意义的，因此这种组合可以作为一个合适的主键。要编写使用这种关系的查询，我们的`FROM`子句需要指定两个`JOIN`语句：一个从`musicians`到`musicians_bands`，一个从`bands`到`musicians_bands`。

例如，让我们获取每位音乐家所在乐队的名字：

```py
SELECT musicians.name, array_agg(bands.name) AS bands FROM musicians JOIN musicians_bands ON musicians.id = musicians_bands.musician_id JOIN bands ON bands.id = musicians_bands.band_id GROUP BY musicians.name ORDER BY musicians.name ASC;
```

这个查询使用连接表将`音乐家`和`乐队`联系起来，然后显示音乐家的名字以及他们所在乐队的聚合列表，并按音乐家的名字排序。

前面的 SQL 查询给出了以下输出：

| `name` | `bands` |
| --- | --- |
| `Bill Bruford` | `{ABWH,"King Crimson",Yes}` |
| `David Gilmour` | `{"Pink Floyd"}` |
| `Greg Lake` | `{ELP,"King Crimson"}` |
| `Keith Emerson` | `{ELP}` |
| `Robert Fripp` | ``{"King Crimson"}`` |

这里使用的`array_agg()`函数将字符串值聚合成数组结构。这种方法和`ARRAY`数据类型是特定于 PostgreSQL 的。没有用于聚合字符串值的 SQL 标准函数，但大多数 SQL 实现都有解决方案。

# 学习更多

这是对 SQL 概念和语法的快速概述；我们已经涵盖了你需要了解的大部分内容，但还有很多东西需要学习。PostgreSQL 手册，可在[`www.postgresql.org/docs/manuals/`](https://www.postgresql.org/docs/manuals/)上找到，是 SQL 语法和 PostgreSQL 特定功能的重要资源和参考。

# 建模关系数据

我们的应用目前将数据存储在一个单独的 CSV 文件中；这种文件通常被称为**平面文件**，因为数据已经被压缩成了两个维度。虽然这种格式对我们的应用程序来说可以接受，并且可以直接转换成 SQL 表，但更准确和有用的数据模型需要更复杂的结构。

# 规范化

将平面数据文件拆分成多个表的过程称为**规范化**。规范化是一个涉及一系列级别的过程，称为**范式**，逐步消除重复并创建更精确的数据模型。虽然有许多范式，但大多数常见业务数据中遇到的问题都可以通过符合前三个范式来解决。

粗略地说，这需要以下条件：

+   **第一范式**要求每个字段只包含一个值，并且必须消除重复的列。

+   **第二范式**还要求每个值必须依赖于整个主键。换句话说，如果一个表有主键字段`A`、`B`和`C`，并且列`X`的值仅取决于列`A`的值，而不考虑`B`或`C`，那么该表就违反了第二范式。

+   **第三范式**还要求表中的每个值只依赖于主键。换句话说，给定一个具有主键`A`和数据字段`X`和`Y`的表，`Y`的值不能依赖于`X`的值。

符合这些规范的数据消除了冗余、冲突或未定义数据情况的可能性。

# 实体关系图

帮助规范化我们的数据并为关系数据库做好准备的一种有效方法是分析数据并创建一个**实体-关系图**，或**ERD**。 ERD 是一种用图表表示数据库存储信息和这些信息之间关系的方法。

这些东西被称为**实体**。**实体**是一个唯一可识别的对象；它对应于单个表的单行。实体具有属性，对应于其表的列。实体与其他实体有关系，这对应于我们在 SQL 中定义的外键关系。

让我们考虑实验室场景中的实体及其属性和关系：

+   有实验室。每个实验室都有一个名字。

+   有地块。每个地块都属于一个实验室，并有一个编号。在地块中种植种子样本。

+   有实验室技术人员，每个人都有一个名字。

+   有实验室检查，由实验室技术人员在特定实验室进行。每个检查都有日期和时间。

+   有地块检查，这是在实验室检查期间在地块上收集的数据。每个地块检查都记录了各种植物和环境数据。

以下是这些实体和关系的图表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/7fd91062-81f2-4025-a39e-26abb3216732.png)

在前面的图表中，实体由矩形表示。我们有五个实体：**实验室**，**地块**，**实验室技术人员**，**实验室检查**和**地块检查**。每个实体都有属性，用椭圆形表示。关系由菱形表示，其中的文字描述了左到右的关系。例如，**实验室技术人员**执行**实验室检查**，**实验室检查**在**实验室**中进行。请注意关系周围的小**1**和**n**字符：这些显示了关系是一对多，多对一还是多对多。

这个图表代表了我们数据的一个相当规范化的结构。要在 SQL 中实现它，我们只需为每个实体创建一个表，为每个属性创建一个列，并为每个关系创建一个外键关系（可能包括一个中间表）。在我们这样做之前，让我们考虑 SQL 数据类型。

# 分配数据类型

标准 SQL 定义了 16 种数据类型，包括各种大小的整数和浮点数类型、固定大小或可变大小的 ASCII 或 Unicode 字符串、日期和时间类型以及位类型。几乎每个 SQL 引擎都会扩展这些类型，以适应二进制数据、特殊类型的字符串或数字等。许多数据类型似乎有点多余，而且有几个别名在不同的实现之间可能是不同的。选择列的数据类型可能会令人困惑！

对于 PostgreSQL，以下图表提供了一些合理的选择：

| **存储的数据** | **推荐类型** | **备注** |
| --- | --- | --- |
| 固定长度字符串 | `CHAR` | 需要长度。 |
| 短到中等长度的字符串 | `VARCHAR` | 需要一个最大长度参数，例如，`VARCHAR(256)`。 |
| 长、自由格式文本 | `TEXT` | 无限长度，性能较慢。 |
| 较小的整数 | `SMALLINT` | 最多±32,767。 |
| 大多数整数 | `INT` | 最多约±21 亿。 |
| 较大的整数 | `BIGINT` | 最多约±922 万亿。 |
| 小数 | `NUMERIC` | 接受可选的长度和精度参数。 |
| 整数主键 | `SERIAL`，`BIGSERIAL` | 自动递增整数或大整数。 |
| 布尔 | `BOOLEAN` |  |
| 日期和时间 | `TIMESTAMP WITH TIMEZONE` | 存储日期、时间和时区。精确到 1 微秒。 |
| 无时间的日期 | `DATE` |  |
| 无日期的时间 | `TIME` | 可以有或没有时区。 |

这些类型可能在大多数应用中满足您的绝大多数需求，我们将在我们的 ABQ 数据库中使用其中的一部分。在创建表时，我们将参考我们的数据字典，并为我们的列选择适当的数据类型。

注意不要选择过于具体或限制性的数据类型。任何数据最终都可以存储在`TEXT`字段中；选择更具体的类型的目的主要是为了能够使用特定类型的运算符、函数或排序。如果不需要这些，可以考虑使用更通用的类型。例如，电话号码和美国社会安全号码可以纯粹用数字表示，但这并不意味着要将它们作为`INTEGER`或`NUMERIC`字段；毕竟，你不会用它们进行算术运算！

# 创建 ABQ 数据库

现在我们已经对数据进行了建模，并对可用的数据类型有了一定的了解，是时候建立我们的数据库了。首先，在您的 SQL 服务器上创建一个名为`abq`的数据库，并将自己设为所有者。

接下来，在您的项目根目录下，创建一个名为`sql`的新目录。在`sql`文件夹中，创建一个名为`create_db.sql`的文件。我们将从这个文件开始编写我们的数据库创建代码。

# 创建我们的表

我们创建表的顺序很重要。在外键关系中引用的任何表都需要在定义关系之前存在。因此，最好从查找表开始，并遵循一对多关系的链，直到所有表都被创建。在我们的 ERD 中，这将使我们从大致左上到右下。

# 创建查找表

我们需要创建以下三个查找表：

+   `labs`：这个查找表将包含我们实验室的 ID 字符串。

+   `lab_techs`：这个查找表将包含实验室技术员的姓名，通过他们的员工 ID 号进行标识。

+   `plots`：这个查找表将为每个物理地块创建一行，由实验室和地块号标识。它还将跟踪地块中种植的当前种子样本。

将用于创建这些表的 SQL 查询添加到`create_db.sql`中，如下所示：

```py
CREATE TABLE labs (id CHAR(1) PRIMARY KEY);
CREATE TABLE lab_techs (id SMALLINT PRIMARY KEY, name VARCHAR(512) UNIQUE NOT NULL);
CREATE TABLE plots (lab_id CHAR(1) NOT NULL REFERENCES labs(id), 
    plot SMALLINT NOT NULL, current_seed_sample CHAR(6), 
    PRIMARY KEY(lab_id, plot), 
    CONSTRAINT valid_plot CHECK (plot BETWEEN 1 AND 20));
```

在我们可以使用我们的数据库之前，查找表将需要被填充：

+   `labs`应该有值`A`到`E`，代表五个实验室。

+   `lab_techs`需要我们四名实验室技术员的姓名和 ID 号：`J Simms`（`4291`）、`P Taylor`（`4319`）、`Q Murphy`（`4478`）和`L Taniff`（`5607`）。

+   `plots`需要所有 100 个地块，每个实验室的地块号为`1`到`20`。种子样本在四个值之间轮换，如`AXM477`、`AXM478`、`AXM479`和`AXM480`。

您可以手动使用 pgAdmin 填充这些表，或者使用包含在示例代码中的`db_populate.sql`脚本。

# 实验室检查表

`lab_check`表是一个技术人员在给定日期的给定时间检查实验室的所有地块的一个实例，如下所示的 SQL 查询：

```py
CREATE TABLE lab_checks(
    date DATE NOT NULL, time TIME NOT NULL, 
    lab_id CHAR(1) NOT NULL REFERENCES labs(id), 
    lab_tech_id SMALLINT NOT NULL REFERENCES lab_techs(id), 
    PRIMARY KEY(date, time, lab_id));
```

`date`、`time`和`lab_id`列一起唯一标识了实验室检查，因此我们将它们指定为主键列。执行检查的实验室技术员的 ID 是这个表中唯一的属性。

# 地块检查表

地块检查是在单个地块收集的实际数据记录。这些是实验室检查的一部分，因此必须参考现有的实验室检查。

我们将从主键列开始：

```py
CREATE TABLE plot_checks(date DATE NOT NULL, time TIME NOT NULL,
lab_id CHAR(1) NOT NULL REFERENCES labs(id), plot SMALLINT NOT NULL,
```

这是`lab_check`表的主键加上`plot`号；它的键约束看起来像这样：

```py
PRIMARY KEY(date, time, lab_id, plot),
FOREIGN KEY(date, time, lab_id)
    REFERENCES lab_checks(date, time, lab_id),
FOREIGN KEY(lab_id, plot) REFERENCES plots(lab_id, plot),
```

现在我们可以添加属性列：

```py
seed_sample CHAR(6) NOT NULL, 
humidity NUMERIC(4, 2) CHECK (humidity BETWEEN 0.5 AND 52.0),
light NUMERIC(5, 2) CHECK (light BETWEEN 0 AND 100),
temperature NUMERIC(4, 2) CHECK (temperature BETWEEN 4 AND 40),
equipment_fault BOOLEAN NOT NULL,
blossoms SMALLINT NOT NULL CHECK (blossoms BETWEEN 0 AND 1000),
plants SMALLINT NOT NULL CHECK (plants BETWEEN 0 AND 20),
fruit SMALLINT NOT NULL CHECK (fruit BETWEEN 0 AND 1000),
max_height NUMERIC(6, 2) NOT NULL CHECK (max_height BETWEEN 0 AND 1000),
min_height NUMERIC(6, 2) NOT NULL CHECK (min_height BETWEEN 0 AND 1000),
median_height NUMERIC(6, 2) NOT NULL 
    CHECK (median_height BETWEEN min_height AND max_height),
notes TEXT);
```

请注意我们对数据类型和`CHECK`约束的使用，以复制我们的`data`字典中的限制。使用这些，我们利用了数据库的功能来防止无效数据。

# 创建视图

在完成数据库设计之前，我们将创建一个视图，以简化对我们数据的访问。视图在大多数方面都像表一样，但不包含实际数据；它实际上只是一个存储的`SELECT`查询。我们的视图将为与 GUI 交互更容易地格式化我们的数据。

视图是使用`CREATE VIEW`命令创建的，如下所示：

```py
CREATE VIEW data_record_view AS (
```

在括号内，我们放置将为我们的视图返回表数据的`SELECT`查询：

```py
SELECT pc.date AS "Date", to_char(pc.time, 'FMHH24:MI') AS "Time",
    lt.name AS "Technician", pc.lab_id AS "Lab", pc.plot AS "Plot",
    pc.seed_sample AS "Seed sample", pc.humidity AS "Humidity",
    pc.light AS "Light", pc.temperature AS "Temperature",
    pc.plants AS "Plants", pc.blossoms AS "Blossoms", pc.fruit AS 
    "Fruit",
    pc.max_height AS "Max Height", pc.min_height AS "Min Height",
    pc.median_height AS "Median Height", pc.notes AS "Notes"
FROM plot_checks AS pc JOIN lab_checks AS lc ON pc.lab_id = lc.lab_id AND pc.date = lc.date AND pc.time = lc.time JOIN lab_techs AS lt ON lc.lab_tech_id = lt.id);
```

我们正在选择`plot_checks`表，并通过外键关系将其与`lab_checks`和`lab_techs`连接起来。请注意，我们使用`AS`关键字给这些表起了别名。像这样的简短别名可以帮助使大查询更易读。我们还将每个字段别名为应用程序数据结构中使用的名称。这些必须用双引号括起来，以允许使用空格并保留大小写。通过使列名与应用程序中的`data`字典键匹配，我们就不需要在应用程序代码中翻译字段名。

诸如 PostgreSQL 之类的 SQL 数据库引擎在连接和转换表格数据方面非常高效。在可能的情况下，利用这种能力，让数据库为了您的应用程序的方便而进行数据格式化工作。

这完成了我们的数据库创建脚本。在您的 PostgreSQL 客户端中运行此脚本，并验证已创建四个表和视图。

# 将 SQL 集成到我们的应用程序中

将我们的应用程序转换为 SQL 后端将不是一项小任务。该应用程序是围绕 CSV 文件的假设构建的，尽管我们已经注意到了分离我们的关注点，但许多事情都需要改变。

让我们分解一下我们需要采取的步骤：

+   我们需要编写一个 SQL 模型

+   我们的`Application`类将需要使用 SQL 模型

+   记录表格需要重新排序以优先考虑我们的键，使用新的查找和使用数据库自动填充

+   记录列表将需要调整以适应新的数据模型和主键

在这个过程中，我们将需要修复其他错误或根据需要实现一些新的 UI 元素。让我们开始吧！

# 创建一个新模型

我们将从`models.py`开始导入`psycopg2`和`DictCursor`：

```py
import psycopg2 as pg
from psycopg2.extras import DictCursor
```

`DictCursor`将允许我们以 Python 字典而不是默认的元组获取结果，这在我们的应用程序中更容易处理。

开始一个名为`SQLModel`的新模型类，并从`CSVModel`复制`fields`属性。

首先清除`Technician`、`Lab`和`Plot`的值列表，并将`Technician`设置为`FT.string_list`类型：

```py
class SQLModel:
    fields = {
        ...
        "Technician": {'req': True, 'type': FT.string_list, 
                       'values': []},
        "Lab": {'req': True, 'type': FT.string_list, 'values': []},
        "Plot": {'req': True, 'type': FT.string_list,'values': []},

```

这些列表将从我们的查找表中填充，而不是硬编码到模型中。

我们将在`__init__()`方法中完成这些列表的填充：

```py
    def __init__(self, host, database, user, password):
        self.connection = pg.connect(host=host, database=database,
            user=user, password=password, cursor_factory=DictCursor)

        techs = self.query("SELECT * FROM lab_techs ORDER BY name")
        labs = self.query("SELECT id FROM labs ORDER BY id")
        plots = self.query(
        "SELECT DISTINCT plot FROM plots ORDER BY plot")
        self.fields['Technician']['values'] = [x['name'] for x in 
        techs]
        self.fields['Lab']['values'] = [x['id'] for x in labs]
        self.fields['Plot']['values'] = [str(x['plot']) for x in plots]
```

`__init__()`接受我们基本的数据库连接细节，并使用`psycopg2.connect()`建立与数据库的连接。因为我们将`DictCursor`作为`cursor_factory`传入，这个连接将返回所有数据查询的字典列表。

然后，我们查询数据库以获取我们三个查找表中的相关列，并使用列表推导式来展平每个查询的结果以获得`values`列表。

这里使用的`query`方法是我们需要接下来编写的包装器：

```py
    def query(self, query, parameters=None):
        cursor = self.connection.cursor()
        try:
            cursor.execute(query, parameters)
        except (pg.Error) as e:
            self.connection.rollback()
            raise e
        else:
            self.connection.commit()
            if cursor.description is not None:
                return cursor.fetchall()
```

使用`psycopg2`查询数据库涉及从连接生成`cursor`对象，然后使用查询字符串和可选参数数据调用其`execute()`方法。默认情况下，所有查询都在事务中执行，这意味着它们在我们提交更改之前不会生效。如果查询因任何原因（SQL 语法错误、约束违反、连接问题等）引发异常，事务将进入损坏状态，并且必须在我们再次使用连接之前回滚（恢复事务的初始状态）。因此，我们将在`try`块中执行我们的查询，并在任何`psycopg2`相关异常（所有都是从`pg.Error`继承的）的情况下使用`connection.rollback()`回滚事务。

在查询执行后从游标中检索数据时，我们使用 `fetchall()` 方法，它将所有结果作为列表检索。但是，如果查询不是返回数据的查询（例如 `INSERT`），`fetchall()` 将抛出异常。为了避免这种情况，我们首先检查 `cursor.description`：如果查询返回了数据（即使是空数据集），`cursor.description` 将包含有关返回表的元数据（例如列名）。如果没有，则为 `None`。

让我们通过编写 `get_all_records()` 方法来测试我们的 `query()` 方法：

```py
    def get_all_records(self, all_dates=False):
        query = ('SELECT * FROM data_record_view '
            'WHERE NOT %(all_dates)s OR "Date" = CURRENT_DATE '
            'ORDER BY "Date", "Time", "Lab", "Plot"')
        return self.query(query, {'all_dates': all_dates})
```

由于我们的用户习惯于仅使用当天的数据，因此默认情况下只显示该数据，但如果我们需要检索所有数据，我们可以添加一个可选标志。我们可以在大多数 SQL 实现中使用 `CURRENT_DATE` 常量获取当前日期，我们在这里使用了它。为了使用我们的 `all_dates` 标志，我们正在使用准备好的查询。

语法 `%(all_dates)s` 定义了一个参数；它告诉 `psycopg2` 检查包含的参数字典，以便将其值替换到查询中。`psycopg2` 库将自动以一种安全的方式执行此操作，并正确处理各种数据类型，如 `None` 或布尔值。

始终使用准备好的查询将数据传递到 SQL 查询中。永远不要使用字符串格式化或连接！不仅比你想象的更难以正确实现，而且可能会导致意外或恶意的数据库损坏。

接下来，让我们创建 `get_record()`：

```py
def get_record(self, date, time, lab, plot):
    query = ('SELECT * FROM data_record_view '
        'WHERE "Date" = %(date)s AND "Time" = %(time)s '
        'AND "Lab" = %(lab)s AND "Plot" = %(plot)s')
    result = self.query(
        query, {"date": date, "time": time, "lab": lab, "plot": plot})
    return result[0] if result else {}
```

我们不再处理像我们的 `CSVModel` 那样的行号，因此此方法需要所有四个关键字段来检索记录。再次，我们使用了准备好的查询，为这四个字段指定参数。请注意参数括号的右括号后面的 `s`；这是一个必需的格式说明符，应始终为 `s`。

即使只有一行，`query()` 也会以列表的形式返回结果。我们的应用程序期望从 `get_record()` 中获得一个单行字典，因此我们的 `return` 语句会在列表不为空时提取 `result` 中的第一项，如果为空则返回一个空的 `dict`。

检索实验室检查记录非常类似：

```py
    def get_lab_check(self, date, time, lab):
        query = ('SELECT date, time, lab_id, lab_tech_id, '
            'lt.name as lab_tech FROM lab_checks JOIN lab_techs lt '
            'ON lab_checks.lab_tech_id = lt.id WHERE '
            'lab_id = %(lab)s AND date = %(date)s AND time = %(time)s')
        results = self.query(
            query, {'date': date, 'time': time, 'lab': lab})
        return results[0] if results else {}
```

在此查询中，我们使用连接来确保我们有技术员名称可用，而不仅仅是 ID。这种方法将在我们的 `save_record()` 方法和表单数据自动填充方法中非常有用。

`save_record()` 方法将需要四个查询：对 `lab_checks` 和 `plot_checks` 的 `INSERT` 和 `UPDATE` 查询。为了保持方法相对简洁，让我们将查询字符串创建为类属性。

我们将从实验室检查查询开始：

```py
    lc_update_query = ('UPDATE lab_checks SET lab_tech_id = '
        '(SELECT id FROM lab_techs WHERE name = %(Technician)s) '
        'WHERE date=%(Date)s AND time=%(Time)s AND lab_id=%(Lab)s')
    lc_insert_query = ('INSERT INTO lab_checks VALUES (%(Date)s, 
        '%(Time)s, %(Lab)s,(SELECT id FROM lab_techs '
        'WHERE name=%(Technician)s))')
```

这些查询非常简单，但请注意我们使用子查询来填充每种情况中的 `lab_tech_id`。我们的应用程序不知道实验室技术员的 ID 是什么，因此我们需要通过名称查找 ID。另外，请注意我们的参数名称与应用程序字段中使用的名称相匹配。这将使我们无需重新格式化从表单获取的记录数据。

地块检查查询更长，但并不复杂：

```py
    pc_update_query = (
        'UPDATE plot_checks SET seed_sample = %(Seed sample)s, '
        'humidity = %(Humidity)s, light = %(Light)s, '
        'temperature = %(Temperature)s, '
        'equipment_fault = %(Equipment Fault)s, '
        'blossoms = %(Blossoms)s, plants = %(Plants)s, '
        'fruit = %(Fruit)s, max_height = %(Max Height)s, '
        'min_height = %(Min Height)s, median_height = '
        '%(Median Height)s, notes = %(Notes)s '
        'WHERE date=%(Date)s AND time=%(Time)s '
        'AND lab_id=%(Lab)s AND plot=%(Plot)s')

    pc_insert_query = (
        'INSERT INTO plot_checks VALUES (%(Date)s, %(Time)s, %(Lab)s,'
        ' %(Plot)s, %(Seed sample)s, %(Humidity)s, %(Light)s,'
        ' %(Temperature)s, %(Equipment Fault)s, %(Blossoms)s,'
        ' %(Plants)s, %(Fruit)s, %(Max Height)s, %(Min Height)s,'
        ' %(Median Height)s, %(Notes)s)')
```

有了这些查询，我们可以开始 `save_record()` 方法：

```py
    def save_record(self, record):
        date = record['Date']
        time = record['Time']
        lab = record['Lab']
        plot = record['Plot']
```

`CSVModel.save_record()` 方法接受一个 `record` 字典和一个 `rownum`，但是我们不再需要 `rownum`，因为它没有意义。我们所有的关键信息已经在记录中。为了方便起见，我们将提取这四个字段并为它们分配本地变量名。

当我们尝试在这个数据库中保存记录时，有三种可能性：

+   实验室检查或地块检查记录都不存在。两者都需要创建。

+   实验室检查存在，但地块检查不存在。如果用户想要更正技术员的值，则需要更新实验室检查，而地块检查需要添加。

+   实验室检查和地块检查都存在。两者都需要使用提交的值进行更新。

为了确定哪种可能性是真实的，我们将利用我们的 `get_` 方法：

```py
        if self.get_lab_check(date, time, lab):
            lc_query = self.lc_update_query
        else:
            lc_query = self.lc_insert_query
        if self.get_record(date, time, lab, plot):
            pc_query = self.pc_update_query
        else:
            pc_query = self.pc_insert_query
```

对于实验室检查和地块检查，我们尝试使用我们的键值从各自的表中检索记录。如果找到了一个，我们将使用我们的更新查询；否则，我们将使用我们的插入查询。

现在，我们只需使用`record`作为参数列表运行这些查询。

```py
        self.query(lc_query, record)
        self.query(pc_query, record)
```

请注意，`psycopg2`不会因为我们传递了一个在查询中没有引用的额外参数的字典而出现问题，因此我们不需要费心从`record`中过滤不需要的项目。

这里还有一件事情要做：记住我们的`Application`需要跟踪更新和插入的行。由于我们不再处理行号，只有数据库模型知道是否执行了插入或更新。

让我们创建一个实例属性来共享这些信息：

```py
        if self.get_record(date, time, lab, plot):
            pc_query = self.pc_update_query
            self.last_write = 'update'
        else:
            pc_query = self.pc_insert_query
            self.last_write = 'insert'
```

现在`Application`可以在调用`save_record()`后检查`last_write`的值，以确定执行了哪种操作。

这个模型还需要最后一个方法；因为我们的数据库知道每个地块当前种子样本是什么，我们希望我们的表单自动为用户填充这些信息。我们需要一个方法，它接受一个`lab`和`plot_id`，并返回种子样本名称。

我们将称其为`get_current_seed_sample()`。

```py
    def get_current_seed_sample(self, lab, plot):
        result = self.query('SELECT current_seed_sample FROM plots '
            'WHERE lab_id=%(lab)s AND plot=%(plot)s',
            {'lab': lab, 'plot': plot})
        return result[0]['current_seed_sample'] if result else ''
```

这次，我们的`return`语句不仅仅是提取结果的第一行，而是提取该第一行中`current_seed_sample`列的值。如果没有`result`，我们将返回一个空字符串。

这完成了我们的模型类；现在让我们将其合并到应用程序中。

# 调整 SQL 后端的 Application 类

`Application`类需要的第一件事是数据库连接信息，以传递给模型。

对于主机和数据库名称，我们可以只需向我们的`SettingsModel`添加设置：

```py
    variables = {
        ...
        'db_host': {'type': 'str', 'value': 'localhost'},
        'db_name': {'type': 'str', 'value': 'abq'}
```

这些可以保存在我们的 JSON`config`文件中，可以编辑以从开发切换到生产，但我们的用户名和密码需要用户输入。为此，我们需要构建一个登录对话框。

# 构建登录窗口

Tkinter 没有为我们提供现成的登录对话框，但它提供了一个通用的`Dialog`类，可以被子类化以创建自定义对话框。

从`tkinter.simpledialog`中导入这个类到我们的`views.py`文件：

```py
from tkinter.simpledialog import Dialog
```

让我们从我们的类声明和`__init__()`方法开始：

```py
class LoginDialog(Dialog):

    def __init__(self, parent, title, error=''):
        self.pw = tk.StringVar()
        self.user = tk.StringVar()
        self.error = tk.StringVar(value=error)
        super().__init__(parent, title=title)
```

我们的类将像往常一样接受一个`parent`，一个窗口`title`，以及一个可选的`error`，如果需要重新显示带有`error`消息的对话框（例如，如果密码错误）。`__init__()`的其余部分为密码、用户名和`error`字符串设置了一些 Tkinter 变量；然后，它以通常的方式调用`super()`结束。

表单本身不是在`__init__()`中定义的；相反，我们需要重写`body()`方法：

```py
    def body(self, parent):
        lf = tk.Frame(self)
        ttk.Label(lf, text='Login to ABQ', font='Sans 20').grid()
```

我们做的第一件事是制作一个框架，并使用大字体在第一行添加一个标题标签。

接下来，我们将检查是否有`error`字符串，如果有，以适当的样式显示它。

```py
        if self.error.get():
            tk.Label(lf, textvariable=self.error,
                     bg='darkred', fg='white').grid()
```

现在我们将添加用户名和密码字段，并将我们的框架打包到对话框中。

```py
        ttk.Label(lf, text='User name:').grid()
        self.username_inp = ttk.Entry(lf, textvariable=self.user)
        self.username_inp.grid()
        ttk.Label(lf, text='Password:').grid()
        self.password_inp = ttk.Entry(lf, show='*', 
        textvariable=self.pw)
        self.password_inp.grid()
        lf.pack()
        return self.username_inp
```

注意我们在密码输入中使用`show`选项，它用我们指定的字符替换任何输入的文本，以创建一个隐藏的文本字段。另外，请注意我们从方法中返回用户名输入小部件。`Dialog`在显示时将聚焦在这里返回的小部件上。

`Dialog`自动提供`OK`和`Cancel`按钮；我们想知道点击了哪个按钮，如果是`OK`按钮，检索输入的信息。

点击 OK 会调用`apply()`方法，因此我们可以重写它来设置一个`result`值。

```py
        def apply(self):
            self.result = (self.user.get(), self.pw.get())
```

`Dialog`默认创建一个名为`result`的属性，其值设置为`None`。但是现在，如果我们的用户点击了 OK，`result`将是一个包含用户名和密码的元组。我们将使用这个属性来确定点击了什么，输入了什么。

# 使用登录窗口

为了使用对话框，我们的应用程序需要一个方法，它将在无限循环中显示对话框，直到用户单击取消或提供的凭据成功验证。

在`Application`中启动一个新的`database_login()`方法：

```py
        def database_login(self):
            error = ''
            db_host = self.settings['db_host'].get()
            db_name = self.settings['db_name'].get()
            title = "Login to {} at {}".format(db_name, db_host)
```

我们首先设置一个空的`error`字符串和一个`title`字符串，以传递给我们的`LoginDialog`类。

现在我们将开始无限循环：

```py
        while True:
            login = v.LoginDialog(self, title, error)
            if not login.result:
                break
```

在循环内部，我们创建一个`LoginDialog`，它将阻塞，直到用户单击其中一个按钮。对话框返回后，如果`login.result`是`None`，则用户已单击取消，因此我们会跳出循环并退出方法。

如果我们有一个非`None`的`login.result`，我们将尝试用它登录：

```py
        else:
            username, password = login.result
            try:
                self.data_model = m.SQLModel(
                 db_host, db_name, username, password)
            except m.pg.OperationalError:
                error = "Login Failed"
            else:
                break
```

从`result`元组中提取`username`和`password`后，我们尝试用它创建一个`SQLModel`实例。如果凭据失败，`psycopg2.connect`将引发`OperationalError`，在这种情况下，我们将简单地填充我们的`error`字符串，让无限循环再次迭代。

如果数据模型创建成功，我们只需跳出循环并退出方法。

回到`__init__()`，在设置我们的设置之后，让我们让`database_login()`开始工作：

```py
        self.database_login()
        if not hasattr(self, 'data_model'):
            self.destroy()
            return
```

在调用`self.database_login()`之后，`Application`要么有一个`data_model`属性（因为登录成功），要么没有（因为用户单击了取消）。如果没有，我们将通过销毁主窗口并立即从`__init__()`返回来退出应用程序。

当然，在这个逻辑生效之前，我们需要删除`CSVModel`的创建：

```py
        # Delete this line:
        self.data_model = m.CSVModel(filename=self.filename.get())
```

# 修复一些模型不兼容性

理论上，我们应该能够用相同的方法调用交换一个新模型，我们的应用程序对象将正常工作，但情况并非完全如此。我们需要做一些小的修复来让`Application`与我们的新模型一起工作。

# DataRecordForm 创建

首先，让我们在`Application.__init__()`中修复`DataRecordForm`的实例化：

```py
        # The data record form
        self.recordform = v.DataRecordForm(
            self, self.data_model.fields, self.settings, 
            self.callbacks)
```

以前，我们从`CSVModel`的静态类属性中提取了`fields`参数。我们现在需要从我们的数据模型实例中提取它，因为实例正在设置一些值。

# 修复 open_record()方法

接下来，我们需要修复我们的`open_record()`方法。它目前需要一个`rownum`，但我们不再有行号；我们有`date`、`time`、`lab`和`plot`。

为了反映这一点，用`rowkey`替换所有`rownum`的实例：

```py
    def open_record(self, rowkey=None):
        if rowkey is None:
        # ...etc
```

最后，在`get_record()`调用中扩展`rowkey`，因为它期望四个位置参数：

```py
        record = self.data_model.get_record(*rowkey)
```

# 修复 on_save()方法

`on_save()`的错误处理部分是好的，但在`if errors:`块之后，我们将开始改变事情：

```py
        data = self.recordform.get()
        try:
            self.data_model.save_record(data)
```

我们不再需要提取行号或将其传递给`save_record()`，并且我们可以删除对`IndexError`的处理，因为`SQLModel`不会引发该异常。我们还需要重写`inserted_rows`和`updated_rows`的更新。

在调用`self.status.set()`之后，删除此方法中的所有代码，并用以下代码替换：

```py
        key = (data['Date'], data['Time'], data['Lab'], data['Plot'])
        if self.data_model.last_write == 'update':
            self.updated_rows.append(key)
        else:
            self.inserted_rows.append(key)
        self.populate_recordlist()
        if self.data_model.last_write == 'insert':
            self.recordform.reset()
```

从传递给方法的`data`中构建主键元组后，我们使用`last_write`的值将其附加到正确的列表中。最后，在插入的情况下重置记录表单。

# 创建新的回调

我们希望为我们的记录表单有两个回调。当用户输入`lab`和`plot`值时，我们希望自动填充当前种植在该`plot`中的正确`seed`值。此外，当`date`、`time`和`lab`值已输入，并且我们有匹配的现有实验室检查时，我们应该填充执行该检查的实验室技术人员的姓名。

当然，如果我们的用户不希望数据自动填充，我们也不应该做这些事情。

让我们从`get_current_seed_sample()`方法开始：

```py
    def get_current_seed_sample(self, *args):
        if not (hasattr(self, 'recordform')
            and self.settings['autofill sheet data'].get()):
            return
        data = self.recordform.get()
        plot = data['Plot']
        lab = data['Lab']
        if plot and lab:
            seed = self.data_model.get_current_seed_sample(lab, plot)
            self.recordform.inputs['Seed sample'].set(seed)
```

我们首先检查是否已创建记录表单对象，以及用户是否希望数据自动填充。如果不是，我们退出该方法。接下来，我们从表单的当前数据中获取`plot`和`lab`。如果我们两者都有，我们将使用它们从模型中获取`seed`样本值，并相应地设置表单的`Seed sample`值。

我们将以类似的方式处理实验技术值：

```py
    def get_tech_for_lab_check(self, *args):
        if not (hasattr(self, 'recordform')
            and self.settings['autofill sheet data'].get()):
            return
        data = self.recordform.get()
        date = data['Date']
        time = data['Time']
        lab = data['Lab']

        if all([date, time, lab]):
            check = self.data_model.get_lab_check(date, time, lab)
            tech = check['lab_tech'] if check else ''
            self.recordform.inputs['Technician'].set(tech)
```

这一次，我们需要`date`、`time`和`lab`参数来获取实验检查记录。因为我们不能确定是否存在与这些值匹配的检查，所以如果我们找不到匹配的实验检查，我们将把`tech`设置为空字符串。

将这两种方法添加到`callbacks`字典中，`Application`类应该准备就绪。

# 更新我们的视图以适应 SQL 后端

让我们回顾一下我们需要在视图中进行的更改：

+   重新排列我们的字段，将所有主键放在前面

+   修复我们表单的`load_record()`方法，使其与新的关键结构配合使用

+   为我们的表单添加触发器以填充`Technician`和`Seed sample`

+   修复我们的记录列表以适应新的关键

让我们从我们的记录表单开始。

# 数据记录表单

我们的第一个任务是移动字段。这实际上只是剪切和粘贴代码，然后修复我们的`grid()`参数。将它们放在正确的键顺序中：Date、Time、Lab、Plot。然后，将 Technician 和 Seed sample 留在 Record Information 部分的末尾。

它应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/c9aa7446-02f5-4cf4-b810-7b805ae2dd1b.png)

这种更改的原因是，所有可能触发 Technician 或 Seed sample 自动填充的字段将出现在这些字段之前。如果它们中的任何一个出现在之后，我们将无用地自动填充用户已经填写的字段。

在`__init__()`的末尾，让我们添加触发器来填充 Technician 和 Seed sample：

```py
        for field in ('Lab', 'Plot'):
            self.inputs[field].variable.trace(
                'w', self.callbacks['get_seed_sample'])
        for field in ('Date', 'Time', 'Lab'):
            self.inputs[field].variable.trace(
                'w', self.callbacks['get_check_tech'])
```

我们正在对实验检查和绘图的关键变量进行跟踪；如果它们中的任何一个发生变化，我们将调用适当的回调函数来自动填充表单。

在`load_record()`中，为了清晰起见，用`rowkey`替换`rownum`，然后修复标签`text`，使其有意义：

```py
        self.record_label.config(
            text='Record for Lab {2}, Plot {3} at {0} {1}'
            .format(*rowkey))
```

对于`DataRecordForm`的最后一个更改涉及一个小的可用性问题。随着我们自动填充表单，确定下一个需要聚焦的字段变得越来越令人困惑。我们将通过创建一个方法来解决这个问题，该方法找到并聚焦表单中的第一个空字段。

我们将称之为`focus_next_empty()`：

```py
    def focus_next_empty(self):
        for labelwidget in self.inputs.values():
            if (labelwidget.get() == ''):
                labelwidget.input.focus()
                break
```

在这个方法中，我们只是迭代所有的输入并检查它们当前的值。当我们找到一个返回空字符串时，我们将聚焦它，然后打破循环，这样就不会再检查了。我们可以删除`DataRecordForm.reset()`中对聚焦字段的任何调用，并将其替换为对此方法的调用。您还可以将其添加到我们应用程序的自动填充方法`get_current_seed_sample()`和`get_tech_for_lab_check()`中。

# 记录列表

在`RecordList`中，`Row`列不再包含我们希望显示的有用信息。

我们无法删除它，但我们可以使用这段代码隐藏它：

```py
self.treeview.config(show='headings')
```

`show`配置选项接受两个值中的任意一个或两个：`tree`和`headings`。`tree`参数代表`#0`列，因为它用于展开`tree`。`headings`参数代表其余的列。通过在这里只指定`headings`，`#0`列被隐藏了。

我们还需要处理我们的`populate()`方法，它在很大程度上依赖于`rownum`。

我们将从更改填充值的`for`循环开始：

```py
        for rowdata in rows:
            rowkey = (str(rowdata['Date']), rowdata['Time'],
            rowdata['Lab'], str(rowdata['Plot']))
            values = [rowdata[key] for key in valuekeys]
```

我们可以删除`enumerate()`调用，只需处理行数据，从中提取`rowkey`元组，通过获取`Date`、`Time`、`Lab`和`Plot`。这些需要转换为字符串，因为它们作为 Python 对象（如`date`和`int`）从数据库中出来，我们需要将它们与`inserted`和`updated`中的键进行匹配，这些键都是字符串值（因为它们是从我们的表单中提取的）。

让我们进行比较并设置我们的行标签：

```py
        if self.inserted and rowkey in self.inserted:
            tag = 'inserted'
        elif self.updated and rowkey in self.updated:
            tag = 'updated'
        else:
            tag = ''
```

现在，我们需要决定如何处理我们行的`iid`值。`iid`值必须是字符串；当我们的主键是整数时，这不是问题（可以轻松转换为字符串），但是我们的元组必须以某种方式进行序列化，以便我们可以轻松地反转。

解决这个问题的一个简单方法是将我们的元组转换为一个分隔的字符串：

```py
        stringkey = '{}|{}|{}|{}'.format(*rowkey)
```

任何不会出现在数据中的字符都可以作为分隔符；在这种情况下，我们选择使用管道字符。

现在我们可以在`treeview`中使用键的字符串版本：

```py
        self.treeview.insert('', 'end', iid=stringkey,
            text=stringkey, values=values, tag=tag)
```

该方法的最后部分将键盘用户聚焦在第一行。以前，为了聚焦第一行，我们依赖于第一个`iid`始终为`0`的事实。现在它将是一些数据相关的元组，所以我们必须在设置选择和焦点之前检索第一个`iid`。

我们可以使用`Treeview.identify_row()`方法来实现这一点：

```py
        if len(rows) > 0:
            firstrow = self.treeview.identify_row(0)
            self.treeview.focus_set()
            self.treeview.selection_set(firstrow)
            self.treeview.focus(firstrow)
```

`identify_row()`方法接受行号并返回该行的`iid`。一旦我们有了这个，我们就可以将它传递给`selection_set()`和`focus()`。

我们最后的更改是`on_open_record()`方法。由于我们使用了我们序列化的元组作为`iid`值，显然我们需要将其转换回一个可以传递回`on_open_record()`方法的元组。

这就像调用`split()`一样简单：

```py
        self.callbacks'on_open_record')
```

这修复了我们所有的视图代码，我们的程序已经准备好运行了！

# 最后的更改

呼！这是一次相当艰难的旅程，但你还没有完成。作业是，您需要更新您的单元测试以适应数据库和登录。最好的方法是模拟数据库和登录对话框。

还有一些 CSV 后端的残留物，比如文件菜单中的选择目标... 项目。您可以删除这些 UI 元素，但是将后端代码保留下来可能会在不久的将来派上用场。

# 总结

在本章中，您了解了关系数据库和 SQL，用于处理它们的语言。您学会了对数据进行建模和规范化，以减少不一致性的可能性，以及如何将平面文件转换为关系数据。您学会了如何使用`psycopg2`库，并经历了将应用程序转换为使用 SQL 后端的艰巨任务。

在下一章中，我们将接触云。我们需要使用不同的网络协议联系一些远程服务器来交换数据。您将了解有关 Python 标准库模块的信息，用于处理 HTTP 和 FTP，并使用它们来下载和上传数据。


# 第十一章：连接到云

似乎几乎每个应用程序迟早都需要与外部世界交流，你的`ABQ 数据录入`应用程序也不例外。您收到了一些新的功能请求，这将需要与远程服务器和服务进行一些交互。首先，质量保证部门正在研究当地天气条件如何影响每个实验室的环境数据；他们要求以按需下载和存储当地天气数据的方式。第二个请求来自您的老板，她仍然需要每天上传 CSV 文件到中央公司服务器。她希望这个过程能够简化，并且可以通过鼠标点击来完成。

在本章中，您将学习以下主题：

+   连接到 Web 服务并使用`urllib`下载数据

+   使用`requests`库管理更复杂的 HTTP 交互

+   使用`ftplib`连接和上传到 FTP 服务

# 使用`urllib`进行 HTTP 连接

每次在浏览器中打开网站时，您都在使用**超文本传输协议，或 HTTP**。 HTTP 是在 25 年前创建的，作为 Web 浏览器下载 HTML 文档的一种方式，但已经发展成为最受欢迎的客户端-服务器通信协议之一，用于任何数量的目的。我们不仅可以使用它在互联网上传输从纯文本到流媒体视频的任何内容，而且应用程序还可以使用它来传输数据，启动远程过程或分发计算任务。

基本的 HTTP 事务包括客户端和服务器，其功能如下：

+   **客户端**：客户端创建请求。请求指定一个称为**方法**的操作。最常见的方法是`GET`，用于检索数据，以及`POST`，用于提交数据。请求有一个 URL，指定了请求所在的主机、端口和路径，以及包含元数据的标头，如数据类型或授权令牌。最后，它有一个有效负载，其中可能包含键值对中的序列化数据。

+   **服务器**：服务器接收请求并返回响应。响应包含一个包含元数据的标头，例如响应的状态代码或内容类型。它还包含实际响应内容的有效负载，例如 HTML、XML、JSON 或二进制数据。

在 Web 浏览器中，这些操作是在后台进行的，但我们的应用程序将直接处理请求和响应对象，以便与远程 HTTP 服务器进行通信。

# 使用`urllib.request`进行基本下载

`urllib.request`模块是一个用于生成 HTTP 请求的 Python 模块。它包含一些用于生成 HTTP 请求的函数和类，其中最基本的是`urlopen()`函数。`urlopen()`函数可以创建`GET`或`POST`请求并将其发送到远程服务器。

让我们探索`urllib`的工作原理；打开 Python shell 并执行以下命令：

```py
>>> from urllib.request import urlopen
>>> response = urlopen('http://packtpub.com')
```

`urlopen()`函数至少需要一个 URL 字符串。默认情况下，它会向 URL 发出`GET`请求，并返回一个包装从服务器接收到的响应的对象。这个`response`对象公开了从服务器接收到的元数据或内容，我们可以在我们的应用程序中使用。

响应的大部分元数据都在标头中，我们可以使用`getheader()`来提取，如下所示：

```py
>>> response.getheader('Content-Type')
'text/html; charset=utf-8'
>>> response.getheader('Server')
'nginx/1.4.5'
```

响应具有状态，指示在请求过程中遇到的错误条件（如果有）；状态既有数字又有文本解释，称为`reason`。

我们可以从我们的`response`对象中提取如下：

```py
>>> response.status
200
>>> response.reason
'OK'
```

在上述代码中，`200`状态表示事务成功。客户端端错误，例如发送错误的 URL 或不正确的权限，由 400 系列的状态表示，而服务器端问题由 500 系列的状态表示。

可以使用类似于文件句柄的接口来检索`response`对象的有效负载，如下所示：

```py
>>> html = response.read()
>>> html[:15]
b'<!DOCTYPE html>'
```

就像文件句柄一样，响应只能使用`read()`方法读取一次；与文件句柄不同的是，它不能使用`seek()`“倒带”，因此如果需要多次访问响应数据，重要的是将响应数据保存在另一个变量中。`response.read()`的输出是一个字节对象，应将其转换或解码为适当的对象。

在这种情况下，我们有一个`utf-8`字符串如下：

```py
>>> html.decode('utf-8')[:15]
'<!DOCTYPE html>'
```

除了`GET`请求之外，`urlopen()`还可以生成`POST`请求。

为了做到这一点，我们包括一个`data`参数如下：

```py
>>> response = urlopen('http://duckduckgo.com', data=b'q=tkinter')
```

`data`值需要是一个 URL 编码的字节对象。URL 编码的数据字符串由用`&`符号分隔的键值对组成，某些保留字符被编码为 URL 安全的替代字符（例如，空格字符是`%20`，或者有时只是`+`）。

这样的字符串可以手工创建，但使用`urllib.parse`模块提供的`urlencode`函数更容易。看一下以下代码：

```py
>>> from urllib.parse import urlencode
>>> data = {'q': 'tkinter, python', 'ko': '-2', 'kz': '-1'}
>>> urlencode(data)
'q=tkinter%2C+python&ko=-2&kz=-1'
>>> response = urlopen('http://duckduckgo.com', data=urlencode(data).encode())
```

`data`参数必须是字节，而不是字符串，因此在`urlopen`接受它之前必须对 URL 编码的字符串调用`encode()`。

让我们尝试下载我们应用程序所需的天气数据。我们将使用`http://weather.gov`提供美国境内的天气数据。我们将要下载的实际 URL 是[`w1.weather.gov/xml/current_obs/STATION.xml`](http://w1.weather.gov/xml/current_obs/STATION.xml)，其中`STATION`被本地天气站的呼号替换。在 ABQ 的情况下，我们将使用位于印第安纳州布卢明顿的 KBMG。

QA 团队希望您记录温度（摄氏度）、相对湿度、气压（毫巴）和天空状况（一个字符串，如阴天或晴天）。他们还需要天气站观测到天气的日期和时间。

# 创建下载函数

我们将创建几个访问网络资源的函数，这些函数不会与任何特定的类绑定，因此我们将它们放在自己的文件`network.py`中。让我们看看以下步骤：

1.  在`abq_data_entry`模块目录中创建`network.py`。

1.  现在，让我们打开`network.py`并开始我们的天气下载功能：

```py
from urllib.request import urlopen

def get_local_weather(station):
    url = (
        'http://w1.weather.gov/xml/current_obs/{}.xml'
        .format(station))
    response = urlopen(url)
```

我们的函数将以`station`字符串作为参数，以防以后需要更改，或者如果有人想在不同的设施使用这个应用程序。该函数首先通过构建天气数据的 URL 并使用`urlopen()`请求来开始。

1.  假设事情进行顺利，我们只需要解析出这个`response`数据，并将其放入`Application`类可以传递给数据库模型的形式中。为了确定我们将如何处理响应，让我们回到 Python shell 并检查其中的数据：

```py
>>> response = urlopen('http://w1.weather.gov/xml/current_obs/KBMG.xml')
>>> print(response.read().decode())
<?xml version="1.0" encoding="ISO-8859-1"?>
<?xml-stylesheet href="latest_ob.xsl" type="text/xsl"?>
<current_observation version="1.0"

         xsi:noNamespaceSchemaLocation="http://www.weather.gov/view/current_observation.xsd">
        <credit>NOAA's National Weather Service</credit>
        <credit_URL>http://weather.gov/</credit_URL>
....
```

1.  如 URL 所示，响应的有效负载是一个 XML 文档，其中大部分我们不需要。经过一些搜索，我们可以找到我们需要的字段如下：

```py
        <observation_time_rfc822>Wed, 14 Feb 2018 14:53:00 
        -0500</observation_time_rfc822>
        <weather>Fog/Mist</weather>
        <temp_c>11.7</temp_c>
        <relative_humidity>96</relative_humidity>
        <pressure_mb>1018.2</pressure_mb>
```

好的，我们需要的数据都在那里，所以我们只需要将它从 XML 字符串中提取出来，以便我们的应用程序可以使用。让我们花点时间了解一下解析 XML 数据。

# 解析 XML 天气数据

Python 标准库包含一个`xml`包，其中包含用于解析或创建 XML 数据的几个子模块。`xml.etree.ElementTree`子模块是一个简单、轻量级的解析器，应该满足我们的需求。

让我们将`ElementTree`导入到我们的`network.py`文件中，如下所示：

```py
from xml.etree import ElementTree
```

现在，在函数的末尾，我们将解析我们的`response`对象中的 XML 数据，如下所示：

```py
    xmlroot = ElementTree.fromstring(response.read())
```

`fromstring()`方法接受一个 XML 字符串并返回一个`Element`对象。为了获得我们需要的数据，我们需要了解`Element`对象代表什么，以及如何使用它。

XML 是数据的分层表示；一个元素代表这个层次结构中的一个节点。一个元素以一个标签开始，这是尖括号内的文本字符串。每个标签都有一个匹配的闭合标签，这只是在标签名称前加上一个斜杠的标签。在开放和关闭标签之间，一个元素可能有其他子元素，也可能有文本。一个元素也可以有属性，这些属性是放在开放标签的尖括号内的键值对，就在标签名称之后。

看一下以下 XML 的示例：

```py
<star_system starname="Sol">
  <planet>Mercury</planet>
  <planet>Venus</planet>
  <planet>Earth
    <moon>Luna</moon>
    </planet>
  <planet>Mars
    <moon>Phobos</moon>
    <moon>Deimos</moon>
    </planet>
  <dwarf_planet>Ceres</dwarf_planet>
</star_system>
```

这是太阳系的（不完整的）XML 描述。根元素的标签是`<star_system>`，具有`starname`属性。在这个根元素下，我们有四个`<planet>`元素和一个`<dwarf_planet>`元素，每个元素都包含行星名称的文本节点。一些行星节点还有子`<moon>`节点，每个节点包含卫星名称的文本节点。

可以说，这些数据可以以不同的方式进行结构化；例如，行星名称可以在行星元素内部的子`<name>`节点中，或者作为`<planet>`标签的属性列出。虽然 XML 语法是明确定义的，但 XML 文档的实际结构取决于创建者，因此完全解析 XML 数据需要了解数据在文档中的布局方式。

如果您在之前在 shell 中下载的 XML 天气数据中查看，您会注意到它是一个相当浅的层次结构。在`<current_observations>`节点下，有许多子元素，它们的标签代表特定的数据字段，如温度、湿度、风寒等。

为了获得这些子元素，`Element`为我们提供了以下各种方法：

| **方法** | **返回** |
| --- | --- |
| `iter()` | 所有子节点的迭代器（递归） |
| `find(tag)` | 匹配给定标签的第一个元素 |
| `findall(tag)` | 匹配给定标签的元素列表 |
| `getchildren()` | 直接子节点的列表 |
| `iterfind(tag)` | 匹配给定标签的所有子节点的迭代器（递归） |

早些时候我们下载 XML 数据时，我们确定了包含我们想要从该文档中提取的数据的五个标签：`<observation_time_rfc822>`、`<weather>`、`<temp_c>`、`<relative_humidity>`和`<pressure_mb>`。我们希望我们的`get_local_weather()`函数返回一个包含每个键的 Python `dict`。

让我们在`network.py`文件中添加以下行：

```py
    xmlroot = ElementTree.fromstring(response.read())
    weatherdata = {
        'observation_time_rfc822': None,
        'temp_c': None,
        'relative_humidity': None,
        'pressure_mb': None,
        'weather': None
    }
```

我们的第一行从响应中提取原始 XML 并将其解析为`Element`树，将根节点返回给`xmlroot`。然后，我们设置了包含我们想要从 XML 数据中提取的标签的`dict`。

现在，让我们通过执行以下代码来获取值：

```py
    for tag in weatherdata:
        element = xmlroot.find(tag)
        if element is not None:
            weatherdata[tag] = element.text
```

对于我们的每个标签名称，我们将使用`find()`方法来尝试在`xmlroot`中定位具有匹配标签的元素。这个特定的 XML 文档不使用重复的标签，所以任何标签的第一个实例应该是唯一的。如果匹配了标签，我们将得到一个`Element`对象；如果没有，我们将得到`None`，因此在尝试访问其`text`值之前，我们需要确保`element`不是`None`。

要完成函数，只需返回`weatherdata`。

您可以在 Python shell 中测试此函数；从命令行，导航到`ABQ_Data_Entry`目录并启动 Python shell：

```py
>>> from abq_data_entry.network import get_local_weather
>>> get_local_weather('KBMG')
{'observation_time_rfc822': 'Wed, 14 Feb 2018 16:53:00 -0500',
 'temp_c': '11.7', 'relative_humidity': '96', 'pressure_mb': '1017.0',
 'weather': 'Drizzle Fog/Mist'}
```

您应该得到一个包含印第安纳州布卢明顿当前天气状况的`dict`。您可以在[`w1.weather.gov/xml/current_obs/`](http://w1.weather.gov/xml/current_obs/)找到美国其他城市的站点代码。

现在我们有了天气函数，我们只需要构建用于存储数据和触发操作的表格。

# 实现天气数据存储

为了存储我们的天气数据，我们将首先在 ABQ 数据库中创建一个表来保存单独的观测数据，然后构建一个`SQLModel`方法来存储数据。我们不需要担心编写代码来检索数据，因为我们实验室的质量保证团队有他们自己的报告工具，他们将使用它来访问数据。

# 创建 SQL 表

打开`create_db.sql`文件，并添加一个新的`CREATE TABLE`语句如下：

```py
CREATE TABLE local_weather (
        datetime TIMESTAMP(0) WITH TIME ZONE PRIMARY KEY,
        temperature NUMERIC(5,2),
        rel_hum NUMERIC(5, 2),
        pressure NUMERIC(7,2),
        conditions VARCHAR(32)
        );
```

我们在记录上使用`TIMESTAMP`数据类型作为主键；保存相同时间戳的观测两次是没有意义的，所以这是一个足够好的键。`TIMESTAMP`数据类型后面的`(0)`大小表示我们需要多少小数位来测量秒。由于这些测量大约每小时进行一次，而且我们每四个小时或更长时间（实验室检查完成时）只需要一次，所以在我们的时间戳中不需要秒的小数部分。

请注意，我们保存了时区；当时间戳可用时，始终将时区数据与时间戳一起存储！这可能看起来并不必要，特别是当您的应用程序将在永远不会改变时区的工作场所运行时，但是有许多边缘情况，比如夏令时变化，缺少时区可能会造成重大问题。

在数据库中运行这个`CREATE`查询来构建表，然后我们继续创建我们的`SQLModel`方法。

# 实现 SQLModel.add_weather_data()方法

在`models.py`中，让我们添加一个名为`add_weather_data()`的新方法到`SQLModel`类中，它只接受一个数据`dict`作为参数。

让我们通过以下方式开始这个方法，编写一个`INSERT`查询：

```py
    def add_weather_data(self, data):
        query = (
            'INSERT INTO local_weather VALUES '
            '(%(observation_time_rfc822)s, %(temp_c)s, '
            '%(relative_humidity)s, %(pressure_mb)s, '
            '%(weather)s)'
        )
```

这是一个使用与`get_local_weather()`函数从 XML 数据中提取的`dict`键匹配的变量名的参数化`INSERT`查询。我们只需要将这个查询和数据`dict`传递给我们的`query()`方法。

然而，有一个问题；如果我们得到重复的时间戳，我们的查询将因为重复的主键而失败。我们可以先进行另一个查询来检查，但这有点多余，因为 PostgreSQL 在插入新行之前会检查重复的键。当它检测到这样的错误时，`psycopg2`会引发一个`IntegrityError`异常，所以我们只需要捕获这个异常，如果它被引发了，就什么都不做。

为了做到这一点，我们将在`try...except`块中包装我们的`query()`调用如下：

```py
        try:
            self.query(query, data)
        except pg.IntegrityError:
            # already have weather for this datetime
            pass
```

现在，我们的数据录入人员可以随意调用这个方法，但只有在有新的观测数据需要保存时才会保存记录。

# 更新`SettingsModel`类

在离开`models.py`之前，我们需要添加一个新的应用程序设置来存储首选的天气站。在`SettingsModel.variables`字典中添加一个新条目如下：

```py
    variables = {
        ...
        'weather_station': {'type': 'str', 'value': 'KBMG'},
        ...
```

我们不会为这个设置添加 GUI，因为用户不需要更新它。这将由我们或其他实验室站点的系统管理员来确保在每台工作站上正确设置。

# 添加天气下载的 GUI 元素

`Application`对象现在需要将`network.py`中的天气下载方法与`SQLModel`中的数据库方法连接起来，并使用适当的回调方法，主菜单类可以调用。按照以下步骤进行：

1.  打开`application.py`并开始一个新的方法如下：

```py
    def update_weather_data(self):

      try:
           weather_data = n.get_local_weather(
               self.settings['weather_station'].get())
```

1.  请记住，在错误场景中，`urlopen()`可能会引发任意数量的异常，这取决于 HTTP 事务出了什么问题。应用程序除了通知用户并退出方法外，实际上没有什么可以处理这些异常的。因此，我们将捕获通用的`Exception`并在`messagebox`中显示文本如下：

```py
        except Exception as e:
            messagebox.showerror(
                title='Error',
                message='Problem retrieving weather data',
                detail=str(e)
            )
            self.status.set('Problem retrieving weather data')
```

1.  如果`get_local_weather()`成功，我们只需要将数据传递给我们的模型方法如下：

```py
        else:
            self.data_model.add_weather_data(weather_data)
            self.status.set(
                'Weather data recorded for {}'
                .format(weather_data['observation_time_rfc822']))
```

除了保存数据，我们还在状态栏中通知用户天气已更新，并显示更新的时间戳。

1.  回调方法完成后，让我们将其添加到我们的`callbacks`字典中：

```py
        self.callbacks = {
            ...
            'update_weather_data': self.update_weather_data,
            ...
```

1.  现在我们可以在主菜单中添加一个回调的命令项。在 Windows 上，这样的功能放在`Tools`菜单中，由于 Gnome 和 macOS 的指南似乎没有指示更合适的位置，我们将在`LinxMainMenu`和`MacOsMainMenu`类中实现一个`Tools`菜单来保存这个命令，以保持一致。在`mainmenu.py`中，从通用菜单类开始，添加一个新菜单如下：

```py
        #Tools menu
        tools_menu = tk.Menu(self, tearoff=False)
        tools_menu.add_command(
            label="Update Weather Data",
            command=self.callbacks['update_weather_data'])
        self.add_cascade(label='Tools', menu=tools_menu)
```

1.  将相同的菜单添加到 macOS 和 Linux 菜单类中，并将命令添加到 Windows 主菜单的`tools_menu`。更新菜单后，您可以运行应用程序并尝试从`Tools`菜单中运行新命令。如果一切顺利，您应该在状态栏中看到如下截图所示的指示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/70ad36a4-d8f7-4fd2-ab4c-544dbb793be8.png)

1.  您还应该使用您的 PostgreSQL 客户端连接到数据库，并通过执行以下 SQL 命令来检查表中是否现在包含一些天气数据：

```py
SELECT * FROM local_weather;
```

该 SQL 语句应返回类似以下的输出：

| `datetime` | `temperature` | `rel[hum]` | `pressure` | `conditions` |
| --- | --- | --- | --- | --- |
| `2018-02-14 22:53:00-06` | `15.00` | `87.00` | `1014.00` | `Overcast` |

# 使用 requests 进行 HTTP

您被要求在您的程序中创建一个函数，将每日数据的 CSV 提取上传到 ABQ 的企业 Web 服务，该服务使用经过身份验证的 REST API。虽然`urllib`足够简单，用于简单的一次性`GET`和`POST`请求，但涉及身份验证令牌、文件上传或 REST 服务的复杂交互令人沮丧和复杂，仅使用`urllib`就很困难。为了完成这项任务，我们将转向`requests`库。

**REST**代表**REpresentational State Transfer**，是围绕高级 HTTP 语义构建的 Web 服务的名称。除了`GET`和`POST`，REST API 还使用额外的 HTTP 方法，如`DELETE`，`PUT`和`PATCH`，以及 XML 或 JSON 等数据格式，以提供完整范围的 API 交互。

Python 社区强烈推荐第三方的`requests`库，用于涉及 HTTP 的任何严肃工作（即使`urllib`文档也推荐它）。正如您将看到的，`requests`消除了`urllib`中留下的许多粗糙边缘和过时假设，并为更现代的 HTTP 交易提供了方便的类和包装函数。`requests`的完整文档可以在[`docs.python-requests.org`](http://docs.python-requests.org)找到，但下一节将涵盖您有效使用它所需的大部分内容。

# 安装和使用 requests

`requests`包是用纯 Python 编写的，因此使用`pip`安装它不需要编译或二进制下载。只需在终端中输入`pip install --user requests`，它就会被添加到您的系统中。

打开您的 Python shell，让我们进行如下请求：

```py
>>> import requests
>>> response = requests.request('GET', 'http://www.alandmoore.com')
```

`requests.request`至少需要一个 HTTP 方法和一个 URL。就像`urlopen()`一样，它构造适当的请求数据包，将其发送到 URL，并返回表示服务器响应的对象。在这里，我们正在向这位作者的网站发出`GET`请求。

除了`request()`函数，`requests`还有与最常见的 HTTP 方法对应的快捷函数。

因此，可以进行相同的请求如下：

```py
response = requests.get('http://www.alandmoore.com')
```

`get()`方法只需要 URL 并执行`GET`请求。同样，`post()`，`put()`，`patch()`，`delete()`和`head()`函数使用相应的 HTTP 方法发送请求。所有请求函数都接受额外的可选参数。

例如，我们可以通过`POST`请求发送数据如下：

```py
>>> response = requests.post(
    'http://duckduckgo.com',
    data={'q': 'tkinter', 'ko': '-2', 'kz': '-1'})
```

请注意，与`urlopen()`不同的是，我们可以直接使用 Python 字典作为`data`参数；`requests`会将其转换为适当的字节对象。

与请求函数一起使用的一些常见参数如下：

| **参数** | **目的** |
| --- | --- |
| `params` | 类似于`data`，但添加到查询字符串而不是有效负载 |
| `json` | 要包含在有效负载中的 JSON 数据 |
| `headers` | 用于请求的头数据字典 |
| `files` | 一个`{fieldnames: file objects}`字典，作为多部分表单数据请求发送 |
| `auth` | 用于基本 HTTP 摘要身份验证的用户名和密码元组 |

# requests.session()函数

Web 服务，特别是私人拥有的服务，通常是受密码保护的。有时，这是使用较旧的 HTTP 摘要身份验证系统完成的，我们可以使用请求函数的`auth`参数来处理这个问题。不过，如今更常见的是，身份验证涉及将凭据发布到 REST 端点以获取会话 cookie 或认证令牌，用于验证后续请求。

端点简单地是与 API 公开的数据或功能对应的 URL。数据被发送到端点或从端点检索。

`requests`方法通过提供`Session`类使所有这些变得简单。`Session`对象允许您在多个请求之间持久保存设置、cookie 和连接。

要创建一个`Session`对象，使用`requests.session()`工厂函数如下：

```py
s = requests.session()
```

现在，我们可以在我们的`Session`对象上调用请求方法，如`get()`、`post()`等，如下所示：

```py
# Assume this is a valid authentication service that returns an auth token
s.post('http://example.com/login', data={'u': 'test', 'p': 'test'})
# Now we would have an auth token
response = s.get('http://example.com/protected_content')
# Our token cookie would be listed here
print(s.cookies.items())
```

这样的令牌和 cookie 处理是在后台进行的，我们不需要采取任何明确的操作。Cookie 存储在`CookieJar`对象中，存储为我们的`Session`对象的`cookies`属性。

我们还可以在`Session`对象上设置值，这些值将在请求之间持续存在，就像这个例子中一样：

```py
s.headers['User-Agent'] = 'Mozilla'
# will be sent with a user-agent string of "Mozilla"
s.get('http://example.com')
```

在这个例子中，我们将用户代理字符串设置为`Mozilla`，这将用于从这个`Session`对象发出的所有请求。我们还可以使用`params`属性设置默认的 URL 参数，或者使用`hooks`属性设置回调函数。

# 响应对象

从这些请求函数返回的响应对象与`urlopen()`返回的对象不同；它们包含相同的数据，但以稍微不同（通常更方便）的形式返回。

例如，响应头已经被转换成 Python 的`dict`，如下所示：

```py
>>> r = requests.get('http://www.alandmoore.com')
>>> r.headers
{'Date': 'Thu, 15 Feb 2018 21:13:42 GMT', 'Server': 'Apache',
 'Last-Modified': 'Sat, 17 Jun 2017 14:13:49 GMT',
 'ETag': '"20c003f-19f7-5945391d"', 'Content-Length': '6647',
 'Keep-Alive': 'timeout=15, max=200', 'Connection': 'Keep-Alive',
 'Content-Type': 'text/html'}
```

另一个区别是，`requests`不会自动在 HTTP 错误时引发异常。但是，可以调用`.raise_for_status()`响应方法来实现这一点。

例如，这个 URL 将返回一个 HTTP `404`错误，如下面的代码所示：

```py
>>> r = requests.get('http://www.example.com/does-not-exist')
>>> r.status_code
404
>>> r.raise_for_status()
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/usr/lib/python3.6/site-packages/requests/models.py", line 935, in raise_for_status
    raise HTTPError(http_error_msg, response=self)
requests.exceptions.HTTPError: 404 Client Error: Not Found for url: http://www.example.com/does-not-exist
```

这使我们可以选择使用异常处理或更传统的流程控制逻辑来处理 HTTP 错误。

# 实现 API 上传

要开始实现我们的上传功能，我们需要弄清楚我们将要发送的请求的类型。我们已经从公司总部得到了一些关于如何与 REST API 交互的文档。

文档告诉我们以下内容：

+   首先，我们需要获取一个认证令牌。我们通过向`/auth`端点提交一个`POST`请求来实现这一点。`POST`请求的参数应包括`username`和`password`。

+   获得认证令牌后，我们需要提交我们的 CSV 文件。请求是一个发送到`/upload`端点的`PUT`请求。文件作为多部分表单数据上传，指定在`file`参数中。

我们已经知道足够的知识来使用`requests`实现我们的 REST 上传功能，但在这之前，让我们创建一个服务，我们可以用来测试我们的代码。

# 创建一个测试 HTTP 服务

开发与外部服务互操作的代码可能会很令人沮丧。在编写和调试代码时，我们需要向服务发送大量错误或测试数据；我们不希望在生产服务中这样做，而且“测试模式”并不总是可用的。自动化测试可以使用`Mock`对象来完全屏蔽网络请求，但在开发过程中，能够看到实际发送到 Web 服务的内容是很好的。

让我们实现一个非常简单的 HTTP 服务器，它将接受我们的请求并打印有关其接收到的信息。我们可以使用 Python 标准库的`http.server`模块来实现这一点。

模块文档显示了一个基本 HTTP 服务器的示例：

```py
from http.server import HTTPServer, BaseHTTPRequestHandler
def run(server_class=HTTPServer, handler_class=BaseHTTPRequestHandler):
    server_address = ('', 8000)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()
run()
```

服务器类`HTTPServer`定义了一个对象，该对象在配置的地址和端口上监听 HTTP 请求。处理程序类`BaseHTTPRequestHandler`定义了一个接收实际请求数据并返回响应数据的对象。我们将使用此代码作为起点，因此请将其保存在名为`sample_http_server.py`的文件中，保存在`ABQ_Data_Entry`目录之外。

如果您运行此代码，您将在本地计算机的端口`8000`上运行一个 Web 服务；但是，如果您对此服务进行任何请求，无论是使用`requests`、类似`curl`的工具，还是只是一个 Web 浏览器，您都会发现它只返回一个 HTTP`501`（`不支持的方法`）错误。为了创建一个足够工作的服务器，就像我们的目标 API 用于测试目的一样，我们需要创建一个自己的处理程序类，该类可以响应必要的 HTTP 方法。

为此，我们将创建一个名为`TestHandler`的自定义处理程序类，如下所示：

```py
class TestHandler(BaseHTTPRequestHandler):
    pass

def run(server_class=HTTPServer, handler_class=TestHandler):
    ...
```

我们的公司 API 使用`POST`方法接收登录凭据，使用`PUT`方法接收文件，因此这两种方法都需要工作。要使 HTTP 方法在请求处理程序中起作用，我们需要实现一个`do_VERB`方法，其中`VERB`是我们的 HTTP 方法名称的大写形式。

因此，对于`PUT`和`POST`，添加以下代码：

```py
class TestHandler(BaseHTTPRequestHandler):
    def do_POST(self, *args, **kwargs):
        pass

    def do_PUT(self, *args, **kwargs):
        pass
```

仅仅这样还不能解决问题，因为这些方法需要导致我们的处理程序发送某种响应。对于我们的目的，我们不需要任何特定的响应；只要有一个状态为`200`（`OK`）的响应就可以了。

由于两种方法都需要这个，让我们添加一个第三种方法，我们可以从其他两种方法中调用如下：

```py
    def _send_200(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
```

这是大多数 HTTP 客户端所需的最小响应：状态为`200`，带有有效`Content-type`的标头。这不会向客户端发送任何实际数据，但会告诉客户端其请求已被接收并成功处理。

我们在我们的方法中还想做的另一件事是打印出发送的任何数据，以便我们可以确保我们的客户端发送了正确的数据。

我们将实现以下方法来实现这一点：

```py
    def _print_request_data(self):
        content_length = self.headers['Content-Length']
        print("Content-length: {}".format(content_length))
        data = self.rfile.read(int(content_length))
        print(data.decode('utf-8'))
```

处理程序对象的`headers`属性是一个包含请求标头的`dict`对象，其中包括发送的字节数（`content-length`）。除了打印该信息之外，我们还可以使用它来读取发送的数据。处理程序的`rfile`属性是一个类似文件的对象，其中包含数据；其`read()`方法需要一个长度参数来指定应该读取多少数据，因此我们使用我们提取的`content-length`值。返回的数据是一个`bytes`对象，因此我们将其解码为`utf-8`。

现在我们有了这两种方法，让我们更新`do_POST()`和`do_PUT()`来调用它们，如下所示：

```py
    def do_POST(self, *args, **kwargs):
        print('POST request received')
        self._print_request_data()
        self._send_200()

    def do_PUT(self, *args, **kwargs):
        print("PUT request received")
        self._print_request_data()
        self._send_200()
```

现在，每个方法都将打印出它接收到的`POST`或`PUT`的长度和数据，以及任何数据。在终端窗口中运行此脚本，以便您可以监视其输出。

现在，打开一个 shell，让我们测试它，如下所示：

```py
>>> import requests
>>> requests.post('http://localhost:8000', data={1: 'test1', 2: 'test2'})
<Response[200]>
```

在 Web 服务器终端中，您应该看到以下输出：

```py
POST request received
Content-length: 15
1=test1&2=test2
127.0.0.1 - - [15/Feb/2018 16:22:41] "POST / HTTP/1.1" 200 -
```

我们可以实现其他功能，比如实际检查凭据并返回身份验证令牌，但目前此服务器已足够帮助我们编写和测试客户端代码。

# 创建我们的网络功能

现在我们的测试服务已经启动，让我们开始编写与 REST API 交互的网络功能：

1.  我们将首先在`network.py`中创建一个函数，该函数将接受 CSV 文件的路径、上传和身份验证 URL 以及用户名和密码：

```py
import requests

...

def upload_to_corporate_rest(
    filepath, upload_url, auth_url, username, password):
```

1.  由于我们将不得不处理身份验证令牌，我们应该做的第一件事是创建一个会话。我们将其称为`session`，如下所示：

```py
    session = requests.session()
```

1.  创建会话后，我们将用户名和密码发布到身份验证端点，如下所示：

```py
    response = session.post(
        auth_url,
        data={'username': username, 'password': password})
    response.raise_for_status()
```

如果成功，`session`对象将自动存储我们收到的令牌。如果出现问题，我们调用`raise_for_status()`，这样函数将中止，调用代码可以处理网络或数据问题引发的任何异常。

1.  假设我们没有引发异常，那么在这一点上我们必须经过身份验证，现在可以提交文件了。这将通过`put()`调用完成，如下所示：

```py
    files = {'file': open(filepath, 'rb')}
    response = session.put(
        upload_url,
        files=files
    )
```

发送文件，我们实际上必须打开它并将其作为文件句柄传递给`put()`；请注意，我们以二进制读取模式（`rb`）打开它。`requests`文档建议这样做，因为它确保正确的`content-length`值将被计算到头部中。

1.  发送请求后，我们关闭文件并再次检查失败状态，然后结束函数，如下所示：

```py
    files['file'].close()
    response.raise_for_status()
```

# 更新应用程序

在我们可以从`Application`中调用新函数之前，我们需要实现一种方法来创建每日数据的 CSV 提取。这将被多个函数使用，因此我们将它与调用上传代码的函数分开实现。按照以下步骤进行：

1.  首先，我们需要一个临时位置来存储我们生成的 CSV 文件。`tempfile`模块包括用于处理临时文件和目录的函数；我们将导入`mkdtemp()`，它将为我们提供一个特定于平台的临时目录的名称。

```py
from tempfile import mkdtemp
```

请注意，`mdktemp()`实际上并不创建目录；它只是在平台首选的`temp`文件位置中提供一个随机命名的目录的绝对路径。我们必须自己创建目录。

1.  现在，让我们开始我们的新`Application`方法，如下所示：

```py
    def _create_csv_extract(self):
        tmpfilepath = mkdtemp()
        csvmodel = m.CSVModel(
            filename=self.filename.get(), filepath=tmpfilepath)
```

创建临时目录名称后，我们创建了我们的`CSVModel`类的一个实例；即使我们不再将数据存储在 CSV 文件中，我们仍然可以使用该模型导出 CSV 文件。我们传递了`Application`对象的默认文件名，仍然设置为`abq_data_record-CURRENTDATE.csv`，以及临时目录的路径作为`filepath`。当然，我们的`CSVModel`目前并不接受`filepath`，但我们马上就会解决这个问题。

1.  创建 CSV 模型后，我们将从数据库中提取我们的记录，如下所示：

```py
        records = self.data_model.get_all_records()
        if not records:
            return None
```

请记住，我们的`SQLModel.get_all_records()`方法默认返回当天的所有记录的列表。如果我们碰巧没有当天的记录，最好立即停止并警告用户，而不是将空的 CSV 文件发送给公司，因此如果没有记录，我们从方法中返回`None`。我们的调用代码可以测试`None`返回值并显示适当的警告。

1.  现在，我们只需要遍历记录并将每个记录保存到 CSV 中，然后返回`CSVModel`对象的文件名，如下所示：

```py
        for record in records:
            csvmodel.save_record(record)

        return csvmodel.filename
```

1.  现在我们有了创建 CSV 提取文件的方法，我们可以编写回调方法，如下所示：

```py
    def upload_to_corporate_rest(self):

        csvfile = self._create_csv_extract()

        if csvfile is None:
            messagebox.showwarning(
                title='No records',
                message='There are no records to upload'
            )
            return
```

首先，我们创建了一个 CSV 提取文件并检查它是否为`None`。如果是，我们将显示错误消息并退出该方法。

1.  在上传之前，我们需要从用户那里获取用户名和密码。幸运的是，我们有一个完美的类来做到这一点：

```py
        d = v.LoginDialog(
            self,
            'Login to ABQ Corporate REST API')
        if d.result is not None:
            username, password = d.result
        else:
            return
```

我们的登录对话框在这里为我们服务。与数据库登录不同，我们不会在无限循环中运行它；如果密码错误，用户可以重新运行命令。请记住，如果用户点击取消，`result`将为`None`，因此在这种情况下我们将退出回调方法。

1.  现在，我们可以执行我们的网络函数，如下所示：

```py
        try:
            n.upload_to_corporate_rest(
                csvfile,
                self.settings['abq_upload_url'].get(),
                self.settings['abq_auth_url'].get(),
                username,
                password)
```

我们在`try`块中执行`upload_to_corporate_rest()`，因为它可能引发许多异常。我们从设置对象中传递上传和身份验证 URL；我们还没有添加这些，所以在完成之前需要这样做。

1.  现在，让我们捕获一些异常，首先是`RequestException`。如果我们发送到 API 的数据出现问题，最有可能是用户名和密码错误，就会发生这种异常。我们将异常字符串附加到向用户显示的消息中，如下所示：

```py
        except n.requests.RequestException as e:
            messagebox.showerror('Error with your request', str(e))
```

1.  接下来我们将捕获`ConnectionError`；这个异常将是网络问题的结果，比如实验室的互联网连接断开，或者服务器没有响应：

```py
        except n.requests.ConnectionError as e:
            messagebox.showerror('Error connecting', str(e))
```

1.  任何其他异常都将显示为`General Exception`，如下所示：

```py
        except Exception as e:
            messagebox.showerror('General Exception', str(e))
```

1.  让我们用以下成功对话框结束这个方法：

```py
        else:
            messagebox.showinfo(
                'Success',
                '{} successfully uploaded to REST API.'
                .format(csvfile))
```

1.  让我们通过将此方法添加到`callbacks`中来完成对`Application`的更改：

```py
        self.callbacks = {
            ...
            'upload_to_corporate_rest':  
           self.upload_to_corporate_rest,
            ...
```

# 更新 models.py 文件

在我们测试新功能之前，`models.py`文件中有一些需要修复的地方。我们将按照以下步骤来解决这些问题：

1.  首先，我们的`CSVModel`类需要能够接受`filepath`：

```py
    def __init__(self, filename, filepath=None):
        if filepath:
            if not os.path.exists(filepath):
                os.mkdir(filepath)
            self.filename = os.path.join(filepath, filename)
        else:
            self.filename = filename
```

如果指定了`filepath`，我们需要首先确保目录存在。由于在`Application`类中调用的`mkdtmp()`方法实际上并没有创建临时目录，我们将在这里创建它。完成后，我们将连接`filepath`和`filename`的值，并将其存储在`CSVModel`对象的`filename`属性中。

1.  我们在`models.py`中需要做的另一件事是添加我们的新设置。滚动到`SettingsModel`类，添加两个更多的`variables`条目如下：

```py
    variables = {
        ...
        'abq_auth_url': {
            'type': 'str',
            'value': 'http://localhost:8000/auth'},
        'abq_upload_url': {
            'type': 'str',
            'value': 'http://localhost:8000/upload'},
         ...
```

我们不会构建一个 GUI 来设置这些设置，它们需要在用户的配置文件中手动创建，尽管在测试时，我们可以使用默认值。

# 收尾工作

最后要做的事情是将命令添加到我们的主菜单中。

在每个菜单类中为`tools_menu`添加一个新条目：

```py
        tools_menu.add_command(
            label="Upload CSV to corporate REST",
            command=self.callbacks['upload_to_corporate_rest'])
```

现在，运行应用程序，让我们试试。为了使其工作，您至少需要有一个数据输入，并且需要启动`sample_http_server.py`脚本。

如果一切顺利，您应该会得到一个像这样的对话框：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/96de4996-9652-43f1-a4c6-a2d6bddc73de.png)

您的服务器还应该在终端上打印出类似这样的输出：

```py
POST request received
Content-length: 27
username=test&password=test
127.0.0.1 - - [16/Feb/2018 10:17:22] "POST /auth HTTP/1.1" 200 -
PUT request received
Content-length: 397
--362eadeb828747769e75d5b4b6d32f31
Content-Disposition: form-data; name="file"; filename="abq_data_record_2018-02-16.csv"

Date,Time,Technician,Lab,Plot,Seed sample,Humidity,Light,Temperature,Equipment Fault,Plants,Blossoms,Fruit,Min Height,Max Height,Median Height,Notes
2018-02-16,8:00,Q Murphy,A,1,AXM477,10.00,10.00,10.00,,1,2,3,1.00,3.00,2.00,"
"

--362eadeb828747769e75d5b4b6d32f31--

127.0.0.1 - - [16/Feb/2018 10:17:22] "PUT /upload HTTP/1.1" 200 -
```

注意`POST`和`PUT`请求，以及`PUT`有效负载中的 CSV 文件的原始文本。我们已成功满足了此功能的 API 要求。

# 使用 ftplib 的 FTP

虽然 HTTP 和 REST API 是客户端-服务器交互的当前趋势，但企业依赖于旧的、经过时间考验的，有时是过时的技术来实现数据传输并不罕见。ABQ 也不例外：除了 REST 上传，您还需要实现对依赖于 FTP 的 ABQ 公司的遗留系统的支持。

# FTP 的基本概念

**文件传输协议**，或**FTP**，可以追溯到 20 世纪 70 年代初，比 HTTP 早了近 20 年。尽管如此，它仍然被许多组织广泛用于在互联网上交换大文件。由于 FTP 以明文形式传输数据和凭据，因此在许多领域被认为有些过时，尽管也有 SSL 加密的 FTP 变体可用。

与 HTTP 一样，FTP 客户端发送包含纯文本命令的请求，类似于 HTTP 方法，FTP 服务器返回包含头部和有效负载信息的响应数据包。

然而，这两种协议之间存在许多重大的区别：

+   FTP 是**有状态连接**，这意味着客户端和服务器在会话期间保持恒定的连接。换句话说，FTP 更像是一个实时电话，而 HTTP 则像是两个人在语音信箱中对话。

+   在发送任何其他命令或数据之前，FTP 需要对会话进行身份验证，即使对于匿名用户也是如此。FTP 服务器还实现了更复杂的权限集。

+   FTP 有用于传输文本和二进制数据的不同模式（主要区别在于文本模式会自动纠正行尾和接收操作系统的编码）。

+   FTP 服务器在其命令的实现上不够一致。

# 创建一个测试 FTP 服务

在实现 FTP 上传功能之前，有一个测试 FTP 服务是有帮助的，就像我们测试 HTTP 服务一样。当然，您可以下载许多免费的 FTP 服务器，如 FileZilla、PureFTPD、ProFTPD 或其他。

不要为了测试应用程序的一个功能而在系统上安装、配置和后来删除 FTP 服务，我们可以在 Python 中构建一个基本的服务器。第三方的`pyftpdlib`包为我们提供了一个简单的实现快速脏 FTP 服务器的方法，足以满足测试需求。

使用`pip`安装`pyftpdlib`：

```py
pip install --user pyftpdlib
```

就像我们简单的 HTTP 服务器一样，FTP 服务由*服务器*对象和*处理程序*对象组成。它还需要一个*授权者*对象来处理身份验证和权限。

我们将从导入这些开始我们的`basic_ftp_server.py`文件：

```py
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
```

为了确保我们的身份验证代码正常工作，让我们用一个测试用户设置我们的`DummyAuthorizer`类：

```py
auth = DummyAuthorizer()
auth.add_user('test', 'test', '.', perm='elrw')
```

`perm`参数接受一个字符的字符串，每个字符代表服务器上的特定权限。在这种情况下，我们有`e`（连接）、`l`（列出）、`r`（读取）和`w`（写入新文件）。还有许多其他权限可用，默认情况下都是关闭的，直到授予，但这对我们的需求已经足够了。

现在，让我们设置处理程序：

```py
handler = FTPHandler
handler.authorizer = auth
```

请注意，我们没有实例化处理程序，只是给类取了别名。服务器类将管理处理程序类的创建。但是，我们可以将我们的`auth`对象分配为处理程序的`authorizer`类，以便任何创建的处理程序都将使用我们的授权者。

最后，让我们设置并运行服务器部分：

```py
address = ('127.0.0.1', 2100)
server = FTPServer(address, handler)

server.serve_forever()
```

这只是简单地用地址元组和处理程序类实例化一个`FTPServer`对象，然后调用对象的`server_forever()`方法。地址元组的形式是`（ip_address，port）`，所以`（'127.0.0.1'，2100）`的元组意味着我们将在计算机的回环地址上的端口`2100`上提供服务。FTP 的默认端口通常是 21，但在大多数操作系统上，启动监听在`1024`以下端口的服务需要 root 或系统管理员权限。为了简单起见，我们将使用一个更高的端口。

虽然可以使用`pyftpdlib`构建生产质量的 FTP 服务器，但我们在这里没有这样做。这个脚本对于测试是足够的，但如果您重视安全性，请不要在生产中使用它。

# 实现 FTP 上传功能

现在测试服务器已经启动，让我们构建我们的 FTP 上传功能和 GUI 的逻辑。虽然标准库中没有包含 FTP 服务器库，但它包含了`ftplib`模块形式的 FTP 客户端库。

首先在我们的`network.py`文件中导入`ftplib`：

```py
import ftplib as ftp
```

可以使用`ftplib.FTP`类创建一个 FTP 会话。因为这是一个有状态的会话，在完成后需要关闭；为了确保我们这样做，`FTP`可以用作上下文管理器。

让我们从连接到 FTP 服务器开始我们的函数：

```py
def upload_to_corporate_ftp(
        filepath, ftp_host,
        ftp_port, ftp_user, ftp_pass):

    with ftp.FTP() as ftp_cx:
        ftp_cx.connect(ftp_host, ftp_port)
        ftp_cx.login(ftp_user, ftp_pass)
```

`upload_to_corporate()`函数接受 CSV 文件路径和`FTP`主机、端口、用户和密码，就像我们的`upload_to_corporate_rest()`函数一样。我们首先创建我们的`FTP`对象，然后调用`FTP.connect()`和`FTP.login`。

接下来，`connect()`接受我们要交谈的主机和端口，并与服务器开始会话。在这一点上，我们还没有经过身份验证，但我们确实建立了连接。

然后，`login()`接受用户名和密码，并尝试验证我们的会话。如果我们的凭据检查通过，我们就登录到服务器上，并可以开始发送更多的命令；如果不通过，就会引发`error_perm`异常。但是，我们的会话仍然是活动的，直到我们关闭它，并且如果需要，我们可以发送额外的登录尝试。

要实际上传文件，我们使用`storbinary()`方法：

```py
        filename = path.basename(filepath)
        with open(filepath, 'rb') as fh:
            ftp_cx.storbinary('STOR {}'.format(filename), fh)
```

要发送文件，我们必须以二进制读取模式打开它，然后调用`storbinary`（是的，“stor”，而不是“store”—20 世纪 70 年代的程序员对删除单词中的字母有一种偏好）。

`storbinary`的第一个参数是一个有效的 FTP`STOR`命令，通常是`STOR filename`，其中“filename”是您希望在服务器上称为上传数据的名称。必须包含实际的命令字符串似乎有点违反直觉；据推测，这必须是指定的，以防服务器使用稍有不同的命令或语法。

第二个参数是文件对象本身。由于我们将其作为二进制数据发送，因此应该以二进制模式打开它。这可能看起来有点奇怪，因为我们发送的 CSV 文件本质上是一个纯文本文件，但将其作为二进制数据发送可以保证服务器在传输过程中不会以任何方式更改文件；这几乎总是在传输文件时所希望的，无论所交换数据的性质如何。

这就是我们的网络功能需要为 FTP 上传完成的所有工作。尽管我们的程序只需要`storbinary()`方法，但值得注意的是，如果您发现自己不得不使用 FTP 服务器，还有一些其他常见的`ftp`方法。

# 列出文件

在 FTP 服务器上列出文件有三种方法。`mlsd()`方法调用`MLSD`命令，通常是可用的最佳和最完整的输出。它可以接受一个可选的`path`参数，指定要列出的路径（否则它将列出当前目录），以及一个`facts`列表，例如“size”、“type”或“perm”，反映了您希望与文件名一起包括的数据。 `mlsd()`命令返回一个生成器对象，可以迭代或转换为另一种序列类型。

`MLSD`是一个较新的命令，不一定总是可用，因此还有另外两种可用的方法，`nlst()`和`dir()`，它们对应于较旧的`NLST`和`DIR`命令。这两种方法都接受任意数量的参数，这些参数将被原样附加到发送到服务器的命令字符串。

# 检索文件

从 FTP 服务器下载文件涉及`retrbinary()`或`retrlines()`方法中的一个，具体取决于我们是否希望使用二进制或文本模式（如前所述，您可能应该始终使用二进制）。与`storbinary`一样，每种方法都需要一个命令字符串作为其第一个参数，但在这种情况下，它应该是一个有效的`RETR`命令（通常“RETR filename”就足够了）。

第二个参数是一个回调函数，它将在每一行（对于`retrlines()`）或每个块（对于`retrbinary()`）上调用。此回调可用于存储已下载的数据。

例如，看一下以下代码：

```py
from ftplib import FTP
from os.path import join

filename = 'raytux.jpg'
path = '/pub/ibiblio/logos/penguins'
destination = open(filename, 'wb')
with FTP('ftp.nluug.nl', 'anonymous') as ftp:
    ftp.retrbinary(
        'RETR {}'.format(join(path, filename)),
        destination.write)
destination.close()
```

每个函数的返回值都是一个包含有关下载的一些统计信息的结果字符串，如下所示：

```py
'226-File successfully transferred\n226 0.000 seconds (measured here), 146.96 Mbytes per second'
```

# 删除或重命名文件

使用`ftplib`删除和重命名文件相对简单。 `delete()`方法只需要一个文件名，并尝试删除服务器上给定的文件。`rename()`方法只需要一个源和目标，并尝试将源重命名为目标名称。

自然地，任何一种方法的成功都取决于登录帐户被授予的权限。

# 将 FTP 上传添加到 GUI

我们的 FTP 上传功能已经准备就绪，所以让我们将必要的部分添加到我们应用程序的其余部分，使其一起运行。

首先，我们将在`models.py`中的`SettingsModel`中添加 FTP 主机和端口：

```py
    variables = {
        ...
        'abq_ftp_host': {'type': 'str', 'value': 'localhost'},
        'abq_ftp_port': {'type': 'int', 'value': 2100}
        ...
```

请记住，我们的测试 FTP 使用端口`2100`，而不是通常的端口`21`，所以现在我们将`2100`作为默认值。

现在，我们将转到`application.py`并创建回调方法，该方法将创建 CSV 文件并将其传递给 FTP 上传功能。

在`Application`对象中创建一个新方法：

```py
    def upload_to_corporate_ftp(self):
        csvfile = self._create_csv_extract()
```

我们要做的第一件事是使用我们为`REST`上传创建的方法创建我们的 CSV 文件。

接下来，我们将要求用户输入 FTP 用户名和密码：

```py
        d = v.LoginDialog(
            self,
            'Login to ABQ Corporate FTP')
```

现在，我们将调用我们的网络功能：

```py
        if d.result is not None:
            username, password = d.result
            try:
                n.upload_to_corporate_ftp(
                    csvfile,
                    self.settings['abq_ftp_host'].get(),
                    self.settings['abq_ftp_port'].get(),
                    username,
                    password)
```

我们在`try`块中调用 FTP 上传函数，因为我们的 FTP 过程可能会引发多个异常。

与其逐个捕获它们，我们可以捕获`ftplib.all_errors`：

```py
            except n.ftp.all_errors as e:
                messagebox.showerror('Error connecting to ftp', str(e))
```

请注意，`ftplib.all_errors`是`ftplib`中定义的所有异常的基类，其中包括认证错误、权限错误和连接错误等。

结束这个方法时，我们将显示一个成功的消息：

```py
            else:
                messagebox.showinfo(
                    'Success',
                    '{} successfully uploaded to FTP'.format(csvfile))
```

写好回调方法后，我们需要将其添加到`callbacks`字典中：

```py
        self.callbacks = {
            ...
            'upload_to_corporate_ftp': self.upload_to_corporate_ftp
        }
```

我们需要做的最后一件事是将我们的回调添加到主菜单类中。

在`mainmenu.py`中，为每个类的`tools_menu`添加一个新的命令：

```py
        tools_menu.add_command(
            label="Upload CSV to corporate FTP",
            command=self.callbacks['upload_to_corporate_ftp'])
```

在终端中启动示例 FTP 服务器，然后运行你的应用程序并尝试 FTP 上传。记得输入`test`作为用户名和密码！

你应该会看到一个成功的对话框，类似这样：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/42dfde62-fea5-4555-ae37-9f3fe4037b68.png)

同样，在你运行示例 FTP 服务器的目录中应该有一个新的 CSV 文件。

FTP 服务器应该已经打印出了一些类似这样的信息：

```py
127.0.0.1:32878-[] FTP session opened (connect)
127.0.0.1:32878-[test] USER 'test' logged in.
127.0.0.1:32878-[test] STOR /home/alanm/FTPserver/abq_data_record_2018-02-17.csv completed=1 bytes=235 seconds=0.001
127.0.0.1:32878-[test] FTP session closed (disconnect).
```

看起来我们的 FTP 上传效果很棒！

# 总结

在本章中，我们使用 HTTP 和 FTP 与云进行了交互。你学会了如何使用`urllib`下载数据并使用`ElementTree`解析 XML。你还了解了`requests`库，并学会了与 REST API 进行交互的基础知识。最后，我们学会了如何使用 Python 的`ftplib`下载和上传文件到 FTP。
