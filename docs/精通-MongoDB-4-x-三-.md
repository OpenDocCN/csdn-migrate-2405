# 精通 MongoDB 4.x（三）

> 原文：[`zh.annas-archive.org/md5/BEDE8058C8DB4FDEC7B98D6DECC4CDE7`](https://zh.annas-archive.org/md5/BEDE8058C8DB4FDEC7B98D6DECC4CDE7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：聚合

在第五章《多文档 ACID 事务》中，我们使用 Ruby 和 Python 的代码解决了新事务功能的两个用例。在本章中，我们将更深入地了解聚合框架，学习它如何有用。我们还将看看 MongoDB 支持的操作符。

为了了解这些信息，我们将使用聚合来处理以太坊区块链的交易数据。完整的源代码可在[`github.com/PacktPublishing/Mastering-MongoDB-4.x-Second-Edition`](https://github.com/PacktPublishing/Mastering-MongoDB-4.x-Second-Edition)上找到。

在本章中，我们将涵盖以下主题：

+   为什么要使用聚合？

+   不同的聚合操作符

+   限制

# 为什么要使用聚合？

聚合框架是由 MongoDB 在 2.2 版本中引入的（在开发分支中是 2.1 版本）。它作为 MapReduce 框架和直接查询数据库的替代方案。

使用聚合框架，我们可以在服务器上执行`GROUP BY`操作。因此，我们可以只投影结果集中需要的字段。使用`$match`和`$project`操作符，我们可以减少通过管道传递的数据量，从而加快数据处理速度。

自连接——也就是在同一集合内连接数据——也可以使用聚合框架来执行，正如我们将在我们的用例中看到的那样。

将聚合框架与仅使用 shell 或其他驱动程序提供的查询进行比较时，重要的是要记住两者都有用途。

对于选择和投影查询，几乎总是更好使用简单的查询，因为开发、测试和部署聚合框架操作的复杂性很难超过使用内置命令的简单性。查找具有`( db.books.find({price: 50} {price: 1, name: 1}) )`的文档，或者没有`( db.books.find({price: 50}) )`只投影一些字段，是简单且足够快速，不需要使用聚合框架。

另一方面，如果我们想使用 MongoDB 执行`GROUP BY`和自连接操作，可能需要使用聚合框架。在 MongoDB shell 中`group()`命令的最重要限制是结果集必须适合一个文档，这意味着它的大小不能超过 16MB。此外，任何`group()`命令的结果不能超过 20,000 个。最后，`group()`不适用于分片输入集合，这意味着当我们的数据量增加时，我们必须重新编写我们的查询。

与 MapReduce 相比，聚合框架在功能和灵活性上更有限。在聚合框架中，我们受到可用操作符的限制。但好的一面是，聚合框架的 API 比 MapReduce 更容易理解和使用。在性能方面，聚合框架在 MongoDB 早期版本中比 MapReduce 快得多，但在 MapReduce 性能改进后，似乎与最新版本持平。

最后，还有一种选择，就是使用数据库作为数据存储，并使用应用程序执行复杂操作。有时这可能会很快开发，但应该避免，因为最终可能会产生内存、网络和性能成本。

在下一节中，我们将在使用实际用例之前描述可用的操作符。

# 聚合操作符

在本节中，我们将学习如何使用聚合操作符。聚合操作符分为两类。在每个阶段中，我们使用**表达式操作符**来比较和处理值。在不同阶段之间，我们使用**聚合阶段操作符**来定义将从一个阶段传递到下一个阶段的数据，因为它被认为是以相同格式呈现的。

# 聚合阶段操作符

聚合管道由不同的阶段组成。这些阶段在数组中声明并按顺序执行，每个阶段的输出都是下一个阶段的输入。

`$out` 阶段必须是聚合管道中的最终阶段，通过替换或添加到现有文档将数据输出到输出集合：

+   `$group`：最常用于按标识符表达式分组，并应用累加器表达式。它输出每个不同组的一个文档。

+   `$project`：用于文档转换，每个输入文档输出一个文档。

+   `$match`：根据条件从输入中过滤文档。

+   `$lookup`：用于从输入中过滤文档。输入可以是同一数据库中另一个集合中的文档，由外部左连接选择。

+   `$out`：将此管道阶段的文档输出到输出集合，以替换或添加到已存在于集合中的文档。

+   `$limit`：根据预定义的条件限制传递到下一个聚合阶段的文档数量。

+   `$count`：返回管道阶段的文档数量。

+   `$skip`：跳过一定数量的文档，防止它们传递到管道的下一阶段。

+   `$sort`：根据条件对文档进行排序。

+   `$redact`：作为 `$project` 和 `$match` 的组合，这将从每个文档中选择的字段进行 redact，并将它们传递到管道的下一阶段。

+   `$unwind`：这将数组中的 *n* 个元素转换为 *n* 个文档，将每个文档映射到数组的一个元素。然后将这些文档传递到管道的下一阶段。

+   `$collStats`：返回有关视图或集合的统计信息。

+   `$indexStats`：返回集合索引的统计信息。

+   `$sample`：从输入中随机选择指定数量的文档。

+   `$facet`：在单个阶段内组合多个聚合管道。

+   `$bucket`：根据预定义的选择标准和桶边界将文档分割成桶。

+   `$bucketAuto`：根据预定义的选择标准将文档分割成桶，并尝试在桶之间均匀分布文档。

+   `$sortByCount`：根据表达式的值对传入的文档进行分组，并计算每个桶中的文档数量。

+   `$addFields`：这将向文档添加新字段，并输出与输入相同数量的文档，带有添加的字段。

+   `$replaceRoot`：用指定的字段替换输入文档的所有现有字段（包括 `standard _id` 字段）。

+   `$geoNear`：根据与指定字段的接近程度返回文档的有序列表。输出文档包括一个计算出的 `distance` 字段。

+   `$graphLookup`：递归搜索集合，并在每个输出文档中添加一个包含搜索结果的数组字段。

# 表达式运算符

在每个阶段中，我们可以定义一个或多个表达式运算符来应用我们的中间计算。本节将重点介绍这些表达式运算符。

# 表达式布尔运算符

布尔运算符用于将 `true` 或 `false` 的值传递到我们聚合管道的下一阶段。

我们也可以选择传递原始的 `integer`、`string` 或任何其他类型的值。

我们可以像在任何编程语言中一样使用 `$and`、`$or` 和 `$not` 运算符。

# 表达式比较运算符

比较运算符可以与布尔运算符结合使用，构建我们需要评估为 `true`/`false` 的表达式，以输出管道阶段的结果。

最常用的运算符如下：

+   `$eq ( equal )`

+   `$ne ( not equal)`

+   `$gt (greater than)`

+   `$gte (greater than or equal)`

+   `$lt`

+   `$lte`

所有上述运算符返回 `true` 或 `false` 的布尔值。

唯一不返回布尔值的运算符是`$cmp`，如果两个参数相等则返回`0`，如果第一个值大于第二个值则返回`1`，如果第二个值大于第一个值则返回`-1`。

# 集合表达式和数组运算符

与大多数编程语言一样，集合操作会忽略重复的条目和元素的顺序，将它们视为集合。结果的顺序是未指定的，并且重复的条目将在结果集中被去重。集合表达式不会递归应用于集合的元素，而只会应用于顶层。这意味着，如果一个集合包含，例如，一个嵌套数组，那么这个数组可能包含重复项，也可能不包含。

可用的集合运算符如下：

+   `$setEquals`：如果两个集合具有相同的不同元素，则为`true`

+   `$setIntersection`：返回所有输入集合的交集（即出现在所有输入集合中的文档）

+   `$setUnion`：返回所有输入集合的并集（即出现在所有输入集合中的至少一个文档）

+   `$setDifference`：返回出现在第一个输入集合中但不在第二个输入集合中的文档

+   `$setIsSubset`：如果第一个集合中的所有文档都出现在第二个集合中，则为`true`，即使这两个集合是相同的。

+   `$anyElementTrue`：如果集合中的任何元素求值为`true`，则为`true`

+   `$allElementsTrue`：如果集合中的所有元素求值为`true`，则为`true`

可用的数组运算符如下：

+   `$arrayElemAt`：返回数组索引位置的元素。

+   `$concatArrays`：返回一个连接的数组。

+   `$filter`：根据指定的条件返回数组的子集。

+   `$indexOfArray`：返回满足搜索条件的数组的索引。如果没有，则返回`-1`。

+   `$isArray`：如果输入是数组，则返回`true`；否则返回`false`。

+   `$range`：根据用户定义的输入输出包含一系列整数的数组。

+   `$reverseArray`：返回元素顺序相反的数组。

+   `$reduce`：根据指定的输入将数组的元素减少为单个值。

+   `$size`：返回数组中的项目数。

+   `$slice`：返回数组的子集。

+   `$zip`：返回合并的数组。

+   `$in`：如果指定的值在数组中，则返回`true`；否则返回`false`。

# 表达式日期运算符

日期运算符用于从日期字段中提取日期信息，当我们想要基于一周/月/年的统计数据计算时，使用管道：

+   `$dayOfYear` 用于获取一年中的日期，范围为 1 到 366（闰年）

+   `$dayOfMonth` 用于获取一个月中的日期，范围为 1 到 31

+   `$dayOfWeek` 用于获取一周中的日期，范围为 1 到 7，其中 1 代表星期日，7 代表星期六（使用英文星期几）

+   `$isoDayOfWeek` 返回 ISO 8601 日期格式中的星期几编号，范围为 1 到 7，其中 1 代表星期一，7 代表星期日

+   `$week` 是 0 到 53 范围内的周数，0 代表每年年初的部分周，53 代表有闰周的年份

+   `$isoWeek` 返回 ISO 8601 日期格式中的周数，范围为 1 到 53，1 代表包含星期四的年份的第一周，53 代表有闰周的年份

+   `$year`、`$month`、`$hour`、`$minute`、`$milliSecond` 返回日期的相关部分，从零开始编号，除了`$month`，它返回从 1 到 12 的值

+   `$isoWeekYear` 根据 ISO 8601 日期格式返回日期的年份，该日期是 ISO 8601 日期格式中最后一周结束的日期（例如，2016/1/1 仍然返回 2015）

+   `$second` 返回 0 到 60 的值，包括闰秒

+   `$dateToString` 将日期输入转换为字符串

# 表达式字符串运算符

与日期运算符一样，字符串运算符用于在我们想要将数据从管道的一个阶段转换到下一个阶段时使用。潜在的用例包括预处理文本字段以提取相关信息，以便在管道的后续阶段中使用：

+   `$concat`: 这用于连接字符串。

+   `$split`: 这用于根据分隔符拆分字符串。如果找不到分隔符，则返回原始字符串。

+   `$strcasecmp`: 这用于不区分大小写的字符串比较。如果字符串相等，则返回`0`，如果第一个字符串较大，则返回`1`；否则返回`-1`。

+   `$toLower`/`$toUpper`: 这用于将字符串转换为全小写或全大写。

+   `$indexOfBytes`: 这用于返回字符串中子字符串的第一个出现的字节位置。

+   `$strLenBytes`: 这是输入字符串的字节数。

+   `$substrBytes`: 这返回子字符串的指定字节。

代码点的等效方法（Unicode 中的一个值，不考虑其表示中的基础字节）如下：

+   `$indexOfCP`

+   `$strLenCP`

+   `$substrCP`

# 表达式算术运算符

在管道的每个阶段，我们可以应用一个或多个算术运算符来执行中间计算。这些运算符在以下列表中显示：

+   `$abs`: 这是绝对值。

+   `$add`: 这可以将数字或日期加上一个数字以得到一个新的日期。

+   `$ceil`/`$floor`: 这些分别是向上取整和向下取整函数。

+   `$divide`: 这用于由两个输入进行除法。

+   `$exp`: 这将自然数*e*提升到指定的指数幂。

+   `$pow`: 这将一个数字提升到指定的指数幂。

+   `$ln`/`$log`/`$log10`: 这些用于计算自然对数、自定义底数的对数或以十为底的对数。

+   `$mod`: 这是模值。

+   `$multiply`: 这用于将输入相乘。

+   `$sqrt`: 这是输入的平方根。

+   `$subtract`: 这是从第二个值中减去第一个值的结果。如果两个参数都是日期，则返回它们之间的差值。如果一个参数是日期（这个参数必须是第一个参数），另一个是数字，则返回结果日期。

+   `$trunc`: 这用于截断结果。

# 聚合累加器

累加器可能是最广泛使用的运算符，因为它们允许我们对我们组中的每个成员进行求和、平均值、获取标准偏差统计数据以及执行其他操作。以下是聚合累加器的列表：

+   `$sum`: 这是数值的总和。它会忽略非数值。

+   `$avg`: 这是数值的平均值。它会忽略非数值。

+   `$first`/`$last`: 这是通过管道阶段的第一个和最后一个值。它仅在组阶段中可用。

+   `$max`/`$min`: 这分别获取通过管道阶段的最大值和最小值。

+   `$push`: 这将一个新元素添加到输入数组的末尾。它仅在组阶段中可用。

+   `$addToSet`: 这将一个元素（仅当它不存在时）添加到数组中，有效地将其视为一个集合。它仅在组阶段中可用。

+   `$stdDevPop`/`$stdDevSamp`: 这些用于在`$project`或`$match`阶段获取总体/样本标准偏差。

这些累加器在组或项目管道阶段中都可用，除非另有说明。

# 条件表达式

表达式可以根据布尔真值测试将不同的数据输出到我们管道中的下一阶段：

```sql
$cond
```

`$cond`短语将评估格式为`if...then...else`的表达式，并根据`if`语句的结果返回`then`语句或`else`分支的值。输入可以是三个命名参数或有序列表中的三个表达式。

```sql
$ifNull
```

`$ifNull`短语将评估一个表达式，并在其不为 null 时返回第一个表达式，如果第一个表达式为 null，则返回第二个表达式。Null 可以是一个缺失的字段或一个具有未定义值的字段：

```sql
$switch
```

类似于编程语言的`switch`语句，`$switch`将在评估为`true`时执行指定的表达式，并跳出控制流。

# 类型转换运算符

在 MongoDB 4.0 中引入的类型转换运算符允许我们将值转换为指定的类型。命令的通用语法如下：

```sql
{
   $convert:
      {
         input: <expression>,
         to: <type expression>,
         onError: <expression>,  // Optional.
         onNull: <expression>    // Optional.
      } }

```

在此语法中，`input`和`to`（唯一的强制参数）可以是任何有效的表达式。在其最简单的形式中，我们可以，例如，有以下内容：

```sql
$convert: { input: "true", to: "bool" } 
```

将值为`true`的字符串转换为布尔值`true`。

`onError`短语可以是任何有效的表达式，指定了在转换过程中 MongoDB 遇到错误时将返回的值，包括不支持的类型转换。其默认行为是抛出错误并停止处理。

`onNull`短语也可以是任何有效的表达式，指定了如果输入为 null 或缺失时 MongoDB 将返回的值。默认行为是返回 null。

MongoDB 还为最常见的`$convert`操作提供了一些辅助函数。这些函数如下：

+   `$toBool`

+   `$toDate`

+   `$toDecimal`

+   `$toDouble`

+   `$toInt`

+   `$toLong`

+   `$toObjectId`

+   `$toString`

这些更简单易用。我们可以将前面的示例重写为以下形式：

```sql
{ $toBool: "true" }
```

# 其他操作符

有一些操作符并不常用，但在特定用例中可能很有用。其中最重要的列在以下部分中。

# 文本搜索

`$meta`运算符用于访问文本搜索元数据。

# 变量

`$map`运算符将子表达式应用于数组的每个元素，并返回结果值的数组。它接受命名参数。

`$let`运算符为子表达式的范围内定义变量，并返回子表达式的结果。它接受命名参数。

# 字面值

`$literal`运算符将返回一个不经解析的值。它用于聚合管道可能解释为表达式的值。例如，您可以将`$literal`表达式应用于以`$`开头的字符串，以避免解析为字段路径。

# 解析数据类型

`$type`运算符返回字段的`BSON`数据类型。

# 限制

聚合管道可以以以下三种不同的方式输出结果：

+   内联作为包含结果集的文档

+   在一个集合中

+   返回结果集的游标

内联结果受`BSON`最大文档大小 16 MB 的限制，这意味着我们只能在最终结果是固定大小时使用它。一个例子是从电子商务网站输出前五个最常订购商品的`ObjectId`。

与此相反的例子是输出前 1,000 个最常订购的商品，以及产品信息，包括描述和其他大小可变的字段。

如果我们想对数据进行进一步处理，将结果输出到集合是首选解决方案。我们可以将结果输出到新集合，或替换现有集合的内容。聚合输出结果只有在聚合命令成功后才会可见；否则，它将根本不可见。

输出集合不能是分片的或有上限的集合（截至 v3.4）。如果聚合输出违反索引（包括每个文档的唯一`ObjectId`上的内置索引）或文档验证规则，聚合将失败。

每个管道阶段可以有超过 16MB 限制的文档，因为这些由 MongoDB 在内部处理。然而，每个管道阶段只能使用最多 100MB 的内存。如果我们期望在我们的阶段中有更多的数据，我们应该将`allowDiskUse:`设置为`true`，以允许多余的数据溢出到磁盘，以换取性能。

`$graphLookup`运算符不支持超过 100MB 的数据集，并将忽略`allowDiskUse`上的任何设置。

# 聚合使用案例

在这个相当冗长的部分中，我们将使用聚合框架来处理以太坊区块链的数据。

使用我们的 Python 代码，我们已经从以太坊中提取了数据，并将其加载到我们的 MongoDB 数据库中。区块链与我们的数据库的关系如下图所示：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/8ad5e8b5-bd05-430e-9e4f-06548aa820a9.png)

我们的数据驻留在两个集合中：**blocks**和**transactions**。

样本区块文档具有以下字段：

+   交易数量

+   承包内部交易的数量

+   区块哈希

+   父区块哈希

+   挖矿难度

+   使用的燃气

+   区块高度

以下代码显示了区块的输出数据：

```sql
> db.blocks.findOne()
{
"_id" : ObjectId("595368fbcedea89d3f4fb0ca"),
"number_transactions" : 28,
"timestamp" : NumberLong("1498324744877"),
"gas_used" : 4694483,
"number_internal_transactions" : 4,
"block_hash" : "0x89d235c4e2e4e4978440f3cc1966f1ffb343b9b5cfec9e5cebc331fb810bded3",
"difficulty" : NumberLong("882071747513072"),
"block_height" : 3923788
}
```

样本交易文档具有以下字段：

+   交易哈希

+   它所属的区块高度

+   从哈希地址

+   到哈希地址

+   交易价值

+   交易费用

以下代码显示了交易的输出数据：

```sql
> db.transactions.findOne()
{
"_id" : ObjectId("59535748cedea89997e8385a"),
"from" : "0x3c540be890df69eca5f0099bbedd5d667bd693f3",
"txfee" : 28594,
"timestamp" : ISODate("2017-06-06T11:23:10Z"),
"value" : 0,
"to" : "0x4b9e0d224dabcc96191cace2d367a8d8b75c9c81",
"txhash" : "0xf205991d937bcb60955733e760356070319d95131a2d9643e3c48f2dfca39e77",
"block" : 3923794
}
```

我们的数据库的样本数据可在 GitHub 上找到：[`github.com/PacktPublishing/Mastering-MongoDB-4.x-Second-Edition`](https://github.com/PacktPublishing/Mastering-MongoDB-4.x-Second-Edition)。

作为使用这种新型区块链技术的好奇开发人员，我们想要分析以太坊交易。我们特别希望做到以下几点：

+   找到交易发起的前十个地址

+   找到交易结束的前十个地址

+   找到每笔交易的平均值，并统计偏差

+   找到每笔交易所需的平均费用，并统计偏差

+   找到网络在一天中的哪个时间更活跃，根据交易的数量或价值

+   找到网络在一周中的哪一天更活跃，根据交易的数量或价值

我们找到了交易发起的前十个地址。为了计算这个指标，我们首先计算每个`from`字段的值为`1`的出现次数，然后按`from`字段的值对它们进行分组，并将它们输出到一个名为`count`的新字段中。

之后，我们按照`count`字段的值按降序（`-1`）排序，最后，我们将输出限制为通过管道的前十个文档。这些文档是我们正在寻找的前十个地址。

以下是一些示例 Python 代码：

```sql
   def top_ten_addresses_from(self):
       pipeline = [
           {"$group": {"_id": "$from", "count": {"$sum": 1}}},
           {"$sort": SON([("count", -1)])},
           {"$limit": 10},
       ]
       result = self.collection.aggregate(pipeline)
       for res in result:
           print(res)
```

前面代码的输出如下：

```sql
{u'count': 38, u'_id': u'miningpoolhub_1'}
{u'count': 31, u'_id': u'Ethermine'}
{u'count': 30, u'_id': u'0x3c540be890df69eca5f0099bbedd5d667bd693f3'}
{u'count': 27, u'_id': u'0xb42b20ddbeabdc2a288be7ff847ff94fb48d2579'}
{u'count': 25, u'_id': u'ethfans.org'}
{u'count': 16, u'_id': u'Bittrex'}
{u'count': 8, u'_id': u'0x009735c1f7d06faaf9db5223c795e2d35080e826'}
{u'count': 8, u'_id': u'Oraclize'}
{u'count': 7, u'_id': u'0x1151314c646ce4e0efd76d1af4760ae66a9fe30f'}
{u'count': 7, u'_id': u'0x4d3ef0e8b49999de8fa4d531f07186cc3abe3d6e'}
```

现在我们找到了交易结束的前十个地址。就像我们对`from`所做的那样，对`to`地址的计算也完全相同，只是使用`to`字段而不是`from`进行分组，如下面的代码所示：

```sql
   def top_ten_addresses_to(self):
       pipeline = [
           {"$group": {"_id": "$to", "count": {"$sum": 1}}},
           {"$sort": SON([("count", -1)])},
           {"$limit": 10},
       ]
       result = self.collection.aggregate(pipeline)
       for res in result:
           print(res)
```

前面代码的输出如下：

```sql
{u'count': 33, u'_id': u'0x6090a6e47849629b7245dfa1ca21d94cd15878ef'}
{u'count': 30, u'_id': u'0x4b9e0d224dabcc96191cace2d367a8d8b75c9c81'}
{u'count': 25, u'_id': u'0x69ea6b31ef305d6b99bb2d4c9d99456fa108b02a'}
{u'count': 23, u'_id': u'0xe94b04a0fed112f3664e45adb2b8915693dd5ff3'}
{u'count': 22, u'_id': u'0x8d12a197cb00d4747a1fe03395095ce2a5cc6819'}
{u'count': 18, u'_id': u'0x91337a300e0361bddb2e377dd4e88ccb7796663d'}
{u'count': 13, u'_id': u'0x1c3f580daeaac2f540c998c8ae3e4b18440f7c45'}
{u'count': 12, u'_id': u'0xeef274b28bd40b717f5fea9b806d1203daad0807'}
{u'count': 9, u'_id': u'0x96fc4553a00c117c5b0bed950dd625d1c16dc894'}
{u'count': 9, u'_id': u'0xd43d09ec1bc5e57c8f3d0c64020d403b04c7f783'}
```

让我们找到每笔交易的平均值，并统计标准偏差。在这个示例中，我们使用`$avg`和`$stdDevPop`操作符来计算`value`字段的统计数据。使用简单的`$group`操作，我们输出一个具有我们选择的 ID（这里是`value`）和`averageValues`的单个文档，如下面的代码所示：

```sql
   def average_value_per_transaction(self):
       pipeline = [
           {"$group": {"_id": "value", "averageValues": {"$avg": "$value"}, "stdDevValues": {"$stdDevPop": "$value"}}},
       ]
       result = self.collection.aggregate(pipeline)
       for res in result:
           print(res)
```

前面代码的输出如下：

```sql
{u'averageValues': 5.227238976440972, u'_id': u'value', u'stdDevValues': 38.90322689649576}
```

让我们找到每笔交易所需的平均费用，返回有关偏差的统计数据。平均费用类似于平均值，只是将`$value`替换为`$txfee`，如下面的代码所示：

```sql
   def average_fee_per_transaction(self):
       pipeline = [
           {"$group": {"_id": "value", "averageFees": {"$avg": "$txfee"}, "stdDevValues": {"$stdDevPop": "$txfee"}}},
       ]
       result = self.collection.aggregate(pipeline)
       for res in result:
           print(res)
```

前面代码片段的输出如下：

```sql
{u'_id': u'value', u'averageFees': 320842.0729166667, u'stdDevValues': 1798081.7305142984} 
```

我们找到网络在特定时间更活跃的时间。

为了找出交易最活跃的小时，我们使用`$hour`运算符从我们存储了`datetime`值并称为`timestamp`的`ISODate()`字段中提取`hour`字段，如下面的代码所示：

```sql
   def active_hour_of_day_transactions(self):
       pipeline = [
           {"$group": {"_id": {"$hour": "$timestamp"}, "transactions": {"$sum": 1}}},
           {"$sort": SON([("transactions", -1)])},
           {"$limit": 1},
       ]
       result = self.collection.aggregate(pipeline)
       for res in result:
           print(res)
```

输出如下：

```sql
{u'_id': 11, u'transactions': 34} 
```

以下代码将计算一天中交易价值最高的小时的交易总值：

```sql
  def active_hour_of_day_values(self):
 pipeline = [
 {"$group": {"_id": {"$hour": "$timestamp"}, "transaction_values": {"$sum": "$value"}}},
 {"$sort": SON([("transactions", -1)])},
 {"$limit": 1},
 ]
 result = self.collection.aggregate(pipeline)
 for res in result:
 print(res)
```

上述代码的输出如下：

```sql
{u'transaction_values': 33.17773841, u'_id': 20} 
```

让我们找出网络活动最频繁的一天是一周中的哪一天，根据交易数量或交易价值。与一天中的小时一样，我们使用`$dayOfWeek`运算符从`ISODate()`对象中提取一周中的哪一天，如下面的代码所示。按照美国的惯例，星期天为一，星期六为七：

```sql
   def active_day_of_week_transactions(self):
       pipeline = [
           {"$group": {"_id": {"$dayOfWeek": "$timestamp"}, "transactions": {"$sum": 1}}},
           {"$sort": SON([("transactions", -1)])},
           {"$limit": 1},
       ]
       result = self.collection.aggregate(pipeline)
       for res in result:
           print(res)

```

上述代码的输出如下：

```sql
{u'_id': 3, u'transactions': 92} 
```

以下代码将计算一周中交易价值最高的一天的交易总值：

```sql
  def active_day_of_week_values(self):
       pipeline = [
           {"$group": {"_id": {"$dayOfWeek": "$timestamp"}, "transaction_values": {"$sum": "$value"}}},
           {"$sort": SON([("transactions", -1)])},
           {"$limit": 1},
       ]
```

```sql
       result = self.collection.aggregate(pipeline)
 for res in result:
 print(res)
```

上述代码的输出如下：

```sql

 {u'transaction_values': 547.62439312, u'_id': 2} 
```

我们计算的聚合可以用以下图表描述：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/e8fe830a-aef7-4dc6-b15a-60247711d69e.png)

在区块方面，我们想了解以下内容：

+   每个区块的平均交易数量，包括总体交易数量和合约内部交易的总体交易数量。

+   每个区块的平均燃气使用量。

+   每个交易到区块的平均燃气使用量。是否有机会在一个区块中提交我的智能合约？

+   每个区块的平均难度及其偏差。

+   每个区块的平均交易数量，总交易数量以及合约内部交易的平均交易数量。

通过对`number_transactions`字段进行平均，我们可以得到每个区块的交易数量，如下面的代码所示：

```sql
   def average_number_transactions_total_block(self):
       pipeline = [
           {"$group": {"_id": "average_transactions_per_block", "count": {"$avg": "$number_transactions"}}},
       ]
       result = self.collection.aggregate(pipeline)
       for res in result:
           print(res)
```

上述代码的输出如下：

```sql
 {u'count': 39.458333333333336, u'_id': u'average_transactions_per_block'}

```

而使用以下代码，我们可以得到每个区块的内部交易的平均数量：

```sql
  def average_number_transactions_internal_block(self):
       pipeline = [
           {"$group": {"_id": "average_transactions_internal_per_block", "count": {"$avg": "$number_internal_transactions"}}},
       ]
       result = self.collection.aggregate(pipeline)
       for res in result:
           print(res)
```

上述代码的输出如下：

```sql
{u'count': 8.0, u'_id': u'average_transactions_internal_per_block'}
```

每个区块使用的平均燃气量可以通过以下方式获得：

```sql
def average_gas_block(self):
       pipeline = [
           {"$group": {"_id": "average_gas_used_per_block",
                       "count": {"$avg": "$gas_used"}}},
       ]
       result = self.collection.aggregate(pipeline)
       for res in result:
           print(res)
```

输出如下：

```sql
{u'count': 2563647.9166666665, u'_id': u'average_gas_used_per_block'} 
```

每个区块的平均难度及其偏差可以通过以下方式获得：

```sql
  def average_difficulty_block(self):
       pipeline = [
           {"$group": {"_id": "average_difficulty_per_block",
                       "count": {"$avg": "$difficulty"}, "stddev": {"$stdDevPop": "$difficulty"}}},
       ]
       result = self.collection.aggregate(pipeline)
       for res in result:
           print(res)
```

输出如下：

```sql
{u'count': 881676386932100.0, u'_id': u'average_difficulty_per_block', u'stddev': 446694674991.6385} 
```

我们的聚合描述如下模式：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/1b5a0878-4238-4012-bca0-c395a951a7f9.png)

现在我们已经计算了基本统计数据，我们想要提高我们的水平，并了解有关我们的交易的更多信息。通过我们复杂的机器学习算法，我们已经确定了一些交易是欺诈或**首次代币发行**（ICO），或者两者兼而有之。

在这些文档中，我们已经在一个名为`tags`的数组中标记了这些属性，如下所示：

```sql
{
 "_id" : ObjectId("59554977cedea8f696a416dd"),
 "to" : "0x4b9e0d224dabcc96191cace2d367a8d8b75c9c81",
 "txhash" : "0xf205991d937bcb60955733e760356070319d95131a2d9643e3c48f2dfca39e77",
 "from" : "0x3c540be890df69eca5f0099bbedd5d667bd693f3",
 "block" : 3923794,
 "txfee" : 28594,
 "timestamp" : ISODate("2017-06-10T09:59:35Z"),
 "tags" : [
 "scam",
 "ico"
 ],
 "value" : 0
 }
```

现在我们想要获取 2017 年 6 月的交易，移除`_id`字段，并根据我们已经识别的标签生成不同的文档。因此，在我们的示例中，我们将在我们的新集合`scam_ico_documents`中输出两个文档，以便进行单独处理。

通过聚合框架进行此操作的方式如下所示：

```sql
def scam_or_ico_aggregation(self):
 pipeline = [
 {"$match": {"timestamp": {"$gte": datetime.datetime(2017,6,1), "$lte": datetime.datetime(2017,7,1)}}},
 {"$project": {
 "to": 1,
 "txhash": 1,
 "from": 1,
 "block": 1,
 "txfee": 1,
 "tags": 1,
 "value": 1,
 "report_period": "June 2017",
 "_id": 0,
 }

 },
 {"$unwind": "$tags"},
 {"$out": "scam_ico_documents"}
 ]
 result = self.collection.aggregate(pipeline)
 for res in result:
 print(res)
```

在聚合框架管道中，我们有以下四个不同的步骤：

1.  使用`$match`，我们只提取具有`timestamp`字段值为 2017 年 6 月 1 日的文档。

1.  使用`$project`，我们添加一个名为`report_period`的新字段，其值为`2017 年 6 月`，并通过将其值设置为`0`来移除`_id`字段。我们通过使用值`1`保持其余字段不变，如前面的代码所示。

1.  使用`$unwind`，我们在我们的`$tags`数组中为每个标签输出一个新文档。

1.  最后，使用`$out`，我们将所有文档输出到一个新的`scam_ico_documents`集合中。

由于我们使用了`$out`运算符，在命令行中将得不到任何结果。如果我们注释掉`{"$out": "scam_ico_documents"}`，我们将得到以下类似的文档：

```sql
{u'from': u'miningpoolhub_1', u'tags': u'scam', u'report_period': u'June 2017', u'value': 0.52415349, u'to': u'0xdaf112bcbd38d231b1be4ae92a72a41aa2bb231d', u'txhash': u'0xe11ea11df4190bf06cbdaf19ae88a707766b007b3d9f35270cde37ceccba9a5c', u'txfee': 21.0, u'block': 3923785}
```

我们数据库中的最终结果将如下所示：

```sql
{
 "_id" : ObjectId("5955533be9ec57bdb074074e"),
 "to" : "0x4b9e0d224dabcc96191cace2d367a8d8b75c9c81",
 "txhash" : "0xf205991d937bcb60955733e760356070319d95131a2d9643e3c48f2dfca39e77",
 "from" : "0x3c540be890df69eca5f0099bbedd5d667bd693f3",
 "block" : 3923794,
 "txfee" : 28594,
 "tags" : "scam",
 "value" : 0,
 "report_period" : "June 2017"
 }
```

现在，我们在`scam_ico_documents`集合中有了明确定义的文档，我们可以很容易地进行进一步的分析。这种分析的一个例子是在一些骗子上附加更多信息。幸运的是，我们的数据科学家已经提供了一些额外的信息，我们已经提取到一个新的集合`scam_details`中，它看起来是这样的：

```sql
{
 "_id" : ObjectId("5955510e14ae9238fe76d7f0"),
 "scam_address" : "0x3c540be890df69eca5f0099bbedd5d667bd693f3",
 Email_address": example@scammer.com"
 }
```

现在，我们可以创建一个新的聚合管道作业，将我们的`scam_ico_documents`与`scam_details`集合连接起来，并将这些扩展结果输出到一个新的集合中，名为`scam_ico_documents_extended`，就像这样：

```sql
def scam_add_information(self):
 client = MongoClient()
 db = client.mongo_book
 scam_collection = db.scam_ico_documents
 pipeline = [
 {"$lookup": {"from": "scam_details", "localField": "from", "foreignField": "scam_address", "as": "scam_details"}},
 {"$match": {"scam_details": { "$ne": [] }}},
 {"$out": "scam_ico_documents_extended"}
 ]
 result = scam_collection.aggregate(pipeline)
 for res in result:
 print(res)
```

在这里，我们使用以下三步聚合管道：

1.  使用`$lookup`命令，从`scam_details`集合和`scam_address`字段中的数据与我们的本地集合（`scam_ico_documents`）中的数据进行连接，基于本地集合属性`from`的值等于`scam_details`集合的`scam_address`字段中的值。如果它们相等，那么管道将在文档中添加一个名为`scam_details`的新字段。

1.  接下来，我们只匹配具有`scam_details`字段的文档，即与查找聚合框架步骤匹配的文档。

1.  最后，我们将这些文档输出到一个名为`scam_ico_documents_extended`的新集合中。

现在这些文档看起来是这样的：

```sql
> db.scam_ico_documents_extended.findOne()
 {
 "_id" : ObjectId("5955533be9ec57bdb074074e"),
 "to" : "0x4b9e0d224dabcc96191cace2d367a8d8b75c9c81",
 "txhash" : "0xf205991d937bcb60955733e760356070319d95131a2d9643e3c48f2dfca39e77",
 "from" : "0x3c540be890df69eca5f0099bbedd5d667bd693f3",
 "block" : 3923794,
 "txfee" : 28594,
 "tags" : "scam",
 "value" : 0,
 "report_period" : "June 2017",
 "scam_details_data" : [
 {
 "_id" : ObjectId("5955510e14ae9238fe76d7f0"),
 "scam_address" : "0x3c540be890df69eca5f0099bbedd5d667bd693f3",
 email_address": example@scammer.com"
 }]}
```

使用聚合框架，我们已经确定了我们的数据，并且可以快速高效地处理它。

前面的步骤可以总结如下图所示：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/0ce20f81-e8bb-4501-94a4-2a855c17c203.png)

# 总结

在本章中，我们深入探讨了聚合框架。我们讨论了为什么以及何时应该使用聚合，而不是简单地使用 MapReduce 或查询数据库。我们详细介绍了聚合的各种选项和功能。

我们讨论了聚合阶段和各种运算符，如布尔运算符、比较运算符、集合运算符、数组运算符、日期运算符、字符串运算符、表达式算术运算符、聚合累加器、条件表达式和变量，以及文字解析数据类型运算符。

使用以太坊用例，我们通过工作代码进行了聚合，并学习了如何解决工程问题。

最后，我们了解了聚合框架目前存在的限制以及何时应避免使用它。

在下一章中，我们将继续讨论索引的主题，并学习如何为我们的读写工作负载设计和实现高性能索引。


# 第七章：索引

本章将探讨任何数据库中最重要的属性之一：索引。与书籍索引类似，数据库索引可以加快数据检索速度。在关系型数据库管理系统中，索引被广泛使用（有时被滥用）以加快数据访问速度。在 MongoDB 中，索引在模式和查询设计中起着至关重要的作用。MongoDB 支持各种索引类型，您将在本章中了解到，包括单字段、复合、多键、地理空间、哈希、部分等等。除了审查不同类型的索引，我们还将向您展示如何为单服务器部署以及复杂的分片环境构建和管理索引。

在本章中，我们将涵盖以下主题：

+   索引内部

+   索引类型

+   构建和管理索引

+   索引的高效使用

# 索引内部

在大多数情况下，索引是 B 树数据结构的变体。由 Rudolf Bayer 和 Ed McCreight 于 1971 年在波音研究实验室工作时发明，**B 树**数据结构允许在对数时间内执行搜索、顺序访问、插入和删除。**对数时间**属性适用于平均情况性能和最坏情况性能，当应用程序无法容忍性能行为的意外变化时，这是一个很好的属性。

为了进一步说明对数时间的重要性，我们将向您展示 Big-O 复杂度图表，该图表来自[`bigocheatsheet.com/`](http://bigocheatsheet.com)：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/1e0681d3-c53a-4ad0-a009-75717d94b0ee.png)

在这个图表中，您可以看到对数时间性能作为图表的*x*轴平行的一条直线。随着元素数量的增加，常数时间（**O(n)**）算法表现更差，而二次时间算法（**O(n²)**）则超出了图表范围。对于我们依赖的算法来尽快将数据返回给我们，时间性能至关重要。

B 树的另一个有趣特性是它是自平衡的，这意味着它将自动调整以始终保持这些属性。它的前身和最接近的亲戚是二叉搜索树，这是一种数据结构，每个父节点只允许两个子节点。

从图表上看，B 树的结构如下图所示，也可以在[`commons.wikimedia.org/w/index.php?curid=11701365`](https://commons.wikimedia.org/w/index.php?curid=11701365)上看到：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/481c69b3-7abe-4924-a3d8-5682382bdf01.png)

在上图中，我们有一个父节点，其值为**7**和**16**，指向三个子节点。

如果我们搜索值为**9**，知道它大于**7**且小于**16**，我们将直接被引导到包含该值的中间子节点。

由于这种结构，我们在每一步都将搜索空间几乎减半，最终达到*log n*的时间复杂度。与顺序扫描每个元素相比，每一步将元素数量减半，使我们的收益呈指数增长，因为我们需要搜索的元素数量增加。

# 索引类型

MongoDB 为不同的需求提供了各种索引类型。在接下来的章节中，我们将确定不同类型的索引以及它们各自满足的需求。

# 单字段索引

最常见和简单的索引类型是单字段索引。单字段和键索引的一个例子是在每个 MongoDB 集合中默认生成的`ObjectId`（`_id`）索引。`ObjectId`索引也是唯一的，防止另一个文档在集合中具有相同的`ObjectId`。

基于我们在前几章中使用的`mongo_book`数据库的单字段索引定义如下：

```sql
> db.books.createIndex( { price: 1 } )
```

在这里，我们按照索引创建的顺序对字段名称创建索引。对于降序，相同的索引将如下创建：

```sql
> db.books.createIndex( { price: -1 } )
```

索引创建的顺序对于我们期望查询优先考虑存储在索引中的第一个文档的值的情况很重要。然而，由于索引具有极其高效的时间复杂度，这对于最常见的用例来说并不重要。

索引可以用于字段值的精确匹配查询或范围查询。在前一种情况下，一旦我们的指针在*O(log n)*时间后到达值，搜索就可以停止。

在范围查询中，由于我们在 B 树索引中按顺序存储值，一旦我们在 B 树的节点中找到范围查询的边界值，我们将知道其所有子节点中的所有值都将成为我们结果集的一部分，从而允许我们结束我们的搜索。

示例如下：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/1fe86237-0faf-44c8-b1e1-603416cc5b3e.png)

# 删除索引

删除索引与创建索引一样简单。我们可以通过名称或由其组成的字段引用索引：

```sql
> db.books.dropIndex( { price: -1 } ) > db.books.dropIndex( "price_index" )
```

# 索引嵌入字段

作为文档数据库，MongoDB 支持在同一文档的嵌套复杂层次结构中嵌入字段和整个文档。自然地，它也允许我们对这些字段进行索引。

在我们的`books`集合示例中，我们可以有以下类似的文档：

```sql
{
"_id" : ObjectId("5969ccb614ae9238fe76d7f1"),
"name" : "MongoDB Indexing Cookbook",
"isbn" : "1001",
"available" : 999,
"meta_data" : {
"page_count" : 256,
"average_customer_review" : 4.8
}
} 
```

在这里，`meta_data`字段本身是一个文档，具有`page_count`和`average_customer_review`字段。同样，我们可以按照以下方式在`page_count`上创建索引：

```sql
db.books.createIndex( { "meta_data.page_count": 1 } )
```

这可以回答关于`meta_data.page_count`字段的相等和范围比较的查询，如下所示：

```sql
> db.books.find({"meta_data.page_count": { $gte: 200 } })
> db.books.find({"meta_data.page_count": 256 })
```

要访问嵌入字段，我们使用点表示法，并且需要在字段名称周围包含引号（`""`）。

# 索引嵌入文档

我们还可以像索引嵌入字段一样索引整个嵌入文档：

```sql
> db.books.createIndex( { "meta_data": 1 } )
```

在这里，我们正在索引整个文档，期望针对其整体进行查询，如下所示：

```sql
> db.books.find({"meta_data": {"page_count":256, "average_customer_review":4.8}})
```

主要区别在于当我们索引嵌入字段时，我们可以使用索引对它们执行范围查询，而当我们索引嵌入文档时，我们只能使用索引执行比较查询。

`db.books.find({"meta_data.average_customer_review": { $gte: 4.8}, "meta_data.page_count": { $gte: 200 } })`命令不会使用我们的`meta_data`索引，而`db.books.find({"meta_data": {"page_count":256, "average_customer_review":4.8}})`会使用它。

# 后台索引

索引可以在前台创建，阻塞集合中的所有操作，直到它们建立完成，或者可以在后台创建，允许并发操作。通过传递`background: true`参数来在后台构建索引：

```sql
> db.books.createIndex( { price: 1 }, { background: true } )
```

后台索引在本章的最后一节*构建和管理索引*中有一些限制，我们将在最后一节中重新讨论。

# 复合索引

复合索引是单键索引的泛化，允许多个字段包含在同一个索引中。当我们期望查询跨多个字段的文档时，以及当我们开始在集合中拥有太多索引时，它们非常有用。

复合索引最多可以有 31 个字段。它们不能有散列索引类型。

复合索引的声明方式与单个索引类似，通过定义要索引的字段和索引的顺序来定义：

```sql
> db.books.createIndex({"name": 1, "isbn": 1})
```

# 使用复合索引进行排序

索引的顺序对于排序结果很有用。在单字段索引中，MongoDB 可以双向遍历索引，因此我们定义的顺序并不重要。

然而，在多字段索引中，排序可以决定我们是否可以使用此索引进行排序。在前面的示例中，与我们索引创建的排序方向匹配的查询将使用我们的索引，如下所示：

```sql
> db.books.find().sort( { "name": 1, "isbn": 1 })
```

它还将使用所有`sort`字段反转的`sort`查询：

```sql
> db.books.find().sort( { "name": -1, "isbn": -1 })
```

在这个查询中，由于我们否定了两个字段，MongoDB 可以使用相同的索引，从末尾到开头遍历它。

另外两种排序顺序如下：

```sql
> db.books.find().sort( { "name": -1, "isbn": 1 })
> db.books.find().sort( { "name": 1, "isbn": -1 })
```

它们不能使用索引进行遍历，因为我们想要的`sort`顺序在我们的索引 B 树数据结构中不存在。

# 重用复合索引

复合索引的一个重要属性是它们可以用于对索引字段的前缀进行多个查询。当我们想要在随着时间在我们的集合中堆积的索引进行合并时，这是有用的。

考虑我们之前创建的复合（多字段）索引：

```sql
> db.books.createIndex({"name": 1, "isbn": 1})
```

这可以用于对`name`或`{name, isbn}`进行查询：

```sql
> db.books.find({"name":"MongoDB Indexing"})
> db.books.find({"isbn": "1001", "name":"MongoDB Indexing"})
```

查询中字段的顺序并不重要；MongoDB 将重新排列字段以匹配我们的查询。

然而，我们索引中字段的顺序是重要的。仅针对`isbn`字段的查询无法使用我们的索引：

```sql
> db.books.find({"isbn": "1001"})
```

根本原因是我们字段的值存储在索引中作为次要、第三等等；每个值都嵌入在前一个值中，就像俄罗斯套娃一样。这意味着当我们在多字段索引的第一个字段上进行查询时，我们可以使用最外层的套娃来找到我们的模式，而当我们搜索前两个字段时，我们可以在最外层的套娃上匹配模式，然后深入到内部的套娃中。

这个概念被称为**前缀索引**，以及索引交集，它是索引合并的最强大工具，正如你将在本章后面看到的。

# 多键索引

在前面的部分中已经解释了标量（单一）值的索引。然而，我们从使用 MongoDB 中获得的优势之一是能够轻松地以数组的形式存储向量值。

在关系世界中，存储数组通常是不受欢迎的，因为它违反了正常形式。在 MongoDB 这样的面向文档的数据库中，它经常是我们设计的一部分，因为我们可以轻松地存储和查询数据的复杂结构。

通过使用多键索引可以对文档数组进行索引。多键索引可以存储标量值数组和嵌套文档数组。

创建多键索引与创建常规索引相同：

```sql
> db.books.createIndex({"tags":1})
```

假设我们已经在我们的`books`集合中创建了一个文档，使用以下命令：

```sql
> db.books.insert({"name": "MongoDB Multikeys Cheatsheet", "isbn": "1002", "available": 1, "meta_data": {"page_count":128, "average_customer_review":3.9}, "tags": ["mongodb", "index","cheatsheet","new"] })
```

我们的新索引将是一个多键索引，允许我们找到包含数组中任何标签的文档：

```sql
> db.books.find({tags:"new"})
{
"_id" : ObjectId("5969f4bc14ae9238fe76d7f2"),
"name" : "MongoDB Multikeys Cheatsheet",
"isbn" : "1002",
"available" : 1,
"meta_data" : {
"page_count" : 128,
"average_customer_review" : 3.9
},
"tags" : [
"mongodb",
"index",
"cheatsheet",
"new"
]
}
>
```

我们还可以使用多键索引创建复合索引，但每个索引文档中最多只能有一个数组。鉴于在 MongoDB 中我们不指定每个字段的类型，这意味着创建具有两个或更多字段的数组值的索引将在创建时失败，并且尝试插入具有两个或更多字段的数组的文档将在插入时失败。

例如，如果我们的数据库中有以下文档，那么在`tags`、`analytics_data`上创建的复合索引将无法创建：

```sql
{
"_id" : ObjectId("5969f71314ae9238fe76d7f3"),
"name": "Mastering parallel arrays indexing",
"tags" : [
"A",
"B"
],
"analytics_data" : [
"1001",
"1002"
]
}

> db.books.createIndex({tags:1, analytics_data:1})
{
"ok" : 0,
"errmsg" : "cannot index parallel arrays [analytics_data] [tags]",
"code" : 171,
"codeName" : "CannotIndexParallelArrays"
}
```

因此，如果我们首先在空集合上创建索引，然后尝试插入此文档，插入将失败，并显示以下错误：

```sql
> db.books.find({isbn:"1001"}).hint("international_standard_book_number_index").explain()
{
 "queryPlanner" : {
 "plannerVersion" : 1,
 "namespace" : "mongo_book.books",
 "indexFilterSet" : false,
 "parsedQuery" : {
 "isbn" : {
 "$eq" : "1001"
 }
 },
 "winningPlan" : {
 "stage" : "FETCH",
 "inputStage" : {
 "stage" : "IXSCAN",
 "keyPattern" : {
 "isbn" : 1
 },
 "indexName" : "international_standard_book_numbe
r_index",
 "isMultiKey" : false,
 "multiKeyPaths" : {
 "isbn" : [ ]
 },
 "isUnique" : false,
 "isSparse" : false,
 "isPartial" : false,
 "indexVersion" : 2,
 "direction" : "forward",
 "indexBounds" : {
 "isbn" : [
 "[\"1001\", \"1001\"]"
 ]
 }
 }
 },
 "rejectedPlans" : [ ]
 },
 "serverInfo" : {
 "host" : "PPMUMCPU0142",
 "port" : 27017,
 "version" : "3.4.7",
 "gitVersion" : "cf38c1b8a0a8dca4a11737581beafef4fe120bcd"
 },
 "ok" : 1
```

散列索引不能是多键索引。

当我们尝试微调我们的数据库时，我们可能会遇到的另一个限制是多键索引无法完全覆盖查询。使用索引覆盖查询意味着我们可以完全从索引中获取我们的结果数据，而根本不访问我们数据库中的数据。这可能会导致性能大幅提升，因为索引很可能存储在 RAM 中。

在多键索引中查询多个值将从索引的角度产生一个两步过程。

在第一步中，索引将用于检索数组的第一个值，然后顺序扫描将运行数组中其余的元素；示例如下：

```sql
> db.books.find({tags: [ "mongodb", "index", "cheatsheet", "new" ] })
```

这将首先搜索具有`mongodb`值的多键`index`标签的所有条目，然后顺序扫描它们以找到也具有`index`、`cheatsheet`和`new`标签的条目。

多键索引不能用作分片键。但是，如果分片键是多键索引的前缀索引，则可以使用。我们将在第十三章 *分片*中更多地介绍这一点。

# 特殊类型的索引

除了通用索引外，MongoDB 还支持特殊用例的索引。在本节中，我们将确定并探讨如何使用它们。

# 文本索引

文本索引是对字符串值字段的特殊索引，用于支持文本搜索。本书基于文本索引功能的第 3 版，自第 3.2 版起可用。

文本索引可以类似于常规索引进行指定，方法是用单词`text`替换索引排序顺序（`-1`，`1），如下所示：

```sql
> db.books.createIndex({"name": "text"})
```

一个集合最多可以有一个文本索引。这个文本索引可以支持多个字段，无论是文本还是其他。它不能支持其他特殊类型，如多键或地理空间。即使它们只是复合索引的一部分，文本索引也不能用于排序结果。

由于每个集合只有一个文本索引，因此我们需要明智地选择字段。重建此文本索引可能需要相当长的时间，并且每个集合只有一个文本索引使得维护非常棘手，正如您将在本章末尾看到的那样。

幸运的是，此索引也可以是复合索引：

```sql
> db.books.createIndex( { "available": 1, "meta_data.page_count": 1,  "$**": "text" } )
```

具有`text`字段的复合索引遵循本章前面解释的排序和前缀索引规则。我们可以使用此索引来查询`available`，或`available`和`meta_data.page_count`的组合，或者如果排序顺序允许在任何方向遍历我们的索引，则对它们进行排序。

我们还可以盲目地对包含字符串的每个字段进行`text`索引：

```sql
> db.books.createIndex( { "$**": "text" } )
```

这可能导致无限制的索引大小，应该避免使用；但是，如果我们有非结构化数据（例如，直接来自应用程序日志，我们不知道哪些字段可能有用，并且希望能够查询尽可能多的字段），这可能是有用的。

文本索引将应用词干处理（删除常见后缀，例如英语单词的复数`s`/`es`）并从索引中删除停用词（`a`，`an`，`the`等）。

文本索引支持 20 多种语言，包括西班牙语，中文，乌尔都语，波斯语和阿拉伯语。文本索引需要特殊配置才能正确地索引英语以外的语言。

文本索引的一些有趣属性如下所述：

+   大小写不敏感和变音符号不敏感：文本索引是大小写和变音符号不敏感的。文本索引的第 3 版（随第 3.4 版一起发布）支持常见的*C*，简单的*S*和特殊的*T*大小写折叠，如**Unicode 字符数据库**（**UCD**）8.0 大小写折叠中所述。除了大小写不敏感外，文本索引的第 3 版还支持变音符号不敏感。这将扩展对带有小写和大写字母形式的重音符号的字符的不敏感性。例如，*e*，*è*，*é*，*ê*，*ë*及其大写字母对应物，在使用文本索引进行比较时都可能相等。在文本索引的先前版本中，这些被视为不同的字符串。

+   **标记化分隔符：**文本索引的第 3 版支持标记化分隔符，定义为`Dash`，`Hyphen`，`Pattern_Syntax`，`Quotation_Mark`，`Terminal_Punctuation`和`White_Space`，如 UCD 8.0 大小写折叠中所述。

# 散列索引

散列索引包含索引字段的`hashed`值：

```sql
> db.books.createIndex( { name: "hashed" } )
```

这将在我们的`books`集合的每本书的名称上创建一个哈希索引。哈希索引非常适合相等匹配，但不能用于范围查询。如果我们希望对字段执行一系列查询，我们可以创建一个常规索引（或包含该字段的复合索引），并且还可以创建一个用于相等匹配的哈希索引。哈希索引在 MongoDB 内部用于基于哈希的分片，我们将在第十三章 *分片*中讨论。哈希索引将浮点字段截断为整数。在可能的情况下，应尽量避免对哈希字段使用浮点数。

# 生存时间索引

**生存时间**（**TTL**）索引用于在过期时间后自动删除文档。它们的语法如下：

```sql
> db.books.createIndex( { "created_at_date": 1 }, { expireAfterSeconds: 86400 } )
```

`created_at_date`字段的值必须是日期或日期数组（将使用最早的日期）。在这个例子中，文档将在`created_at_date`之后的一天（`86400`秒）被删除。

如果字段不存在或值不是日期，则文档将不会过期。换句话说，TTL 索引会默默失败，不会在失败时返回任何错误。

数据将通过每 60 秒运行一次的后台作业进行删除。因此，关于文档在其过期日期之后还会持续存在多长时间，没有明确的准确性保证。

TTL 索引是常规的单字段索引。它可以用于像常规索引一样的查询。TTL 索引不能是复合索引，不能在封顶集合上操作，也不能使用`_id`字段。`_id`字段隐含地包含了文档创建时间的时间戳，但不是一个`Date`字段。如果我们希望每个文档在不同的自定义日期点过期，我们必须设置`{expireAfterSeconds: 0}`，并手动设置 TTL 索引的`Date`字段为我们希望文档过期的日期。

# 部分索引

集合上的部分索引是仅适用于满足`partialFilterExpression`查询的文档的索引。

我们将使用我们熟悉的`books`集合，如下所示：

```sql
> db.books.createIndex(
 { price: 1, name: 1 },
 { partialFilterExpression: { price: { $gt: 30 } } }
)
```

使用这个，我们可以为只有价格大于`30`的书籍创建一个索引。部分索引的优点是在创建和维护上更轻量，并且使用更少的存储空间。

`partialFilterExpression`过滤器支持以下运算符：

+   相等表达式（即`field: value`，或使用`$eq`运算符）

+   `$exists: true`表达式

+   `$gt`，`$gte`，`$lt`和`$lte`表达式

+   `$type`表达式

+   `$and`运算符，仅在顶层

只有当查询可以完全满足部分索引时，才会使用部分索引。

如果我们的查询匹配或比`partialFilterExpression`过滤器更严格，那么将使用部分索引。如果结果可能不包含在部分索引中，则索引将被完全忽略。

`partialFilterExpression`不需要是稀疏索引字段的一部分。以下索引是有效的稀疏索引：

```sql

 > db.books.createIndex({ name: 1 },{ partialFilterExpression: { price: { $gt: 30 } } })
```

然而，要使用这个部分索引，我们需要查询`name`和`price`都等于或大于`30`。

优先选择部分索引而不是稀疏索引。稀疏索引提供了部分索引提供的功能的子集。部分索引是在 MongoDB 3.2 中引入的，因此如果您有早期版本的稀疏索引，升级它们可能是一个好主意。`_id`字段不能是部分索引的一部分。分片键索引不能是部分索引。`partialFilterExpression`不能与`sparse`选项结合使用。

# 稀疏索引

稀疏索引类似于部分索引，但比它早几年（自 1.8 版本以来就可用）。

`sparse`索引只索引包含以下字段的值：

```sql
> db.books.createIndex( { "price": 1 }, { sparse: true } )
```

它只会创建一个包含包含`price`字段的文档的索引。

由于其性质，有些索引始终是稀疏的：

+   `2d`，`2dsphere`（版本 2）

+   `geoHaystack`

+   `text`

稀疏和唯一的索引将允许多个文档缺少索引键。它不会允许具有相同索引字段值的文档。具有地理空间索引（`2d`，`2dsphere`和`geoHaystack`）的稀疏和复合索引将索引文档，只要它具有`geospatial`字段。

具有`text`字段的稀疏和复合索引将索引文档，只要它具有`text`字段。没有前两种情况的稀疏和复合索引将索引文档，只要它至少有一个字段。

在 MongoDB 的最新版本中避免创建新的稀疏索引；改用部分索引。

# 唯一索引

唯一索引类似于 RDBMS 唯一索引，禁止索引字段的重复值。MongoDB 默认在每个插入的文档的`_id`字段上创建唯一索引：

```sql
> db.books.createIndex( { "name": 1 }, { unique: true } )
```

这将在书的`name`上创建一个`unique`索引。唯一索引也可以是复合嵌入字段或嵌入文档索引。

在复合索引中，唯一性是在索引的所有字段的值的组合中强制执行的；例如，以下内容不会违反唯一索引：

```sql
> db.books.createIndex( { "name": 1, "isbn": 1 }, { unique: true } )
> db.books.insert({"name": "Mastering MongoDB", "isbn": "101"})
> db.books.insert({"name": "Mastering MongoDB", "isbn": "102"})
```

这是因为即使名称相同，我们的索引也在寻找`name`和`isbn`的唯一组合，而这两个条目在`isbn`上有所不同。

唯一索引不适用于散列索引。如果集合已包含索引字段的重复值，则无法创建唯一索引。唯一索引不会阻止同一文档具有多个值。

如果文档缺少索引字段，则将插入该字段。如果第二个文档缺少索引字段，则不会插入。这是因为 MongoDB 将缺少的字段值存储为 null，只允许字段中缺少一个文档。

唯一和部分组合的索引只会在应用部分索引后应用唯一索引。这意味着如果它们不是部分过滤的一部分，可能会有几个具有重复值的文档。

# 不区分大小写

大小写敏感是索引中的常见问题。我们可能会将数据存储在混合大小写中，并且需要索引在查找存储的数据时忽略大小写。直到 3.4 版本，这是在应用程序级别处理的，方法是创建所有小写字符的重复字段，并将所有小写字段索引以模拟不区分大小写的索引。

使用`collation`参数，我们可以创建不区分大小写的索引，甚至可以创建行为不区分大小写的集合。

通常，`collation`允许用户指定特定于语言的字符串比较规则。可能的（但不是唯一的）用法是用于不区分大小写的索引和查询。

使用我们熟悉的`books`集合，我们可以在名称上创建一个不区分大小写的索引，如下所示：

```sql
> db.books.createIndex( { "name" : 1 },
 { collation: {
 locale : 'en',
 strength : 1
 }
 } )
```

`strength`参数是`collation`参数之一：用于区分大小写比较的定义参数。强度级别遵循**国际 Unicode 组件**（**ICU**）比较级别。它接受的值如下：

| **强度值** | **描述** |
| --- | --- |
| `1a` | 比较的主要级别。基于字符串值的比较，忽略任何其他差异，如大小写和变音符。 |
| `2` | 比较的次要级别，基于主要级别的比较，如果相等，则比较变音符（即重音）。 |
| `3`（默认） | 第三级比较。与级别*2*相同，添加大小写和变体。 |
| `4` | 第四级。仅限于特定用例，考虑标点符号，当级别 1-3 忽略标点符号时，或用于处理日文文本。 |
| `5` | 相同级别。仅限于特定用例：决定胜负者。 |

使用`collation`创建索引不足以获得不区分大小写的结果。我们需要在查询中指定`collation`，如下所示：

```sql
> db.books.find( { name: "Mastering MongoDB" } ).collation( { locale: 'en', strength: 1 } )
```

如果我们在查询中指定与我们的索引相同级别的`collation`，那么将使用该索引。我们可以按如下方式指定不同级别的`collation`：

```sql
> db.books.find( { name: "Mastering MongoDB" } ).collation( { locale: 'en', strength: 2 } )
```

在这里，我们无法使用索引，因为我们的索引具有`collation`级别 1，而我们的查询寻找`collation`级别`2`。

如果我们在查询中不使用任何`collation`，我们将得到默认级别为 3 的结果，即区分大小写。

使用与默认不同的`collation`创建的集合中的索引将自动继承此`collation`级别。

假设我们创建了一个`collation`级别为 1 的集合，如下所示：

```sql
> db.createCollection("case_sensitive_books", { collation: { locale: 'en_US', strength: 1 } } )
```

以下索引也将具有`name: 1`的排序：

```sql
> db.case_sensitive_books.createIndex( { name: 1 } )
```

对该集合的默认查询将使用排序`strength: 1`，区分大小写。如果我们想在查询中覆盖这一点，我们需要在查询中指定不同级别的`collation`，或者完全忽略`strength`部分。以下两个查询将返回`case_sensitive_books`集合中不区分大小写的默认`collation`级别结果：

```sql
> db.case_sensitive_books.find( { name: "Mastering MongoDB" } ).collation( { locale: 'en', strength: 3 } ) // default collation strength value
> db.case_sensitive_books.find( { name: "Mastering MongoDB" } ).collation( { locale: 'en'  } ) // no value for collation, will reset to global default (3) instead of default for case_sensitive_books collection (1)
```

排序在 MongoDB 中是一个相当强大且相对较新的概念，因此我们将在不同章节中继续探讨它。

# 地理空间索引

地理空间索引在 MongoDB 早期就被引入，而 Foursquare 是 MongoDB（当时是 10gen Inc.）最早的客户和成功案例之一，这可能并非巧合。在本章中，我们将探讨三种不同类型的地理空间索引，并将在以下部分中进行介绍。

# 2D 地理空间索引

`2d`地理空间索引将地理空间数据存储为二维平面上的点。它主要用于传统原因，用于 MongoDB 2.2 之前创建的坐标对，并且在大多数情况下，不应该与最新版本一起使用。

# 2dsphere 地理空间索引

`2dsphere`地理空间索引支持在类似地球的平面上计算几何。它比简单的`2d`索引更精确，并且可以支持 GeoJSON 对象和坐标对作为输入。

自 MongoDB 3.2 以来的当前版本是版本 3。默认情况下，它是稀疏索引，只索引具有`2dsphere`字段值的文档。假设我们的`books`集合中有一个位置字段，跟踪每本书的主要作者的家庭地址，我们可以按如下方式在该字段上创建索引：

```sql
> db.books.createIndex( { "location" : "2dsphere" } )
```

`location`字段需要是一个 GeoJSON 对象，就像这样一个：

```sql
location : { type: "Point", coordinates: [ 51.5876, 0.1643 ] }
```

`2dsphere`索引也可以作为复合索引的一部分，作为第一个字段或其他字段：

```sql
> db.books.createIndex( { name: 1, location : "2dsphere" } )
```

# geoHaystack 索引

当我们需要在一个小区域内搜索基于地理位置的结果时，`geoHaystack`索引非常有用。就像在干草堆中搜索针一样，使用`geoHaystack`索引，我们可以定义地理位置点的存储桶，并返回属于该区域的所有结果。

我们将创建一个`geoHaystack`索引，如下所示：

```sql
> db.books.createIndex( { "location" : "geoHaystack" ,
 "name": 1 } ,
 { bucketSize: 2 } )
```

这将在每个文档周围的纬度或经度`2`单位内创建文档的存储桶。

在这里，使用前面的`location`示例：

```sql
location : { type: "Point", coordinates: [ 51.5876, 0.1643 ] }
```

基于`bucketSize: 2`，每个具有`location` `[49.5876..53.5876, -2.1643..2.1643]`的文档将属于与我们的位置相同的存储桶。

一个文档可以出现在多个存储桶中。如果我们想使用球面几何，`2dsphere`是一个更好的解决方案。`geoHaystack`索引默认是稀疏的。

如果我们需要计算最接近我们位置的文档，而它超出了我们的`bucketSize`（即，在我们的示例中大于 2 个纬度/经度单位），查询将是低效的，可能不准确。对于这样的查询，请使用`2dsphere`索引。

# 构建和管理索引

索引可以使用 MongoDB shell 或任何可用的驱动程序构建。默认情况下，索引是在前台构建的，会阻塞数据库中的所有其他操作。这样更快，但通常是不可取的，特别是在生产实例中。

我们还可以通过在 shell 中的索引命令中添加`{background: true}`参数来在后台构建索引。后台索引只会阻塞当前连接/线程。我们可以打开一个新连接（即在命令行中使用`mongo`）连接到同一个数据库：

```sql
> db.books.createIndex( { name: 1 }, { background: true } )
```

后台索引构建可能比前台索引构建需要更长的时间，特别是如果索引无法适应可用的 RAM。

尽早创建索引，并定期重新审视索引以进行合并。查询不会看到部分索引结果。只有在索引完全创建后，查询才会开始从索引中获取结果。

不要使用主要应用程序代码来创建索引，因为这可能会导致不可预测的延迟。相反，从应用程序获取索引列表，并在维护窗口期间标记这些索引进行创建。

# 强制使用索引

我们可以通过应用`hint()`参数来强制 MongoDB 使用索引：

```sql
> db.books.createIndex( { isbn: 1 }, { background: true } )
{
"createdCollectionAutomatically" : false,
"numIndexesBefore" : 8,
"numIndexesAfter" : 9,
"ok" : 1
}
```

`createIndex`的输出通知我们索引已创建（`"ok" : 1`），索引创建过程中没有自动创建集合（`"createdCollectionAutomatically" : false`），在此索引创建之前，该集合中的索引数量为`8`，现在总共有九个索引。

现在，如果我们尝试通过`isbn`搜索书籍，我们可以使用`explain()`命令来查看`winningPlan`子文档，从中我们可以找到使用的查询计划：

```sql
> db.books.find({isbn: "1001"}).explain()
…
"winningPlan" : {
"stage" : "FETCH",
"inputStage" : {
"stage" : "IXSCAN",
"keyPattern" : {
"isbn" : 1,
"name" : 1
},
"indexName" : "isbn_1_name_1",
...
```

这意味着使用了具有`isbn`为`1`和`name`为`1`的索引，而不是我们新创建的索引。我们还可以在输出的`rejectedPlans`子文档中查看我们的索引，如下所示：

```sql
…
"rejectedPlans" : [
{
"stage" : "FETCH",
"inputStage" : {
"stage" : "IXSCAN",
"keyPattern" : {
"isbn" : 1
},
"indexName" : "isbn_1",
...
```

事实上，这是正确的，因为 MongoDB 正在尝试重用比通用索引更具体的索引。

在我们的`isbn_1`索引表现比`isbn_1_name_1`更好的情况下，我们可能不确定。

我们可以强制 MongoDB 使用我们新创建的索引，如下所示：

```sql
> db.books.find({isbn: "1001"}).hint("international_standard_book_number_index")
.explain()
{
...
 "winningPlan" : {
 "stage" : "FETCH",
 "inputStage" : {
 "stage" : "IXSCAN",
 "keyPattern" : {
 "isbn" : 1
 },
...
```

现在，`winningPlan`子文档包含我们的索引`isbn_1`，并且没有`rejectedPlans`元素。结果集中是一个空数组。

我们不能在特殊类型的文本索引上使用`hint()`。

# 提示和稀疏索引

根据设计，稀疏索引不包括索引中的某些文档，根据字段的存在/缺失。可能包含不在索引中的文档的查询将不使用稀疏索引。

使用稀疏索引的`hint()`可能导致不正确的计数，因为它强制 MongoDB 使用可能不包含我们想要的所有结果的索引。

旧版本的`2dsphere`、`2d`、`geoHaystack`和文本索引默认是稀疏的。应谨慎使用`hint()`，并在仔细考虑其影响后使用。

# 在副本集上构建索引

在副本集中，如果我们发出`createIndex()`命令，主服务器完成创建后，次要服务器将开始创建索引。同样，在分片环境中，主服务器将开始构建索引，而分片的每个次要服务器将在主服务器完成后开始。

在副本集中构建索引的推荐方法如下：

+   停止副本集中的一个次要节点

+   在不同端口上重新启动为独立服务器

+   在 shell 中构建独立索引

+   重启副本集中的次要节点

+   允许次要节点赶上主节点

我们需要在主服务器中有足够大的 oplog 大小，以确保辅助服务器在重新连接后能够追赶上来。oplog 大小在配置中以 MB 定义，它定义了主服务器中日志中将保留多少个操作。如果 oplog 大小只能容纳主服务器中发生的最后 100 个操作，而发生了 101 个或更多的操作，这意味着辅助服务器将无法与主服务器同步。这是主服务器没有足够的内存来跟踪其操作并通知辅助服务器的后果。在副本集中构建索引是一个手动过程，涉及每个主服务器和辅助服务器的几个步骤。

这种方法可以在副本集中的每个辅助服务器上重复。然后，对于主服务器，我们可以执行以下操作之一：

+   在后台构建索引

+   使用`rs.stepDown()`将主服务器降级，然后使用服务器作为辅助服务器重复前面的过程

使用第二种方法时，当主服务器降级时，我们的集群将在一段时间内不接受任何写入。我们的应用程序在此期间不应该超时（通常不到 30-60 秒）。

在主服务器后台构建索引也会在辅助服务器上后台构建。这可能会影响索引创建期间我们服务器的写入，但好处是没有手动步骤。在生产环境中建立一个与生产环境相似的临时环境，并在其中运行影响实时集群的操作，以避免意外。

# 管理索引

在本节中，您将学习如何为您的索引指定人性化的名称，以及一些特殊的考虑和限制，我们必须牢记索引。

# 命名索引

默认情况下，索引名称是根据字段索引和索引方向（`1`，`-1`）自动分配的。如果我们想在创建时分配自己的`name`，我们可以这样做：

```sql
> db.books.createIndex( { isbn: 1 }, { name: "international_standard_book_number_index" } )
```

现在，我们有一个名为`international_standard_book_number_index`的新索引，而不是 MongoDB 将会命名的(`"isbn_1"`)。

我们可以使用`db.books.getIndexes()`来查看我们的`books`集合中的所有索引。完全限定的索引名称必须少于或等于 128 个字符。这也包括`database_name`，`collection_name`和它们之间的点。

# 特殊考虑

以下是一些关于索引的限制需要牢记：

+   索引条目必须少于 1,024 字节。这主要是一个内部考虑，但如果我们在索引方面遇到问题，我们可以牢记这一点。

+   一个集合最多可以有 64 个索引。

+   复合索引最多可以有 31 个字段。

+   特殊索引不能在查询中组合使用。这包括必须使用特殊索引的特殊查询操作符，例如文本索引的`$text`和地理空间索引的`$near`。这是因为 MongoDB 可以使用多个索引来满足查询，但并非在所有情况下都可以。关于这个问题将在*索引交集*部分有更多内容。

+   多键和地理空间索引无法覆盖查询。这意味着仅仅使用索引数据将不足以满足查询，MongoDB 需要处理底层文档才能获取完整的结果集。

+   索引对字段有唯一约束。我们不能在相同的字段上创建多个索引，只是选项不同。这是稀疏和部分索引的限制，因为我们不能创建多个这些索引的变体，这些变体只在过滤查询上有所不同。

# 高效使用索引

创建索引是一个不应轻率对待的决定。尽管通过 shell 创建索引很容易，但如果我们最终拥有太多或效率不高的索引，它可能会在后续出现问题。在本节中，您将学习如何测量现有索引的性能，一些改进性能的技巧，以及如何合并索引数量，以便拥有性能更好的索引。

# 测量性能

学习如何使用`explain()`命令将有助于您优化和理解索引的性能。当与查询一起使用时，`explain()`命令将返回 MongoDB 为此查询使用的查询计划，而不是实际结果。

通过在查询末尾链接它来调用它，如下所示：

```sql
> db.books.find().explain()
```

它可以有三个选项：`queryPlanner`（默认值），`executionStats`和`allPlansExecution`。

让我们使用最详细的输出，`allPlansExecution`：

```sql
> db.books.find().explain("allPlansExecution")
```

在这里，我们可以获取获胜查询计划的信息，以及在规划阶段考虑过但被拒绝的查询计划的部分信息，因为查询规划程序认为它们更慢。`explain()`命令无论如何都会返回相当冗长的输出，允许深入了解查询计划如何工作以返回我们的结果。

乍一看，我们需要关注应该使用的索引是否被使用，以及扫描的文档数量是否尽可能与返回的文档数量匹配。

对于第一个，我们可以检查`stage`字段并查找`IXSCAN`，这意味着使用了索引。然后，在兄弟`indexName`字段中，我们应该看到我们期望的索引名称。

对于第二个，我们需要比较`keysExamined`和`nReturned`字段。理想情况下，我们希望我们的索引在查询方面尽可能具有选择性，这意味着为了返回 100 个文档，这些将是我们的索引检查的 100 个文档。

当然，这是一个权衡，因为索引在我们的集合中数量和大小增加。我们每个集合可以有限数量的索引，而且我们的 RAM 可以容纳这些索引的数量是有限的，因此我们必须在拥有最佳可用索引和这些索引不适合我们的内存并变慢之间取得平衡。

# 提高性能

一旦我们开始熟悉测量用户最常见和重要查询的性能，我们就可以开始尝试改进它们。

总体思路是，当我们期望（或已经有）重复查询开始运行缓慢时，我们需要索引。索引并非免费，因为它们在创建和维护时会带来性能损失，但对于频繁查询来说，它们是非常值得的，并且可以减少数据库中的锁定百分比，如果设计正确的话。

回顾上一节的建议，我们希望我们的索引能够做到以下几点：

+   适应 RAM

+   确保选择性

+   用于对查询结果进行排序

+   用于我们最常见和重要的查询

通过在我们的集合中使用`getIndexes()`并确保我们不会通过检查系统级可用 RAM 和是否使用交换来创建大型索引来确保适应 RAM。

如前所述，通过比较每个查询的`IXSCAN`阶段中的`nReturned`和`keysExamined`来确保选择性。我们希望这两个数字尽可能接近。

确保我们的索引用于对查询结果进行排序是使用复合索引（将作为整体使用，也用于任何基于前缀的查询）并声明我们的索引方向与我们最常见的查询一致的组合。

最后，将索引与我们的查询对齐是应用使用模式的问题，这可以揭示大部分时间使用的查询，然后通过在这些查询上使用`explain()`来识别每次使用的查询计划。

# 索引交集

索引交集是指使用多个索引来满足查询的概念。这是最近添加的功能，还不完美；然而我们可以利用它来 consolodate 我们的索引。

我们可以通过在查询上使用`explain()`并在执行的查询计划中观察`AND_SORTED`或`AND_HASH`阶段来验证查询中是否发生了索引交集。

索引交集可能发生在我们使用`OR`(`$or`)查询时，通过为每个`OR`子句使用不同的索引。索引交集可能发生在我们使用`AND`查询时，我们对每个`AND`子句都有完整的索引或者对一些（或全部）子句有索引前缀。

例如，考虑对我们的`books`集合的查询如下：

```sql
> db.books.find({ "isbn":"101", "price": { $gt: 20 }})
```

在这里，使用两个索引（一个在`isbn`上，另一个在`price`上），MongoDB 可以使用每个索引来获取相关结果，然后在索引结果上进行交集运算以获取结果集。

使用复合索引，正如您在本章中之前学到的，我们可以使用索引前缀来支持包含复合索引的前 *1…n-1* 个字段的查询。

我们无法通过复合索引支持寻找复合索引中字段的查询，其中一个或多个之前定义的字段缺失。

复合索引中的顺序很重要。

为了满足这些查询，我们可以在各个字段上创建索引，然后使用索引交集来满足我们的需求。这种方法的缺点是，随着字段数（*n*）的增加，我们需要创建的索引数量呈指数增长，因此增加了我们对存储和内存的需求。

索引交集不适用于`sort()`。我们不能使用一个索引来查询，然后使用不同的索引对结果应用`sort()`。

然而，如果我们有一个索引可以满足查询的一部分和`sort()`字段，那么这个索引将被使用。

# 进一步阅读

您可以参考以下链接以获取更多信息：

+   [`bigocheatsheet.com/`](http://bigocheatsheet.com/)

+   [`commons.wikimedia.org/`](https://commons.wikimedia.org/)

+   [`docs.mongodb.com/manual/core/index-intersection/`](https://docs.mongodb.com/manual/core/index-intersection/)

# 总结

在本章中，您了解了索引和索引内部的基础知识。然后我们探讨了如何使用 MongoDB 中可用的不同索引类型，如单字段、复合和多键索引，以及一些特殊类型，如文本、哈希、TTL、部分、解析、唯一、不区分大小写和地理空间。

在本章的下一部分，您将学习如何使用 shell 构建和管理索引，这是管理和数据库管理的基本部分，即使对于 NoSQL 数据库也是如此。最后，我们讨论了如何在高层次上改进我们的索引，以及我们如何在实践中使用索引交集，以便 consolodate 索引数量。

在下一章中，我们将讨论如何监视我们的 MongoDB 集群并保持一致的备份。您还将学习如何处理 MongoDB 中的安全性。


# 第三部分：管理和数据管理

在本节中，我们将介绍操作概念以及 MongoDB 与数据处理生态系统的交互。我们将首先学习 MongoDB 如何处理监控、备份和安全性，然后概述 MongoDB 中可用的不同存储引擎。在 MongoDB 工具章节中，我们将了解所有工具，包括 Stitch 和 Atlas，我们可以用来与 MongoDB 交互，然后是一个涵盖如何使用 MongoDB 处理大数据的用例章节。

本节包括以下章节：

+   第八章，监控、备份和安全性

+   第九章，存储引擎

+   第十章，MongoDB 工具

+   第十一章，利用 MongoDB 处理大数据


# 第八章：监控、备份和安全性

监控、备份和安全性不应该是事后才考虑的，而是在将 MongoDB 部署到生产环境之前必须进行的过程。此外，监控可以（并且应该）用于在开发阶段排除故障和提高性能。

在本章中，我们将讨论 MongoDB 的运营方面。本章将涵盖制定正确和一致的备份策略以及确保我们的备份策略在需要备份时能够正常工作的内容。最后，我们将讨论 MongoDB 的安全性，包括身份验证、授权、网络级安全性以及如何审计我们的安全设计。

本章将重点关注以下三个领域：

+   监控

+   备份

+   安全

# 监控

当我们设计软件系统时，我们进行了许多明确和隐含的假设。我们总是试图根据我们的知识做出最佳决策，但可能有一些参数我们低估了或没有考虑到。

通过监控，我们可以验证我们的假设，并验证我们的应用程序是否按预期执行并扩展。良好的监控系统对于检测软件错误和帮助我们及早发现潜在的安全事件也至关重要。

# 我们应该监控什么？

迄今为止，在 MongoDB 中监视的最重要的指标是内存使用情况。MongoDB（以及每个数据库系统）广泛使用系统内存来提高性能。无论我们使用 MMAPv1 还是 WiredTiger 存储引擎，使用的内存都是我们应该关注的第一件事。

了解计算机内存的工作原理可以帮助我们评估监控系统的指标。这些是与计算机内存相关的最重要的概念。

# 页面错误

RAM 速度快，但价格昂贵。硬盘驱动器或固态硬盘相对便宜，速度较慢，并且在系统和电源故障的情况下为我们的数据提供耐用性。我们所有的数据都存储在磁盘上，当我们执行查询时，MongoDB 将尝试从内存中获取数据。如果数据不在内存中，它将从磁盘中获取数据并将其复制到内存中。这是一个**页面错误事件**，因为内存中的数据是以页面形式组织的。

随着页面错误的发生，内存被填满，最终，一些页面需要被清除以便将最新的数据放入内存。这被称为**页面驱逐事件**。除非我们有一个非常静态的数据集，否则我们无法完全避免页面错误，但我们确实希望尽量减少页面错误。这可以通过将我们的工作集保留在内存中来实现。

# 常驻内存

**常驻内存**大小是 MongoDB 在 RAM 中拥有的总内存量。这是要监视的基本指标，应该小于可用内存的 80%。

# 虚拟和映射内存

当 MongoDB 请求内存地址时，操作系统将返回一个虚拟地址。这可能是 RAM 中的实际地址，也可能不是，这取决于数据所在的位置。MongoDB 将使用这个虚拟地址来请求底层数据。当我们启用日志记录（几乎总是应该启用），MongoDB 将为日志记录的数据保留另一个地址。虚拟内存指的是 MongoDB 请求的所有数据的大小，包括日志记录。

映射内存不包括日志记录引用。

所有这些意味着，随着时间的推移，我们的映射内存将大致等于我们的工作集，而虚拟内存将大约是我们映射内存的两倍。

# 工作集

工作集是 MongoDB 使用的数据大小。在事务性数据库的情况下，这将成为 MongoDB 持有的数据大小，但也可能存在一些集合根本没有被使用，不会对我们的工作集产生影响。

# 监控 WiredTiger 中的内存使用情况

理解 MMAPv1 中的内存使用相对比较简单。MMAPv1 在底层使用`mmap()`系统调用来将内存页的责任传递给底层操作系统。这就是为什么当我们使用 MMAPv1 时，内存使用量会不受限制地增长，因为操作系统试图尽可能多地将我们的数据集放入内存中。

另一方面，使用 WiredTiger，我们可以在启动时定义内部缓存的内存使用情况。默认情况下，内部缓存最多占用我们 RAM 的一半，即 1GB 或 256MB 之间。

除了内部缓存之外，MongoDB 还可以为其他操作分配内存，比如维护连接和数据处理（内存排序，MapReduce，聚合等）。

MongoDB 进程也会使用底层操作系统的文件系统缓存，就像在 MMAPv1 中一样。文件系统缓存中的数据是压缩的。

我们可以通过 mongo shell 查看 WiredTiger 缓存的设置，如下所示：

```sql
> db.serverStatus().wiredTiger.cache
```

我们可以使用`storage.wiredTiger.engineConfig.cacheSizeGB`参数来调整其大小。

一般的建议是将 WiredTiger 内部缓存大小保持默认。如果我们的数据具有较高的压缩比，可能值得将内部缓存大小减少 10%至 20%，以释放更多内存用于文件系统缓存。

# 跟踪页面错误

页面错误的数量可以保持相对稳定，不会对性能产生显著影响。然而，一旦页面错误数量达到一定阈值，我们的系统将迅速严重地受到影响。对于 HDD 来说更加明显，但对**固态硬盘**（SSD）也有影响。

确保我们不会遇到页面错误的方法是始终拥有一个与我们生产环境设置相同的临时环境。这个环境可以用来压力测试我们的系统可以处理多少页面错误，而不会降低性能。通过比较我们生产系统中实际的页面错误数量和从临时系统计算出的最大页面错误数量，我们可以找出我们还剩下多少余地。

查看页面错误的另一种方法是通过 shell，查看`serverStatus`输出的`extra_info`字段：

```sql
> db.adminCommand({"serverStatus" : 1})['extra_info']
{ "note" : "fields vary by platform", "page_faults" : 3465 }
```

正如`note`所述，这些字段可能不会出现在每个平台上。

# 跟踪 B 树未命中

正如您在前一章中看到的，适当的索引是保持 MongoDB 响应和高性能的最佳方法。B 树未命中指的是当我们尝试访问 B 树索引时发生的页面错误。索引通常被频繁使用，与我们的工作集和可用内存相比相对较小，因此它们应该始终在内存中。

如果 B 树未命中的数量或 B 树命中比例增加，或者 B 树未命中的数量减少，这表明我们的索引已经增长或者设计不够优化。B 树未命中也可以通过 MongoDB Cloud Manager 或 shell 进行监控。

在 shell 中，我们可以使用集合统计来定位它。

# I/O 等待

**I/O 等待**指的是操作系统等待 I/O 操作完成的时间。它与页面错误有很强的正相关性。如果我们看到 I/O 等待随时间增加，这是页面错误即将发生的强烈迹象。我们应该努力保持 I/O 等待在健康的操作集群中低于 60%至 70%。设定这样的阈值将为我们争取一些时间，以便在突然增加的负载情况下进行升级。

# 读写队列

查看 I/O 等待和页面错误的另一种方法是通过读写队列。当出现页面错误和 I/O 等待时，请求将不可避免地开始排队进行读取或写入。队列是效果，而不是根本原因，所以当队列开始积累时，我们知道我们有问题要解决。

# 锁定百分比

这在较早版本的 MongoDB 中更为常见，在使用 WiredTiger 存储引擎时则不太常见。**锁定百分比**显示了数据库被锁定等待使用独占锁的操作释放的时间百分比。通常应该很低：最多为 10%至 20%。超过 50%意味着有问题。

# 后台刷新

默认情况下，MongoDB 每分钟将数据刷新到磁盘。**后台刷新**指的是数据持久化到磁盘所需的时间。对于每 1 分钟的时间段，它不应超过 1 秒。

修改刷新间隔可能有助于后台刷新时间；通过更频繁地写入磁盘，将减少需要写入的数据。在某些情况下，这可能会加快写入速度。

后台刷新时间受写入负载影响的事实意味着，如果我们的后台刷新时间开始变得过长，我们应该考虑对数据库进行分片，以增加写入容量。

# 跟踪空闲空间

使用 MMAPv1（使用 WiredTiger 时较少）时的常见问题是空闲磁盘空间。与内存一样，我们需要跟踪磁盘空间的使用情况，并且要有预见性，而不是被动应对。要保持监控磁盘空间的使用情况，并在达到 40%、60%或 80%时发出适当的警报，特别是对于快速增长的数据集。

磁盘空间问题通常是管理员、DevOps 和开发人员头疼的问题，因为移动数据需要花费时间。

`directoryperdb`选项可以帮助确定数据大小，因为我们可以将存储分割成不同的物理挂载磁盘。

# 监控复制

副本集使用**操作日志**（**oplog**）来保持同步状态。每个操作都会应用在主服务器上，然后写入主服务器的操作日志中，这是一个有上限的集合。辅助服务器会异步读取此操作日志，并逐个应用这些操作。

如果主服务器负载过重，那么辅助服务器将无法快速读取和应用操作，从而产生复制延迟。**复制延迟**是指主服务器上应用的最后一个操作与辅助服务器上应用的最后一个操作之间的时间差，存储在操作日志的有上限的集合中。

例如，如果时间是下午 4:30:00，而辅助服务器刚刚应用了在我们的主服务器上下午 4:25:00 应用的操作，这意味着辅助服务器落后于我们的主服务器五分钟。

在我们的生产集群中，复制延迟应该接近（或等于）零。

# 操作日志大小

副本集中的每个成员都会在`db.oplog.rs()`中有一个操作日志的副本。原因是，如果主服务器下线，其中一个辅助服务器将被选举，并且它需要有最新版本的操作日志，以便新的辅助服务器进行跟踪。

操作日志大小是可配置的，我们应该尽可能设置得更大。操作日志大小不会影响内存使用情况，并且在操作问题的情况下可能会使数据库出现问题。

原因是，如果复制延迟随时间增加，最终会导致辅助服务器落后到无法从主服务器的操作日志中读取的地步，因为主服务器的操作日志中最旧的条目将晚于在辅助服务器上应用的最新条目。

一般来说，操作日志应至少包含一到两天的操作。出于之前详细说明的同样原因，操作日志应比初始同步所需的时间更长。

# 工作集计算

工作集是我们内存需求的最强指标。理想情况下，我们希望整个数据集都在内存中，但大多数情况下，这是不可行的。下一个最好的选择是将我们的工作集放在内存中。工作集可以直接或间接地计算出来。

直接地，我们可以从 shell 中调用`serverStatus`中的`workingSet`标志，如下所示：

```sql
> db.adminCommand({"serverStatus" : 1, "workingSet" : 1})
```

不幸的是，这在 3.0 版本中被移除，因此我们将专注于计算工作集的间接方法。

间接地，我们的工作集是我们需要满足 95%或更多用户请求的数据大小。为了计算这一点，我们需要从日志中识别用户发出的查询以及他们使用的数据集。为了满足索引内存需求，我们可以将其增加 30%到 50%，从而得出工作集的计算。

另一种间接估计工作大小的方法是通过页面错误的数量。如果我们没有页面错误，那么我们的工作集适合内存。通过反复试验，我们可以估计页面错误开始发生的点，并了解我们的系统可以处理多大负载。

如果我们不能将工作集放入内存中，那么我们至少应该有足够的内存，使索引可以放入内存中。在上一章中，我们描述了如何计算索引内存需求，以及如何使用这个计算来相应地调整我们的 RAM 大小。

# 监控工具

有几种监控选项。在本节中，我们将讨论如何使用 MongoDB 自己的工具或第三方工具进行监控。

# 托管工具

MongoDB, Inc.自己的工具 MongoDB Cloud Manager（以前称为 MongoDB Monitoring Service）是一个强大的工具，用于监控之前描述的所有指标。MongoDB Cloud Manager 有一个有限的免费套餐和一个 30 天的试用期。

使用 MongoDB Cloud Manager 的另一个选择是通过 MongoDB Atlas，MongoDB, Inc.的 DBaaS 产品。这也有一个有限的免费套餐，并且在三个主要的云提供商（亚马逊、谷歌和微软）中都可用。

# 开源工具

所有主要的开源工具，如**Nagios**，**Munin**，**Cacti**等，都为 MongoDB 提供了插件支持。虽然这超出了本书的范围，但运维和 DevOps 应该熟悉之前描述的设置和理解指标，以有效地解决 MongoDB 的故障并在问题变得严重之前预先解决问题。

在 mongo shell 中，`mongotop`和`mongostat`命令和脚本也可以用于临时监控。然而，这种手动过程的一个风险是脚本的任何失败可能会危及我们的数据库。如果有为您的监控需求而知名且经过测试的工具，请避免编写自己的工具。

# 备份

一句来自著名格言的引语如下：

“抱最好的希望，为最坏的打算。”

- 约翰·杰伊（1813 年）

这应该是我们设计 MongoDB 备份策略时的方法。有几种不同的故障事件可能发生。

备份应该是我们灾难恢复策略的基石，以防发生意外。一些开发人员可能依赖于复制进行灾难恢复，因为似乎有三份数据已经足够。如果其中一份数据丢失，我们可以从其他两份数据重新构建集群。

这在磁盘故障事件中是适用的。磁盘故障是生产集群中最常见的故障之一，一旦磁盘开始接近其**平均故障时间**（**MTBF**）时间，故障就会发生。

然而，这并不是唯一可能发生的故障事件。安全事件或纯粹的人为错误同样可能发生，并且应该成为我们计划的一部分。一旦所有副本集成员同时丢失，如火灾、洪水、地震或不满的员工，这些事件不应导致生产数据丢失。

一个有用的临时选择，处于复制和实施适当备份之间的中间地带，可能是设置一个延迟的副本集成员。这个成员可以滞后于主服务器几个小时或几天，这样就不会受到主服务器中恶意更改的影响。需要注意的重要细节是，操作日志需要配置成可以保持几个小时的延迟。此外，这个解决方案只是一个临时解决方案，因为它没有考虑到我们需要灾难恢复的全部原因，但肯定可以帮助解决其中的一部分。

这被称为**灾难恢复**。灾难恢复是一类需要定期进行备份的故障，而且还需要使用一个过程来将它们（无论是地理上还是访问规则上）与我们的生产数据隔离开。

# 备份选项

根据我们的部署策略，我们可以选择不同的备份选项。

# 基于云的解决方案

如果我们使用云 DBaaS 解决方案，最直接的解决方案就是在 MongoDB 的例子中，我们可以通过 GUI 管理备份。

如果我们在自己的服务器上托管 MongoDB，我们可以使用 MongoDB, Inc.的 MongoDB Cloud Manager。Cloud Manager 是一个 SaaS，我们可以将其指向我们自己的服务器来监视和备份我们的数据。它使用与复制相同的操作日志，并且可以备份副本集和分片集群。

如果我们不想（或者出于安全原因不能）将我们的服务器指向外部的 SaaS 服务，我们可以在本地使用 MongoDB Cloud Manager 的功能，使用 MongoDB Ops Manager。要获得 MongoDB Ops Manager，我们需要为我们的集群订阅 MongoDB 企业高级版。

# 文件系统快照备份

过去最常见的备份方法，也是目前广泛使用的方法，依赖于底层文件系统的时间点快照功能来备份我们的数据。

EBS on EC2 和 Linux 上的**逻辑卷管理器**（**LVM**）支持时间点快照。

如果我们使用最新版本的 MongoDB 和 WiredTiger，我们可以进行卷级备份，即使我们的数据和日志文件存储在不同的卷中。

我们可以按照以下步骤备份副本集：

+   要备份副本集，我们需要为我们的数据库保持一致的状态。这意味着我们的所有写操作要么已经提交到磁盘，要么在我们的日志文件中。

+   如果我们使用 WiredTiger 存储，我们的快照将与最新的检查点一致，这要么是 2GB 的数据，要么是最后一分钟的备份。

确保将快照存储在离线卷中，以备灾难恢复之需。您需要启用日志记录以使用时间点快照。无论如何，启用日志记录都是一个好的做法。

# 备份分片集群

如果我们想备份整个分片集群，我们需要在开始之前停止平衡器。原因是，如果在我们拍摄快照时有不同分片之间的数据块迁移，我们的数据库将处于不一致状态，拥有在我们拍摄快照时正在传输的不完整或重复的数据块。

整个分片集群的备份将是近似时间的。如果我们需要时间点精度，我们需要停止数据库中的所有写操作，这通常对于生产系统来说是不可能的。

首先，我们需要通过 mongo shell 连接到我们的 mongos 来禁用平衡器：

```sql
> use config
> sh.stopBalancer()
```

然后，如果我们的辅助服务器没有启用日志记录，或者如果我们的日志和数据文件存储在不同的卷中，我们需要锁定所有分片和配置服务器副本集的辅助 mongo 实例。

我们还需要在这些服务器上设置足够的操作日志大小，以便它们可以在我们解锁它们后赶上主服务器；否则，我们将需要从头开始重新同步它们。

假设我们不需要锁定我们的辅助副本，下一步是备份配置服务器。在 Linux（使用 LVM），这类似于执行以下操作：

```sql
$ lvcreate --size 100M --snapshot --name snap-14082017 /dev/vg0/mongodb
```

然后，我们需要为每个分片中每个副本集的单个成员重复相同的过程。

最后，我们需要使用相同的 mongo shell 重新启动平衡器，该 shell 用于停止它：

```sql
> sh.setBalancerState(true)
```

不详细介绍，显而易见的是，备份分片集是一个复杂且耗时的过程。它需要事先规划和广泛测试，以确保它不仅可以在最小干扰下工作，而且我们的备份可用且可以恢复到我们的集群中。

# 使用 mongodump 进行备份

`mongodump`工具是一个可以备份我们 MongoDB 集群中数据的命令行工具。因此，缺点是在恢复时需要重新创建所有索引，这可能是一个耗时的操作。

`mongodump`工具的主要缺点是，为了将数据写入磁盘，它需要首先将数据从内部 MongoDB 存储器带到内存中。这意味着在承受压力运行的生产集群中，`mongodump`将使内存中的数据无效，从而使工作集中的数据与常规操作下不会驻留在内存中的数据相混合。这会降低我们集群的性能。

另一方面，当我们使用`mongodump`时，我们可以继续在我们的集群中进行写入，并且如果我们有一个副本集，我们可以使用`--oplog`选项将`mongodump`操作期间发生的条目包括在其输出 oplog 中。

如果我们选择这个选项，我们需要在使用`mongorestore`工具将数据恢复到 MongoDB 集群时使用`--oplogReplay`。

`mongodump`是单服务器部署的好工具，但一旦我们扩大规模，我们应该考虑使用不同（并且更好计划的）方法来备份我们的数据。

# 通过复制原始文件进行备份

如果我们不想使用前面概述的任何选项，我们的最后选择是使用`cp`/`rsync`或类似的东西复制原始文件。一般来说，这是不推荐的，原因如下：

+   在复制文件之前，我们需要停止所有写入操作

+   备份大小将更大，因为我们需要复制索引和任何底层填充和碎片化存储开销。

+   我们无法通过这种方法为副本集实现恢复到特定时间点，并且以一种一致且可预测的方式从分片集群中复制数据是非常困难的

除非真的没有其他选择，否则应避免通过复制原始文件进行备份。

# 使用排队进行备份

实际上使用的另一种策略是利用排队系统，拦截我们的数据库和前端软件系统。在我们的数据库中插入/更新/删除之前使用类似 ActiveMQ 队列的东西意味着我们可以安全地将数据发送到不同的接收端，这些接收端可以是 MongoDB 服务器或独立存储库中的日志文件。像延迟副本集方法一样，这种方法对于一类备份问题可能有用，但对于其他一些问题可能会失败。

这是一个有用的临时解决方案，但不应作为永久解决方案。

# EC2 备份和恢复

MongoDB Cloud Manager 可以自动从 EC2 卷中进行备份；而且，由于我们的数据在云中，为什么不使用 Cloud Manager 呢？

如果由于某种原因我们无法使用它，我们可以编写一个脚本来通过实施以下步骤进行备份：

1.  假设我们已经启用了日志记录（我们确实应该这样做），并且我们已经将包含数据和日志文件的`dbpath`映射到单个 EBS 卷上，我们首先需要使用`ec2-describe-instances`找到与运行实例相关联的 EBS 块实例。

1.  下一步是使用`lvdisplay`找到我们的 MongoDB 数据库的`dbpath`映射到的逻辑卷。

1.  一旦我们从逻辑卷中确定了逻辑设备，我们可以使用`ec2-create-snapshot`来创建新的快照。我们需要包括每一个映射到我们的`dbpath`目录的逻辑设备。

为了验证我们的备份是否有效，我们需要基于快照创建新卷并将新卷挂载在那里。最后，`mongod`进程应该能够开始挂载新数据，并且我们应该使用 MongoDB 进行连接以验证这些内容。

# 增量备份

每次进行完整备份对于一些部署来说可能是可行的，但是当大小达到一定阈值时，完整备份会花费太多时间和空间。

在这一点上，我们会想要偶尔进行完整备份（例如每月一次），并在此期间进行增量备份（例如每晚）。

Ops Manager 和 Cloud Manager 都支持增量备份，如果我们达到这个规模，使用工具进行备份可能是一个好主意，而不是自己开发。

如果我们不想（或不能）使用这些工具，我们可以通过 oplog 进行恢复，如下所示：

1.  使用之前描述的任何方法进行完整备份

1.  锁定我们副本集的辅助服务器的写入

1.  注意 oplog 中的最新条目

1.  在 oplog 中的最新条目之后导出条目：

```sql
> mongodump --host <secondary> -d local -c oplog.rs -o /mnt/mongo-oldway_backup
 --query '{ "ts" : { $gt :  Timestamp(1467999203, 391) } }'
```

1.  在辅助服务器上解锁写入

要恢复，我们可以使用刚刚导出的`oplog.rs`文件，并使用`mongorestore`选项`--oplogReplay`：

```sql
> mongorestore -h <primary> --port <port> --oplogReplay <data_file_position>
```

这种方法需要锁定写入，并且在将来的版本中可能无法使用。

更好的解决方案是使用**逻辑卷管理（LVM）**文件系统进行增量备份，但这取决于底层的 LVM 实现，我们可能无法进行调整。

# 安全性

安全性是 MongoDB 集群中的一个多方面目标。在本章的其余部分，我们将研究不同的攻击向量以及我们如何保护自己免受攻击。除了这些最佳实践之外，开发人员和管理员必须始终使用常识，以便安全性只在操作目标所需的程度上干扰。

# 认证

**认证**是指验证客户端的身份。这可以防止冒充他人以获取其数据的行为。

最简单的认证方式是使用`username`和`password`对。可以通过两种方式之一在 shell 中完成，第一种方式如下：

```sql
> db.auth( <username>, <password> )
```

传递逗号分隔的`username`和`password`将假定其余字段的默认值：

```sql
> db.auth( {
 user: <username>,
 pwd: <password>,
 mechanism: <authentication mechanism>,
 digestPassword: <boolean>
} )
```

如果我们传递一个文档对象，我们可以定义比`username`/`password`更多的参数。

（认证）`mechanism`参数可以采用几种不同的值，默认值为`SCRAM-SHA-1`。参数值`MONGODB-CR`用于与 3.0 之前的版本向后兼容。

MONGODB-x.509 用于 TLS/SSL 认证。用户和内部副本集服务器可以通过使用 SSL 证书进行认证，这些证书可以是自动生成和签名的，也可以来自受信任的第三方机构。

要为副本集成员的内部认证配置 x.509，我们需要提供以下参数之一。

以下是配置文件的内容：

```sql
security.clusterAuthMode / net.ssl.clusterFile
```

以下是在命令行上使用的：

```sql
--clusterAuthMode and --sslClusterFile
> mongod --replSet <name> --sslMode requireSSL --clusterAuthMode x509 --sslClusterFile <path to membership certificate and key PEM file> --sslPEMKeyFile <path to SSL certificate and key PEM file> --sslCAFile <path to root CA PEM file>
```

MongoDB 企业版是 MongoDB，Inc.提供的付费产品，增加了两个认证选项，如下所示：

+   第一个添加的选项是**通用安全服务应用程序接口**（**GSSAPI**）Kerberos。Kerberos 是一个成熟和强大的认证系统，可用于基于 Windows 的 Active Directory 部署等场景。

+   第二个添加的选项是 PLAIN（LDAP SASL）。LDAP 就像 Kerberos 一样：是一种成熟和健壮的身份验证机制。使用 PLAIN 身份验证机制时的主要考虑因素是凭据以明文形式在网络上传输。这意味着我们应该通过 VPN 或 TSL/SSL 连接来保护客户端和服务器之间的路径，以避免中间人窃取我们的凭据。

# 授权

在我们配置了身份验证以验证用户在连接到我们的 MongoDB 服务器时是否是他们声称的身份后，我们需要配置每个用户在我们数据库中拥有的权限。

这是权限的**授权**方面。MongoDB 使用基于角色的访问控制来控制不同用户类别的权限。

每个角色都有权限在资源上执行一些操作。

资源可以是一个集合/多个集合或一个数据库/多个数据库。

命令的格式如下：

```sql
{ db: <database>, collection: <collection> }
```

如果我们为`db`或`collection`指定了`""`（空字符串），这意味着任何`db`或`collection`。例如：

```sql
{ db: "mongo_books", collection: "" }
```

这将应用我们的操作到`mongo_books`数据库中的每个`collection`。

如果数据库不是`admin`数据库，则不会包括系统集合。系统集合，如`<db>.system.profile`，`<db>.system.js`，`admin.system.users`和`admin.system.roles`，需要明确定义。

与前面的选项类似，我们可以定义以下内容：

```sql
{ db: "", collection: "" }
```

我们定义这个规则，将其应用到所有数据库的所有集合，当然除了系统集合。

我们还可以应用规则到整个集群，如下：

```sql
{ resource: { cluster : true }, actions: [ "addShard" ] }
```

前面的示例授予了在整个集群中执行`addShard`操作（向系统添加新的分片）的权限。集群资源只能用于影响整个集群而不是集合或数据库的操作（例如`shutdown`，`replSetReconfig`，`appendOplogNote`，`resync`，`closeAllDatabases`和`addShard`）。

接下来是一个广泛的特定于集群的操作列表，以及一些最常用的操作。

最常用操作的列表如下：

+   查找

+   插入

+   删除

+   更新

+   绕过文档验证

+   查看角色/查看用户

+   创建角色/删除角色

+   创建用户/删除用户

+   inprog

+   killop

+   replSetGetConfig/replSetConfigure/replSetStateChange/resync

+   获取分片映射/获取分片版本/列出分片/移动分片/移除分片/添加分片

+   删除数据库/删除索引/fsync/修复数据库/关闭

+   服务器状态/顶部/验证

特定于集群的操作如下：

+   解锁

+   authSchemaUpgrade

+   清理孤立

+   cpuProfiler

+   inprog

+   使用户缓存无效

+   killop

+   追加操作日志注释

+   replSetConfigure

+   replSetGetConfig

+   replSetGetStatus

+   replSetHeartbeat

+   replSetStateChange

+   重新同步

+   添加分片

+   刷新路由器配置

+   获取分片映射

+   列出分片

+   移除分片

+   分片状态

+   应用消息

+   关闭所有数据库

+   connPoolSync

+   fsync

+   获取参数

+   主机信息

+   日志轮转

+   设置参数

+   关闭

+   触摸

+   connPoolStats

+   游标信息

+   诊断日志

+   获取 CmdLineOpts

+   获取日志

+   列出数据库

+   netstat

+   服务器状态

+   顶部

如果听起来太复杂，那是因为它确实如此！MongoDB 允许在资源上配置不同操作的灵活性意味着我们需要研究和理解之前描述的广泛列表。

幸运的是，一些最常见的操作和资源已经包含在内置角色中。

我们可以使用这些内置角色来建立我们将授予用户的权限基线，然后根据广泛的列表进行细化。

# 用户角色

我们可以指定两种不同的通用用户角色，如下：

+   读取：在非系统集合和以下系统集合上的只读角色：`system.indexes`，`system.js`和`system.namespaces`集合

+   `readWrite`：在非系统集合和`system.js`集合上具有读写权限

# 数据库管理角色

有三种特定于数据库的管理角色，如下所示：

+   `dbAdmin`：可以执行与模式相关的任务、索引和收集统计信息的基本管理员用户角色。`dbAdmin`不能执行用户和角色管理。

+   `userAdmin`：创建和修改角色和用户。这是`dbAdmin`角色的补充。

`userAdmin`可以修改自身以成为数据库中的超级用户，或者，如果范围限定为`admin`数据库，则可以成为 MongoDB 集群的超级用户。

+   `dbOwner`：结合了`readWrite`、`dbAdmin`和`userAdmin`角色，这是最强大的管理员用户角色。

# 集群管理角色

以下是可用的集群范围管理角色：

+   `hostManager`：监视和管理集群中的服务器。

+   `clusterManager`：提供对集群的管理和监控操作。拥有此角色的用户可以访问用于分片和复制的配置和本地数据库。

+   `clusterMonitor`：只读访问权限，用于监控工具，如 MongoDB Cloud Manager 和 Ops Manager 代理提供的工具。

+   `clusterAdmin`：提供最大的集群管理访问权限。该角色结合了`clusterManager`、`clusterMonitor`和`hostManager`角色授予的权限。此外，该角色提供`dropDatabase`操作。

# 备份和恢复角色

基于角色的授权角色可以在备份和恢复的粒度级别中定义：

+   `backup`：提供备份数据所需的权限。该角色提供足够的权限来使用 MongoDB Cloud Manager 备份代理、Ops Manager 备份代理或`mongodump`。

+   `restore`：提供使用`mongorestore`还原数据所需的权限，但不包括`--oplogReplay`选项或`system.profile`集合数据。

# 所有数据库中的角色

同样，以下是所有数据库中可用的角色集合：

+   `readAnyDatabase`：提供与`read`相同的只读权限，但适用于集群中除了本地和配置数据库之外的所有数据库。该角色还在整个集群上提供`listDatabases`操作。

+   `readWriteAnyDatabase`：提供与`readWrite`相同的读写权限，但适用于集群中除了本地和配置数据库之外的所有数据库。该角色还在整个集群上提供`listDatabases`操作。

+   `userAdminAnyDatabase`：提供与`userAdmin`相同的用户管理操作权限，但适用于集群中除了本地和配置数据库之外的所有数据库。由于`userAdminAnyDatabase`角色允许用户向任何用户授予任何权限，包括自己，该角色间接地提供了超级用户访问权限。

+   `dbAdminAnyDatabase`：提供与`dbAdmin`相同的数据库管理操作权限，但适用于集群中除了本地和配置数据库之外的所有数据库。该角色还在整个集群上提供`listDatabases`操作。

# 超级用户

最后，以下是可用的超级用户角色：

+   `root`：提供对`readWriteAnyDatabase`、`dbAdminAnyDatabase`、`userAdminAnyDatabase`、`clusterAdmin`、`restore`和`backup`的操作和所有资源的访问权限

+   `__internal`：类似于 root 用户，任何`__internal`用户都可以对服务器上的任何对象执行任何操作。

应避免使用超级用户角色，因为它们可能对服务器上的所有数据库具有潜在破坏性的权限。

# 网络级安全

除了 MongoDB 特定的安全措施，还有针对网络级安全建立的最佳实践：

+   只允许服务器之间的通信，并且只打开用于它们之间通信的端口。

+   始终使用 TLS/SSL 进行服务器之间的通信。这可以防止中间人攻击冒充客户端。

+   始终使用不同的开发、暂存和生产环境以及安全凭据。理想情况下，为每个环境创建不同的帐户，并在暂存和生产环境中启用双因素身份验证。

# 审计安全

无论我们如何计划我们的安全措施，来自我们组织之外的第二或第三双眼睛可以对我们的安全措施提供不同的视角，并发现我们可能低估或忽视的问题。不要犹豫，要请安全专家和白帽黑客对服务器进行渗透测试。

# 特殊情况

出于数据隐私原因，医疗或金融应用程序需要增加安全级别。

如果我们正在构建一个涉及医疗保健领域的应用程序，访问用户的个人身份信息，我们可能需要获得 HIPAA 认证。

如果我们正在构建一个与支付交互并管理持卡人信息的应用程序，我们可能需要符合 PCI/DSS 标准。

每个认证的具体细节超出了本书的范围，但重要的是要知道 MongoDB 在这些领域有使用案例，满足要求，并且在适当的设计前可以成为正确的工具。

# 概述

总结涉及安全的最佳实践建议，我们有以下内容：

+   **强制进行身份验证**：始终在生产环境中启用身份验证。

+   **启用访问控制**：首先创建一个系统管理员，然后使用该管理员创建更有限的用户。为每个用户角色提供所需的最少权限。

+   **定义细粒度的访问控制角色**：不要给予每个用户比所需权限更多的权限。

+   **加密客户端和服务器之间的通信**：在生产环境中，始终使用 TLS/SSL 进行客户端和服务器之间的通信。对于`mongod`和`mongos`或配置服务器之间的通信，也应始终使用 TLS/SSL。

+   **加密静止数据**：MongoDB 企业版提供了在存储时加密数据的功能，使用 WiredTiger 静止加密。

或者，我们可以使用文件系统、设备或物理加密来加密数据。在云中，我们通常也可以选择加密（例如，在 Amazon EC2 上使用 EBS）。

+   **限制网络暴露**：MongoDB 服务器应该只连接到应用程序服务器和其他必需的服务器。除了我们为 MongoDB 通信设置的端口之外，不应该对外界开放其他端口。如果我们想要调试 MongoDB 的使用，重要的是设置一个代理服务器，以受控访问与我们的数据库进行通信。

+   **审计服务器以查找异常活动**：MongoDB 企业版提供了一个审计实用程序。通过使用它，我们可以将事件输出到控制台、JSON 文件、BSON 文件或 syslog。无论如何，重要的是确保审计事件存储在对系统用户不可用的分区中。

+   使用专用操作系统用户来运行 MongoDB。确保专用操作系统用户可以访问 MongoDB，但不具备不必要的权限。

+   如果不需要，禁用 JavaScript 服务器端脚本。

MongoDB 可以使用 JavaScript 进行服务器端脚本，使用以下命令：`mapReduce()`、`group()`和`$where`。如果我们不需要这些命令，我们应该在命令行上使用`--noscripting`选项禁用服务器端脚本。

# 总结

在本章中，您了解了 MongoDB 的三个操作方面：监控、备份和安全。

我们讨论了在 MongoDB 中应该监控的指标，以及如何监控它们。在此之后，我们讨论了如何进行备份并确保我们可以使用它们来恢复我们的数据。最后，您了解了身份验证和授权概念以及网络级安全以及如何对其进行审计。

设计、构建和根据需要扩展我们的应用程序同样重要，同样重要的是要确保在运营过程中我们能够心无旁骛，并且能够防范意外事件，比如人为错误和内部或外部恶意用户。

在下一章中，您将了解可插拔存储引擎，这是在 MongoDB 3.0 版本中引入的新概念。可插拔存储引擎允许满足不同的用例，特别是在具有特定和严格的数据处理和隐私要求的应用领域。
