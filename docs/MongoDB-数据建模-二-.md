# MongoDB 数据建模（二）

> 原文：[`zh.annas-archive.org/md5/3D36993E61CA808CF2348E9B049B1823`](https://zh.annas-archive.org/md5/3D36993E61CA808CF2348E9B049B1823)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：索引

正如您在关系数据库的主题中所看到的，索引是在考虑性能提升时重要的结构。实际上，索引非常重要，以至于对于大多数数据库管理员来说，它们是搜索持续改进数据库性能的关键工具。

在 MongoDB 等 NoSQL 数据库中，索引是更大策略的一部分，这将使我们能够在性能上获得许多收益，并为我们的数据库分配重要的行为，这对数据模型的维护至关重要。

这是因为在 MongoDB 中，我们可以有具有非常特殊属性的索引。例如，我们可以定义一个日期类型字段的索引，该索引将控制何时从集合中删除文档。

因此，在本章中我们将看到：

+   索引文档

+   索引类型

+   特殊索引属性

# 索引文档

在本书迄今为止讨论的所有主题中，这是我们最熟悉的地方。索引概念几乎存在于每个关系数据库中，因此如果您对此有任何基本的先前知识，您在本章中很可能不会有困难。

但是，如果您觉得自己对索引的概念不够熟悉，理解它们的简单方法是与书籍进行类比。假设我们有一本书，其索引如下：

![索引文档](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-dt-mdl/img/B04075_04_01.jpg)

有了这个，如果我们决定阅读有关互联网的信息，我们知道在第**4**页上会找到有关这个主题的信息。另一方面，如果没有页码，我们如何能找到我们正在寻找的信息呢？答案很简单：逐页浏览整本书，直到找到“互联网”这个词。

正如您可能已经知道的那样，索引是保存来自我们主要数据源的数据部分的数据结构。在关系数据库中，索引保存表的部分，而在 MongoDB 中，由于索引是在集合级别上的，这些将保存文档的部分。与关系数据库类似，索引在实现级别使用 B-Tree 数据结构。

根据我们应用程序的要求，我们可以创建字段的索引或嵌入文档的字段。当我们创建索引时，它将保存我们选择的字段的排序值集。

因此，当我们执行查询时，如果有一个覆盖查询条件的索引，MongoDB 将使用该索引来限制要扫描的文档数量。

我们有一个`customers`集合，我们在第三章中使用过，*查询文档*，其中包含这些文档：

```sql
{
 "_id" : ObjectId("54aecd26867124b88608b4c9"),
 "username" : "customer1",
 "email" : "customer1@customer.com",
 "password" : "b1c5098d0c6074db325b0b9dddb068e1"
}

```

我们可以在 mongo shell 上使用`createIndex`方法在`username`字段上创建索引：

```sql
db.customers.createIndex({username: 1})

```

以下查询将使用先前创建的索引：

```sql
db.customers.find({username: "customer1"})

```

### 注意

自 3.0.0 版本以来，`ensureIndex`方法已被弃用，并且是`createIndex`方法的别名。

我们可以说这是在 MongoDB 中创建和使用索引的最简单方法。除此之外，我们还可以在多键字段或嵌入文档的字段上创建索引，例如。

在下一节中，我们将介绍所有这些索引类型。

## 对单个字段进行索引

正如我们在上一节中所述，在 MongoDB 上创建索引的最简单方法是在单个字段上这样做。索引可以在文档集合中的任何类型的字段上创建。

考虑到我们之前使用过的`customers`集合，对其进行了一些修改以适应本节的工作：

```sql
{
 "_id" : ObjectId("54aecd26867124b88608b4c9"),
 "username" : "customer1",
 "email" : "customer1@customer.com",
 "password" : "b1c5098d0c6074db325b0b9dddb068e1",
 "age" : 25,
 "address" : {

 "street" : "Street 1",
 "zipcode" : "87654321",
 "state" : "RJ"

 }
}

```

以下命令在`username`字段中创建一个升序索引：

```sql
db.customers.createIndex({username: 1})

```

为了在 MongoDB 中创建索引，我们使用`createIndex`方法。在前面的代码中，我们只是将单个文档作为参数传递给`createIndex`方法。文档`{username: 1}`包含对应于应该创建索引的字段和顺序的引用：1 表示升序，-1 表示降序。

创建相同的索引的另一种方法，但按降序顺序进行：

```sql
db.customers.createIndex({username: -1})

```

在下面的查询中，MongoDB 将使用在`username`字段中创建的索引来减少应该检查的`customers`集合中文档的数量：

```sql
db.customers.find({username: "customer1"})

```

除了在集合文档中的字符串或数字字段上创建索引，我们还可以在嵌入式文档的字段上创建索引。因此，这样的查询将使用创建的索引：

```sql
db.customers.createIndex({"address.state": 1})

```

以下代码创建了嵌入地址文档的`state`字段的索引：

```sql
db.customers.find({"address.state": "RJ"})

```

虽然有点复杂，但我们也可以创建整个嵌入式文档的索引：

```sql
db.customers.createIndex({address: 1})

```

以下查询将使用索引：

```sql
db.customers.find(
{
 "address" : 
 { 
 "street" : "Street 1", 
 "zipcode" : "87654321", 
 "state" : "RJ"
 }
}
)

```

但是，这些查询都不会这样做：

```sql
db.customers.find({state: "RJ"})

db.customers.find({address: {zipcode: "87654321"}})

```

这是因为为了匹配嵌入式文档，我们必须精确匹配整个文档，包括字段顺序。以下查询也不会使用索引：

```sql
db.customers.find(
{
 "address" : 
 { 
 "state" : "RJ", 
 "street" : "Street 1", 
 "zipcode" : "87654321" 
 }
}
)

```

尽管文档包含所有字段，但这些字段的顺序不同。

在继续下一种索引类型之前，让我们回顾一下您在第三章中学到的一个概念，即`_id`字段。对于集合中创建的每个新文档，我们应该指定`_id`字段。如果我们不指定，MongoDB 会自动为我们创建一个`ObjectId`类型的`_id`。此外，每个集合都会自动创建`_id`字段的唯一升序索引。也就是说，我们可以说`_id`字段是文档的主键。

## 索引多个字段

在 MongoDB 中，我们可以创建一个保存多个字段值的索引。我们应该称这种索引为复合索引。单字段索引和复合索引之间没有太大的区别。最大的区别在于排序顺序。在我们继续讨论复合索引的特点之前，让我们使用`customers`集合来创建我们的第一个复合索引：

```sql
{
 "_id" : ObjectId("54aecd26867124b88608b4c9"),
 "username" : "customer1",
 "email" : "customer1@customer.com",
 "password" : "b1c5098d0c6074db325b0b9dddb068e1",
 "age" : 25,
 "address" : {
 "street" : "Street 1",
 "zipcode" : "87654321",
 "state" : "RJ"
 }
}

```

我们可以想象一个应用程序，它想要使用`username`和`password`字段一起在查询中对客户进行身份验证。

```sql
db.customers.find(
{
username: "customer1", 
password: "b1c5098d0c6074db325b0b9dddb068e1"
}
)

```

为了在执行此查询时获得更好的性能，我们可以创建`username`和`password`字段的索引：

```sql
db.customers.createIndex({username: 1, password: 1})

```

尽管如此，对于以下查询，MongoDB 是否使用复合索引？

```sql
#Query 1
db.customers.find({username: "customer1"})
#Query 2
db.customers.find({password: "b1c5098d0c6074db325b0b9dddb068e1"})
#Query 3
db.customers.find(
{
 password: "b1c5098d0c6074db325b0b9dddb068e1", 
 username: "customer1"
}
)

```

对于`Query 1`和`Query 3`的答案是肯定的。如前所述，顺序在创建复合索引时非常重要。创建的索引将引用按`username`字段排序的文档，并在每个用户名条目内，按密码条目排序。因此，只有`password`字段作为条件的查询将不使用索引。

假设我们在`customers`集合中有以下索引：

```sql
db.customers.createIndex(
{
 "address.state":1, 
 "address.zipcode": 1, 
 "address.street": 1
})

```

您可能会问哪些查询将使用我们的新复合索引？在回答这个问题之前，我们需要了解 MongoDB 中的复合索引概念：**前缀**。复合索引中的前缀是索引字段的子集。顾名思义，它是索引中优先于其他字段的字段。在我们的例子中，`{"address.state":1}`和`{"address.state":1, "address.zipcode": 1}`都是索引前缀。

具有任何索引前缀的查询都将使用复合索引。因此，我们可以推断出：

+   包括`address.state`字段的查询将使用复合索引

+   包括`address.state`和`address.zipcode`字段的查询也将使用复合索引

+   具有`address.state`、`address.zipcode`和`address.street`的查询也将使用复合索引

+   同时具有`address.state`和`address.street`的查询也将使用复合索引

复合索引不会在以下查询中使用：

+   只有`address.zipcode`字段

+   只有`address.street`字段

+   同时具有`address.zipcode`和`address.street`字段

### 注意

我们应该注意，尽管查询同时使用`address.state`和`address.street`字段使用索引，如果我们为每个字段单独创建单个索引，我们可以在此查询中获得更好的性能。这是因为复合索引首先按`address.state`排序，然后按`address.zipcode`字段排序，最后按`address.street`字段排序。因此，MongoDB 检查此索引要比检查其他两个索引要昂贵得多。

因此，对于此查询：

```sql
db.customers.find(
{
 "address.state": "RJ", 
 "address.street": "Street 1"
}
)

```

如果我们有这个索引将更有效：

```sql
db.customers.createIndex({"address.state": 1, "address.street": 1})

```

## 多键字段的索引

在 MongoDB 中创建索引的另一种方法是创建数组字段的索引。这些索引可以包含原始值的数组，例如字符串和数字，甚至包含文档的数组。

在创建多键索引时，我们必须特别注意。特别是当我们想要创建复合多键索引时。无法创建两个数组字段的复合索引。

### 注意

我们无法创建并行数组的索引的主要原因是因为它们将要求索引包括复合键的笛卡尔积中的条目，这将导致一个大型索引。

考虑具有以下文档的`customers`集合：

```sql
{
 "_id" : ObjectId("54aecd26867124b88608b4c9"),
 "username" : "customer1",
 "email" : "customer1@customer.com",
 "password" : "b1c5098d0c6074db325b0b9dddb068e1",
 "age" : 25,
 "address" : {
 "street" : "Street 1",
 "zipcode" : "87654321",
 "state" : "RJ"
 },
 "followedSellers" : [
 "seller1",
 "seller2",
 "seller3"
 ],
 "wishList" : [
 {
 "sku" : 123,
 "seller" : "seller1"
 },
 {
 "sku" : 456,
 "seller" : "seller2"
 },
 {
 "sku" : 678,
 "seller" : "seller3"
 }
 ]
}

```

我们可以为此集合创建以下索引：

```sql
db.customers.createIndex({followedSellers: 1})

db.customers.createIndex({wishList: 1})

db.customers.createIndex({"wishList.sku": 1})

db.customers.createIndex({"wishList.seller": 1})

```

但是无法创建以下索引：

```sql
db.customers.createIndex({followedSellers: 1, wishList: 1}

```

## 用于文本搜索的索引

自 2.4 版本以来，MongoDB 为我们提供了创建索引以帮助我们进行文本搜索的机会。尽管有许多专门的工具，例如 Apache Solr、Sphinx 和 ElasticSearch，用于此目的，但大多数关系型和 NoSQL 数据库都具有本地全文搜索功能。

可以在集合中创建字符串或字符串字段数组的文本索引。对于以下示例，我们将使用我们在第三章中也使用的`products`集合，*查询文档*，但进行了一些修改：

```sql
{ 
 "_id" : ObjectId("54837b61f059b08503e200db"), 
 "name" : "Product 1", 
 "description" : 
 "Product 1 description", 
 "price" : 10, 
 "supplier" : { 
 "name" : "Supplier 1", 
 "telephone" : "+552199998888" 
 }, 
 "review" : [ 
 { 
 "customer" : { 
 "email" : "customer@customer.com" 
 }, 
 "stars" : 5 
 }
 ],
 "keywords" : [ "keyword1", "keyword2", "keyword3" ] 
}

```

我们可以通过在`createIndex`方法中指定`text`参数来创建文本索引：

```sql
db.products.createIndex({name: "text"})

db.products.createIndex({description: "text"})

db.products.createIndex({keywords: "text"})

```

所有上述命令都可以创建`products`集合的文本索引。但是，MongoDB 有一个限制，即每个集合只能有一个文本索引。因此，只能为`products`集合执行先前的命令中的一个。

尽管每个集合只能创建一个文本索引的限制，但可以创建复合文本索引：

```sql
db.products.createIndex({name: "text", description: "text"})

```

上述命令为`name`和`description`字段创建了一个`text`索引字段。

### 注意

创建集合的文本索引的一种常见且有用的方法是为集合的所有文本字段创建索引。有一个特殊的语法用于创建此索引，您可以如下所示：

```sql
db.products.createIndex({"$**","text"})

```

要使用文本索引进行查询，我们应该在其中使用`$text`运算符。为了更好地理解如何创建有效的查询，了解索引的创建方式是很好的。事实上，使用`$text`运算符执行查询时使用相同的过程。

总结该过程，我们可以将其分为三个阶段：

+   标记化

+   删除后缀和/或前缀，或词干处理

+   删除停用词

为了优化我们的查询，我们可以指定我们在文本字段中使用的语言，因此在我们的文本索引中使用的语言，以便 MongoDB 将在索引过程的所有三个阶段中使用单词列表。

自 2.6 版本以来，MongoDB 支持以下语言：

+   `da`或`danish`

+   `nl`或`dutch`

+   `en`或`english`

+   `fi`或`finnish`

+   `fr`或`french`

+   `de`或`german`

+   `hu`或`hungarian`

+   `it`或`italian`

+   `nb`或`norwegian`

+   `pt`或`portuguese`

+   `ro`或`romanian`

+   `ru`或`russian`

+   `es`或`spanish`

+   `sv`或`swedish`

+   `tr`或`turkish`

具有语言的索引创建示例可能是：

```sql
db.products.createIndex({name: "text"},{ default_language: "pt"})

```

我们还可以选择不使用任何语言，只需使用`none`值创建索引：

```sql
db.products.createIndex({name: "text"},{ default_language: "none"})

```

通过使用`none`值选项，MongoDB 将仅执行标记化和词干处理；它不会加载任何停用词列表。

当我们决定使用文本索引时，我们应该始终加倍注意。每一个细节都会对我们设计文档的方式产生副作用。在 MongoDB 的早期版本中，在创建文本索引之前，我们应该将所有集合的分配方法更改为**usePowerOf2Sizes**。这是因为文本索引被认为是较大的索引。

另一个主要关注点发生在创建索引的时刻。根据现有集合的大小，索引可能非常大，要创建一个非常大的索引，我们需要很多时间。因此，最好安排这个过程在更及时的机会发生。

最后，我们必须预测文本索引对我们的写操作的影响。这是因为，对于我们集合中创建的每条新记录，还将创建一个引用所有索引值字段的索引条目。

# 创建特殊索引

除了我们到目前为止创建的所有索引类型，无论是升序还是降序，还是文本类型，我们还有三种特殊的索引：生存时间、唯一和稀疏。

## 生存时间索引

**生存时间**（**TTL**）索引是基于生存时间的索引。该索引仅在日期类型的字段中创建。它们不能是复合索引，并且它们将在一定时间后自动从文档中删除。

这种类型的索引可以从日期向量创建。文档将在达到较低数组值时过期。MongoDB 负责通过后台任务在 60 秒的间隔内控制文档的过期。例如，让我们使用本章中一直在使用的`customers`集合：

```sql
{ 
"_id" : ObjectId("5498da405d0ffdd8a07a87ba"), 
"username" : "customer1", 
"email" : "customer1@customer.com", 
"password" : "b1c5098d0c6074db325b0b9dddb068e1", "accountConfirmationExpireAt" : ISODate("2015-01-11T20:27:02.138Z") 
}

```

基于`accountConfirmationExpireAt`字段的生存时间索引的创建命令将如下所示：

```sql
db.customers.createIndex(
{accountConfirmationExpireAt: 1}, {expireAfterSeconds: 3600}
)

```

该命令指示超过`expireAfterSeconds`字段中请求的秒值的每个文档将被删除。

还有另一种基于生存时间创建索引的方法，即定时方式。以下示例向我们展示了这种实现方法：

```sql
db.customers.createIndex({
accountConfirmationExpireAt: 1}, {expireAfterSeconds: 0}
)

```

这将确保您在上一个示例中看到的文档在 2015 年 1 月 11 日 20:27:02 过期。

这种类型的索引对于使用机器生成的事件、日志和会话信息的应用程序非常有用，这些信息只需要在特定时间内持久存在，正如您将在第八章中再次看到的那样，“使用 MongoDB 进行日志记录和实时分析”。

## 唯一索引

与绝大多数关系数据库一样，MongoDB 具有唯一索引。唯一索引负责拒绝索引字段中的重复值。唯一索引可以从单个字段或多键字段以及复合索引创建。创建唯一复合索引时，值的组合必须是唯一的。

如果我们在`insert`操作期间没有设置任何值，唯一字段的默认值将始终为 null。正如您之前所见，对于集合的`_id`字段创建的索引是唯一的。考虑`customers`集合的最后一个示例，可以通过执行以下操作创建唯一索引：

```sql
db.customers.createIndex({username: 1}, {unique: true})

```

该命令将创建一个`username`字段的索引，不允许重复的值。

## 稀疏索引

稀疏索引是仅在文档具有将被索引的字段值时才创建的索引。我们可以仅使用文档中的一个字段或使用更多字段来创建稀疏索引。这种情况被称为**复合索引**。当我们创建复合索引时，至少一个字段必须具有非空值。

以`customers`集合中的以下文档为例：

```sql
{ "_id" : ObjectId("54b2e184bc471cf3f4c0a314"), "username" : "customer1", "email" : "customer1@customer.com", "password" : "b1c5098d0c6074db325b0b9dddb068e1" }
{ "_id" : ObjectId("54b2e618bc471cf3f4c0a316"), "username" : "customer2", "email" : "customer2@customer.com", "password" : "9f6a4a5540b8ebdd3bec8a8d23efe6bb" }
{ "_id" : ObjectId("54b2e629bc471cf3f4c0a317"), "username" : "customer3", "email" : "customer3@customer.com" }

```

使用以下示例命令，我们可以在`customers`集合中创建一个`sparse`索引：

```sql
db.customers.createIndex({password: 1}, {sparse: true})

```

以下示例查询使用了创建的索引：

```sql
db.customers.find({password: "9f6a4a5540b8ebdd3bec8a8d23efe6bb"})

```

另一方面，下面的示例查询，请求按索引字段的降序排列，将不使用索引：

```sql
db.customers.find().sort({password: -1})

```

# 总结

在本章中，我们看到索引是数据模型维护中非常重要的工具。通过在查询规划阶段包括索引创建，这将带来许多好处，尤其是在所谓的查询文档性能方面。

因此，您学会了如何创建单个、复合和多键索引。接下来，我们讨论了在 MongoDB 上如何以及何时使用索引进行文本搜索。然后我们介绍了特殊的索引类型，如 TTL、唯一和稀疏索引。

在下一章中，您将看到如何分析查询，从而以更高效的方式创建它们。


# 第五章：优化查询

现在，我们已经在理解如何使用索引来提高读写性能方面迈出了重要的一步，让我们看看如果这些索引表现如预期，我们如何分析它们，以及索引如何影响数据库的生命周期。除此之外，通过这种分析，我们将能够评估和优化创建的查询和索引。

因此，在本章中，我们将学习查询计划的概念以及 MongoDB 如何处理它。这包括理解查询覆盖和查询选择性，以及在分片环境和副本集中使用这些计划时的行为。

# 理解查询计划

当我们运行查询时，MongoDB 将通过从 MongoDB 查询优化器执行的查询分析中提取的一组可能性中选择最佳方式来执行查询。这些可能性称为**查询计划**。

要更好地理解查询计划，我们必须回到游标概念和游标方法之一：`explain()`。`explain()`方法是 MongoDB 3.0 版本中的重大变化之一。由于新的查询内省系统的出现，它得到了显着增强。

输出不仅发生了变化，正如我们之前看到的那样，使用方式也发生了变化。现在，我们可以向`explain()`方法传递一个选项参数，该参数指定`explain`输出的详细程度。可能的模式是`"queryPlanner"`、`"executionStats"`和`"allPlansExecution"`。默认模式是`"queryPlanner"`。

+   在`"queryPlanner"`模式下，MongoDB 运行查询优化器选择评估中的获胜计划，并将信息返回给评估方法。

+   在`"executionStats"`模式下，MongoDB 运行查询优化器选择获胜计划，执行它，并将信息返回给评估方法。如果我们对写操作执行`explain()`方法，则返回有关将执行的操作的信息，但实际上不执行它。

+   最后，在`"allPlansExecution"`模式下，MongoDB 运行查询优化器选择获胜计划，执行它，并将信息返回给评估方法，以及其他候选计划的信息。

### 提示

您可以在 MongoDB 3.0 参考指南的[`docs.mongodb.org/manual/reference/method/db.collection.explain/#db.collection.explain`](http://docs.mongodb.org/manual/reference/method/db.collection.explain/#db.collection.explain)中找到有关`explain()`方法的更多信息。

`explain`执行的输出将查询计划显示为阶段树。从叶子到根，每个阶段将其结果传递给父节点。第一个阶段发生在叶节点上，访问集合或索引并将结果传递给内部节点。这些内部节点操作结果，最终阶段或根节点从中派生结果集。

有四个阶段：

+   `COLLSCAN`：这意味着在此阶段发生了完整的集合扫描

+   `IXSCAN`：这表示在此阶段发生了索引键扫描

+   `FETCH`：这是当我们检索文档时的阶段

+   `SHARD_MERGE`：这是来自每个分片的结果被合并并传递给父阶段的阶段

获胜计划阶段的详细信息可以在`explain()`执行输出的`explain.queryPlanner.winningPlan`键中找到。`explain.queryPlanner.winningPlan.stage`键向我们展示了根阶段的名称。如果有一个或多个子阶段，该阶段将具有一个`inputStage`或`inputStages`键，取决于我们有多少阶段。子阶段将由`explain()`执行输出的`explain.queryPlanner.winningPlan.inputStage`和`explain.queryPlanner.winningPlan.inputStages`键表示。

### 注意

要了解更多关于`explain()`方法的信息，请访问 MongoDB 3.0 手册页面[`docs.mongodb.org/manual/reference/explain-results/`](http://docs.mongodb.org/manual/reference/explain-results/)。

`explain()`方法的执行和输出的所有这些变化主要是为了提高 DBA 的生产力。与以前的 MongoDB 版本相比，最大的优势之一是`explain()`不需要执行查询来计算查询计划。它还将查询内省暴露给了更广泛的操作，包括 find、count、update、remove、group 和 aggregate，使 DBA 有能力优化每种类型的查询。

## 评估查询

直截了当地说，`explain`方法将为我们提供查询执行的统计信息。例如，我们将在这些统计信息中看到是否使用了游标或索引。

让我们以以下`products`集合为例：

```sql
{
 "_id": ObjectId("54bee5c49a5bc523007bb779"),
 "name": "Product 1",
 "price": 56
}
{
 "_id": ObjectId("54bee5c49a5bc523007bb77a"),
 "name": "Product 2",
 "price": 64
}
{
 "_id": ObjectId("54bee5c49a5bc523007bb77b"),
 "name": "Product 3",
 "price": 53
}
{
 "_id": ObjectId("54bee5c49a5bc523007bb77c"),
 "name": "Product 4",
 "price": 50
}
{
 "_id": ObjectId("54bee5c49a5bc523007bb77d"),
 "name": "Product 5",
 "price": 89
}
{
 "_id": ObjectId("54bee5c49a5bc523007bb77e"),
 "name": "Product 6",
 "price": 69
}
{
 "_id": ObjectId("54bee5c49a5bc523007bb77f"),
 "name": "Product 7",
 "price": 71
}
{
 "_id": ObjectId("54bee5c49a5bc523007bb780"),
 "name": "Product 8",
 "price": 40
}
{
 "_id": ObjectId("54bee5c49a5bc523007bb781"),
 "name": "Product 9",
 "price": 41
}
{
 "_id": ObjectId("54bee5c49a5bc523007bb782"),
 "name": "Product 10",
 "price": 53
}

```

正如我们已经看到的，当集合被创建时，`_id`字段上会自动添加一个索引。为了获取集合中的所有文档，我们将在 mongod shell 中执行以下查询：

```sql
db.products.find({price: {$gt: 65}})

```

查询的结果将是以下内容：

```sql
{
 "_id": ObjectId("54bee5c49a5bc523007bb77d"),
 "name": "Product 5",
 "price": 89
}
{
 "_id": ObjectId("54bee5c49a5bc523007bb77e"),
 "name": "Product 6",
 "price": 69
}
{
 "_id": ObjectId("54bee5c49a5bc523007bb77f"),
 "name": "Product 7",
 "price": 71
}

```

为了帮助您理解 MongoDB 是如何得出这个结果的，让我们在通过`find`命令返回的游标上使用`explain`方法：

```sql
db.products.find({price: {$gt: 65}}).explain("executionStats")

```

这个操作的结果是一个包含有关所选查询计划信息的文档：

```sql
{
 "queryPlanner" : {
 "plannerVersion" : 1,
 "namespace" : "ecommerce.products",
 "indexFilterSet" : false,
 "parsedQuery" : {
 "price" : {
 "$gt" : 65
 }
 },
 "winningPlan" : {
 "stage" : "COLLSCAN",
 "filter" : {
 "price" : {
 "$gt" : 65
 }
 },
 "direction" : "forward"
 },
 "rejectedPlans" : [ ]
 },
 "executionStats" : {
 "executionSuccess" : true,
 "nReturned" : 3,
 "executionTimeMillis" : 0,
 "totalKeysExamined" : 0,
 "totalDocsExamined" : 10,
 "executionStages" : {
 "stage" : "COLLSCAN",
 "filter" : {
 "price" : {
 "$gt" : 65
 }
 },
 "nReturned" : 3,
 "executionTimeMillisEstimate" : 0,
 "works" : 12,
 "advanced" : 3,
 "needTime" : 8,
 "needFetch" : 0,
 "saveState" : 0,
 "restoreState" : 0,
 "isEOF" : 1,
 "invalidates" : 0,
 "direction" : "forward",
 "docsExamined" : 10
 }
 },
 "serverInfo" : {
 "host" : "c516b8098f92",
 "port" : 27017,
 "version" : "3.0.2",
 "gitVersion" : "6201872043ecbbc0a4cc169b5482dcf385fc464f"
 },
 "ok" : 1
}

```

最初，让我们只检查这个文档中的四个字段：`queryPlanner.winningPlan.stage`、`queryPlanner.executionStats.nReturned`、`queryPlanner.executionStats.totalKeysExamined`和`queryPlanner.executionStats.totalDocsExamined`：

+   `queryPlanner.winningPlan.stage`字段显示了将执行完整的集合扫描。

+   `queryPlanner.executionStats.nReturned`字段显示了有多少文档符合查询条件。换句话说，它显示了有多少文档将从查询执行中返回。在这种情况下，结果将是三个文档。

+   `queryPlanner.executionStats.totalDocsExamined`字段是将要扫描的集合中的文档数。在这个例子中，所有的文档都被扫描了。

+   `queryPlanner.executionStats.totalKeysExamined`字段显示了扫描的索引条目数。

+   在执行集合扫描时，就像前面的例子中一样，`nscanned`也代表了在集合中扫描的文档数。

如果我们为我们的集合的`price`字段创建一个索引会发生什么？让我们看看：

```sql
db.products.createIndex({price: 1})

```

显然，查询结果将是在先前执行中返回的相同的三个文档。然而，`explain`命令的结果将是以下内容：

```sql
{
 "queryPlanner" : {
 "plannerVersion" : 1,
 "namespace" : "ecommerce.products",
 "indexFilterSet" : false,
 "parsedQuery" : {
 …
 },
 "winningPlan" : {
 "stage" : "FETCH",
 "inputStage" : {
 "stage" : "IXSCAN",
 "keyPattern" : {
 "price" : 1
 },
 "indexName" : "price_1",
 ...
 }
 },
 "rejectedPlans" : [ ]
 },
 "executionStats" : {
 "executionSuccess" : true,
 "nReturned" : 3,
 "executionTimeMillis" : 20,
 "totalKeysExamined" : 3,
 "totalDocsExamined" : 3,
 "executionStages" : {
 "stage" : "FETCH",
 "nReturned" : 3,
 ...
 "inputStage" : {
 "stage" : "IXSCAN",
 "nReturned" : 3,
 ...
 }
 }
 },
 "serverInfo" : {
 ...
 },
 "ok" : 1
}

```

返回的文档与之前的文档有很大的不同。再次，让我们专注于这四个字段：`queryPlanner.winningPlan.stage`、`queryPlanner.executionStats.nReturned`、`queryPlanner.executionStats.totalKeysExamined`和`queryPlanner.executionStats.totalDocsExamined`。

这一次，我们可以看到我们没有进行完整的集合扫描。而是有一个带有子`IXSCAN`阶段的`FETCH`阶段，正如我们在`queryPlanner.winningPlan.inputStage.stage`字段中所看到的。这意味着查询使用了索引。索引的名称可以在字段`queryPlanner.winningPlan.inputStage.indexName`中找到，在这个例子中是`price_1`。

此外，这个结果的平均差异是，`queryPlanner.executionStats.totalDocsExamined`和`queryPlanner.executionStats.totalKeysExamined`都返回了值`3`，显示了扫描了三个文档。这与在没有索引的情况下执行查询时看到的 10 个文档非常不同。

我们应该指出的一点是，扫描的文档和键的数量与`queryPlanner.executionStats.totalDocsExamined`和`queryPlanner.executionStats.totalKeysExamined`中所示的相同。这意味着我们的查询未被索引覆盖。在下一节中，我们将看到如何使用索引覆盖查询以及其好处。

## 覆盖查询

有时我们可以选择根据它们在查询中出现的频率创建一个或多个字段的索引。我们还可以选择创建索引以提高查询性能，不仅用于匹配条件，还用于从索引本身提取结果。

我们可以说，当查询中的所有字段都是索引的一部分，且查询中的所有字段都是同一个索引的一部分时，此查询将被索引覆盖。

在前一节中所示的示例中，我们创建了`products`集合的`price`字段的索引：

```sql
db.products.createIndex({price: 1})

```

当我们执行以下查询时，该查询检索`price`字段的值大于`65`的文档，但投影中排除了结果中的`_id`字段，只包括`price`字段，我们将得到与之前显示的结果不同的结果：

```sql
db.products.find({price: {$gt: 65}}, {price: 1, _id: 0})

```

结果将是：

```sql
{ "price" : 69 }
{ "price" : 71 }
{ "price" : 89 }

```

然后我们使用`explain`命令分析查询，如下所示：

```sql
db.products.explain("executionStats")
.find({price: {$gt: 65}}, {price: 1, _id: 0})

```

通过这样做，我们还得到了与之前示例不同的结果：

```sql
{
 "queryPlanner" : {
 "plannerVersion" : 1,
 "namespace" : "ecommerce.products",
 "indexFilterSet" : false,
 "parsedQuery" : {
 "price" : {
 "$gt" : 65
 }
 },
 "winningPlan" : {
 "stage" : "PROJECTION",
 ...
 "inputStage" : {
 "stage" : "IXSCAN",
 ...

 }
 },
 "rejectedPlans" : [ ]
 },
 "executionStats" : {
 "executionSuccess" : true,
 "nReturned" : 3,
 "executionTimeMillis" : 0,
 "totalKeysExamined" : 3,
 "totalDocsExamined" : 0,
 "executionStages" : {
 ...
 }
 },
 "serverInfo" : {
 ...
 },
 "ok" : 1
}

```

我们注意到的第一件事是`queryPlanner.executionStats.totalDocsExamined`的值为`0`。这可以解释为我们的查询被索引覆盖。这意味着我们不需要扫描集合中的文档。我们将使用索引返回结果，正如我们在`queryPlanner.executionStats.totalKeysExamined`字段的值`3`中观察到的那样。

另一个不同之处是`IXSCAN`阶段不是`FETCH`阶段的子级。每当索引覆盖查询时，`IXSCAN`都不会是`FETCH`阶段的后代。

### 注意

被索引覆盖的查询可能非常快。这是因为索引键通常比文档本身要小得多，而且索引通常位于易失性内存或磁盘顺序写入模式中。

不幸的是，我们并不总是能够覆盖查询，即使我们有相同的条件。

考虑以下`customers`集合：

```sql
{
 "_id": ObjectId("54bf0d719a5bc523007bb78f"),
 "username": "customer1",
 "email": "customer1@customer.com",
 "password": "1185031ff57bfdaae7812dd705383c74",
 "followedSellers": [
 "seller3",
 "seller1"
 ]
}
{
 "_id": ObjectId("54bf0d719a5bc523007bb790"),
 "username": "customer2",
 "email": "customer2@customer.com",
 "password": "6362e1832398e7d8e83d3582a3b0c1ef",
 "followedSellers": [
 "seller2",
 "seller4"
 ]
}
{
 "_id": ObjectId("54bf0d719a5bc523007bb791"),
 "username": "customer3",
 "email": "customer3@customer.com",
 "password": "f2394e387b49e2fdda1b4c8a6c58ae4b",
 "followedSellers": [
 "seller2",
 "seller4"
 ]
}
{
 "_id": ObjectId("54bf0d719a5bc523007bb792"),
 "username": "customer4",
 "email": "customer4@customer.com",
 "password": "10619c6751a0169653355bb92119822a",
 "followedSellers": [
 "seller1",
 "seller2"
 ]
}
{
 "_id": ObjectId("54bf0d719a5bc523007bb793"),
 "username": "customer5",
 "email": "customer5@customer.com",
 "password": "30c25cf1d31cbccbd2d7f2100ffbc6b5",
 "followedSellers": [
 "seller2",
 "seller4"
 ]
}

```

并且创建了`followedSellers`字段的索引，执行以下命令在 mongod shell 上：

```sql
db.customers.createIndex({followedSellers: 1})

```

如果我们在 mongod shell 上执行以下查询，该查询应该被索引覆盖，因为我们在查询条件中使用了`followedSellers`：

```sql
db.customers.find(
{
 followedSellers: {
 $in : ["seller1", "seller3"]
 }
}, 
{followedSellers: 1, _id: 0}
)

```

当我们使用 mongod shell 上的`explain`命令分析此查询以查看查询是否被索引覆盖时，我们可以观察到：

```sql
db.customers.explain("executionStats").find(
{
 followedSellers: {
 $in : ["seller1", "seller3"]
 }
}, 
{followedSellers: 1, _id: 0}
)

```

我们有以下文档作为结果。我们可以看到，尽管在条件中使用了索引中的字段并将结果限制为此字段，但返回的输出将`FETCH`阶段作为`IXSCAN`阶段的父级。此外，`totalDocsExamined`和`totalKeysExamined`的值是不同的：

```sql
{
 "queryPlanner" : {
 "plannerVersion" : 1,
 "namespace" : "ecommerce.customers",
 ...
 "winningPlan" : {
 "stage" : "PROJECTION",
 ...
 "inputStage" : {
 "stage" : "FETCH",
 "inputStage" : {
 "stage" : "IXSCAN",
 "keyPattern" : {
 "followedSellers" : 1
 },
 "indexName" : "followedSellers_1",
 ...
 }
 }
 },
 "rejectedPlans" : [ ]
 },
 "executionStats" : {
 "executionSuccess" : true,
 "nReturned" : 2,
 "executionTimeMillis" : 0,
 "totalKeysExamined" : 4,
 "totalDocsExamined" : 2,
 "executionStages" : {
 ...
 }
 },
 "serverInfo" : {
 ...
},
 "ok" : 1
}

```

`totalDocsExamined`字段返回`2`，这意味着需要扫描集合中的五个文档中的两个。与此同时，`totalKeysExamined`字段返回`4`，表明需要扫描四个索引条目以获取返回结果。

另一种情况是，当查询执行使用嵌入文档的字段的索引时，我们无法通过索引覆盖查询。

让我们使用`supplier.name`字段的索引检查已经在第四章中使用的`products`集合的示例：

```sql
db.products.createIndex({"supplier.name": 1})

```

以下查询将不被索引覆盖：

```sql
db.products.find(
 {"supplier.name": "Supplier 1"}, 
 {"supplier.name": 1, _id: 0}
)

```

### 注意

请记住，尽管此查询未被索引覆盖，但它将在计划中使用索引。

最后，当我们在分片集合中通过**mongos**执行查询时，此查询永远不会被索引覆盖。

## 查询优化器

现在您已经了解了使用`explain()`方法评估查询性能以及如何利用索引覆盖查询，我们将继续介绍在 MongoDB 中选择和维护查询计划的重大责任，即查询优化器。

查询优化器负责处理和选择查询的最佳和最有效的查询计划。为此，它考虑了所有集合索引。

查询优化器执行的过程并不是一门精确的科学，这意味着它有点经验主义，换句话说，是基于试错的。

当我们第一次执行查询时，查询优化器将针对集合的所有可用索引运行查询并选择最有效的索引。此后，每当我们运行相同的查询或具有相同模式的查询时，所选的索引将用于查询计划。

在本章前面使用的相同的`products`集合中，以下查询将通过相同的查询计划运行，因为它们具有相同的模式：

```sql
db.products.find({name: 'Product 1'})
db.products.find({name: 'Product 5'})

```

随着集合数据的变化，查询优化器会重新评估。此外，随着集合的增长（更准确地说，每进行 1,000 次写操作，每次索引创建，`mongod`进程重新启动，或者我们调用`explain()`方法），优化器会重新评估自身。

即使有了这个被称为查询优化器的神奇自动过程，我们可能还想选择我们想要使用的索引。为此，我们使用`hint`方法。

假设我们的先前的`products`集合中有这些索引：

```sql
db.products.createIndex({name: 1, price: -1})
db.products.createIndex({price: -1})

```

如果我们想检索所有`price`字段值大于 10 的产品，并按`name`字段降序排序，可以使用以下命令来执行：

```sql
db.products.find({price: {$gt: 10}}).sort({name: -1})

```

查询优化器选择的索引将是在`name`和`price`字段上创建的索引，我们可以通过运行`explain()`方法来查看：

```sql
db.products.explain("executionStats").find({price: {$gt: 10}}).sort({name: -1})

```

结果是：

```sql
{
 "queryPlanner" : {
 "plannerVersion" : 1,
 "namespace" : "ecommerce.products",
 ...
 "winningPlan" : {
 "stage" : "FETCH",
 ...
 "inputStage" : {
 "stage" : "IXSCAN",
 "keyPattern" : {
 "name" : 1,
 "price" : -1
 },
 "indexName" : "name_1_price_-1"
 ...
 }
 },
 ...
 },
 "executionStats" : {
 "executionSuccess" : true,
 "nReturned" : 10,
 "executionTimeMillis" : 0,
 "totalKeysExamined" : 10,
 "totalDocsExamined" : 10,
 "executionStages" : {
 ...
 }
 },
 "serverInfo" : {
 ...
},
 "ok" : 1
}

```

然而，我们只能强制使用`price`字段的索引，如下所示：

```sql
db.products.find(
 {price: {$gt: 10}}
).sort({name: -1}).hint({price: -1})

```

为了确定，我们使用`explain`方法：

```sql
db.products.explain("executionStats").find(
 {price: {$gt: 10}}).sort({name: -1}
).hint({price: -1})

```

这产生了以下文档：

```sql
{
 "queryPlanner" : {
 "plannerVersion" : 1,
 "namespace" : "ecommerce.products",
 ...
 "winningPlan" : {
 "stage" : "SORT",
 ...
 "inputStage" : {
 "stage" : "KEEP_MUTATIONS",
 "inputStage" : {
 "stage" : "FETCH",
 "inputStage" : {
 "stage" : "IXSCAN",
 "keyPattern" : {
 "price" : -1
 },
 "indexName" : "price_-1",
 ...
 }
 }
 }
 },
 "rejectedPlans" : [ ]
 },
 "executionStats" : {
 "executionSuccess" : true,
 "nReturned" : 10,
 "executionTimeMillis" : 0,
 "totalKeysExamined" : 10,
 "totalDocsExamined" : 10,
 "executionStages" : {
 ...
 }
 },
 "serverInfo" : {
 ...
 },
 "ok" : 1
}

```

## 从多个 MongoDB 实例中读取

到目前为止，我们已经大谈特谈了从一个 MongoDB 实例中读取。然而，重要的是我们简要谈一下从分片环境或副本集中读取。

![从多个 MongoDB 实例中读取](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-dt-mdl/img/B04075_05_01.jpg)

当我们从分片中读取时，重要的是将分片键作为查询条件的一部分。这是因为当我们有分片键时，我们将针对一个特定的分片执行，而如果我们没有分片键，我们将强制在集群中的所有分片上执行。因此，在分片环境中查询的性能在很大程度上取决于分片键。

默认情况下，在 MongoDB 中有一个副本集时，我们总是从主节点读取。我们可以修改此行为，通过修改读取偏好来强制在辅助节点上执行读取操作。

假设我们有一个包含三个节点的副本集：`rs1s1`、`rs1s2`和`rs1s3`，`rs1s1`是主节点，`rs1s2`和`rs1s3`是辅助节点。要执行一个读操作并强制在辅助节点上进行读取，我们可以这样做：

```sql
db.customers.find().readPref({mode: 'secondary'})

```

此外，我们还有以下读取偏好选项：

+   `primary`，这是默认选项，将强制用户从主节点读取。

+   `primaryPreferred`，它将优先从主节点读取，但在不可用的情况下将从辅助节点读取。

+   `secondaryPreferred`，它将从辅助节点读取，但在不可用的情况下将从主节点读取。

+   `nearest`，它将从集群中网络延迟最低的节点读取。换句话说，就是从网络距离最短的节点读取，无论它是主节点还是辅助节点。

简而言之，如果我们的应用程序希望最大化一致性，那么我们应该优先考虑在主节点上进行读取；当我们寻求可用性时，我们应该使用`primaryPreferred`，因为我们可以保证大多数读取的一致性。当主节点出现问题时，我们可以依靠任何辅助节点。最后，如果我们寻求最低的延迟，我们可以使用`nearest`，提醒自己我们没有数据一致性的保证，因为我们优先考虑最低延迟的网络节点。

# 总结

在本章中，您学会了使用 MongoDB 的原生工具分析查询性能，并优化我们的查询。

在下一章中，我们将讨论如何通过功能或地理分离更好地管理我们的数据库和其集合。您还将了解如何维护应支持高读写吞吐量的集合。


# 第六章：管理数据

- 计划数据库操作是数据模型维护中最重要的阶段之一。在 MongoDB 中，根据数据的性质，我们可以通过功能或地理分组来隔离应用程序的操作。

在本章中，我们将回顾一些在第五章中已经介绍的概念，如读取偏好和写入关注。但这次我们将专注于理解这些功能如何帮助我们通过 MongoDB 部署分割操作，例如，分离读取和写入操作，或者考虑应用程序特性，通过副本集节点进行写入传播来确保信息一致性。

您还将了解如何通过探索特殊属性来支持高读/写吞吐量的集合，这对某些应用程序至关重要。

因此，在本章中，您将了解：

+   操作隔离

+   有限集合

+   - 数据自动过期

# 操作隔离

到目前为止，我们已经看到我们应用程序的查询如何影响了我们对文档设计的决策。然而，读取偏好和写入关注概念还有更多内容需要探讨。

MongoDB 为我们提供了一系列功能，允许我们通过功能或地理分组来隔离应用程序操作。在使用功能隔离时，我们可以指示负责报告生成的应用程序仅使用特定的 MongoDB 部署。地理隔离意味着我们可以针对距离 MongoDB 部署的地理距离来定位操作。

## - 优先考虑读操作

可以想象一旦构建了一个应用程序，营销或商业人员将要求提供应用程序数据的新报告，顺便说一句，这将是必不可少的报告。我们知道为了报告的目的而在我们的主数据库中构建和插入这样的应用程序是多么危险。除了与其他应用程序的数据并发性外，我们知道这种类型的应用程序可能通过进行复杂查询和操作大量数据来过载我们的数据库。

这就是为什么我们必须将处理大量数据并需要数据库更重的处理的操作定位到专用的 MongoDB 部署。我们将通过读取偏好使应用程序定位到正确的 MongoDB 部署，就像您在第五章中看到的那样，*优化查询*。

默认情况下，应用程序将始终从我们的副本集中读取第一个节点。这种行为确保应用程序始终读取最新的数据，从而确保数据的一致性。但是，如果意图是减少第一个节点的吞吐量，并且我们可以接受最终一致性，可以通过启用`secondary`或`secondaryPreferred`模式将读操作重定向到副本集中的辅助节点。

- 除了在主节点上减少吞吐量的功能之外，在次要节点中优先考虑读操作对于分布在多个数据中心的应用程序至关重要，因此我们在地理上分布了副本集。这是因为我们可以通过设置最近模式选择最近的节点或延迟最低的节点来执行读操作。

- 最后，通过使用`primaryPreferred`模式，我们可以大大提高数据库的可用性，允许读操作在任何副本集节点中执行。

但是，除了读取偏好规范，主要或次要，如果我们还可以指定将操作定位到哪个实例呢？例如，考虑一个分布在两个不同位置的副本集，每个实例都有不同类型的物理存储。除此之外，我们希望确保写操作将在至少一个具有**ssd**磁盘的每个数据中心的实例中执行。这是可能的吗？答案是*是*！

这是由于**标签集**。标签集是一个配置属性，可以控制副本集的写关注和读偏好。它们由一个包含零个或多个标签的文档组成。我们将把这个配置存储在副本集配置文档的`members[n].tags`字段中。

在读取偏好的情况下，标签集允许您为副本集的特定成员定位读取操作。当选择读取过程的副本集成员时，标签集值将被应用。

标签集只会影响读取偏好模式之一，即`primaryPreferred`、`secondary`、`secondaryPreferred`和`nearest`。标签集不会影响`primary`模式，这意味着它只会影响副本集次要成员的选择，除非与`nearest`模式结合使用，在这种情况下，最接近的节点或延迟最小的节点可以成为主节点。

在看如何进行此配置之前，您需要了解副本集成员是如何选择的。将执行操作的客户端驱动程序进行选择，或者在分片集群的情况下，选择是由**mongos**实例完成的。

因此，选择过程是这样进行的：

1.  创建主要和次要成员的列表。

1.  如果指定了标签集，则不符合规范的成员将被跳过。

1.  确定最接近应用程序的客户端。

1.  创建其他副本集成员的列表，考虑其他成员之间的延迟。此延迟可以在通过`secondaryAcceptableLatencyMS`属性执行写操作时定义。在分片集群的情况下，可以通过`--localThreshold`或`localPingThresholdMs`选项进行设置。如果没有设置这些配置中的任何一个，那么默认值将为 15 毫秒。

### 提示

您可以在 MongoDB 手册参考中找到有关此配置的更多信息[`docs.mongodb.org/manual/reference/configuration-options/#replication.localPingThresholdMs`](http://docs.mongodb.org/manual/reference/configuration-options/#replication.localPingThresholdMs)。

1.  将随机选择要执行操作的主机，并执行读操作。

标签集配置与任何其他 MongoDB 配置一样简单。与往常一样，我们使用文档来创建配置，并且如前所述，标签集是副本集配置文档的一个字段。可以通过在副本集成员上运行`conf()`方法来检索此配置文档。

### 提示

您可以在 MongoDB 文档中找到有关`conf()`方法的更多信息[`docs.mongodb.org/manual/reference/method/rs.conf/#rs.conf`](http://docs.mongodb.org/manual/reference/method/rs.conf/#rs.conf)。

以下文件显示了在`rs1`的 mongod shell 上执行`rs.conf()`命令后，读操作的标签集示例，这是我们副本集的主节点。

```sql
rs1:PRIMARY> rs.conf()
{ // This is the replica set configuration document

 "_id" : "rs1",
 "version" : 4,
 "members" : [
 {
 "_id" : 0,
 "host" : "172.17.0.2:27017"
 },
 {
 "_id" : 1,
 "host" : "172.17.0.3:27017"
 },
 {
 "_id" : 2,
 "host" : "172.17.0.4:27017"
 }
 ]
}

```

要为副本集的每个节点创建标签集配置，我们必须在主要的 mongod shell 中执行以下命令序列：

首先，我们将获取副本集配置文档并将其存储在`cfg`变量中：

```sql
rs1:PRIMARY> cfg = rs.conf()
{
 "_id" : "rs1",
 "version" : 4,
 "members" : [
 {
 "_id" : 0,
 "host" : "172.17.0.7:27017"
 },
 {
 "_id" : 1,
 "host" : "172.17.0.5:27017"
 },
 {
 "_id" : 2,
 "host" : "172.17.0.6:27017"
 }
 ]
}

```

然后，通过使用`cfg`变量，我们将为我们的三个副本集成员中的每一个设置一个文档作为`members[n].tags`字段的新值：

```sql
rs1:PRIMARY> cfg.members[0].tags = {"media": "ssd", "application": "main"}
rs1:PRIMARY> cfg.members[1].tags = {"media": "ssd", "application": "main"}
rs1:PRIMARY> cfg.members[2].tags = {"media": "ssd", "application": "report"}

```

最后，我们调用`reconfig()`方法，传入存储在`cfg`变量中的新配置文档以重新配置我们的副本集：

```sql
rs1:PRIMARY> rs.reconfig(cfg)

```

如果一切正确，我们必须在 mongod shell 中看到这个输出：

```sql
{ "ok" : 1 }

```

要检查配置，我们可以重新执行命令`rs.conf()`。这将返回以下内容：

```sql
rs1:PRIMARY> cfg = rs.conf()
{
 "_id" : "rs1",
 "version" : 5,
 "members" : [
 {
 "_id" : 0,
 "host" : "172.17.0.7:27017",
 "tags" : {
 "application" : "main",
 "media" : "ssd"
 }
 },
 {
 "_id" : 1,
 "host" : "172.17.0.5:27017",
 "tags" : {
 "application" : "main",
 "media" : "ssd"
 }
 },
 {
 "_id" : 2,
 "host" : "172.17.0.6:27017",
 "tags" : {
 "application" : "report",
 "media" : "ssd"
 }
 }
 ]
}

```

现在，考虑以下`customer`集合：

```sql
{
 "_id": ObjectId("54bf0d719a5bc523007bb78f"),
 "username": "customer1",
 "email": "customer1@customer.com",
 "password": "1185031ff57bfdaae7812dd705383c74",
 "followedSellers": [
 "seller3",
 "seller1"
 ]
}
{
 "_id": ObjectId("54bf0d719a5bc523007bb790"),
 "username": "customer2",
 "email": "customer2@customer.com",
 "password": "6362e1832398e7d8e83d3582a3b0c1ef",
 "followedSellers": [
 "seller2",
 "seller4"
 ]
}
{
 "_id": ObjectId("54bf0d719a5bc523007bb791"),
 "username": "customer3",
 "email": "customer3@customer.com",
 "password": "f2394e387b49e2fdda1b4c8a6c58ae4b",
 "followedSellers": [
 "seller2",
 "seller4"
 ]
}
{
 "_id": ObjectId("54bf0d719a5bc523007bb792"),
 "username": "customer4",
 "email": "customer4@customer.com",
 "password": "10619c6751a0169653355bb92119822a",
 "followedSellers": [
 "seller1",
 "seller2"
 ]
}
{
 "_id": ObjectId("54bf0d719a5bc523007bb793"),
 "username": "customer5",
 "email": "customer5@customer.com",
 "password": "30c25cf1d31cbccbd2d7f2100ffbc6b5",
 "followedSellers": [
 "seller2",
 "seller4"
 ]
}

```

接下来的读操作将使用我们副本集实例中创建的标签：

```sql
db.customers.find(
 {username: "customer5"}
).readPref(
 {
 tags: [{application: "report", media: "ssd"}]
 }
)
db.customers.find(
 {username: "customer5"}
).readPref(
 {
 tags: [{application: "main", media: "ssd"}]
 }
)

```

前面的配置是*按应用操作分离*的一个例子。我们创建了标签集，标记了应用的性质以及将要读取的媒体类型。

正如我们之前所看到的，当我们需要在地理上分离我们的应用时，标签集非常有用。假设我们在两个不同的数据中心中有 MongoDB 应用程序和副本集的实例。让我们通过在副本集主节点 mongod shell 上运行以下序列来创建标签，这些标签将指示我们的实例位于哪个数据中心。首先，我们将获取副本集配置文档并将其存储在`cfg`变量中：

```sql
rs1:PRIMARY> cfg = rs.conf()

```

然后，通过使用`cfg`变量，我们将为我们的三个副本集成员中的每一个设置一个文档作为`members[n].tags`字段的新值：

```sql
rs1:PRIMARY> cfg.members[0].tags = {"media": "ssd", "application": "main", "datacenter": "A"}
rs1:PRIMARY> cfg.members[1].tags = {"media": "ssd", "application": "main", "datacenter": "B"}
rs1:PRIMARY> cfg.members[2].tags = {"media": "ssd", "application": "report", "datacenter": "A"}

```

最后，我们调用`reconfig()`方法，传入存储在`cfg`变量中的新配置文档以重新配置我们的副本集：

```sql
rs1:PRIMARY> rs.reconfig(cfg)

```

如果一切正确，我们将在 mongod shell 中看到这个输出：

```sql
{ "ok" : 1 }

```

我们的配置结果可以通过执行命令`rs.conf()`来检查：

```sql
rs1:PRIMARY> rs.conf()
{
 "_id" : "rs1",
 "version" : 6,
 "members" : [
 {
 "_id" : 0,
 "host" : "172.17.0.7:27017",
 "tags" : {
 "application" : "main",
 "datacenter" : "A",
 "media" : "ssd"
 }
 },
 {
 "_id" : 1,
 "host" : "172.17.0.5:27017",
 "tags" : {
 "application" : "main",
 "datacenter" : "B",
 "media" : "ssd"
 }
 },
 {
 "_id" : 2,
 "host" : "172.17.0.6:27017",
 "tags" : {
 "application" : "report",
 "datacenter" : "A",
 "media" : "ssd"
 }
 }
 ]
}

```

为了将读操作定位到特定的数据中心，我们必须在查询中指定一个新的标签。以下查询将使用标签，并且每个查询将在自己的数据中心中执行：

```sql
db.customers.find(
 {username: "customer5"}
).readPref(
 {tags: [{application: "main", media: "ssd", datacenter: "A"}]}
) // It will be executed in the replica set' instance 0 
db.customers.find(
 {username: "customer5"}
).readPref(
 {tags: [{application: "report", media: "ssd", datacenter: "A"}]}
) //It will be executed in the replica set's instance 2 
db.customers.find(
 {username: "customer5"}
).readPref(
 {tags: [{application: "main", media: "ssd", datacenter: "B"}]}
) //It will be executed in the replica set's instance 1

```

在写操作中，标签集不用于选择可用于写入的副本集成员。尽管可以通过创建自定义写关注来在写操作中使用标签集。

让我们回到本节开头提出的要求。我们如何确保写操作将分布在地理区域的至少两个实例上？通过在副本集主节点 mongod shell 上运行以下命令序列，我们将配置一个具有五个实例的副本集：

```sql
rs1:PRIMARY> cfg = rs.conf()
rs1:PRIMARY> cfg.members[0].tags = {"riodc": "rack1"}
rs1:PRIMARY> cfg.members[1].tags = {"riodc": "rack2"}
rs1:PRIMARY> cfg.members[2].tags = {"riodc": "rack3"}
rs1:PRIMARY> cfg.members[3].tags = {"spdc": "rack1"}
rs1:PRIMARY> cfg.members[4].tags = {"spdc": "rack2"}
rs1:PRIMARY> rs.reconfig(cfg)

```

标签`riodc`和`spdc`表示我们的实例所在的地理位置。

现在，让我们创建一个自定义的`writeConcern` MultipleDC，使用`getLastErrorModes`属性。这将确保写操作将分布到至少一个位置成员。

为此，我们将执行前面的序列，其中我们在副本集配置文档的`settings`字段上设置了一个代表我们自定义写关注的文档：

```sql
rs1:PRIMARY> cfg = rs.conf()
rs1:PRIMARY> cfg.settings = {getLastErrorModes: {MultipleDC: {"riodc": 1, "spdc":1}}}

```

mongod shell 中的输出应该是这样的：

```sql
{
 "getLastErrorModes" : {
 "MultipleDC" : {
 "riodc" : 1,
 "spdc" : 1
 }
 }
}

```

然后我们调用`reconfig()`方法，传入新的配置：

```sql
rs1:PRIMARY> rs.reconfig(cfg)

```

如果执行成功，在 mongod shell 中的输出将是这样的文档：

```sql
{ "ok" : 1 }

```

从这一刻起，我们可以使用`writeConcern` MultipleDC 来确保写操作将在每个显示的数据中心的至少一个节点中执行，如下所示：

```sql
db.customers.insert(
 {
 username: "customer6", 
 email: "customer6@customer.com",
 password: "1185031ff57bfdaae7812dd705383c74", 
 followedSellers: ["seller1", "seller3"]
 }, 
 {
 writeConcern: {w: "MultipleDC"} 
 }
)

```

回到我们的要求，如果我们希望写操作至少在每个数据中心的两个实例中执行，我们必须按以下方式配置：

```sql
rs1:PRIMARY> cfg = rs.conf()
rs1:PRIMARY> cfg.settings = {getLastErrorModes: {MultipleDC: {"riodc": 2, "spdc":2}}}
rs1:PRIMARY> rs.reconfig(cfg)

```

并且，满足我们的要求，我们可以创建一个名为`ssd`的`writeConcern` MultipleDC。这将确保写操作将发生在至少一个具有这种类型磁盘的实例中：

```sql
rs1:PRIMARY> cfg = rs.conf()
rs1:PRIMARY> cfg.members[0].tags = {"riodc": "rack1", "ssd": "ok"}
rs1:PRIMARY> cfg.members[3].tags = {"spdc": "rack1", "ssd": "ok"}
rs1:PRIMARY> rs.reconfig(cfg)
rs1:PRIMARY> cfg.settings = {getLastErrorModes: {MultipleDC: {"riodc": 2, "spdc":2}, ssd: {"ssd": 1}}}
rs1:PRIMARY> rs.reconfig(cfg)

```

在下面的查询中，我们看到使用`writeConcern` MultipleDC 需要写操作至少出现在具有`ssd`的一个实例中：

```sql
db.customers.insert(
 {
 username: "customer6", 
 email: "customer6@customer.com", 
 password: "1185031ff57bfdaae7812dd705383c74", 
 followedSellers: ["seller1", "seller3"]
 }, 
 {
 writeConcern: {w: "ssd"} 
 }
)

```

在我们的数据库中进行操作分离并不是一项简单的任务。但是，对于数据库的管理和维护非常有用。这种任务的早期实施需要对我们的数据模型有很好的了解，因为数据库所在的存储的细节非常重要。

在下一节中，我们将看到如何为需要高吞吐量和快速响应时间的应用程序规划集合。

### 提示

如果您想了解如何配置副本集标签集，可以访问 MongoDB 参考手册[`docs.mongodb.org/manual/tutorial/configure-replica-set-tag-sets/#replica-set-configuration-tag-sets`](http://docs.mongodb.org/manual/tutorial/configure-replica-set-tag-sets/#replica-set-configuration-tag-sets)。

# 固定大小集合

非功能性需求通常与应用程序的响应时间有关。特别是在当今时代，我们一直连接到新闻源，希望最新信息能在最短的响应时间内可用。

MongoDB 有一种特殊类型的集合，满足非功能性需求，即固定大小的集合。固定大小的集合支持高读写吞吐量。这是因为文档按其自然顺序插入，无需索引执行写操作。

MongoDB 保证了自然插入顺序，将数据写入磁盘。因此，在文档的生命周期中不允许增加文档大小的更新。一旦集合达到最大大小，MongoDB 会自动清理旧文档，以便插入新文档。

一个非常常见的用例是应用程序日志的持久性。MongoDB 本身使用副本集操作日志`oplog.rs`作为固定大小集合。在第八章*使用 MongoDB 进行日志记录和实时分析*中，您将看到另一个实际示例。

MongoDB 的另一个非常常见的用途是作为发布者/订阅者系统，特别是如果我们使用可追溯的游标。可追溯的游标是即使客户端读取了所有返回的记录，仍然保持打开状态的游标。因此，当新文档插入集合时，游标将其返回给客户端。

以下命令创建`ordersQueue`集合：

```sql
db.createCollection("ordersQueue",{capped: true, size: 10000})

```

我们使用`util`命令`createCollection`创建了我们的固定大小集合，传递给它名称`ordersQueue`和一个带有`capped`属性值为`true`和`size`值为`10000`的集合。如果`size`属性小于 4,096，MongoDB 会调整为 4,096 字节。另一方面，如果大于 4,096，MongoDB 会提高大小并调整为 256 的倍数。

可选地，我们可以使用`max`属性设置集合可以拥有的最大文档数量：

```sql
db.createCollection(
 "ordersQueue",
 {capped: true, size: 10000, max: 5000}
)

```

### 注意

如果我们需要将集合转换为固定大小集合，应该使用`convertToCapped`方法如下：

```sql
db.runCommand(
 {"convertToCapped": " ordersQueue ", size: 100000}
)

```

正如我们已经看到的，MongoDB 按自然顺序保留文档，换句话说，按照它们插入 MongoDB 的顺序。考虑以下文档，如`ordersQueue`集合中所示插入：

```sql
{
 "_id" : ObjectId("54d97db16840a9a7c089fa30"), 
 "orderId" : "order_1", 
 "time" : 1423539633910 
}
{
 "_id" : ObjectId("54d97db66840a9a7c089fa31"), 
 "orderId" : "order_2", 
 "time" : 1423539638006 
}
{
 "_id" : ObjectId("54d97dba6840a9a7c089fa32"), 
 "orderId" : "order_3", 
 "time" : 1423539642022 
}
{
 "_id" : ObjectId("54d97dbe6840a9a7c089fa33"), 
 "orderId" : "order_4", 
 "time" : 1423539646015 
}
{
 "_id" : ObjectId("54d97dcf6840a9a7c089fa34"), 
 "orderId" : "order_5", 
 "time" : 1423539663559 
}

```

查询`db.ordersQueue.find()`产生以下结果：

```sql
{ 
 "_id" : ObjectId("54d97db16840a9a7c089fa30"), 
 "orderId" : "order_1", 
 "time" : 1423539633910 
}
{ 
 "_id" : ObjectId("54d97db66840a9a7c089fa31"), 
 "orderId" : "order_2", 
 "time" : 1423539638006 
}
{ 
 "_id" : ObjectId("54d97dba6840a9a7c089fa32"), 
 "orderId" : "order_3", 
 "time" : 1423539642022 
}
{ 
 "_id" : ObjectId("54d97dbe6840a9a7c089fa33"), 
 "orderId" : "order_4", 
 "time" : 1423539646015 
}
{ 
 "_id" : ObjectId("54d97dcf6840a9a7c089fa34"), 
 "orderId" : "order_5", 
 "time" : 1423539663559 
}

```

如果我们像以下查询中所示使用`$natural`操作符，将得到与前面输出中相同的结果：

```sql
db.ordersQueue.find().sort({$natural: 1})

```

但是，如果我们需要最后插入的文档先返回，我们必须在`$natural`操作符上执行带有`-1`值的命令：

```sql
db.ordersQueue.find().sort({$natural: -1})

```

在创建固定大小集合时，我们必须小心：

+   我们不能对固定大小集合进行分片。

+   我们不能在固定大小集合中更新文档；否则，文档会增大。如果需要在固定大小集合中更新文档，则必须确保大小保持不变。为了更好的性能，在更新时应创建索引以避免集合扫描。

+   我们无法在封顶集合中删除文档。

当我们具有高读/写吞吐量作为非功能性要求，或者需要按字节大小或文档数量限制集合大小时，封顶集合是一个很好的工具。

尽管如此，如果我们需要根据时间范围自动使数据过期，我们应该使用**生存时间**（TTL）函数。

# 数据自动过期

正如您在第四章中已经看到的，MongoDB 为我们提供了一种索引类型，可以帮助我们在一定时间后或特定日期之后从集合中删除数据。

实际上，TTL 是在 mongod 实例上执行的后台线程，它会查找索引上具有日期类型字段的文档，并将其删除。

考虑一个名为`customers`的集合，其中包含以下文档：

```sql
{ 
 "_id" : ObjectId("5498da405d0ffdd8a07a87ba"), 
 "username" : "customer1", 
 "email" : "customer1@customer.com", 
 "password" : "b1c5098d0c6074db325b0b9dddb068e1", "accountConfirmationExpireAt" : ISODate("2015-01-11T20:27:02.138Z") 
}

```

为了在 360 秒后使该集合中的文档过期，我们应该创建以下索引：

```sql
db.customers.createIndex(
 {accountConfirmationExpireAt: 1}, 
 {expireAfterSeconds: 3600}
)

```

为了在 2015-01-11 20:27:02 准确地使文档过期，我们应该创建以下索引：

```sql
db.customers.createIndex(
 {accountConfirmationExpireAt: 1}, 
 {expireAfterSeconds: 0}
)

```

在使用 TTL 函数时，我们必须格外小心，并牢记以下几点：

+   我们无法在封顶集合上创建 TTL 索引，因为 MongoDB 无法从集合中删除文档。

+   TTL 索引不能具有作为另一个索引一部分的字段。

+   索引字段应为日期或日期类型的数组。

+   尽管在每个副本集节点中都有后台线程，可以在具有 TTL 索引时删除文档，但它只会从主节点中删除它们。复制过程将从副本集的辅助节点中删除文档。

# 总结

在本章中，您看到了除了根据我们的查询来思考架构设计之外，还要考虑规划操作和维护来创建我们的集合。

您学会了如何使用标签集来处理数据中心感知操作，以及为什么通过创建封顶集合来限制我们集合中存储的文档数量。同样，您还了解了 TTL 索引在实际用例中的用处。

在下一章中，您将看到如何通过创建分片来扩展我们的 MongoDB 实例。


# 第七章：扩展

多年来，可扩展性一直是一个备受讨论的话题。尽管关于它已经有很多言论，但这个话题非常重要，在这本书中，它肯定也会找到自己的位置。

我们不感兴趣涉及涉及数据库可扩展性的所有概念，特别是在 NoSQL 数据库中，而是展示 MongoDB 在处理我们的集合时提供的可能性以及 MongoDB 数据模型的灵活性如何影响我们的选择。

可以基于简单的基础架构和低成本的分片请求来水平扩展 MongoDB。分片是通过多个名为“分片”的物理分区分发数据的技术。尽管数据库在物理上被分区，但对于我们的客户来说，数据库本身是一个单一实例。分片技术对数据库的客户完全透明。

亲爱的读者，准备好了吗！在本章中，您将看到一些关于数据库维护的关键主题，例如：

+   使用分片进行横向扩展

+   选择分片键

+   扩展社交收件箱架构设计

# 使用分片来扩展 MongoDB

当我们谈论数据库的可扩展性时，有两种参考方法：

+   **纵向扩展或垂直扩展**：在这种方法中，我们向一台机器添加更多资源。例如，CPU、磁盘和内存，以增加系统的容量。

+   **横向扩展或水平扩展**：在这种方法中，我们向系统添加更多节点，并在可用节点之间分配工作。

选择其中一种并不取决于我们的意愿，而是取决于我们想要扩展的系统。有必要了解是否可能以我们想要的方式扩展该系统。我们还必须记住这两种技术之间存在差异和权衡。

增加存储容量、CPU 或内存可能非常昂贵，有时甚至由于服务提供商的限制而不可能。另一方面，增加系统中的节点数量也可能会增加概念上和操作上的复杂性。

然而，考虑到虚拟化技术的进步和云服务提供商提供的便利，对于某些应用程序来说，横向扩展正在成为更实际的解决方案。

MongoDB 准备好了进行水平扩展。这是通过分片技术来实现的。这种技术包括对数据集进行分区，并将数据分布在许多服务器之间。分片的主要目的是支持能够通过在每个分片之间分配操作负载来处理高吞吐量操作的更大型数据库。

例如，如果我们有一个 1TB 的数据库和四个配置好的分片，每个分片应该有 256GB 的数据。但是，这并不意味着每个分片将管理 25%的吞吐量操作。这将完全取决于我们决定构建分片的方式。这是一个巨大的挑战，也是本章的主要目标。

以下图表展示了 MongoDB 中分片的工作原理：

![使用分片扩展 MongoDB](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-dt-mdl/img/B04075_07_01.jpg)

在撰写本书时，MongoDB 在其 3.0 版本中提供了多种分片策略：基于范围、基于哈希和基于位置的分片。

+   在基于范围的策略中，MongoDB 将根据分片键的值对数据进行分区。接近彼此的分片键值的文档将分配到同一个分片中。

+   在基于哈希的策略中，文档是根据分片键的 MD5 值进行分布的。

+   在基于位置的策略中，文档将根据将分片范围值与特定分片相关联的配置分布在分片中。这种配置使用标签来实现，这与我们在第六章中看到的“管理数据”中讨论的操作隔离非常相似。

在 MongoDB 中，分片工作在集合级别，这意味着我们可以在同一个数据库中启用分片和不启用分片的集合。要在集合中设置分片，我们必须配置一个分片集群。分片集群的元素包括分片、查询路由器和配置服务器：

+   **分片**是我们的数据集的一部分将被分配的地方。一个分片可以是一个 MongoDB 实例或一个副本集

+   **查询路由器**是为数据库客户端提供的接口，负责将操作定向到正确的分片

+   **配置服务器**是一个负责保持分片集群配置或者说是集群元数据的 MongoDB 实例

以下图显示了一个共享集群及其组件：

![使用分片扩展 MongoDB](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-dt-mdl/img/B04075_07_02.jpg)

我们不会深入讨论分片集群的创建和维护，因为这不是本章的目标。然而，重要的是要知道，分片集群的设置取决于场景。

在生产环境中，最低建议的设置是至少三个配置服务器，两个或更多副本集，这将是我们的分片，以及一个或多个查询路由器。通过这样做，我们可以确保环境的最低冗余和高可用性。

## 选择分片键

一旦我们决定我们需要一个分片集群，下一步就是选择分片键。分片键负责确定文档在集群的分片之间的分布。这些也将是决定我们的数据库成功或失败的关键因素。

对于每个写操作，MongoDB 将根据分片键的范围值分配一个新文档。分片键的范围也被称为**块**。一个块的默认长度为 64MB，但如果您希望将此值定制到您的需求，它是可以配置的。在下图中，您可以看到如何在给定一个从负无穷到正无穷的数字分片键上分布文档：

![选择分片键](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-dt-mdl/img/B04075_07_03.jpg)

在开始讨论可能影响我们分片键构建的事情之前，必须尊重 MongoDB 中的一些限制。这些限制是重要的，在某些方面，它们帮助我们消除我们选择中的一些错误的可能性。

分片键的长度不能超过 512 字节。分片键是文档中的索引字段。这个索引可以是一个简单的字段或一个组合的字段，但它永远不会是一个多键字段。自 MongoDB 2.4 版本以来，也可以使用简单哈希字段的索引。

以下信息必须安静地阅读，就像一个咒语，这样你就不会从一开始就犯任何错误。

### 注意

你必须记住一件事：分片键是不可更改的。

重申一遍，分片键是不可更改的。这意味着，亲爱的读者，一旦创建了分片键，你就永远无法更改它。永远！

您可以在 MongoDB 手册参考[`docs.mongodb.org/manual/reference/limits/#sharded-clusters`](http://docs.mongodb.org/manual/reference/limits/#sharded-clusters)中找到有关 MongoDB 分片集群限制的详细信息。

但如果我创建了一个分片键，我想要改变它怎么办？我应该怎么做？与其试图改变它，我们应该做以下事情：

1.  在磁盘文件中执行数据库的转储。

1.  删除集合。

1.  使用新的分片键配置一个新的集合。

1.  执行预分割的块。

1.  恢复转储文件。

正如你所看到的，我们不改变分片键。我们几乎是从头开始重新创建的。因此，在执行分片键创建的命令时要小心，否则如果需要更改它，你会头疼的。

### 注意

你需要记住的下一个信息是，你不能更新分片键的一个或多个字段的值。换句话说，分片键的值也是不可更改的。

尝试在分片键的字段中执行`update()`方法是没有用的。它不起作用。

在我们继续之前，让我们实际看一下我们到目前为止讨论的内容。让我们为测试创建一个分片集群。以下的分片配置对于测试和开发非常有用。在生产环境中永远不要使用这个配置。给出的命令将创建：

+   两个分片

+   一个配置服务器

+   一个查询路由器

作为第一步，让我们启动一个配置服务器实例。配置服务器只是一个带有初始化参数`--configsvr`的`mongod`实例。如果我们不为参数`--port <port number>`设置一个值，它将默认在端口 27019 上启动：

```sql
mongod --fork --configsvr --dbpath /data/configdb --logpath /log/configdb.log

```

下一步是启动查询路由器。查询路由器是一个`mongos` MongoDB 实例，它使用参数`--configdb <configdb hostname or ip:port>`来将查询和写操作路由到分片，该参数指示配置服务器。默认情况下，MongoDB 在端口 27017 上启动它：

```sql
mongos --fork --configdb localhost --logpath /log/router.log

```

最后，让我们启动分片。在这个例子中，分片将是两个简单的`mongod`实例。与`mongos`类似，`mongod`实例默认在端口 27017 上启动。由于我们已经在这个端口上启动了`mongos`实例，让我们为`mongod`实例设置一个不同的端口：

```sql
mongod --fork --dbpath /data/mongod1 --port 27001 --logpath /log/mongod1.log
mongod --fork --dbpath /data/mongod2 --port 27002 --logpath /log/mongod2.log

```

完成！现在我们为测试分片集群建立了基本的基础设施。但是，等等！我们还没有一个分片集群。下一步是向集群添加分片。为此，我们必须将已经启动的`mongos`实例连接到查询路由器：

```sql
mongo localhost:27017

```

一旦在`mongos` shell 中，我们必须以以下方式执行`addShard`方法：

```sql
mongos> sh.addShard("localhost:27001")
mongos> sh.addShard("localhost:27002")

```

如果我们想要检查前面操作的结果，我们可以执行`status()`命令，并查看关于创建的分片的一些信息：

```sql
mongos> sh.status()
--- Sharding Status --- 
 sharding version: {
 "_id" : 1,
 "minCompatibleVersion" : 5,
 "currentVersion" : 6,
 "clusterId" : ObjectId("54d9dc74fadbfe60ef7b394e")
}
 shards:
 {  "_id" : "shard0000",  "host" : "localhost:27001" }
 {  "_id" : "shard0001",  "host" : "localhost:27002" }
 databases:
 {  "_id" : "admin",  "partitioned" : false,  "primary" : "config" }

```

在返回的文档中，我们只能看到基本信息，比如我们的分片集群的主机是谁，我们有哪些数据库。目前，我们没有任何使用分片启用的集合。因此，信息被大大简化了。

现在我们有了分片、配置服务器和查询路由器，让我们在数据库中启用分片。在对集合进行相同操作之前，必须先在数据库中启用分片。以下命令在名为`ecommerce`的数据库中启用分片：

```sql
mongos> sh.enableSharding("ecommerce")

```

通过查询分片集群的状态，我们可以注意到我们有关于我们的`ecommerce`数据库的信息：

```sql
mongos> sh.status()
--- Sharding Status --- 
 sharding version: {
 "_id" : 1,
 "minCompatibleVersion" : 5,
 "currentVersion" : 6,
 "clusterId" : ObjectId("54d9dc74fadbfe60ef7b394e")
}
 shards:
 {  "_id" : "shard0000",  "host" : "172.17.0.23:27017" }
 {  "_id" : "shard0001",  "host" : "172.17.0.24:27017" }
 databases:
 {  "_id" : "admin",  "partitioned" : false,  "primary" : "config" }
 {  "_id" : "ecommerce",  "partitioned" : true,  "primary" : "shard0000" }

```

考虑一下，在`ecommerce`数据库中，我们有一个`customers`集合，其中包含以下文档：

```sql
{
 "_id" : ObjectId("54fb7110e7084a229a66eda2"),
 "isActive" : true,
 "age" : 28,
 "name" : "Paige Johnson",
 "gender" : "female",
 "email" : "paigejohnson@combot.com",
 "phone" : "+1 (830) 484-2397",
 "address" : {
 "city" : "Dennard",
 "state" : "Kansas",
 "zip" : 2492,
 "latitude" : -56.564242,
 "longitude" : -160.872178,
 "street" : "998 Boerum Place"
 },
 "registered" : ISODate("2013-10-14T14:44:34.853Z"),
 "friends" : [
 {
 "id" : 0,
 "name" : "Katelyn Barrett"
 },
 {
 "id" : 1,
 "name" : "Weeks Valentine"
 },
 {
 "id" : 2,
 "name" : "Wright Jensen"
 }
 ]
}

```

我们必须执行`shardCollection`命令来在这个集合中启用分片，使用集合名称和一个将代表我们的分片键的文档作为参数。

通过在`mongos` shell 中执行以下命令来启用`customers`集合中的分片：

```sql
mongos> sh.shardCollection("ecommerce.customers", {"address.zip": 1, "registered": 1})
{
 "proposedKey" : {
 "address.zip" : 1,
 "registered" : 1
 },
 "curIndexes" : [
 {
 "v" : 1,
 "key" : {
 "_id" : 1
 },
 "name" : "_id_",
 "ns" : "ecommerce.customers"
 }
 ],
 "ok" : 0,
 "errmsg" : "please create an index that starts with the shard key before sharding."
}

```

正如你所看到的，命令执行过程中出现了一些问题。MongoDB 警告我们必须有一个索引，并且分片键必须是一个前缀。因此，我们必须在`mongos` shell 上执行以下序列：

```sql
mongos> db.customers.createIndex({"address.zip": 1, "registered": 1})
mongos> sh.shardCollection("ecommerce.customers", {"address.zip": 1, "registered": 1})
{ "collectionsharded" : "ecommerce.customers", "ok" : 1 }

```

干得好！现在我们有了启用了分片的`ecommerce`数据库的`customers`集合。

### 注意

如果你正在对一个空集合进行分片，`shardCollection`命令将创建分片键的索引。

但是是什么因素决定了选择`address.zip`和`registered`作为分片键？在这种情况下，正如我之前所说的，我选择了一个随机字段来进行说明。从现在开始，让我们考虑什么因素可以确定一个好的分片键的创建。

## 选择分片键时的基本注意事项

选择分片键并不是一项容易的任务，也没有固定的配方。大多数情况下，提前了解我们的领域及其用途是至关重要的。在进行此操作时要非常小心。一个不太合适的分片键可能会给我们的数据库带来一系列问题，从而影响其性能。

首先是可分性。我们必须考虑一个分片键，使我们能够在分片之间可视化文档的分割。具有有限数量值的分片键可能导致“不可分割”的块。

我们可以说，这个领域必须具有高基数，例如具有高多样性值和唯一字段的字段。识别字段，如电子邮件地址、用户名、电话号码、社会安全号码和邮政编码，是高基数字段的一个很好的例子。

实际上，如果考虑到某种情况，它们每一个都可以是独特的。在电子商务系统中，如果我们有一个与装运相关的文档，我们将有多个具有相同邮政编码的文档。但是，考虑另一个例子，一个城市中美容沙龙的目录系统。那么，如果一个文档代表一个美容沙龙，那么邮政编码将比在前一个例子中更独特。

第三点可能是迄今为止最有争议的，因为它在某种程度上与上一个点相矛盾。我们已经看到，具有高随机性的分片键是尝试增加写操作性能的良好实践。现在，我们将考虑创建一个分片键以针对单个分片。当我们考虑读操作的性能时，从单个分片读取是一个好主意。正如您已经知道的，在分片集群中，数据库复杂性被抽象为查询路由器。换句话说，发现应该在哪些分片上搜索查询中请求的信息是**mongos**的责任。如果我们的分片键分布在多个分片上，那么`mongos`将在分片上搜索信息，收集并合并它们，然后交付。但是，如果分片键旨在针对单个分片，那么 mongos 任务将在这个唯一的分片中搜索信息，然后交付。

第四个也是最后一个点是关于当文档中没有任何字段适合作为我们的分片键的选择时。在这种情况下，我们必须考虑一个组合的分片键。在前面的例子中，我们使用了一个由字段`address.zip`和`registered`组成的分片键。组合的分片键也将帮助我们拥有一个更可分的键，因为如果分片键的第一个值没有高基数，添加第二个值将增加基数。

因此，这些基本问题告诉我们，根据我们想要搜索的内容，我们应该选择不同的分片键文档方法。如果我们需要查询隔离，那么可以专注于一个分片的分片键是一个不错的选择。但是，当我们需要扩展写操作时，我们的分片键越随机，对性能的影响就越好。

# 扩展社交收件箱模式设计

2014 年 10 月 31 日，MongoDB 公司在其社区博客上介绍了解决一个非常常见的问题，社交收件箱的三种不同方法。

### 注意

如果您想查看博客文章，请参阅[`blog.mongodb.org/post/65612078649/schema-design-for-social-inboxes-in-mongodb`](http://blog.mongodb.org/post/65612078649/schema-design-for-social-inboxes-in-mongodb)。

从所呈现的三种模式设计中，可以看到我们迄今为止以一种简单有效的方式应用了所有扩展概念。在所有情况下，都应用了扇出的概念，即工作负载在分片之间并行分布。每种方法都根据数据库客户端的需求有其自己的应用。

三种模式设计是：

+   在读取时进行扇出操作

+   在写入时进行扇出操作

+   在写入时进行扇出操作

## 在读取时进行扇出操作

由于查询路由器在客户端读取收件箱时的行为，扇出读设计被称为这个名字。与其他设计相比，它被认为是具有最简单机制的设计。它也是最容易实现的。

在扇出读设计中，我们将有一个“收件箱”集合，我们将在其中插入每条新消息。将驻留在此集合中的文档有四个字段：

+   `from`：表示消息发送者的字符串

+   `to`：包含所有消息接收者的数组

+   `sent`：表示消息发送给接收者的日期字段

+   `message`：表示消息本身的字符串字段

在下面的文件中，我们可以看到一个从约翰发送给迈克和比莉的消息的示例：

```sql
{
from: "John", 
to: ["Mike", "Billie"], 
sent: new Date(), 
message: "Hey Mike, Billie"
}

```

这个集合上的操作将是所有操作中最直接的。发送消息就是在“收件箱”集合中进行插入操作，而读取消息就是查找具有特定接收者的所有消息。

要在数据库上启用分片，我们的“收件箱”集合位于一个名为`social`的数据库中。为了做到这一点，以及我们在本章中将要做的所有其他事情，我们将使用`mongos` shell。所以，让我们开始吧：

```sql
mongos> sh.enableSharding("social")

```

现在，我们将不得不创建集合的分片键。为了实现这个设计，我们将使用“收件箱”集合的`from`字段创建一个分片键：

```sql
mongos> sh.shardCollection("social.inbox", {from: 1})

```

### 注意

如果我们的集合已经有文档，我们应该为分片键字段创建索引。

最后一步是在`to`和`sent`字段上创建一个复合索引，以寻求更好的读操作性能：

```sql
mongos> db.inbox.createIndex({to: 1, sent: 1})

```

我们现在准备好在我们的“收件箱”集合中发送和读取消息了。在`mongos` shell 上，让我们创建一条消息并将其发送给接收者：

```sql
mongos> var msg = {
from: "John", 
to: ["Mike", "Billie"], 
sent: new Date(), 
message: "Hey Mike, Billie"
}; // this command creates a msg variable and stores a message json as a value
mongos> db.inbox.insert(msg); // this command inserts the message on the inbox collection

```

如果我们想读取迈克的收件箱，我们应该使用以下命令：

```sql
mongos> db.inbox.find({to: "Mike"}).sort({sent: -1})

```

在这种设计中，写操作可能被认为是有效的。根据活跃用户的数量，我们将在分片之间有均匀的数据分布。

另一方面，查看收件箱并不那么有效。每次收件箱读取都会使用`to`字段进行`find`操作，并按`sent`字段排序。因为我们的集合将`from`字段作为分片键，这意味着消息在分片上是按发送者分组的，所以任何不使用分片键的查询都将被路由到所有分片。

如果我们的应用程序旨在发送消息，这种设计就适用。由于我们需要一个社交应用程序，其中您可以发送和阅读消息，让我们来看看下一个设计方法，即扇出写。

## 扇出写

使用扇出写设计，我们可以说与之前相比，我们将产生相反的效果。在扇出读中，我们到达了集群上的每个分片来查看收件箱，而在扇出写中，我们将在所有分片之间分发写操作。

为了实现扇出写而不是在发送者上进行分片，我们将在消息的接收者上进行分片。以下命令在“收件箱”集合中创建了分片键：

```sql
mongos> sh.shardCollection("social.inbox", {recipient: 1, sent: 1})

```

我们将使用在扇出读设计中使用的相同文档。因此，要将一条消息从约翰发送给迈克和比莉，我们将在`mongos` shell 中执行以下命令：

```sql
mongos> var msg = {
 "from": "John",
 "to": ["Mike", "Billie"], // recipients
 "sent": new Date(),
 "message": "Hey Mike, Billie"
}

mongos> for(recipient in msg.to){ // iterate though recipients
msg.recipient = msg.to[recipient]; // creates a recipient field on the message and stores the recipient of the message
db.inbox.insert(msg); // inserts the msg document for every recipient
}

```

为了更好地理解发生了什么，让我们做一个小的代码分解：

+   我们应该做的第一件事是创建一个`msg`变量，并在那里存储一个 JSON 消息：

```sql
var msg = {
 "from": "John",
 "to": ["Mike", "Billie"], // recipients
 "sent": new Date(),
 "message": "Hey Mike, Billie"
}

```

+   要向每个接收者发送消息，我们必须迭代`to`字段中的值，在消息 JSON 中创建一个新字段`msg.recipient`，并存储消息的接收者：

```sql
for(recipient in msg.to){
msg.recipient = msg.to[recipient];

```

+   最后，我们将消息插入“收件箱”集合中：

```sql
db.inbox.insert(msg); 
}

```

对于消息的每个接收者，我们将在“收件箱”集合中插入一个新文档。在`mongos` shell 上执行的以下命令显示了迈克的收件箱：

```sql
mongos> db.inbox.find ({recipient: "Mike"}).sort({ sent:-1})
{
 "_id": ObjectId("54fe6319b40b90bd157eb0b8"),
 "from": "John",
 "to": [
 "Mike",
 "Billie"
 ],
 "sent": ISODate("2015-03-10T03:20:03.597Z"),
 "message": "Hey Mike, Billie",
 "recipient": "Mike"
}

```

由于消息同时有迈克和比莉作为接收者，我们也可以阅读比莉的收件箱：

```sql
mongos> db.inbox.find ({recipient: "Billie"}).sort({ sent:-1})
{
 "_id": ObjectId("54fe6319b40b90bd157eb0b9"),
 "from": "John",
 "to": [
 "Mike",
 "Billie"
 ],
 "sent": ISODate("2015-03-10T03:20:03.597Z"),
 "message": "Hey Mike, Billie",
 "recipient": "Billie"
}

```

通过这样做，当我们读取用户的收件箱时，我们将针对单个分片，因为我们使用分片键作为查找查询的条件。

但是，即使我们只能到达一个分片来查看收件箱，当用户数量增长时，我们将有许多随机读取。为了解决这个问题，我们将介绍分桶的概念。

## 写入时的扇出与桶

写入时的扇出设计是解决社交收件箱问题的一个非常有趣的方法。每当需要时，我们可以向集群中添加更多的分片，并且收件箱数据将在它们之间均匀分布。然而，正如我们之前所述，随着数据库的增长，我们所做的随机读取是我们必须处理的瓶颈。尽管我们通过使用分片键作为查找查询的条件来针对读操作目标单个分片，但在查看收件箱时我们将始终进行随机读取。假设每个用户平均有 50 条消息，那么每次查看收件箱都会产生 50 次随机读取。因此，当我们将这些随机读取与同时访问其收件箱的用户相乘时，我们可以想象我们将如何快速饱和我们的数据库。

为了减少这种瓶颈，出现了写入时的扇出与桶方法。扇出与桶是对写入时的扇出的改进，通过将消息分桶在按时间排序的消息文档中。

这种设计的实现与以前的设计相比有很大不同。在写入时的扇出与桶中，我们将有两个集合：

+   一个`users`集合

+   一个`inbox`集合

`users`集合将具有包含用户数据的文档。在此文档中，除了基本用户信息外，我们还有一个字段，用于存储用户拥有的收件箱消息总数。

`inbox`集合将存储具有一组用户消息的文档。我们将在此集合中有一个`owner`字段，用于标识用户，以及一个`sequence`字段，用于标识桶。这些是我们将使用的字段来对`inbox`集合进行分片。

在我们的示例中，每个桶将有 50 条消息。以下命令将在社交数据库上启用分片，并在`inbox`集合中创建分片键：

```sql
mongos> sh.enableSharding("social")
mongos> sh.shardCollection("social.inbox", {owner: 1, sequence: 1})

```

正如之前提到的，我们还有一个`users`集合。以下命令在`user`集合中创建一个分片键：

```sql
mongos> sh.shardCollection("social.users", {user_name: 1})

```

现在我们已经创建了分片键，让我们从 John 发送一条消息给 Mike 和 Billie。消息文档将与之前的非常相似。它们之间的区别在于`owner`和`sequence`字段。在`mongos` shell 上执行以下代码将从 John 发送一条消息给 Mike 和 Billie：

```sql
mongos> var msg = { 
 "from": "John",
 "to": ["Mike", "Billie"], //recipients
 "sent": new Date(),
 "message": "Hey Mike, Billie"
}

mongos> for(recipient in msg.to) {

var count = db.users.findAndModify({
 query: {user_name: msg.to[recipient]},
 update:{"$inc":{"msg_count":1}},
 upsert: true,
 new: true}).msg_count;

 var sequence = Math.floor(count/50);

 db.inbox.update({
 owner: msg.to[recipient], sequence: sequence},
 {$push:{"messages":msg}},
 {upsert: true});
}

```

与之前一样，为了理解发送消息，让我们对代码进行分解：

+   首先，我们创建一个`msg`变量，并将消息 JSON 存储在其中

+   我们遍历`to`字段中的收件人，并执行`findAndModify`方法，在其中我们查找`users`集合中的文档以确定消息接收者的所有者。由于我们使用了`upsert`选项，并将其值设为`true`，如果我们没有找到用户，那么我们将创建一个新用户。`update`字段使用了`$inc`运算符，这意味着我们将`msg_count`字段增加一。该方法还使用了`new`选项，并且我们将执行保存的文档作为此命令的结果。

+   从返回的文档中，我们获取`msg_count`字段的值，该字段表示用户的总消息数，并将该值存储在`count`变量中。

+   为了发现消息将被保存的存储桶，我们将使用`mongos` shell 上可用的`Math`类的`floor`函数。正如我们之前所说，我们将在每个存储桶中有 50 条消息，因此我们将通过 50 除以`count`变量的值，并得到结果的`floor`函数。例如，如果我们发送第三条用户消息，那么保存此消息的存储桶的结果是`Math.floor(3/50)`，即 0。当我们达到第 50 条消息时，存储桶的值变为 1，这意味着下一条消息将在一个新的存储桶中。

+   我们将更新`收件箱`集合中具有我们计算的`所有者`和`序列`值的文档。由于我们在`update`命令上使用了`upsert`选项，并且将值设置为`true`，如果文档不存在，它将创建该文档。

通过这种方式，我们将确保用户的收件箱完全位于单个分片上。与扇入写相反，在查看收件箱时我们有许多随机读取，而在扇出写与存储桶中，我们对于每 50 条用户消息只进行一次文档读取。

在写入时使用存储桶进行扇出无疑是社交收件箱模式设计的最佳选择，当我们的要求是高效地发送和阅读消息时。然而，`收件箱`集合的文档大小可能会成为一个问题。根据消息的大小，我们将不得不小心管理我们的存储空间。

# 总结

模式设计是更好的可扩展性策略。无论我们手头有多少技术和工具，了解我们的数据将如何使用并花时间设计是更便宜和持久的方法。

在下一章中，您将运用到目前为止学到的一切，为一个真实的例子从零开始创建一个模式设计。
